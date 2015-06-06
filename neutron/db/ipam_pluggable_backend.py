# Copyright (c) 2015 Infoblox Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import netaddr
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy import and_

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.common import ipv6_utils
from neutron.db import ipam_backend_mixin
from neutron.db import models_v2
from neutron.i18n import _LE
from neutron import ipam
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import utils as ipam_utils


LOG = logging.getLogger(__name__)


class IpamPluggableBackend(ipam_backend_mixin.IpamBackendMixin):

    def _ipam_deallocate_ips(self, ipam_driver, ips, revert_on_fail=True):
        """Deallocate set of ips over IPAM.

            If any single ip deallocation fails, tries to allocate deallocated
            ip addresses with fixed ip request
        """
        deallocated = []

        try:
            for ip in ips:
                try:
                    ipam_subnet = ipam_driver.get_subnet(ip['subnet_id'])
                    ipam_subnet.deallocate(ip['ip_address'])
                    deallocated.append(ip)
                except n_exc.SubnetNotFound:
                    LOG.debug("Subnet was not found on ip deallocation: %s",
                              ip)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(
                    _LE("An exception occurred during IP deallocation."))
                if revert_on_fail and deallocated:
                    LOG.error(_LE("Reverting deallocation"))
                    self._ipam_allocate_ips(ipam_driver, deallocated,
                                            revert_on_fail=False)
        return deallocated

    def _ipam_try_allocate_ip(self, ipam_driver, ip):
        # A factory pattern with a tweak
        if 'eui64_address' in ip:
            ip_request = ipam.AutomaticAddressRequest(
                prefix=ip['subnet_cidr'],
                mac=ip['mac'])
        else:
            fixed_ip = ip['ip_address'] if 'ip_address' in ip else None
            ip_request = ipam.AddressRequestFactory(fixed_ip)
        ipam_subnet = ipam_driver.get_subnet(ip['subnet_id'])
        return ipam_subnet.allocate(ip_request)

    def _ipam_allocate_single_ip(self, ipam_driver, network_id, subnets):
        """Allocates single ip from set of subnets

            Raises n_exc.IpAddressGenerationFailure if allocation failed for
            all subnets.
        """
        for subnet_ip in subnets:
            try:
                return [self._ipam_try_allocate_ip(ipam_driver, subnet_ip),
                        subnet_ip]
            except ipam_exc.IpAddressGenerationFailure:
                continue
        raise n_exc.IpAddressGenerationFailure(
            net_id=network_id)

    def _ipam_allocate_ips(self, ipam_driver, ips, revert_on_fail=True):
        """Allocate set of ips over IPAM.

            If any single ip allocation fails, tries to deallocate all
            allocated ip addresses.
        """
        allocated = []

        # we need to start with entries that asked for a specific IP in case
        # those IPs happen to be next in the line for allocation for ones that
        # didn't ask for a specific IP
        ips.sort(key=lambda x: 'ip_address' not in x)
        try:
            for ip in ips:
                subnets = ip['subnets'] if 'subnets' in ip else [ip]
                ip_address, ip_subnet = self._ipam_allocate_single_ip(
                    ipam_driver, ip['network_id'], subnets)
                allocated.append({'ip_address': ip_address,
                                  'subnet_cidr': ip_subnet['subnet_cidr'],
                                  'subnet_id': ip_subnet['subnet_id']})
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("An exception occurred during IP allocation."))

                if revert_on_fail and allocated:
                    LOG.error(_LE("Reverting allocation"))
                    self._ipam_deallocate_ips(ipam_driver, allocated,
                                              revert_on_fail=False)

        return allocated

    def _ipam_update_allocation_pools(self, ipam_driver, subnet_id, cidr,
                                      allocation_pools, tenant_id=None):
        self._validate_allocation_pools(allocation_pools, cidr)
        ip_range_pool = [netaddr.IPRange(p['start'], p['end'])
                         for p in allocation_pools]

        subnet_request = ipam.SubnetRequestFactory(
            tenant_id,
            subnet_id,
            cidr,
            allocation_pools=ip_range_pool)
        ipam_driver.update_subnet(subnet_request)

    def _populate_subnet_cidr(self, context, ips):
        """Populates 'ips' dict with subnet_cidr from subnet_id
        Warning: affects incoming 'ips' dict
        """
        for ip in ips:
            if 'subnet_cidr' not in ip:
                subnet = self._get_subnet(context, ip['subnet_id'])
                ip['subnet_cidr'] = subnet['cidr']
        return ips

    def ipam_delete_subnet(self, context, subnet_id):
        ipam_driver = self._get_ipam_subnetpool_driver(context)
        ipam_driver.remove_subnet(subnet_id)

    def allocate_ips_for_port_and_store(self, context, port, port_id):
        network_id = port['port']['network_id']
        ips = []
        try:
            ips = self._allocate_ips_for_port(context, port)
            if ips:
                for ip in ips:
                    ip_address = ip['ip_address']
                    subnet_id = ip['subnet_id']
                    IpamPluggableBackend._store_ip_allocation(
                        context, ip_address, network_id,
                        subnet_id, port_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                if ips:
                    LOG.error(
                        _LE("An exception occurred during port creation."
                            "Reverting IP allocation"))
                    ipam_driver = self._get_ipam_subnetpool_driver(context)
                    self._ipam_deallocate_ips(ipam_driver, ips,
                                              revert_on_fail=False)

    def _allocate_ips_for_port(self, context, port):
        """Allocate IP addresses for the port. IPAM version.

        If port['fixed_ips'] is set to 'ATTR_NOT_SPECIFIED', allocate IP
        addresses for the port. If port['fixed_ips'] contains an IP address or
        a subnet_id then allocate an IP address accordingly.
        """
        p = port['port']
        ips = []
        v6_stateless = []
        net_id_filter = {'network_id': [p['network_id']]}
        subnets = self._get_subnets(context, filters=net_id_filter)
        is_router_port = (
            p['device_owner'] in constants.ROUTER_INTERFACE_OWNERS or
            p['device_owner'] == constants.DEVICE_OWNER_ROUTER_SNAT)

        fixed_configured = p['fixed_ips'] is not attributes.ATTR_NOT_SPECIFIED
        if fixed_configured:
            ips = self._test_fixed_ips_for_port(context,
                                                p["network_id"],
                                                p['fixed_ips'],
                                                p['device_owner'],
                                                p['mac_address'])
            # For ports that are not router ports, implicitly include all
            # auto-address subnets for address association.
            if not is_router_port:
                v6_stateless += [subnet for subnet in subnets
                                 if ipv6_utils.is_auto_address_subnet(subnet)]
        else:
            # Split into v4, v6 stateless and v6 stateful subnets
            v4 = []
            v6_stateful = []
            for subnet in subnets:
                if subnet['ip_version'] == 4:
                    v4.append(subnet)
                else:
                    if ipv6_utils.is_auto_address_subnet(subnet):
                        if not is_router_port:
                            v6_stateless.append(subnet)
                    else:
                        v6_stateful.append(subnet)

            version_subnets = [v4, v6_stateful]
            for subnets in version_subnets:
                if subnets:
                    subs = {'subnets': [],
                            'network_id': p["network_id"]}
                    for subnet in subnets:
                        subs['subnets'].append({
                            'subnet': subnet,
                            'subnet_id': subnet['id'],
                            'subnet_cidr': subnet['cidr']})
                    ips.append(subs)

        for subnet in v6_stateless:
            # IP addresses for IPv6 SLAAC and DHCPv6-stateless subnets
            # are implicitly included.
            ips.append({'subnet_id': subnet['id'],
                        'subnet': subnet,
                        'subnet_cidr': subnet['cidr'],
                        'network_id': p['network_id'],
                        'eui64_address': True,
                        'mac': p['mac_address']})
        ipam_driver = self._get_ipam_subnetpool_driver(context)
        return self._ipam_allocate_ips(ipam_driver, ips)

    def _test_fixed_ips_for_port(self, context, network_id, fixed_ips,
                                 device_owner, mac):
        """Test fixed IPs for port.

        Check that configured subnets are valid prior to allocating any
        IPs. Include the subnet_id in the result if only an IP address is
        configured.

        :raises: InvalidInput, IpAddressInUse, InvalidIpForNetwork,
                 InvalidIpForSubnet
        """
        fixed_ip_set = []
        for fixed in fixed_ips:
            found = False
            if 'subnet_id' not in fixed:
                if 'ip_address' not in fixed:
                    msg = _('IP allocation requires subnet_id or ip_address')
                    raise n_exc.InvalidInput(error_message=msg)

                filter = {'network_id': [network_id]}
                subnets = self._get_subnets(context, filters=filter)
                for subnet in subnets:
                    if ipam_utils.check_subnet_ip(subnet['cidr'],
                                                  fixed['ip_address']):
                        found = True
                        subnet_id = subnet['id']
                        subnet_cidr = subnet['cidr']
                        break
                if not found:
                    raise n_exc.InvalidIpForNetwork(
                        ip_address=fixed['ip_address'])
            else:
                subnet = self._get_subnet(context, fixed['subnet_id'])
                if subnet['network_id'] != network_id:
                    msg = (_("Failed to create port on network %(network_id)s"
                             ", because fixed_ips included invalid subnet "
                             "%(subnet_id)s") %
                           {'network_id': network_id,
                            'subnet_id': fixed['subnet_id']})
                    raise n_exc.InvalidInput(error_message=msg)
                subnet_id = subnet['id']
                subnet_cidr = subnet['cidr']
            is_auto_addr_subnet = ipv6_utils.is_auto_address_subnet(subnet)
            if 'ip_address' in fixed:
                if (is_auto_addr_subnet and device_owner not in
                        constants.ROUTER_INTERFACE_OWNERS):
                    msg = (_("IPv6 address %(address)s can not be directly "
                            "assigned to a port on subnet %(id)s since the "
                            "subnet is configured for automatic addresses") %
                           {'address': fixed['ip_address'],
                            'id': subnet_id})
                    raise n_exc.InvalidInput(error_message=msg)
                fixed_ip_set.append({'subnet_id': subnet_id,
                                     'network_id': network_id,
                                     'subnet_cidr': subnet_cidr,
                                     'ip_address': fixed['ip_address']})
            else:
                # A scan for auto-address subnets on the network is done
                # separately so that all such subnets (not just those
                # listed explicitly here by subnet ID) are associated
                # with the port.
                if (device_owner in constants.ROUTER_INTERFACE_OWNERS or
                    device_owner == constants.DEVICE_OWNER_ROUTER_SNAT or
                    not is_auto_addr_subnet):
                    ip = {'subnet_id': subnet_id,
                          'network_id': network_id,
                          'subnet_cidr': subnet_cidr}
                    if is_auto_addr_subnet:
                        ip['eui64_address'] = True
                        ip['mac'] = mac
                    fixed_ip_set.append(ip)

        if len(fixed_ip_set) > cfg.CONF.max_fixed_ips_per_port:
            msg = _('Exceeded maximim amount of fixed ips per port')
            raise n_exc.InvalidInput(error_message=msg)
        return fixed_ip_set

    def _update_ips_for_port(self, context, network_id,
                             original_ips, new_ips, mac, device_owner):
        """Add or remove IPs from the port. IPAM version"""
        added = []
        removed = []
        changes = self._get_changed_ips_for_port(context, original_ips,
                                                 new_ips, device_owner)
        # Check if the IP's to add are OK
        to_add = self._test_fixed_ips_for_port(context, network_id,
                                               changes.add, device_owner, mac)

        ipam_driver = self._get_ipam_subnetpool_driver(context)
        if changes.remove:
            self._populate_subnet_cidr(context, changes.remove)
            removed = self._ipam_deallocate_ips(ipam_driver, changes.remove)
        if to_add:
            self._populate_subnet_cidr(context, to_add)
            added = self._ipam_allocate_ips(ipam_driver, to_add)
        return self.Changes(add=added,
                            original=changes.original,
                            remove=removed)

    def save_allocation_pools(self, context, subnet, allocation_pools):
        for pool in allocation_pools:
            first_ip = str(netaddr.IPAddress(pool.first))
            last_ip = str(netaddr.IPAddress(pool.last))
            ip_pool = models_v2.IPAllocationPool(subnet=subnet,
                                                 first_ip=first_ip,
                                                 last_ip=last_ip)
            context.session.add(ip_pool)

    def update_port_with_ips(self, context, db_port, new_port, new_mac):
        changes = self.Changes(add=[], original=[], remove=[])

        if 'fixed_ips' in new_port:
            original = self._make_port_dict(db_port,
                                            process_extensions=False)
            changes = self._update_ips_for_port(context,
                                                db_port['network_id'],
                                                original["fixed_ips"],
                                                new_port['fixed_ips'],
                                                new_mac,
                                                db_port['device_owner'])
        try:
            # Check if the IPs need to be updated
            network_id = db_port['network_id']
            for ip in changes.add:
                IpamPluggableBackend._store_ip_allocation(
                    context, ip['ip_address'], network_id,
                    ip['subnet_id'], db_port.id)
            for ip in changes.remove:
                IpamPluggableBackend._delete_ip_allocation(
                    context, network_id,
                    ip['subnet_id'], ip['ip_address'])
            self._update_db_port(context, db_port, new_port, network_id,
                                 new_mac)
        except Exception:
            with excutils.save_and_reraise_exception():
                if 'fixed_ips' in new_port:
                    LOG.error(
                        _LE("An exception occurred during port update."))
                    ipam_driver = self._get_ipam_subnetpool_driver(context)
                    if changes.add:
                        LOG.error(_LE("Reverting IP allocation."))
                        self._ipam_deallocate_ips(ipam_driver, changes.add,
                                                  revert_on_fail=False)
                    if changes.remove:
                        LOG.error(_LE("Reverting IP deallocation."))
                        self._ipam_allocate_ips(ipam_driver, changes.remove,
                                                revert_on_fail=False)
        return changes

    def delete_port(self, context, id):
        # Get fixed_ips list before port deletion
        port = self._get_port(context, id)
        ipam_driver = self._get_ipam_subnetpool_driver(context)
        self._populate_subnet_cidr(context, port['fixed_ips'])

        super(IpamPluggableBackend, self).delete_port(context, id)
        # Deallocating ips via IPAM after port is deleted locally.
        # So no need to do rollback actions on remote server
        # in case of fail to delete port locally
        self._ipam_deallocate_ips(ipam_driver, port['fixed_ips'])

    def update_db_subnet(self, context, id, s, old_pools):
        ipam_driver = self._get_ipam_subnetpool_driver(context)
        if "allocation_pools" in s:
            self._ipam_update_allocation_pools(ipam_driver,
                                               id,
                                               s['cidr'],
                                               s['allocation_pools'])

        try:
            subnet, changes = super(IpamPluggableBackend,
                                    self).update_db_subnet(context, id,
                                                           s, old_pools)
        except Exception:
            with excutils.save_and_reraise_exception():
                if "allocation_pools" in s and old_pools:
                    LOG.error(
                        _LE("An exception occurred during subnet update."
                            "Reverting allocation pool changes"))
                    self._ipam_update_allocation_pools(ipam_driver, id,
                                                       s['cidr'], old_pools)
        return [subnet, changes]

    def add_auto_addrs_on_network_ports(self, context, subnet, ipam_subnet):
        """For an auto-address subnet, add addrs for ports on the net."""
        with context.session.begin(subtransactions=True):
            network_id = subnet['network_id']
            port_qry = context.session.query(models_v2.Port)
            for port in port_qry.filter(
                and_(models_v2.Port.network_id == network_id,
                     models_v2.Port.device_owner !=
                     constants.DEVICE_OWNER_ROUTER_SNAT,
                     ~models_v2.Port.device_owner.in_(
                         constants.ROUTER_INTERFACE_OWNERS))):
                ip_request = ipam.AutomaticAddressRequest(
                    prefix=subnet['cidr'],
                    mac=port['mac_address'])
                ip_address = ipam_subnet.allocate(ip_request)
                allocated = models_v2.IPAllocation(network_id=network_id,
                                                   port_id=port['id'],
                                                   ip_address=ip_address,
                                                   subnet_id=subnet['id'])
                try:
                    # Do the insertion of each IP allocation entry within
                    # the context of a nested transaction, so that the entry
                    # is rolled back independently of other entries whenever
                    # the corresponding port has been deleted.
                    with context.session.begin_nested():
                        context.session.add(allocated)
                except db_exc.DBReferenceError:
                    LOG.debug("Port %s was deleted while updating it with an "
                              "IPv6 auto-address. Ignoring.", port['id'])
                    LOG.debug("Reverting IP allocation for %s", ip_address)
                    # Do not fail if reverting allocation was unsuccessful
                    try:
                        ipam_subnet.deallocate(ip_address)
                    except Exception:
                        LOG.debug("Reverting IP allocation failed for %s",
                                  ip_address)
