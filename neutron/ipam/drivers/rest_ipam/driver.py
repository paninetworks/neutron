# Copyright 2015 OpenStack LLC.
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

import simplejson
import urllib2
import netaddr
from oslo_log import log

from oslo_config import cfg
from neutron.common import exceptions as n_exc
from neutron.common import ipv6_utils
from neutron.i18n import _LE
from neutron import ipam
from neutron.ipam import driver as ipam_base
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import subnet_alloc
from neutron.ipam import utils as ipam_utils
from neutron import manager
from neutron.openstack.common import uuidutils


LOG = log.getLogger(__name__)


class RestDbSubnet(ipam_base.Subnet):
    

    @classmethod
    def create_from_subnet_request(cls, subnet_request, ctx):
        tenant_id = ctx.tenant_id
        ipam_subnet_id = uuidutils.generate_uuid()
        # Create subnet resource
        session = ctx.session
        
        me = cls(ipam_subnet_id,
                   ctx,
                   cidr=subnet_request.subnet_cidr,
                   allocation_pools=None,
                   gateway_ip=subnet_request.gateway_ip,
                   tenant_id=subnet_request.tenant_id,
                   subnet_id=subnet_request.subnet_id)
        me.allocate_segment()
        return me

    def allocate_segment(self):
        url = "%s/addSegmentByName?tenantName=%s&segmentName=%s" % (self.ipam_url, self._tenant_id, self._subnet_id)
        try:
            r = urllib2.urlopen(url)
            resp = r.read()
            print resp
        except Exception, e:
            raise ipam_exc.IpAddressGenerationFailure()
        
    
    @classmethod
    def load(cls, neutron_subnet_id, ctx):
        neutron_subnet = cls._fetch_subnet(ctx, neutron_subnet_id)
        return cls(neutron_subnet_id,
                   ctx,
                   cidr=neutron_subnet['cidr'],
                   allocation_pools=None,
                   gateway_ip=neutron_subnet['gateway_ip'],
                   tenant_id=neutron_subnet['tenant_id'],
                   subnet_id=neutron_subnet_id)

    @classmethod
    def _fetch_subnet(cls, context, id):
        plugin = manager.NeutronManager.get_plugin()
        return plugin._get_subnet(context, id)

    def __init__(self, internal_id, ctx, cidr=None,
                 allocation_pools=None, gateway_ip=None, tenant_id=None,
                 subnet_id=None):
        # NOTE: In theory it could have been possible to grant the IPAM
        # driver direct access to the database. While this is possible,
        # it would have led to duplicate code and/or non-trivial
        # refactorings in neutron.db.db_base_plugin_v2.
        # This is because in the Neutron V2 plugin logic DB management is
        # encapsulated within the plugin.
        self._cidr = cidr
        self._pools = allocation_pools
        self._gateway_ip = gateway_ip
        self._tenant_id = tenant_id
        self._subnet_id = subnet_id
        self._context = ctx
        self._neutron_id = internal_id
        
        if not cfg.CONF.ipam_driver_config:
            raise ipam_exc.exceptions.InvalidConfigurationOption({'opt_name' : 'ipam_driver_config', 
                                                                  'opt_value' : 'missing'})
        ipam_config_filename = cfg.CONF.ipam_driver_config
        lines = []
        with open(ipam_config_filename) as ipam_config_f:
            lines = ipam_config_f.readlines()
        self.ipam_url = None
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            kv = line.split('=',1)
            if len(kv) != 2:
                ipam_exc.exceptions.InvalidConfigurationOption({'opt_name' : '%s' % kv, 
                                                                'opt_value' : 'missing'})
            key= kv[0].strip()
            val = kv[1].strip()
            if key == 'ipam_driver_url':
                self.ipam_url = val
            break
        if not self.ipam_url:
            raise ipam_exc.exceptions.InvalidConfigurationOption({'opt_name' : 'ipam_driver_url', 
                                                                  'opt_value' : 'missing'})
            
        
        

    def _allocate_specific_ip(self, session, ip_address,
                              allocation_pool_id=None):
        """Remove an IP address from subnet's availability ranges.

        This method is supposed to be called from within a database
        transaction, otherwise atomicity and integrity might not be
        enforced and the operation might result in incosistent availability
        ranges for the subnet.

        :param session: database session
        :param ip_address: ip address to mark as allocated
        :param allocation_pool_id: identifier of the allocation pool from
             which the ip address has been extracted. If not specified this
             routine will scan all allocation pools.
        :returns: list of IP ranges as instances of IPAvailabilityRange
        """
        # Return immediately for EUI-64 addresses. For this
        # class of subnets availability ranges do not apply
        if ipv6_utils.is_eui64_address(ip_address):
            return

        LOG.debug("Removing %(ip_address)s from availability ranges for "
                  "subnet id:%(subnet_id)s",
                  {'ip_address': ip_address,
                   'subnet_id': self._neutron_id})
        # Netaddr's IPRange and IPSet objects work very well even with very
        # large subnets, including IPv6 ones.
        final_ranges = []
        if allocation_pool_id:
            av_ranges = self.subnet_manager.list_ranges_by_allocation_pool(
                session, allocation_pool_id, locking=True)
        else:
            av_ranges = self.subnet_manager.list_ranges_by_subnet_id(
                session, locking=True)
        for db_range in av_ranges:
            initial_ip_set = netaddr.IPSet(netaddr.IPRange(
                db_range['first_ip'], db_range['last_ip']))
            final_ip_set = initial_ip_set - netaddr.IPSet([ip_address])
            if not final_ip_set:
                # Range exhausted - bye bye
                session.delete(db_range)
                continue
            if initial_ip_set == final_ip_set:
                # IP address does not fall within the current range, move
                # to the next one
                final_ranges.append(db_range)
                continue
            for new_range in final_ip_set.iter_ipranges():
                # store new range in database
                # use netaddr.IPAddress format() method which is equivalent
                # to str(...) but also enables us to use different
                # representation formats (if needed) for IPv6.
                first_ip = netaddr.IPAddress(new_range.first)
                last_ip = netaddr.IPAddress(new_range.last)
                if (db_range['first_ip'] == first_ip.format() or
                    db_range['last_ip'] == last_ip.format()):
                    db_range['first_ip'] = first_ip.format()
                    db_range['last_ip'] = last_ip.format()
                    LOG.debug("Adjusted availability range for pool %s",
                              db_range['allocation_pool_id'])
                    final_ranges.append(db_range)
                else:
                    new_ip_range = self.subnet_manager.create_range(
                        session,
                        db_range['allocation_pool_id'],
                        first_ip.format(),
                        last_ip.format())
                    LOG.debug("Created availability range for pool %s",
                              new_ip_range['allocation_pool_id'])
                    final_ranges.append(new_ip_range)
        # Most callers might ignore this return value, which is however
        # useful for testing purposes
        LOG.debug("Availability ranges for subnet id %(subnet_id)s "
                  "modified: %(new_ranges)s",
                  {'subnet_id': self._neutron_id,
                   'new_ranges': ", ".join(["[%s; %s]" %
                                            (r['first_ip'], r['last_ip']) for
                                            r in final_ranges])})
        return final_ranges

    def _rebuild_availability_ranges(self, session):
        pass

    def _generate_ip(self, session):
        try:
            return self._try_generate_ip(session)
        except ipam_exc.IpAddressGenerationFailure:
            self._rebuild_availability_ranges(session)

        return self._try_generate_ip(session)

    def _try_generate_ip(self, session):
        """Generate an IP address from availability ranges."""
        ip_range = self.subnet_manager.get_first_range(session, locking=True)
        if not ip_range:
            LOG.debug("All IPs from subnet %(subnet_id)s allocated",
                      {'subnet_id': self._neutron_id})
            raise ipam_exc.IpAddressGenerationFailure(
                subnet_id=self._neutron_id)
        # A suitable range was found. Return IP address.
        ip_address = ip_range['first_ip']
        LOG.debug("Allocated IP - %(ip_address)s from range "
                  "[%(first_ip)s; %(last_ip)s]",
                  {'ip_address': ip_address,
                   'first_ip': ip_address,
                   'last_ip': ip_range['last_ip']})
        return ip_address, ip_range['allocation_pool_id']

    def allocate(self, address_request):
        if isinstance(address_request, ipam.SpecificAddressRequest):
            raise Exception("We don't do that.")
        url = "%s/allocateIpByName?tenantName=%s&segmentName=%s&hostName=%s&instanceId=0" % (self.ipam_url, self._tenant_id, self._subnet_id, address_request.host_id)
        try:
            response = urllib2.urlopen(url)
            r = response.read()
            json = simplejson.loads(r)
            ip = json['ip']
        except Exception, e:
            raise ipam_exc.IpAddressGenerationFailure()
        return ip
       
       

    def deallocate(self, address):
        # This is almost a no-op because the Neutron DB IPAM driver does not
        # delete IPAllocation objects, neither rebuilds availability ranges
        # at every deallocation. The only operation it performs is to delete
        # an IPRequest entry.
        session = self._context.session

        count = self.subnet_manager.delete_allocation(
            session, address)
        # count can hardly be greater than 1, but it can be 0...
        if not count:
            raise ipam_exc.IpAddressAllocationNotFound(
                subnet_id=self._neutron_id,
                ip_address=address)

    def update_allocation_pools(self, pools):
        pass

    def get_details(self):
        """Return subnet data as a SpecificSubnetRequest"""
        return ipam.SpecificSubnetRequest(
            self._tenant_id, self._neutron_id,
            self._cidr, self._gateway_ip, self._pools)


class RestDbPool(subnet_alloc.SubnetAllocator):
   
    def get_subnet(self, subnet_id):
        """Retrieve an IPAM subnet.

        :param subnet_id: Neutron subnet identifier
        :returns: a RestDbSubnet instance
        """
        return RestDbSubnet.load(subnet_id, self._context)

    def allocate_subnet(self, subnet_request):
        """Create an IPAMSubnet object for the provided cidr.

        This method does not actually do any operation in the driver, given
        its simplified nature.

        :param cidr: subnet's CIDR
        :returns: a RestDbSubnet instance
        """
        if not isinstance(subnet_request, ipam.SpecificSubnetRequest):
            raise ipam_exc.InvalidSubnetRequestType(
                subnet_type=type(subnet_request))
        return RestDbSubnet.create_from_subnet_request(subnet_request,
                                                          self._context)

    def update_subnet(self, subnet_request):
        """Update subnet info the in the IPAM driver.

        The only update subnet information the driver needs to be aware of
        are allocation pools.
        """
        if not subnet_request.subnet_id:
            raise ipam_exc.InvalidSubnetRequest(
                reason=("An identifier must be specified when updating "
                        "a subnet"))
        if not subnet_request.allocation_pools:
            LOG.debug("Update subnet request for subnet %s did not specify "
                      "new allocation pools, there is nothing to do",
                      subnet_request.subnet_id)
            return
        subnet = RestDbSubnet.load(subnet_request.subnet_id, self._context)
        subnet.update_allocation_pools(subnet_request.allocation_pools)
        return subnet

    def remove_subnet(self, subnet_id):
        raise n_exc.SubnetNotFound(subnet_id=subnet_id)
