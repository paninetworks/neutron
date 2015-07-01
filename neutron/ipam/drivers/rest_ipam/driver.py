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
        retval = cls(neutron_subnet_id,
                   ctx,
                   cidr=neutron_subnet['cidr'],
                   gateway_ip=neutron_subnet['gateway_ip'],
                   tenant_id=neutron_subnet['tenant_id'],
                   subnet_id=neutron_subnet_id)
        LOG.debug("IPAM subnet loaded: %s" % retval)
        return retval

    @classmethod
    def _fetch_subnet(cls, context, id):
        plugin = manager.NeutronManager.get_plugin()
        return plugin._get_subnet(context, id)

    def __init__(self, internal_id, ctx, cidr=None,
                 gateway_ip=None, tenant_id=None,
                 subnet_id=None):
        self._cidr = cidr
        self._pools = []
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
        LOG.debug("IPAM URL: %s" % self.ipam_url)
            
        
        


    def allocate(self, address_request):
        if isinstance(address_request, ipam.SpecificAddressRequest):
            raise Exception("We don't do that.")
        url = "%s/allocateIpByName?tenantName=%s&segmentName=%s&hostName=%s&instanceId=0" % (self.ipam_url, self._tenant_id, self._subnet_id, address_request.host_id)
        try:
            response = urllib2.urlopen(url)
            LOG.debug("IPAM: Calling %s" % url)
            r = response.read()
            LOG.debug("IPAM: Received %s" % r)
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

        count = 1
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
