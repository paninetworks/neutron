Routed Networks
===============

This document describes and proposes a type of Neutron network in
which connectivity between the VMs attached to that network is
provided by L3 routing.  This type of network provides full (subject
to security policy) IP connectivity between VMs in that and other
routed networks: v4 and v6, unicast and multicast; but it provides no
L2 capability, except as required for this IP connectivity, plus
correct operation of the ICMP, ARP and NDP protocols that exist to
support IP.  Therefore, this kind of network is suitable for VMs that
only communicate over IP.

Why would anyone want that?  Compared to the other kinds of networks
that provide connectivity at L2, its arguable benefits are as follows.

- It is conceptually simpler, in that VM data is transported in a
  uniform way between a VM and its compute host, between compute
  hosts, and between the data center network and the outside world,
  without any encapsulation changes anywhere.

- As a practical consequence, it is easier to debug, using standard
  tools such as ping, traceroute, wireshark and tcpdump.

- Its scale is not limited in the way that VLAN-based networks are, by
  the practical diameter of the physical underlying L2 network.

As far as we are aware, Project Calico is the first public
implementation of the routed network model.  Implementers and
operators are invited to study the details and operational
considerations of a functional example of the routed model at the
project's website_.

.. _website: http://www.projectcalico.org/

Description on the Neutron API
------------------------------

A routed network is described on the Neutron API using a new provider
network type: TYPE_ROUTED = 'routed'.  The related physical network
and segmentation ID parameters are not meaningful and should be left
unspecified.

  Note: The best way to model a routed network in Neutron is a matter
  of current debate on the openstack-dev mailing list as well as in
  comments on this devref, and it may well end up involving one of the
  more obviously L3 Neutron objects (routers, subnets, pools and
  address scopes), instead of being a new network type.  Until there
  seems to be a consensus way forward, however, this devref continues
  to describe a new network type, for the sake of proposing something
  concrete.

A routed network can be shared or private; this is indicated as usual
by presence or absence of the 'shared' flag.

As normal in Neutron, 'private' primarily means that that network is
only available for use by the tenant that created it.  It may also
mean that the network uses IP addressing in a non-default address
scope - typically private to the tenant; this permits its IP addresses
to overlap with the same IP addresses in other address scopes.

Similarly, 'shared' primarily means available to all tenants, and
typically also that the network uses IP addresses in the default
address scope.  But it's possible also to create a shared network in a
non-default address scope.

There is assumed automatic connectivity between routed networks in the
same address scope; and between the outside world and routed networks
in the default address scope.  Routed networks thus differ from
L2-based network types, as the latter would require an explicit
Neutron router object, for mutual or external connectivity.

  Note that with this automatic connectivity, it is still easy for a
  particular tenant to get effective isolation for its own group of
  VMs.  The tenant just needs to create its own security group, and
  use that security group when launching its own instances.

Floating IPs are not used with routed networks.  Because of the
preceding connectivity point, it is practical to configure two routed
networks, one with DC-private (e.g. RFC 1918) IP addresses, and one
with a range of globally routable IP addresses.  Then, when launching
a VM, it can simply be attached to the latter if it requires inbound
connectivity from the Internet, and to the former if not.

Connectivity Implementation - Default Address Scope
---------------------------------------------------

For networks in the default address scope, everything happens in the
default namespace of the relevant compute hosts.  Standard Linux
routing routes VM data, with iptables used to implement the configured
security policy.

A VM is 'plugged' with a TAP device on the host that connects to the
VM's network stack.  The host end of the TAP is left unbridged and
without any IP addresses (except for link-local IPv6).  The host is
configured to respond to any ARP or NDP requests, through that TAP,
with its own MAC address; hence data arriving through the TAP is
always addressed at L2 to the host, and is passed to the Linux routing
layer.

For each local VM, the host programs a route to that VM's IP
address(es) through the relevant TAP device.  The host also runs a BGP
client (BIRD) so as to export those routes to other compute hosts.
The routing table on a compute host might therefore look like this:

.. code::

 user@host02:~$ route -n
 Kernel IP routing table
 Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
 0.0.0.0         172.18.203.1    0.0.0.0         UG    0      0        0 eth0
 10.65.0.21      172.18.203.126  255.255.255.255 UGH   0      0        0 eth0
 10.65.0.22      172.18.203.129  255.255.255.255 UGH   0      0        0 eth0
 10.65.0.23      172.18.203.129  255.255.255.255 UGH   0      0        0 eth0
 10.65.0.24      0.0.0.0         255.255.255.255 UH    0      0        0 tapa429fb36-04
 172.18.203.0    0.0.0.0         255.255.255.0   U     0      0        0 eth0

This shows one local VM on this host with IP address 10.65.0.24,
accessed via a TAP named tapa429fb36-04; and three VMs, with the .21,
.22 and .23 addresses, on two other hosts (172.18.203.126 and .129),
and hence with routes via those compute host addresses.

DHCP
----

DHCP service in this type of network can be provided by Dnsmasq using
its --bridge-interface option.  The following patches enhance the DHCP
agent and IP library to allow it to be used in this way.

- https://review.openstack.org/205181
- https://review.openstack.org/206077
- https://review.openstack.org/206078
- https://review.openstack.org/206079

This patch then shows how a custom interface driver can be defined, to
drive the DHCP agent as needed for routed networking.

- https://review.openstack.org/197578

Note that these patches are independent of however we decide to model
routed network in terms of Neutron objects, because the DHCP agent's
behaviour is currently driven by a config-specified interface_driver
setting (pointing to an InterfaceDriver class that may be either in or
out of tree) and not by any properties of the runtime Neutron network
object.

Connectivity Implementation - Non-Default Address Scopes
--------------------------------------------------------

Full details here are still to be tied down, but broadly this is the
same as in the default case except for the following points.

- For each non-default address scope, there is a corresponding
  non-default namespace on the host, in which the routing for that
  address scope is performed.

- The TAP devices for ports in a non-default address scope are moved
  into the corresponding namespace, on the host side.

- Some translation, tunneling or overlay technology is used to connect
  those namespaces, between participating compute hosts.  Options here
  include 464XLAT and any of the tunneling technologies used in
  Neutron L2 network types.

Work Needed
-----------

For the default address scope case, the following work is needed for
Neutron to support routed networks in principle, and for Project
Calico to provide a working practical implementation, using vanilla
Neutron.

- Create an openstack/networking-calico project, in the Neutron big
  tent, to contain Project Calico's Neutron-specific code.  As the
  implementation currently stands, this consists of an ML2 mechanism
  driver, a custom interface driver for the DHCP agent, and a Devstack
  plugin.  (This work is currently out-of-tree at
  https://github.com/Metaswitch/calico and is already fairly mature.
  It will move to openstack/networking-calico project once that
  project has been created.)

- Review, revise and merge the DHCP agent patches listed above
  (excepting the custom interface driver).  This will allow
  openstack/networking-calico to work 'out of the box' with a vanilla
  Neutron core.

- Discuss and decide how 'routed' networking should best be modelled
  in the Neutron API and data model, and document that.

- Work on any further adaptations of the DHCP agent (and any other
  relevant components of the Neutron reference implementation) that
  are needed to support the agreed 'routed' model.

- Work on any adaptation of the openstack/networking-calico that is
  needed so as to properly reflect the agreed model for routed
  networking.

Further work will be needed for non-default address scopes, and for IP
multicast, but we propose to cover those in separate future phases.

References
----------

 - https://review.openstack.org/#/c/197578/
 - https://github.com/Metaswitch/calico
 - http://www.projectcalico.org/
