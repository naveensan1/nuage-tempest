# Copyright 2017 - Nokia
# All Rights Reserved.

from testtools.matchers import Equals
from testtools.matchers import ContainsDict

from netaddr import IPNetwork, IPAddress

from tempest import config
from tempest.common.utils import data_utils
from tempest.lib import exceptions as tempest_exceptions

from nuagetempest.lib.utils import constants as nuage_constants
from nuagetempest.lib.utils import exceptions as nuage_exceptions
from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import BaseNuageNetworksTestCase
from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import VsdTestCaseMixin
from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import NetworkTestCaseMixin

CONF = config.CONF

MSG_INVALID_GATEWAY = "Invalid IPv6 network gateway"
MSG_INVALID_IPV6_ADDRESS = "Invalid network IPv6 address"
MSG_IP_ADDRESS_INVALID_OR_RESERVED = "IP Address is not valid or cannot be in reserved address space"


class TestVSDManagedDualStackSubnetL2(VsdTestCaseMixin,
                                      NetworkTestCaseMixin,
                                      BaseNuageNetworksTestCase):

    def test_create_ipv6_subnet_in_vsd_managed_l2domain_dhcp_managed(self):
        """
            OpenStack IPv4 and IPv6 subnets linked to VSD l2 dualstack l2 domain
            - create VSD l2 domain template dualstack
            - create VSD l2 domain
            - create OS network
            - create OS subnets
            - create OS port
        """

        # create l2domain on VSD
        subnet_cidr = IPNetwork('10.10.100.0/24')
        subnet_gateway = str(IPAddress(subnet_cidr) + 1)
        subnet_ipv6_cidr = IPNetwork("2001:5f74:c4a5:b82e::/64")
        subnet_ipv6_gateway = str(IPAddress(subnet_ipv6_cidr) + 1)

        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=subnet_cidr,
            cidr6=subnet_ipv6_cidr,
            gateway=subnet_gateway,
            gateway6=subnet_ipv6_gateway)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=subnet_cidr,
                                           cidr6=subnet_ipv6_cidr,
                                           IPv6Gateway=subnet_ipv6_gateway,
                                           gateway=subnet_gateway)

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
        self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=subnet_gateway,
            cidr=subnet_cidr,
            mask_bits=24,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(ipv4_subnet['cidr'], str(subnet_cidr))

        # create a port in the network
        port_ipv4_only = self.create_port(network)
        self._verify_port(port_ipv4_only, subnet4=ipv4_subnet, subnet6=None,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)

        nuage_vports = self.nuage_vsd_client.get_vport(nuage_constants.L2_DOMAIN,
                                                       vsd_l2domain['ID'],
                                                       filters='externalID',
                                                       filter_value=port_ipv4_only['id'])
        self.assertEqual(len(nuage_vports), 1, "Must find one VPort matching port: %s" % port_ipv4_only['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport, ContainsDict({'name': Equals(port_ipv4_only['id'])}))

        # create Openstack IPv6 subnet on Openstack based on VSD l3domain subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=vsd_l2domain_template['IPv6Gateway'],
            cidr=IPNetwork(vsd_l2domain_template['IPv6Address']),
            mask_bits=64,
            enable_dhcp=False,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)

        self.assertEqual(ipv6_subnet['cidr'], vsd_l2domain_template['IPv6Address'])

        # create a port in the network
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)

        nuage_vports = self.nuage_vsd_client.get_vport(nuage_constants.L2_DOMAIN,
                                                       vsd_l2domain['ID'],
                                                       filters='externalID',
                                                       filter_value=port['id'])
        self.assertEqual(len(nuage_vports), 1, "Must find one VPort matching port: %s" % port['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport, ContainsDict({'name': Equals(port['id'])}))

    def test_create_ipv6_subnet_in_vsd_managed_l2domain_dhcp_unmanaged(self):
        """
            OpenStack IPv4 and IPv6 subnets linked to VSD l2 dualstack l2 domain
            - create VSD l2 domain template dualstack
            - create VSD l2 domain
            - create OS network
            - create OS subnets
            - create OS port
        """

        # create l2domain on VSD
        subnet_cidr = IPNetwork('10.10.100.0/24')
        subnet_gateway = str(IPAddress(subnet_cidr) + 1)
        subnet_ipv6_cidr = IPNetwork("2001:5f74:c4a5:b82e::/64")
        subnet_ipv6_gateway = str(IPAddress(subnet_ipv6_cidr) + 1)

        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=False,
            cidr4=subnet_cidr,
            cidr6=subnet_ipv6_cidr,
            gateway=subnet_gateway,
            gateway6=subnet_ipv6_gateway)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=False,
                                           cidr4=subnet_cidr,
                                           cidr6=subnet_ipv6_cidr,
                                           IPv6Gateway=subnet_ipv6_gateway,
                                           gateway=subnet_gateway)

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
        self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=subnet_gateway,
            cidr=subnet_cidr,
            mask_bits=24,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(ipv4_subnet['cidr'], str(subnet_cidr))

        # create a port in the network
        port_ipv4_only = self.create_port(network)
        self._verify_port(port_ipv4_only, subnet4=ipv4_subnet, subnet6=None,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)

        nuage_vports = self.nuage_vsd_client.get_vport(nuage_constants.L2_DOMAIN,
                                                       vsd_l2domain['ID'],
                                                       filters='externalID',
                                                       filter_value=port_ipv4_only['id'])
        self.assertEqual(len(nuage_vports), 1, "Must find one VPort matching port: %s" % port_ipv4_only['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport, ContainsDict({'name': Equals(port_ipv4_only['id'])}))

        # create Openstack IPv6 subnet on Openstack based on VSD l3domain subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=vsd_l2domain_template['IPv6Gateway'],
            cidr=IPNetwork(vsd_l2domain_template['IPv6Address']),
            mask_bits=64,
            enable_dhcp=False,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)

        self.assertEqual(ipv6_subnet['cidr'], vsd_l2domain_template['IPv6Address'])

        # create a port in the network
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)

        nuage_vports = self.nuage_vsd_client.get_vport(nuage_constants.L2_DOMAIN,
                                                       vsd_l2domain['ID'],
                                                       filters='externalID',
                                                       filter_value=port['id'])
        self.assertEqual(len(nuage_vports), 1, "Must find one VPort matching port: %s" % port['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport, ContainsDict({'name': Equals(port['id'])}))

    def test_create_ipv6_subnet_in_vsd_managed_l2domain_with_ipv6_network_first(self):
        """
            OpenStack IPv4 and IPv6 subnets linked to VSD l2 dualstack l2 domain
            - create VSD l2 domain template dualstack
            - create VSD l2 domain
            - create OS network
            - create OS subnets
            -- first the ipv6 network
            -- than the ipv4 network
            - create OS port
        """

        # create l2domain on VSD
        subnet_cidr = IPNetwork('10.10.100.0/24')
        subnet_gateway = str(IPAddress(subnet_cidr) + 1)
        subnet_ipv6_cidr = IPNetwork("2001:5f74:c4a5:b82e::/64")
        subnet_ipv6_gateway = str(IPAddress(subnet_ipv6_cidr) + 1)

        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=subnet_cidr,
            cidr6=subnet_ipv6_cidr,
            gateway=subnet_gateway,
            gateway6=subnet_ipv6_gateway)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=subnet_cidr,
                                           cidr6=subnet_ipv6_cidr,
                                           IPv6Gateway=subnet_ipv6_gateway,
                                           gateway=subnet_gateway)

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
        self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)

        # create Openstack IPv6 subnet on Openstack based on VSD l3domain subnet
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=vsd_l2domain_template['IPv6Gateway'],
            cidr=IPNetwork(vsd_l2domain_template['IPv6Address']),
            mask_bits=IPNetwork(vsd_l2domain_template['IPv6Address'])._prefixlen,
            enable_dhcp=False,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)

        self.assertEqual(ipv6_subnet['cidr'], vsd_l2domain_template['IPv6Address'])

        # should not allow to create a port in this network, as we do not have IPv4 network linked
        self.assertRaises(
            tempest_exceptions.ServerFault,
            self.create_port,
            network)

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        ipv4_subnet = self.create_subnet(
            network,
            gateway=subnet_gateway,
            cidr=subnet_cidr,
            mask_bits=24,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(ipv4_subnet['cidr'], str(subnet_cidr))  # create a port in the network - IPAM by OS
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)

        nuage_vports = self.nuage_vsd_client.get_vport(nuage_constants.L2_DOMAIN,
                                                       vsd_l2domain['ID'],
                                                       filters='externalID',
                                                       filter_value=port['id'])
        self.assertEqual(len(nuage_vports), 1, "Must find one VPort matching port: %s" % port['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport, ContainsDict({'name': Equals(port['id'])}))

        # create a port in the network - IPAM by OS
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)

        nuage_vports = self.nuage_vsd_client.get_vport(nuage_constants.L2_DOMAIN,
                                                       vsd_l2domain['ID'],
                                                       filters='externalID',
                                                       filter_value=port['id'])
        self.assertEqual(len(nuage_vports), 1, "Must find one VPort matching port: %s" % port['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport, ContainsDict({'name': Equals(port['id'])}))

    ####################################################################################################################
    # Special cases
    ####################################################################################################################

    ########################################
    # backwards compatibility
    ########################################
    def test_create_vsd_l2domain_template_ipv4(self):
        """
            Create IPV4 l2 domain template does not provides IPv6 address -
        """
        subnet_cidr = IPNetwork(CONF.network.tenant_network_cidr)

        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="IPV4",
            cidr4=subnet_cidr,
            dhcp_managed=True)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="IPV4",
                                           dhcp_managed=True,
                                           cidr4=subnet_cidr,
                                           gateway=str(IPAddress(subnet_cidr) + 1),
                                           netmask=str(subnet_cidr.netmask))

    ########################################
    # minimal attributes - default values
    ########################################
    def test_create_vsd_l2domain_template_dhcp_managed_default(self):
        subnet_cidr = IPNetwork(CONF.network.tenant_network_cidr)

        vsd_l2domain_template = self.create_vsd_l2domain_template(
            dhcp_managed=True,
            cidr4=subnet_cidr)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="IPV4",
                                           dhcp_managed=True,
                                           cidr4=subnet_cidr)

    def test_create_vsd_l2domain_template_dualstack_default(self):
        subnet_cidr = IPNetwork(CONF.network.tenant_network_cidr)
        subnet_ipv6_cidr = IPNetwork(CONF.network.tenant_network_v6_cidr)

        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="DUALSTACK",
            cidr4=subnet_cidr,
            cidr6=subnet_ipv6_cidr,
            dhcp_managed=True)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=subnet_cidr,
                                           cidr6=subnet_ipv6_cidr)

    def test_create_subnets_in_l2domain_without_dhcp_management_and_ip_ranges(self):
        """ create l2domain on VSD with minimal arguments

            Default l2 domain template will have
            - no dhcp management
            - no IPv4 nor IPv6 addressing information
        """
        vsd_l2domain_template = self.create_vsd_l2domain_template()
        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="IPV4",
                                           dhcp_managed=False,
                                           IPv6Address=None,
                                           IPv6Gateway=None,
                                           address=None,
                                           gateway=None,
                                           netmask=None)

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        network = self.create_network()

        subnet_cidr = IPNetwork(CONF.network.tenant_network_cidr)
        subnet_maskbits = CONF.network.tenant_network_mask_bits
        subnet = self.create_subnet(
            network,
            cidr=subnet_cidr,
            mask_bits=subnet_maskbits,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition,
            enable_dhcp=False
        )

        # create ipv6 subnet
        subnet_ipv6_cidr = IPNetwork(CONF.network.tenant_network_v6_cidr)
        subnet_ipv6_gateway = str(IPAddress(subnet_ipv6_cidr) + 1)
        subnet_ipv6_mask_bits = subnet_ipv6_cidr._prefixlen
        # create Openstack IPv6 subnet on Openstack based on VSD l3domain subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=subnet_ipv6_gateway,
            cidr=subnet_ipv6_cidr,
            mask_bits=subnet_ipv6_mask_bits,
            enable_dhcp=False,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)

        # create a port in the network
        port = self.create_port(network)
        self._verify_port(port, subnet4=subnet, subnet6=ipv6_subnet, status='DOWN')

        nuage_vports = self.nuage_vsd_client.get_vport(nuage_constants.L2_DOMAIN,
                                                       vsd_l2domain['ID'],
                                                       filters='externalID',
                                                       filter_value=port['id'])
        self.assertEqual(len(nuage_vports), 1, "Must find one VPort matching port: %s" % port['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport, ContainsDict({'name': Equals(port['id'])}))

        # Todo
        # I can create an IPv6 subnet and ports get dual stack although the l2 domain template is supposed to
        # be IPv4 only

    ########################################
    # IPv6 address formats
    ########################################
    def test_create_vsd_l2domain_template_dualstack_valid(self):
        subnet_cidr = IPNetwork(CONF.network.tenant_network_cidr)

        # noinspection PyPep8
        valid_ipv6 = [
            ("2001:5f74:c4a5:b82e::/64", "2001:5f74:c4a5:b82e:0000:0000:0000:0001"),
                # valid address range, gateway full addressing - at first addres
            ("2001:5f74:c4a5:b82e::/64", "2001:5f74:c4a5:b82e::1"),
                # valid address range, gateway zero's compressed addressing - at first addres
            ("2001:5f74:c4a5:b82e::/64", "2001:5f74:c4a5:b82e:0:000::1"),
                # valid address range, gateway partly compressed addressing - at first addres

            ("2001:5f74:c4a5:b82e::/64", "2001:5f74:c4a5:b82e:ffff:ffff:ffff:ffff"),
                 # valid address, gateway at last addres
            ("2001:5f74:c4a5:b82e::/64", "2001:5f74:c4a5:b82e:f483:3427:ab3e:bc21"),
                 # valid address, gateway at random address

            ("2001:5F74:c4A5:B82e::/64", "2001:5f74:c4a5:b82e:f483:3427:aB3E:bC21"),
                 # valid address, gateway at random address - mixed case

            ("2001:5f74:c4a5:b82e::/64", "2001:5f74:c4a5:b82e:f4:00::f"),
                 # valid address, gateway at random address - compressed
            ("3ffe:0b00:0000:0001:5f74:0001:c4a5:b82e/64", "3ffe:0b00:0000:0001:5f74:0001:c4a5:ffff"),
                 # prefix not matching bit mask
            ("3ffe:0b00::/32", "3ffe:0b00::1"),
                  # prefix < 64
            ("2001::/16", "2001::1"),
                  # prefix 16
        ]

        for ipv6_cidr, ipv6_gateway in valid_ipv6:
            vsd_l2domain_template = self.create_vsd_l2domain_template(
                ip_type="DUALSTACK",
                cidr4=subnet_cidr,
                dhcp_managed=True,
                IPv6Address=ipv6_cidr,
                IPv6Gateway=ipv6_gateway
            )

            self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                               ip_type="DUALSTACK",
                                               dhcp_managed=True,
                                               cidr4=subnet_cidr,
                                               IPv6Address=ipv6_cidr,
                                               IPv6Gateway=ipv6_gateway)

            vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
            self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)

            # create Openstack IPv6 subnet on Openstack based on VSD l3domain subnet
            net_name = data_utils.rand_name('network-')
            network = self.create_network(network_name=net_name)

            ipv6_network = IPNetwork(ipv6_cidr)
            mask_bits = ipv6_network._prefixlen
            ipv6_subnet = self.create_subnet(
                network,
                ip_version=6,
                gateway=vsd_l2domain_template['IPv6Gateway'],
                cidr=IPNetwork(vsd_l2domain_template['IPv6Address']),
                mask_bits=mask_bits,
                enable_dhcp=False,
                nuagenet=vsd_l2domain['ID'],
                net_partition=CONF.nuage.nuage_default_netpartition)

            self.assertEqual(IPNetwork(ipv6_subnet['cidr']), IPNetwork(vsd_l2domain_template['IPv6Address']))

            # create Openstack IPv4 subnet on Openstack based on VSD l2domain
            ipv4_subnet = self.create_subnet(
                network,
                cidr=subnet_cidr,
                mask_bits=subnet_cidr._prefixlen,
                nuagenet=vsd_l2domain['ID'],
                net_partition=CONF.nuage.nuage_default_netpartition)
            self.assertEqual(ipv4_subnet['cidr'], str(subnet_cidr))  # create a port in the network - IPAM by OS

            # create a port in the network - IPAM by OS
            port = self.create_port(network)
            self._verify_port(port, subnet4=None, subnet6=ipv6_subnet,
                              status='DOWN',
                              nuage_policy_groups=None,
                              nuage_redirect_targets=[],
                              nuage_floatingip=None)

    def test_create_vsd_l2domain_template_dualstack_valid_failing_at_vsd(self):
        subnet_cidr = IPNetwork(CONF.network.tenant_network_cidr)

        valid_ipv6 = [
            ("2001:5f74:c4a5:b82e::/64", "2001:5f74:c4a5:b82e:100.12.13.1"),
            # valid address, gateway at mixed ipv4 and ipv6 format (digit-dot notation)
        ]

        for ipv6_cidr, ipv6_gateway in valid_ipv6:
            vsd_l2domain_template = self.create_vsd_l2domain_template(
                ip_type="DUALSTACK",
                cidr4=subnet_cidr,
                dhcp_managed=True,
                IPv6Address=ipv6_cidr,
                IPv6Gateway=ipv6_gateway
            )

            self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                               ip_type="DUALSTACK",
                                               dhcp_managed=True,
                                               cidr4=subnet_cidr,
                                               IPv6Address=ipv6_cidr,
                                               IPv6Gateway=ipv6_gateway)
            # todo create ports in these subnets

    def test_create_fixed_ipv6_ports_in_vsd_managed_l2domain(self):
        """
            OpenStack IPv4 and IPv6 subnets linked to VSD l2 dualstack l2 domain
            - create VSD l2 domain template dualstack
            - create VSD l2 domain
            - create OS network
            - create OS subnets
            - create OS port
        """

        # create l2domain on VSD
        subnet_cidr = IPNetwork('10.10.100.0/24')
        subnet_gateway = str(IPAddress(subnet_cidr) + 1)
        subnet_ipv6_cidr = IPNetwork("2001:5f74:c4a5:b82e::/64")
        subnet_ipv6_gateway = str(IPAddress(subnet_ipv6_cidr) + 1)

        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=subnet_cidr,
            cidr6=subnet_ipv6_cidr,
            gateway=subnet_gateway,
            gateway6=subnet_ipv6_gateway)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=subnet_cidr,
                                           cidr6=subnet_ipv6_cidr,
                                           IPv6Gateway=subnet_ipv6_gateway,
                                           gateway=subnet_gateway)

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
        self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=subnet_gateway,
            cidr=subnet_cidr,
            mask_bits=24,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(ipv4_subnet['cidr'], str(subnet_cidr))

        # create a port in the network
        port_ipv4_only = self.create_port(network)
        self._verify_port(port_ipv4_only, subnet4=ipv4_subnet, subnet6=None,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)

        nuage_vports = self.nuage_vsd_client.get_vport(nuage_constants.L2_DOMAIN,
                                                       vsd_l2domain['ID'],
                                                       filters='externalID',
                                                       filter_value=port_ipv4_only['id'])
        self.assertEqual(len(nuage_vports), 1, "Must find one VPort matching port: %s" % port_ipv4_only['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport, ContainsDict({'name': Equals(port_ipv4_only['id'])}))

        # create Openstack IPv6 subnet on Openstack based on VSD l3domain subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=vsd_l2domain_template['IPv6Gateway'],
            cidr=IPNetwork(vsd_l2domain_template['IPv6Address']),
            mask_bits=IPNetwork(vsd_l2domain_template['IPv6Address'])._prefixlen,
            enable_dhcp=False,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)

        self.assertEqual(ipv6_subnet['cidr'], vsd_l2domain_template['IPv6Address'])

        # create a port in the network
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)

        nuage_vports = self.nuage_vsd_client.get_vport(nuage_constants.L2_DOMAIN,
                                                       vsd_l2domain['ID'],
                                                       filters='externalID',
                                                       filter_value=port['id'])
        self.assertEqual(len(nuage_vports), 1, "Must find one VPort matching port: %s" % port['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport, ContainsDict({'name': Equals(port['id'])}))

    ####################################################################################################################
    # Negative cases
    ####################################################################################################################
    def test_l2domain_template_with_dhcp_management_should_have_ipv4_cidr_neg(self):
        """ create l2domain on VSD with

            - dhcp management
            - no IPv4 addressing information
        """

        # no IPv4 nor IPv6 addressing information
        self.assertRaises(
            nuage_exceptions.Conflict,
            self.create_vsd_l2domain_template,
            dhcp_managed=True)

        # no IPv6 addressing information for DUALSTACK
        subnet_ipv6_cidr = IPNetwork(CONF.network.tenant_network_v6_cidr)

        self.assertRaises(
            nuage_exceptions.Conflict,
            self.create_vsd_l2domain_template,
            ip_type="DUALSTACK",
            cidr6=subnet_ipv6_cidr,
            dhcp_managed=True)

    def test_l2domain_template_without_dhcp_management_should_not_have_ipv4_cidr_neg(self):
        """
            On creation of the l2 domain template, we expect the IPv6 address, netmask and gateway to be provisioned
            This will not happen when dhcp_managed attributes is not set to dhcp_managed=True
        """
        subnet_cidr = IPNetwork(CONF.network.tenant_network_cidr)

        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="IPV4",
            cidr4=subnet_cidr)

        self.assertRaises(
            AssertionError,
            self._verify_vsd_l2domain_template,
            vsd_l2domain_template,
            dhcp_managed=False,
            cidr4=subnet_cidr)

    def test_ipv4_l2domain_should_not_link_to_openstack_ipv4_subnet(self):
        """

        """
        subnet_cidr = IPNetwork(CONF.network.tenant_network_cidr)

        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="IPV4",
            cidr4=subnet_cidr,
            dhcp_managed=True)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="IPV4",
                                           dhcp_managed=True,
                                           cidr4=subnet_cidr,
                                           gateway=str(IPAddress(subnet_cidr) + 1),
                                           netmask=str(subnet_cidr.netmask))

    def test_create_vsd_l2domain_template_dualstack_invalid_ipv6_neg(self):
        subnet_cidr = IPNetwork(CONF.network.tenant_network_cidr)

        invalid_ipv6 = [
            # ('FE80::/8', 'FE80::1', MSG_IP_ADDRESS_INVALID_OR_RESERVED),
            #     # Link local address
            ("FF00:5f74:c4a5:b82e::/64", "FF00:5f74:c4a5:b82e:ffff:ffff:ffff:ffff", MSG_IP_ADDRESS_INVALID_OR_RESERVED),
            # multicast
            ('FF00::/8', 'FF00::1', MSG_IP_ADDRESS_INVALID_OR_RESERVED),
            # multicast address
            ('::/128', '::1', MSG_IP_ADDRESS_INVALID_OR_RESERVED),
            # not specified address
            ('::/0', '', MSG_INVALID_GATEWAY),
            # empty string
            ("2001:5f74:c4a5:b82e::/64", "2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff", MSG_INVALID_GATEWAY),
            # valid address, invalid gateway - not in cidr
            ("2001:5f74:c4a5:b82e::/64", "2001:5f74:c4a5:b82e:ffff:ffff:ffff", MSG_INVALID_GATEWAY),
            # valid address, invalid gateway - seven segments
            ("::/0", "::1", "")
            # prefix 0
        ]

        for ipv6_cidr, ipv6_gateway, msg in invalid_ipv6:
            self.assertRaisesRegexp(
                nuage_exceptions.Conflict,
                msg,
                self.create_vsd_l2domain_template,
                ip_type="DUALSTACK",
                cidr4=subnet_cidr,
                dhcp_managed=True,
                IPv6Address=ipv6_cidr,
                IPv6Gateway=ipv6_gateway)

            # todo: invalid port IP addresses in valid subnets

    @classmethod
    def link_l2domain_to_shared_domain(cls, domain_id, shared_domain_id):
        update_params = {
            'associatedSharedNetworkResourceID': shared_domain_id
        }
        cls.nuage_vsd_client.update_l2domain(domain_id, update_params=update_params)

    # TODO: under construction
    # def test_create_vsd_shared_l2domain_dualstack_neg(self):
    #     # create l2domain on VSD
    #     subnet_cidr = IPNetwork('10.10.100.0/24')
    #     subnet_gateway = str(IPAddress(subnet_cidr) + 1)
    #     subnet_ipv6_cidr = IPNetwork("2001:5f74:c4a5:b82e::/64")
    #     subnet_ipv6_gateway = str(IPAddress(subnet_ipv6_cidr) + 1)
    #
    #     vsd_l2domain_template = self.create_vsd_l2domain_template(
    #         ip_type="DUALSTACK",
    #         dhcp_managed=True,
    #         cidr4=subnet_cidr,
    #         cidr6=subnet_ipv6_cidr,
    #         gateway=subnet_gateway,
    #         gateway6=subnet_ipv6_gateway)
    #
    #     self._verify_vsd_l2domain_template(vsd_l2domain_template,
    #                                        ip_type="DUALSTACK",
    #                                        dhcp_managed=True,
    #                                        cidr4=subnet_cidr,
    #                                        cidr6=subnet_ipv6_cidr,
    #                                        IPv6Gateway=subnet_ipv6_gateway,
    #                                        gateway=subnet_gateway)
    #
    #     vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
    #     self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)
    #
    #     name = data_utils.rand_name('vsd-l2domain-shared-unmgd')
    #     extra_params = { 'IPType': 'DUALSTACK'}
    #     vsd_l2_shared_domains = self.nuage_vsd_client.create_vsd_shared_resource(name=name, type='L2DOMAIN',
    #                                                                              extra_params=extra_params)
    #     vsd_l2_shared_domain = vsd_l2_shared_domains[0]
    #     self.link_l2domain_to_shared_domain(vsd_l2domain['ID'], vsd_l2_shared_domain['ID'])
    #     pass

