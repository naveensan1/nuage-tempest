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
from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import VsdTestCaseMixin
from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import NetworkTestCaseMixin

CONF = config.CONF

MSG_INVALID_GATEWAY = "Invalid network gateway"
MSG_INVALID_ADDRESS = "Invalid network address"

MSG_INVALID_IPV6_ADDRESS = "Invalid network IPv6 address"
MSG_INVALID_IPV6_NETMASK = "Invalid IPv6 netmask"
MSG_INVALID_IPV6_GATEWAY = "Invalid IPv6 network gateway"

MSG_IP_ADDRESS_INVALID_OR_RESERVED = "IP Address is not valid or cannot be in reserved address space"

MSG_INVALID_INPUT_FOR_FIXED_IPS = "Invalid input for fixed_ips. Reason: '%s' is not a valid IP address."
MSG_INVALID_IP_ADDRESS_FOR_SUBNET = "IP address %s is not a valid IP for the specified subnet."


class VSDManagedL2DomainDHCPManagedTest(VsdTestCaseMixin,
                                        NetworkTestCaseMixin):
    @classmethod
    def resource_setup(cls):
        super(VSDManagedL2DomainDHCPManagedTest, cls).resource_setup()
        cls.cidr4 = IPNetwork('1.2.3.0/24')
        cls.mask_bits = cls.cidr4._prefixlen
        cls.gateway4 = str(IPAddress(cls.cidr4) + 1)

        cls.cidr6 = IPNetwork(CONF.network.tenant_network_v6_cidr)
        cls.gateway6 = str(IPAddress(cls.cidr6) + 1)

    def test_create_vsd_managed_l2domain_dhcp_managed_ipv4(self):
        vsd_l2domain_template = self.create_vsd_l2domain_template(
            dhcp_managed=True,
            IPType="IPV4",
            cidr4=self.cidr4)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           dhcp_managed=True,
                                           IPType='IPV4',
                                           cidr4=self.cidr4,
                                           IPv6Address=None,
                                           IPv6Gateway=None)

    def test_create_vsd_managed_l2domain_dhcp_managed_dualstack(self):
        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=self.cidr4,
            cidr6=self.cidr6,
            gateway=self.gateway4,
            gateway6=self.gateway6)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=self.cidr4,
                                           cidr6=self.cidr6,
                                           IPv6Gateway=self.gateway6,
                                           gateway=self.gateway4)

    ####################################################################################################################
    # Special cases
    ####################################################################################################################
    def test_create_vsd_managed_l2domain_dhcp_managed_no_ip_type(self):
        """
        If not IPType is sent to VSD, by default IPV4 is selected.
        The selected IPType appears in the VSD API response
        """
        vsd_l2domain_template = self.create_vsd_l2domain_template(
            dhcp_managed=True,
            cidr4=self.cidr4)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           dhcp_managed=True,
                                           IPType='IPV4',
                                           cidr4=self.cidr4,
                                           IPv6Address=None,
                                           IPv6Gateway=None)

    ####################################################################################################################
    # Negative cases
    ####################################################################################################################
    def test_vsd_l2domain_managed_unsupported_ip_type_neg(self):
        self.assertRaisesRegexp(
            nuage_exceptions.Conflict,
            "Invalid IP type",
            self.create_vsd_l2domain_template,
            dhcp_managed=True,
            cidr4=self.cidr4,
            cidr6=self.cidr6,
            IPType="IPV6")

    def test_vsd_l2domain_managed_unsupported_ip_type_no_addressing_neg(self):
        self.assertRaisesRegexp(
            nuage_exceptions.Conflict,
            "IPType",
            self.create_vsd_l2domain_template,
            dhcp_managed=True,
            IPType="MULTISTACK")

    def test_vsd_l2domain_managed_dualstack_with_only_ipv4_addressing_neg(self):
        self.assertRaisesRegexp(
            nuage_exceptions.Conflict,
            MSG_INVALID_IPV6_ADDRESS,
            self.create_vsd_l2domain_template,
            dhcp_managed=True,
            IPType="DUALSTACK",
            cidr4=self.cidr4,
            cidr6=None)

    def test_vsd_l2domain_managed_dualstack_with_only_ipv6_addressing_neg(self):
        self.assertRaisesRegexp(
            nuage_exceptions.Conflict,
            MSG_INVALID_ADDRESS,
            self.create_vsd_l2domain_template,
            dhcp_managed=True,
            IPType="DUALSTACK",
            cidr4=None,
            cidr6=self.cidr6)

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
        self.assertRaises(
            nuage_exceptions.Conflict,
            self.create_vsd_l2domain_template,
            ip_type="DUALSTACK",
            cidr6=self.cidr6,
            dhcp_managed=True)

    # VSD-18510 - VSD API should fail on creation of DUALSTACK l2 domain template
    # with cidr ::0 has been successfully created
    def test_create_vsd_l2domain_template_dualstack_invalid_ipv6_neg_vsd_18510(self):
        cidr4 = IPNetwork(CONF.network.tenant_network_cidr)

        invalid_ipv6 = [
            ("::/0", "::1", "Invalid IPv6 netmask")
            # prefix 0
        ]

        for ipv6_cidr, ipv6_gateway, msg in invalid_ipv6:
            self.assertRaisesRegexp(
                nuage_exceptions.Conflict,
                msg,
                self.create_vsd_l2domain_template,
                ip_type="DUALSTACK",
                cidr4=cidr4,
                dhcp_managed=True,
                IPv6Address=ipv6_cidr,
                IPv6Gateway=ipv6_gateway)

    def test_create_vsd_l2domain_template_dualstack_invalid_ipv6_neg(self):
        cidr4 = IPNetwork(CONF.network.tenant_network_cidr)

        invalid_ipv6 = [
            ('FE80::/8', 'FE80::1', MSG_INVALID_IPV6_NETMASK),
                # Link local address
            ("FF00:5f74:c4a5:b82e::/64", "FF00:5f74:c4a5:b82e:ffff:ffff:ffff:ffff", MSG_IP_ADDRESS_INVALID_OR_RESERVED),
                # multicast
            ('FF00::/8', 'FF00::1', MSG_IP_ADDRESS_INVALID_OR_RESERVED),
                # multicast address
            ('::/128', '::1', MSG_IP_ADDRESS_INVALID_OR_RESERVED),
                # not specified address
            ('::/0', '', "Invalid IPv6 netmask"),
                # empty string
            ("2001:5f74:c4a5:b82e::/64", "2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff", MSG_INVALID_IPV6_GATEWAY),
                # valid address, invalid gateway - not in cidr
            ("2001:5f74:c4a5:b82e::/64", "2001:5f74:c4a5:b82e:ffff:ffff:ffff", MSG_INVALID_IPV6_GATEWAY),
                # valid address, invalid gateway - seven segments
            ("2001:5f74:c4a5:b82e::/64", "2001:5f74:c4a5:b82e:100.12.13.1", MSG_INVALID_IPV6_GATEWAY),
                # needs :: between hex and decimal part.
            ("2001:5f74:c4a5:b82e:b000::/63", "2001:5f74:c4a5:b82e:b0:000::1", MSG_INVALID_IPV6_NETMASK),
                # unsupported netmask
            ("2001:5f74:c4a5:b82e::/129", "2001:5f74:c4a5:b82e::0", MSG_INVALID_IPV6_ADDRESS),
                # unsupported netmask
            ("3ffe:0b00::/32", "3ffe:0b00::1", MSG_INVALID_IPV6_NETMASK),
                # prefix < 64
            ("2001::/16", "2001::1", MSG_INVALID_IPV6_NETMASK),
                # prefix 16
        ]

        for ipv6_cidr, ipv6_gateway, msg in invalid_ipv6:
            self.assertRaisesRegexp(
                nuage_exceptions.Conflict,
                msg,
                self.create_vsd_l2domain_template,
                ip_type="DUALSTACK",
                cidr4=cidr4,
                dhcp_managed=True,
                IPv6Address=ipv6_cidr,
                IPv6Gateway=ipv6_gateway)


class VSDManagedDualStackSubnetL2DHCPManagedTest(VsdTestCaseMixin,
                                                 NetworkTestCaseMixin):
    @classmethod
    def resource_setup(cls):
        super(VSDManagedDualStackSubnetL2DHCPManagedTest, cls).resource_setup()
        # cls.cidr4 = IPNetwork(CONF.network.tenant_network_cidr)
        # cls.mask_bits = CONF.network.tenant_network_mask_bits
        cls.cidr4 = IPNetwork('1.2.3.0/24')
        cls.mask_bits = cls.cidr4._prefixlen
        cls.gateway4 = str(IPAddress(cls.cidr4) + 1)

        cls.cidr6 = IPNetwork(CONF.network.tenant_network_v6_cidr)
        cls.gateway6 = str(IPAddress(cls.cidr6) + 1)

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
        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=self.cidr4,
            cidr6=self.cidr6,
            gateway=self.gateway4,
            gateway6=self.gateway6)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=self.cidr4,
                                           cidr6=self.cidr6,
                                           IPv6Gateway=self.gateway6,
                                           gateway=self.gateway4)

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
        self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=self.gateway4,
            cidr=self.cidr4,
            mask_bits=24,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(ipv4_subnet['cidr'], str(self.cidr4))

        # create a port in the network
        port_ipv4_only = self.create_port(network)
        self._verify_port(port_ipv4_only, subnet4=ipv4_subnet, subnet6=None,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port_ipv4_only, vsd_l2domain)

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

        # create a port with fixed-ip in the IPv4 subnet, and no IP in IPv6
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'], 'ip_address': IPAddress(self.cidr4.first + 7)}]}
        port = self.create_port(network, **port_args)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=None),
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

        # create a port with fixed-ip in the IPv4 subnet and in IPv6
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'], 'ip_address': IPAddress(self.cidr4.first + 11)},
                                   {'subnet_id': ipv6_subnet['id'], 'ip_address': IPAddress(self.cidr6.first + 11)}]}
        port = self.create_port(network, **port_args)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet),
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

        # create a port with no fixed ip in the IPv4 subnet but in fixed-ip IPv6
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id']},
                                   {'subnet_id': ipv6_subnet['id'], 'ip_address': IPAddress(self.cidr6.first + 21)}]}
        port = self.create_port(network, **port_args)
        self._verify_port(port, subnet4=None, subnet6=ipv6_subnet),
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

        # can have multiple fixed ip's in same subnet
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'], 'ip_address': IPAddress(self.cidr4.first + 33)},
                                   {'subnet_id': ipv6_subnet['id'], 'ip_address': IPAddress(self.cidr6.first + 33)},
                                   {'subnet_id': ipv6_subnet['id'], 'ip_address': IPAddress(self.cidr6.first + 34)}]}
        port = self.create_port(
            network,
            **port_args)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet, status='DOWN')
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

        # create a port in the network
        # OpenStack now chooses a random IP address. To avoid conflict with the above fixed IP's, do this case last
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

        pass

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
        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=self.cidr4,
            cidr6=self.cidr6,
            gateway=self.gateway4,
            gateway6=self.gateway6)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=self.cidr4,
                                           cidr6=self.cidr6,
                                           IPv6Gateway=self.gateway6,
                                           gateway=self.gateway4)

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
        if CONF.nuage_sut.openstack_version >= 'newton':
            expected_exception = tempest_exceptions.BadRequest
        else:
            expected_exception = tempest_exceptions.ServerFault

        self.assertRaises(
            expected_exception,
            self.create_port,
            network)

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        ipv4_subnet = self.create_subnet(
            network,
            gateway=self.gateway4,
            cidr=self.cidr4,
            mask_bits=self.mask_bits,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(ipv4_subnet['cidr'], str(self.cidr4))  # create a port in the network - IPAM by OS
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

        # create a port in the network - IPAM by OS
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

    ####################################################################################################################
    # Special cases
    ####################################################################################################################

    ########################################
    # backwards compatibility
    ########################################
    def test_ipv4_subnet_linked_to_ipv4_vsd_l2domain(self):
        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="IPV4",
            cidr4=self.cidr4,
            dhcp_managed=True)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="IPV4",
                                           dhcp_managed=True,
                                           cidr4=self.cidr4,
                                           gateway=str(IPAddress(self.cidr4) + 1),
                                           netmask=str(self.cidr4.netmask))

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
        self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            cidr=self.cidr4,
            mask_bits=self.mask_bits,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(ipv4_subnet['cidr'], str(self.cidr4))

        # create a port in the network
        port_ipv4_only = self.create_port(network)
        self._verify_port(port_ipv4_only, subnet4=ipv4_subnet, subnet6=None,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port_ipv4_only, vsd_l2domain)

    ########################################
    # minimal attributes - default values
    ########################################

    ########################################
    # IPv6 address formats
    ########################################
    def test_create_vsd_l2domain_template_dualstack_valid(self):
        cidr4 = IPNetwork(CONF.network.tenant_network_cidr)

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
        ]

        for ipv6_cidr, ipv6_gateway in valid_ipv6:
            vsd_l2domain_template = self.create_vsd_l2domain_template(
                ip_type="DUALSTACK",
                cidr4=cidr4,
                dhcp_managed=True,
                IPv6Address=ipv6_cidr,
                IPv6Gateway=ipv6_gateway
            )

            self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                               ip_type="DUALSTACK",
                                               dhcp_managed=True,
                                               cidr4=cidr4,
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
                cidr=cidr4,
                mask_bits=cidr4._prefixlen,
                nuagenet=vsd_l2domain['ID'],
                net_partition=CONF.nuage.nuage_default_netpartition)
            self.assertEqual(ipv4_subnet['cidr'], str(cidr4))  # create a port in the network - IPAM by OS

            # create a port in the network - IPAM by OS
            port = self.create_port(network)
            self._verify_port(port, subnet4=None, subnet6=ipv6_subnet,
                              status='DOWN',
                              nuage_policy_groups=None,
                              nuage_redirect_targets=[],
                              nuage_floatingip=None)
            self._verify_vport_in_l2_domain(port, vsd_l2domain)

    # see VSD-18509: VSD does not accept IPv6 address like 2001:5f74:c4a5:b82e:100.12.13.1 has been successfully created
    def test_create_vsd_l2domain_template_dualstack_valid_failing_at_vsd(self):
        cidr4 = IPNetwork(CONF.network.tenant_network_cidr)

        valid_ipv6 = [
            ("0:0:0:ffff::/64", "::ffff:100.12.13.1"),
            #("2001:5f74:c4a5:b82e::/64", "2001:5f74:c4a5:b82e::100.12.13.1"),
            # valid address, gateway at mixed ipv4 and ipv6 format (digit-dot notation)
        ]

        for ipv6_cidr, ipv6_gateway in valid_ipv6:
            vsd_l2domain_template = self.create_vsd_l2domain_template(
                ip_type="DUALSTACK",
                cidr4=cidr4,
                dhcp_managed=True,
                IPv6Address=ipv6_cidr,
                IPv6Gateway=ipv6_gateway
            )

            self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                               ip_type="DUALSTACK",
                                               dhcp_managed=True,
                                               cidr4=cidr4,
                                               IPv6Address=ipv6_cidr,
                                               IPv6Gateway=ipv6_gateway)

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
        cidr4 = IPNetwork('10.10.100.0/24')
        self.gateway4 = str(IPAddress(cidr4) + 1)
        self.cidr6 = IPNetwork("2001:5f74:c4a5:b82e::/64")
        self.gateway6 = str(IPAddress(self.cidr6) + 1)

        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=cidr4,
            cidr6=self.cidr6,
            gateway=self.gateway4,
            gateway6=self.gateway6)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=cidr4,
                                           cidr6=self.cidr6,
                                           IPv6Gateway=self.gateway6,
                                           gateway=self.gateway4)

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
        self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=self.gateway4,
            cidr=cidr4,
            mask_bits=24,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(ipv4_subnet['cidr'], str(cidr4))

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
    def test_ipv6_subnet_linked_to_ipv4_vsd_l2domain_neg(self):
        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="IPV4",
            cidr4=self.cidr4,
            dhcp_managed=True)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="IPV4",
                                           dhcp_managed=True,
                                           cidr4=self.cidr4,
                                           gateway=str(IPAddress(self.cidr4) + 1),
                                           netmask=str(self.cidr4.netmask))

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
        self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)

        # create Openstack IPv6 subnet on linked to VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        if CONF.nuage_sut.openstack_version >= 'newton':
            expected_exception = tempest_exceptions.BadRequest
            expected_message = "Subnet with ip_version 6 can't be linked to vsd subnet with IPType IPV4"
        else:
            expected_exception = tempest_exceptions.ServerFault
            expected_message = "create_subnet_postcommit failed."

        self.assertRaisesRegexp(
            expected_exception,
            expected_message,
            self.create_subnet,
            network,
            ip_version=6,
            enable_dhcp=False,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)

    def test_create_port_in_vsd_managed_l2domain_dhcp_managed_neg(self):
        """
            OpenStack IPv4 and IPv6 subnets linked to VSD l2 dualstack l2 domain
            - create VSD l2 domain template dualstack
            - create VSD l2 domain
            - create OS network
            - create OS subnets
            - create OS port
        """
        # create l2domain on VSD
        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=self.cidr4,
            cidr6=self.cidr6,
            gateway=self.gateway4,
            gateway6=self.gateway6)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=self.cidr4,
                                           cidr6=self.cidr6,
                                           IPv6Gateway=self.gateway6,
                                           gateway=self.gateway4)

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
        self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=self.gateway4,
            cidr=self.cidr4,
            mask_bits=24,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(ipv4_subnet['cidr'], str(self.cidr4))

        # shall not create a port with fixed-ip IPv6 in ipv4 subnet
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'], 'ip_address': IPAddress(self.cidr6.first + 21)}]}
        self.assertRaisesRegexp(
            tempest_exceptions.BadRequest,
            "IP address %s is not a valid IP for the specified subnet" % (IPAddress(self.cidr6.first + 21)),
            self.create_port,
            network,
            **port_args)

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

        # shall not create port with IP already in use
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'], 'ip_address': IPAddress(self.cidr4.first + 10)},
                                   {'subnet_id': ipv6_subnet['id'], 'ip_address': IPAddress(self.cidr6.first + 10)}]}

        valid_port = self.create_port(network, **port_args)
        self.assertIsNotNone(valid_port)

        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'], 'ip_address': IPAddress(self.cidr4.first + 11)},
                                   {'subnet_id': ipv6_subnet['id'], 'ip_address': IPAddress(self.cidr6.first + 10)}]}

        if CONF.nuage_sut.openstack_version >= 'newton':
            expected_exception = tempest_exceptions.Conflict,
            expected_message = "IP address %s already allocated in subnet %s" \
                % (IPAddress(self.cidr6.first + 10), ipv6_subnet['id'] )
        else:
            expected_exception = tempest_exceptions.Conflict,
            expected_message = "Unable to complete operation for network %s. The IP address %s is in use." \
                % (network['id'], IPAddress(self.cidr6.first + 10)),

        self.assertRaisesRegexp(
            expected_exception,
            expected_message,
            self.create_port,
            network,
            **port_args)

        # shall not create port with fixed ip in outside cidr
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'], 'ip_address': IPAddress(self.cidr4.first + 201)},
                                   {'subnet_id': ipv6_subnet['id'], 'ip_address': IPAddress(self.cidr6.first - 20)}]}
        self.assertRaisesRegexp(
            tempest_exceptions.BadRequest,
            "IP address %s is not a valid IP for the specified subnet" % (IPAddress(self.cidr6.first - 20)),
            self.create_port,
            network,
            **port_args)

        # shall not a port with no ip in the IPv4 subnet but only fixed-ip IPv6
        port_args = {'fixed_ips': [{'subnet_id': ipv6_subnet['id'], 'ip_address': IPAddress(self.cidr6.first + 21)}]}

        if CONF.nuage_sut.openstack_version >= 'newton':
            expected_exception = tempest_exceptions.BadRequest
            expected_message = "Port can't be a pure ipv6 port. Need ipv4 fixed ip."
        else:
            expected_exception = tempest_exceptions.ServerFault
            expected_message = "Got server fault"

        self.assertRaisesRegexp(
            expected_exception,
            expected_message,
            self.create_port,
            network,
            **port_args)

        # shall not a port with no ip in the IPv4 subnet but only fixed-ip IPv6
        port_args = {'fixed_ips': [{'subnet_id': ipv6_subnet['id'], 'ip_address': IPAddress(self.cidr6.first + 21)}]}

        if CONF.nuage_sut.openstack_version >= 'newton':
            expected_exception = tempest_exceptions.BadRequest
            expected_message = "Port can't be a pure ipv6 port. Need ipv4 fixed ip."
        else:
            expected_exception = tempest_exceptions.ServerFault
            expected_message = "Got server fault"

        self.assertRaisesRegexp(
            expected_exception,
            expected_message,
            self.create_port,
            network,
            **port_args)

        # Openstack-17001 - VSD accept openstack port creation in L2 dualstack network with fixed-ip = IPv6Gateway IP
        # shall not create port with fixed ip on the IPv6 gateway address
        port_args = dict(fixed_ips=[{'subnet_id': ipv4_subnet['id']},
                                    {'subnet_id': ipv6_subnet['id'], 'ip_address': vsd_l2domain_template['IPv6Gateway']}
                                    ])
        if CONF.nuage_sut.openstack_version >= 'newton':
            expected_exception = tempest_exceptions.Conflict,
            expected_message = "IP address %s already allocated in subnet %s" \
                               % (vsd_l2domain_template['IPv6Gateway'], ipv6_subnet['id'] )
        else:
            expected_exception = tempest_exceptions.ServerFault
            expected_message = "The IP address %s is in use." % vsd_l2domain_template['IPv6Gateway'],

        self.assertRaisesRegexp(
            expected_exception,
            expected_message,
            self.create_port,
            network,
            **port_args)
        pass

    def test_create_port_neg(self):
        """
            OpenStack IPv4 and IPv6 subnets linked to VSD l2 dualstack l2 domain
            - create VSD l2 domain template dualstack
            - create VSD l2 domain
            - create OS network
            - create OS subnets
            - create OS port
        """
        # create l2domain on VSD
        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=self.cidr4,
            cidr6=self.cidr6)
        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=self.gateway4,
            cidr=self.cidr4,
            enable_dhcp=True,
            mask_bits=self.mask_bits,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)

        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=self.gateway6,
            cidr=self.cidr6,
            mask_bits=self.cidr6._prefixlen,
            enable_dhcp=False,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)

        # noinspection PyPep8
        invalid_ipv6 = [
            ('::1', MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            #     # Loopback
            ('FE80::1', MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            #     # Link local address
            ("FF00:5f74:c4a5:b82e:ffff:ffff:ffff:ffff", MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            # multicast
            ('FF00::1', MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            # multicast address
            ('::1', MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            # not specified address
            ('::', MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            # empty address
            ("2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff", MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            # valid address, not in subnet

            ('', MSG_INVALID_INPUT_FOR_FIXED_IPS),
            # empty string
            ("2001:5f74:c4a5:b82e:ffff:ffff:ffff:ffff:ffff", MSG_INVALID_INPUT_FOR_FIXED_IPS),
            # invalid address, too much segments
            ("2001:5f74:c4a5:b82e:ffff:ffff:ffff", MSG_INVALID_INPUT_FOR_FIXED_IPS),
            # invalid address, seven segments
            ("2001;5f74.c4a5.b82e:ffff:ffff:ffff", MSG_INVALID_INPUT_FOR_FIXED_IPS),
            # invalid address, wrong characters
            ("2001:5f74:c4a5:b82e:100.12.13.1", MSG_INVALID_INPUT_FOR_FIXED_IPS),
            # invalid fornmat: must have :: between hex and decimal part.
        ]

        for ipv6, msg in invalid_ipv6:
            port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'], 'ip_address': IPAddress(self.cidr4.first + 40)},
                                       {'subnet_id': ipv6_subnet['id'], 'ip_address': ipv6}]}
            self.assertRaisesRegexp(tempest_exceptions.BadRequest, msg % ipv6, self.create_port, network, **port_args)

        pass

    # TODO: shared VSD networks use case?
    # def test_create_vsd_shared_l2domain_dualstack_neg(self):
    #     # create l2domain on VSD
    #     vsd_l2domain_template = self.create_vsd_l2domain_template(
    #         ip_type="DUALSTACK",
    #         dhcp_managed=False)
    #
    #     vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
    #     self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)
    #
    #     name = data_utils.rand_name('vsd-l2domain-shared-unmgd')
    #     vsd_l2_shared_domains = self.nuage_vsd_client.create_vsd_shared_resource(name=name, type='L2DOMAIN')
    #     vsd_l2_shared_domain = vsd_l2_shared_domains[0]
    #     self.link_l2domain_to_shared_domain(vsd_l2domain['ID'], vsd_l2_shared_domain['ID'])
    #
    #     # create Openstack IPv4 subnet on Openstack based on VSD l2domain
    #     net_name = data_utils.rand_name('network-')
    #     network = self.create_network(network_name=net_name)
    #     ipv4_subnet = self.create_subnet(
    #         network,
    #         gateway=self.gateway4,
    #         cidr=self.cidr4,
    #         enable_dhcp=False,
    #         mask_bits=self.mask_bits,
    #         nuagenet=vsd_l2domain['ID'],
    #         net_partition=CONF.nuage.nuage_default_netpartition)
    #
    #     ipv6_subnet = self.create_subnet(
    #         network,
    #         ip_version=6,
    #         gateway=self.gateway6,
    #         cidr=self.cidr6,
    #         mask_bits=self.cidr6._prefixlen,
    #         enable_dhcp=False,
    #         nuagenet=vsd_l2domain['ID'],
    #         net_partition=CONF.nuage.nuage_default_netpartition)
    #
    #     # shall not create port with IP already in use
    #     port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'], 'ip_address': IPAddress(self.cidr4.first + 10)}, \
    #                                {'subnet_id': ipv6_subnet['id'], 'ip_address': IPAddress(self.cidr6.first + 10)}]}
    #
    #     valid_port = self.create_port(network, **port_args)
    #
    #     pass
    #
