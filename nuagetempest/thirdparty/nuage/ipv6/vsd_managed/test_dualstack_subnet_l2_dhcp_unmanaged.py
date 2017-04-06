# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPNetwork, IPAddress

from tempest import config
from tempest.common.utils import data_utils
from tempest.lib import exceptions as tempest_exceptions

from nuagetempest.lib.utils import exceptions as nuage_exceptions
from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import VsdTestCaseMixin
from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import NetworkTestCaseMixin

CONF = config.CONF

MSG_INVALID_GATEWAY = "Invalid IPv6 network gateway"
MSG_INVALID_IPV6_ADDRESS = "Invalid network IPv6 address"
MSG_IP_ADDRESS_INVALID_OR_RESERVED = "IP Address is not valid or cannot be in reserved address space"

MSG_INVALID_INPUT_FOR_FIXED_IPS = "Invalid input for fixed_ips. Reason: '%s' is not a valid IP address."
MSG_INVALID_IP_ADDRESS_FOR_SUBNET = "IP address %s is not a valid IP for the specified subnet."


class VSDManagedL2DomainDHCPUnmanagedTest(VsdTestCaseMixin):
    @classmethod
    def resource_setup(cls):
        super(VSDManagedL2DomainDHCPUnmanagedTest, cls).resource_setup()
        cls.cidr4 = IPNetwork('1.2.3.0/24')
        cls.mask_bits = cls.cidr4._prefixlen
        cls.gateway4 = str(IPAddress(cls.cidr4) + 1)

        cls.cidr6 = IPNetwork(CONF.network.tenant_network_v6_cidr)
        cls.gateway6 = str(IPAddress(cls.cidr6) + 1)

    def test_create_vsd_managed_l2domain_dhcp_unmanaged(self):
        vsd_l2domain_template = self.create_vsd_l2domain_template(
            dhcp_managed=False)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           dhcp_managed=False,
                                           IPType=None,
                                           netmask=None,
                                           address=None,
                                           gateway=None,
                                           IPv6Address=None,
                                           IPv6Gateway=None)

    ####################################################################################################################
    # Negative cases
    ####################################################################################################################
    # VSD-18557
    # see (resolved as duplicate ?) VSD-18607 -
    # see (resolved as duplicate ?) VSD-18415
    def test_vsd_l2domain_unmanaged_ipv4_only_neg(self):
        self.assertRaisesRegexp(
            nuage_exceptions.Conflict,
            "TODO: Should not allow IPType IPv4",
            self.create_vsd_l2domain_template,
            dhcp_managed=False,
            IPType="IPV4")

    def test_vsd_l2domain_managed_ipv6_only_neg(self):
        self.assertRaisesRegexp(
            nuage_exceptions.Conflict,
            "TODO: Should not allow unsupported IPType",
            self.create_vsd_l2domain_template,
            dhcp_managed=False,
            IPType="IPV6")

    def test_vsd_l2domain_unmanaged_ipv6_dualstack_neg(self):
        self.assertRaisesRegexp(
            nuage_exceptions.Conflict,
            "TODO: Should not allow DUALSTACK IPType",
            self.create_vsd_l2domain_template,
            dhcp_managed=False,
            IPType="DUALSTACK")

    def test_vsd_l2domain_unmanaged_with_ipv4_addresses_neg(self):
        self.assertRaisesRegexp(
            nuage_exceptions.Conflict,
            "TODO: Should not allow IPv4 addressing in unmanaged template",
            self.create_vsd_l2domain_template,
            dhcp_managed=False,
            cidr4=self.cidr4,
            cidr6=None)

    def test_vsd_l2domain_unmanaged_with_ipv6_addresses_neg(self):
        self.assertRaisesRegexp(
            nuage_exceptions.Conflict,
            "TODO: Should not allow IPv6 addressing in unmanaged template",
            self.create_vsd_l2domain_template,
            dhcp_managed=False,
            cidr4=None,
            cidr6=self.cidr6)


class VSDManagedDualStackSubnetL2DHCPUnmanagedTest(VsdTestCaseMixin,
                                                   NetworkTestCaseMixin):

    @classmethod
    def resource_setup(cls):
        super(VSDManagedDualStackSubnetL2DHCPUnmanagedTest, cls).resource_setup()
        # cls.cidr4 = IPNetwork(CONF.network.tenant_network_cidr)
        # cls.mask_bits = CONF.network.tenant_network_mask_bits
        cls.cidr4 = IPNetwork('1.2.3.0/24')
        cls.mask_bits = cls.cidr4._prefixlen
        cls.gateway4 = str(IPAddress(cls.cidr4) + 1)

        cls.cidr6 = IPNetwork(CONF.network.tenant_network_v6_cidr)
        cls.gateway6 = str(IPAddress(cls.cidr6) + 1)

    def test_create_ipv6_subnet_in_vsd_managed_l2domain_dhcp_unmanaged(self):
        """
            OpenStack IPv4 and IPv6 subnets linked to VSD l2 dualstack l2 domain
            - create VSD l2 domain template dualstack
            - create VSD l2 domain
            - create OS network
            - create OS subnets
            - create OS port
        """

        # Given I have a VSD-L2-Unmanaged subnet
        vsd_l2_domain = self._given_vsd_l2domain(cidr4=self.cidr4, cidr6=self.cidr6, dhcp_managed=False)

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=self.gateway4,
            enable_dhcp=False,
            cidr=self.cidr4,
            mask_bits=self.mask_bits,
            nuagenet=vsd_l2_domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(ipv4_subnet['cidr'], str(self.cidr4))

        # create a port in the network
        port_ipv4_only = self.create_port(network)
        self._verify_port(port_ipv4_only, subnet4=ipv4_subnet, subnet6=None,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port_ipv4_only, vsd_l2_domain)

        # create Openstack IPv6 subnet on Openstack based on VSD l3domain subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=self.gateway6,
            cidr=self.cidr6,
            mask_bits=self.cidr6._prefixlen,
            enable_dhcp=False,
            nuagenet=vsd_l2_domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)

        # create a port in the network
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port, vsd_l2_domain)

    ####################################################################################################################
    # Special cases
    ####################################################################################################################

    ########################################
    # backwards compatibility
    ########################################
    def test_ipv4_subnet_linked_to_ipv4_vsd_l2domain_unmanaged(self):
        # Given I have a VSD-L2-Unmanaged subnet
        vsd_l2_domain = self._given_vsd_l2domain(cidr4=self.cidr4, cidr6=self.cidr6, dhcp_managed=False)

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=self.gateway4,
            enable_dhcp=False,
            cidr=self.cidr4,
            mask_bits=self.mask_bits,
            nuagenet=vsd_l2_domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(ipv4_subnet['cidr'], str(self.cidr4))

        # create a port in the network
        port_ipv4_only = self.create_port(network)
        self._verify_port(port_ipv4_only, subnet4=ipv4_subnet, subnet6=None,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port_ipv4_only, vsd_l2_domain)

    ########################################
    # IPv6 address formats
    ########################################
    def test_create_vsd_l2domain_template_dualstack_valid(self):

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
                dhcp_managed=False
            )

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
                gateway=ipv6_gateway,
                cidr=IPNetwork(ipv6_cidr),
                mask_bits=mask_bits,
                enable_dhcp=False,
                nuagenet=vsd_l2domain['ID'],
                net_partition=CONF.nuage.nuage_default_netpartition)

            # create Openstack IPv4 subnet on Openstack based on VSD l2domain
            ipv4_subnet = self.create_subnet(
                network,
                cidr=self.cidr4,
                enable_dhcp=False,
                mask_bits=self.mask_bits,
                nuagenet=vsd_l2domain['ID'],
                net_partition=CONF.nuage.nuage_default_netpartition)
            self.assertEqual(ipv4_subnet['cidr'], str(self.cidr4))  # create a port in the network - IPAM by OS

            # create a port in the network - IPAM by OS
            port = self.create_port(network)
            self._verify_port(port, subnet4=None, subnet6=ipv6_subnet,
                              status='DOWN',
                              nuage_policy_groups=None,
                              nuage_redirect_targets=[],
                              nuage_floatingip=None)
            self._verify_vport_in_l2_domain(port, vsd_l2domain)

    ####################################################################################################################
    # Negative cases
    ####################################################################################################################

    # see  OPENSTACK-1668
    def test_create_port_in_ipv6_subnet_linked_to_vsd_l2domain_unmanaged_neg(self):
        vsd_l2domain_template = self.create_vsd_l2domain_template(
            dhcp_managed=False)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           dhcp_managed=False)

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
        self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)

        # create Openstack IPv6 subnet on linked to VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        self.create_subnet(
            network,
            ip_version=6,
            enable_dhcp=False,
            nuagenet=vsd_l2domain['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)

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
            network)

    def test_create_ports_in_vsd_managed_l2domain_dhcp_unmanaged_neg(self):
        """
            OpenStack IPv4 and IPv6 subnets linked to VSD l2 dualstack l2 domain
            - create VSD l2 domain template dualstack
            - create VSD l2 domain
            - create OS network
            - create OS subnets
            - create OS port
        """
        # create l2domain on VSD
        vsd_l2domain_template = self.create_vsd_l2domain_template(dhcp_managed=False)
        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
        self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            enable_dhcp=False,
            gateway=self.gateway4,
            cidr=self.cidr4,
            mask_bits=self.mask_bits,
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

        # create Openstack IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=vsd_l2domain_template['IPv6Gateway'],
            cidr=self.cidr6,
            mask_bits=self.cidr6.prefixlen,
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
            expected_exception = tempest_exceptions.Conflict
            expected_message = "IP address %s already allocated in subnet %s" \
                % (IPAddress(self.cidr6.first + 10), ipv6_subnet['id'])
        else:
            expected_exception = tempest_exceptions.Conflict
            expected_message = "Unable to complete operation for network %s. The IP address %s is in use." \
                % (network['id'], IPAddress(self.cidr6.first + 10))

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

        # shall not create a port with no ip in the IPv4 subnet but only fixed-ip IPv6
        port_args = {'fixed_ips': [{'subnet_id': ipv6_subnet['id'], 'ip_address': IPAddress(self.cidr6.first + 21)}]}

        if CONF.nuage_sut.openstack_version >= 'newton':
            expected_exception = tempest_exceptions.BadRequest
            expected_message = "Port can't be a pure ipv6 port. Need ipv4 fixed ip."
        else:
            tempest_exceptions.ServerFault,
            expected_message = "Got server fault"

        self.assertRaisesRegexp(
            expected_exception,
            expected_message,
            self.create_port,
            network,
            **port_args)

        # shall not create a port with no ip in the IPv4 subnet but only fixed-ip IPv6
        port_args = {'fixed_ips': [{'subnet_id': ipv6_subnet['id'], 'ip_address': IPAddress(self.cidr6.first + 21)}]}
        if CONF.nuage_sut.openstack_version >= 'newton':
            expected_exception = tempest_exceptions.BadRequest
            expected_message = "Port can't be a pure ipv6 port. Need ipv4 fixed ip."
        else:
            tempest_exceptions.ServerFault,
            expected_message = "Got server fault"

        self.assertRaisesRegexp(
            expected_exception,
            expected_message,
            self.create_port,
            network,
            **port_args)

        pass

    def test_create_port_in_vsd_managed_l2domain_dhcp_unmanaged_neg(self):
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
            dhcp_managed=False)
        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=self.gateway4,
            cidr=self.cidr4,
            enable_dhcp=False,
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
