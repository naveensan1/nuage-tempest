# Copyright 2017 - Nokia
# All Rights Reserved.

from testtools.matchers import Equals
from testtools.matchers import ContainsDict

from netaddr import *
from tempest import config
from tempest.lib import exceptions
from tempest.lib.common.utils import data_utils

from nuagetempest.lib.test import nuage_test

from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import NetworkTestCaseMixin

CONF = config.CONF


class DualStackNetworksTest(NetworkTestCaseMixin):
    @staticmethod
    def mask_to_prefix(mask):
        return sum([bin(int(x)).count('1') for x in mask.split('.')])

    @classmethod
    def resource_setup(cls):
        super(DualStackNetworksTest, cls).resource_setup()

        cls.cidr4 = IPNetwork(CONF.network.tenant_network_cidr)
        cls.mask_bits = CONF.network.tenant_network_mask_bits
        cls.cidr6 = IPNetwork(CONF.network.tenant_network_v6_cidr)

    ####################################################################################################################
    # Negative cases
    ####################################################################################################################
    @nuage_test.header()
    def test_os_managed_dual_stack_subnet_neg(self):
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        # create Openstack IPv4 subnet
        ipv4_subnet = self.create_subnet(
            network,
            cidr=self.cidr4,
            mask_bits=self.mask_bits)

        self.assertThat(ipv4_subnet, ContainsDict({'vsd_managed': Equals(False)}))

        # create Openstack IPv6 subnet
        self.assertRaisesRegexp(
            exceptions.BadRequest,
            "Subnet with ip_version 6 is currently not supported for OpenStack managed subnets.",
            self.create_subnet,
            network,
            ip_version=6,
            cidr=self.cidr6,
            mask_bits=self.cidr6._prefixlen,
            enable_dhcp=False)

    @nuage_test.header()
    def test_os_managed_ipv6_subnet_neg(self):
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        # create Openstack IPv6 subnet
        self.assertRaisesRegexp(
            exceptions.BadRequest,
            "Subnet with ip_version 6 is currently not supported for OpenStack managed subnets.",
            self.create_subnet,
            network,
            ip_version=6,
            cidr=self.cidr6,
            mask_bits=self.cidr6._prefixlen,
            enable_dhcp=False)

    @nuage_test.header()
    def test_os_managed_dual_stack_subnet_with_net_partition_neg(self):
        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            cidr=self.cidr4,
            mask_bits=self.mask_bits)

        # create Openstack IPv6 subnet
        # In serverlog: "NuageBadRequest: Bad request: nuagenet is required in subnet"
        self.assertRaisesRegexp(
            exceptions.BadRequest,
            "Subnet with ip_version 6 is currently not supported for OpenStack managed subnets.",
            self.create_subnet,
            network,
            ip_version=6,
            cidr=self.cidr6,
            mask_bits=self.cidr6._prefixlen,
            enable_dhcp=False,
            net_partition=CONF.nuage.nuage_default_netpartition)

        pass

    @nuage_test.header()
    def test_os_managed_ipv6_subnet_with_net_partition_neg(self):
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        # create Openstack IPv6 subnet
        # In serverlog: "NuageBadRequest: Bad request: nuagenet is required in subnet"
        self.assertRaisesRegexp(
            exceptions.BadRequest,
            "Subnet with ip_version 6 is currently not supported for OpenStack managed subnets.",
            self.create_subnet,
            network,
            ip_version=6,
            cidr=self.cidr6,
            mask_bits=self.cidr6._prefixlen,
            enable_dhcp=False,
            net_partition=CONF.nuage.nuage_default_netpartition)

        pass
