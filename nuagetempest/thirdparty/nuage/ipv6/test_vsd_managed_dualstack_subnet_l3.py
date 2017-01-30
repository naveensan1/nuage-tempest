# Copyright 2017 - Nokia
# All Rights Reserved.

from testtools.matchers import Equals
from testtools.matchers import ContainsDict

from netaddr import IPNetwork, IPAddress

from tempest import config
from tempest.common.utils import data_utils

from nuagetempest.lib.utils import constants as nuage_constants
from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import BaseNuageNetworksTestCase
from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import VsdTestCaseMixin
from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import NetworkTestCaseMixin

CONF = config.CONF

MSG_INVALID_GATEWAY = "Invalid IPv6 network gateway"
MSG_INVALID_IPV6_ADDRESS = "Invalid network IPv6 address"
MSG_IP_ADDRESS_INVALID_OR_RESERVED = "IP Address is not valid or cannot be in reserved address space"


class TestVSDManagedDualStackSubnetL3(VsdTestCaseMixin,
                                      NetworkTestCaseMixin):

    ####################################################################################################################
    # Typical cases
    ####################################################################################################################
    def test_create_ipv6_subnet_in_vsd_managed_l3domain(self):
        name = data_utils.rand_name('l3domain-')
        vsd_l3domain_template = self.create_vsd_l3dom_template(
            name=name)
        vsd_l3domain = self.create_vsd_l3domain(name=name,
                                                tid=vsd_l3domain_template['ID'])

        self.assertEqual(vsd_l3domain['name'], name)
        zone_name = data_utils.rand_name('zone-')
        extra_params = None
        vsd_zone = self.create_vsd_zone(name=zone_name,
                                        domain_id=vsd_l3domain['ID'],
                                        extra_params=extra_params)

        subnet_name = data_utils.rand_name('l3domain-subnet-')
        subnet_cidr = IPNetwork('10.10.100.0/24')
        subnet_gateway = str(IPAddress(subnet_cidr) + 1)

        subnet_ipv6_cidr = IPNetwork("2001:5f74:c4a5:b82e::/64")
        subnet_ipv6_gateway = str(IPAddress(subnet_ipv6_cidr) + 1)

        vsd_l3domain_subnet = self.create_vsd_l3domain_dualstack_subnet(
            zone_id=vsd_zone['ID'],
            subnet_name=subnet_name,
            cidr=subnet_cidr,
            gateway=subnet_gateway,
            cidr6=subnet_ipv6_cidr,
            gateway6=subnet_ipv6_gateway)

        self.assertEqual(vsd_l3domain_subnet['name'], subnet_name)

        # create Openstack IPv4 subnet on Openstack based on VSD l3domain subnet
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=None,
            cidr=subnet_cidr,
            enable_dhcp=True,
            mask_bits=IPNetwork(subnet_cidr).prefixlen,
            nuagenet=vsd_l3domain_subnet['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(ipv4_subnet['cidr'], str(subnet_cidr))

        # create Openstack IPv6 subnet on Openstack based on VSD l3domain subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=vsd_l3domain_subnet['IPv6Gateway'],
            cidr=IPNetwork(vsd_l3domain_subnet['IPv6Address']),
            mask_bits=IPNetwork(vsd_l3domain_subnet['IPv6Address']).prefixlen,
            enable_dhcp=False,
            nuagenet=vsd_l3domain_subnet['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)

        self.assertEqual(ipv6_subnet['cidr'], vsd_l3domain_subnet['IPv6Address'])

        # create a port in the network
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)

        nuage_vports = self.nuage_vsd_client.get_vport(nuage_constants.SUBNETWORK,
                                                       vsd_l3domain_subnet['ID'],
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

    ########################################
    # minimal attributes - default values
    ########################################

    ####################################################################################################################
    # Negative cases
    ####################################################################################################################



