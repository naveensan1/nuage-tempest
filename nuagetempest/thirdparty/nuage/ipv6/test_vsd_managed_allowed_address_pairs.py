# Copyright 2017 - Nokia
# All Rights Reserved.

from testtools.matchers import Equals
from testtools.matchers import ContainsDict

from netaddr import *
from tempest import config
from tempest.lib.common.utils import data_utils

from nuagetempest.lib.utils import constants
from nuagetempest.lib.test import nuage_test
from nuagetempest.lib.utils import constants as nuage_constants

from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import VsdTestCaseMixin
from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import NetworkTestCaseMixin

CONF = config.CONF

VALID_MAC_ADDRESS = 'fa:fa:3e:e8:e8:01'
VALID_MAC_ADDRESS_2A = 'fa:fa:3e:e8:e8:2a'
VALID_MAC_ADDRESS_2B = 'fa:fa:3e:e8:e8:2b'

################################################################################################################
################################################################################################################
# MultiVIP . allowed address pairsallowable address pairs)
################################################################################################################
################################################################################################################


class VSDManagedAllowedAddresPairsTest(VsdTestCaseMixin,
                                       NetworkTestCaseMixin):

    @staticmethod
    def mask_to_prefix( mask):
        return sum([bin(int(x)).count('1') for x in mask.split('.')])

    @classmethod
    def resource_setup(cls):
        super(VSDManagedAllowedAddresPairsTest, cls).resource_setup()

        cls.cidr4 = IPNetwork('1.1.20.0/24')
        cls.cidr6 = IPNetwork("2001:5f74:1111:b82e::/64")

        # noinspection PyPep8
        cls.port_configs = {
            'case-no-aap': # no fixed-ips, no allowed address pairs
                {'fixed-ips': [],
                 'allowed-address-pairs': [],
                },
            'case-aap-ipv4':
                {'fixed-ips': [],
                 'allowed-address-pairs': [
                      {'ip_address': str(IPAddress(cls.cidr4.first)+10)}
                 ]
                },
            'case-aap-ipv6':
                {'fixed-ips': [],
                 'allowed-address-pairs': [
                     {'ip_address': str(IPAddress(cls.cidr6.first)+10)}
                 ]
                },
            'case-aap-ipv4-ipv6':
                {'fixed-ips': [],
                 'allowed-address-pairs': [
                     {'ip_address': str(IPAddress(cls.cidr4.first)+10)},
                     {'ip_address': str(IPAddress(cls.cidr6.first)+10)}
                 ]
                },
            'case-aap-ipv4-mac4-ipv6':
                {'fixed-ips': [],
                 'allowed-address-pairs': [
                     {'ip_address': str(IPAddress(cls.cidr4.first)+10), 'mac_address': VALID_MAC_ADDRESS_2A},
                     {'ip_address': str(IPAddress(cls.cidr6.first)+10)}
                 ]
                },
            'case-aap-ipv4-ipv6-mac6':
                {'fixed-ips': [],
                 'allowed-address-pairs': [
                     {'ip_address': str(IPAddress(cls.cidr4.first)+10)},
                     {'ip_address': str(IPAddress(cls.cidr6.first)+10), 'mac_address': VALID_MAC_ADDRESS_2B}
                 ]
                },
            'case-aap-ipv4-mac4-ipv6-mac6':
                {'fixed-ips': [],
                 'allowed-address-pairs': [
                     {'ip_address': str(IPAddress(cls.cidr4.first)+10), 'mac_address': VALID_MAC_ADDRESS_2A},
                     {'ip_address': str(IPAddress(cls.cidr6.first)+10), 'mac_address': VALID_MAC_ADDRESS_2B}
                 ]
                }
            }

    def _has_ipv6_allowed_address_pairs(self, allowed_address_pairs):
        has_ipv6 = False
        for pair in allowed_address_pairs:
            if not 'ip_address' in pair:
                assert "Must have ip_addres defined for each allowed address pair"
            if str(pair['ip_address']).count(":"):
                has_ipv6 = True
                break
        return has_ipv6

    def _check_crud_port(self, scenario, network, subnet4, subnet6, vsd_l3_subnet):
        port_config = self.port_configs[scenario]

        params = {}
        allowed_address_pairs = port_config['allowed-address-pairs']
        if len(allowed_address_pairs) > 0:
            params.update({'allowed_address_pairs': allowed_address_pairs })

        port = self.create_port(
            network,
            name=scenario,
            **params)

        kwargs = {}
        if len(port_config['fixed-ips']) > 0:
            kwargs.update({'fixed_ips': port_config['fixed-ips']})

        expected_allowed_address_pairs = []
        for pair in port_config['allowed-address-pairs']:
            if not 'mac_address' in pair:
                expected_allowed_address_pairs.append({'ip_address': pair['ip_address'], 'mac_address': port['mac_address']})
            else:
                expected_allowed_address_pairs.append({'ip_address': pair['ip_address'], 'mac_address': pair['mac_address']})

        self._verify_port(port, subnet4=subnet4, subnet6=subnet6,
                          status='DOWN',
                          allowed_address_pairs=expected_allowed_address_pairs,
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None,
                          **kwargs)

        nuage_vports = self.nuage_vsd_client.get_vport(nuage_constants.SUBNETWORK,
                                                       vsd_l3_subnet['ID'],
                                                       filters='externalID',
                                                       filter_value=port['id'])
        self.assertEqual(len(nuage_vports), 1, "Must find one VPort matching port: %s" % port['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport, ContainsDict({'name': Equals(port['id'])}))
        self.assertThat(nuage_vport, ContainsDict({'multiNICVPortID': Equals(None)}))

        # And anti-address spoofing is disabled on vport in VSD (in VSD addressSpoofing ENABLED)
        if self._has_ipv6_allowed_address_pairs(port_config['allowed-address-pairs']):
            expected_address_spoofing = constants.ENABLED
        else:
            expected_address_spoofing = constants.INHERITED

        self.assertThat(nuage_vport, ContainsDict({'addressSpoofing': Equals(expected_address_spoofing)}))

    def _given_network_linked_to_vsd_l3_subnet(self, vsd_subnet, cidr4=None, cidr6=None, net_partition=None ):
        # create Openstack IPv4 subnet on Openstack based on VSD l3domain subnet
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        if net_partition:
            actual_net_partition = net_partition
        else:
            actual_net_partition = CONF.nuage.nuage_default_netpartition

        subnet4 = self.create_subnet(
            network,
            gateway=None,
            cidr=cidr4,
            enable_dhcp=True,
            mask_bits=cidr4.prefixlen,
            nuagenet=vsd_subnet['ID'],
            net_partition=actual_net_partition)

        # create Openstack IPv6 subnet on Openstack based on VSD l3domain subnet
        subnet6 = None
        if cidr6:
            subnet6 = self.create_subnet(
                network,
                ip_version=6,
                gateway=vsd_subnet['IPv6Gateway'],
                cidr=IPNetwork(vsd_subnet['IPv6Address']),
                mask_bits=IPNetwork(vsd_subnet['IPv6Address']).prefixlen,
                enable_dhcp=False,
                nuagenet=vsd_subnet['ID'],
                net_partition=actual_net_partition)

        self.assertEqual(subnet6['cidr'], vsd_subnet['IPv6Address'])

        return network, subnet4, subnet6

    @nuage_test.header()
    def test_provision_port_without_address_pairs_in_l3_subnet(self):
        # Given I have a VSD-L3-Managed subnet
        vsd_l3_domain, vsd_l3_subnet = self._given_vsd_l3subnet(
            cidr4=self.cidr4, cidr6=self.cidr6 )
        network, subnet4, subnet6 = self._given_network_linked_to_vsd_l3_subnet(
            vsd_l3_subnet, cidr4=self.cidr4, cidr6=self.cidr6)

        self._check_crud_port("case-no-aap", network, subnet4, subnet6, vsd_l3_subnet)

        pass

    @nuage_test.header()
    def test_provision_ports_with_address_pairs_in_l3_subnet(self):
        # Given I have a VSD-L3-Managed subnet - dhcp-managed
        vsd_l3_domain, vsd_l3_subnet = self._given_vsd_l3subnet(
            cidr4=self.cidr4, cidr6=self.cidr6 )
        network, subnet4, subnet6 = self._given_network_linked_to_vsd_l3_subnet(
            vsd_l3_subnet, cidr4=self.cidr4, cidr6=self.cidr6)

        for scenario, port_config in self.port_configs.iteritems():
            self._check_crud_port(scenario, network, subnet4, subnet6, vsd_l3_subnet)

        pass

    # def test_ipv6_address(self):
    #     for scenario, port_config in self.port_configs.iteritems():
    #         allowed_address_pairs = port_config['allowed-address-pairs']
    #         print "Config %s : %s has value %s" % (scenario, allowed_address_pairs, self._has_ipv6_allowed_address_pairs(allowed_address_pairs))
    #
    # def test_dict_match(self):
    #     listofdict1 = [{'ip_address': '1.1.20.10', 'mac_address': 'fa:fa:3e:e8:e8:2a'},
    #                    {'ip_address': '2001:5f74:1111:b82e::a', 'mac_address': u'fa:16:3e:59:2b:03'}]
    #
    #     listofdict2 = [{u'ip_address': u'2001:5f74:1111:b82e::a',
    #                     u'mac_address': u'fa:16:3e:59:2b:03'},
    #                     {u'ip_address': u'1.1.20.10', u'mac_address': u'fa:fa:3e:e8:e8:2a'}]
    #
    #     self.assertItemsEqual(listofdict1, listofdict2)