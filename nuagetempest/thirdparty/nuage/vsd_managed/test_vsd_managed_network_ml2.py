# Copyright 2015 OpenStack Foundation
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
from nuagetempest.thirdparty.nuage.vsd_managed import test_vsd_managed_network

import testtools
from netaddr import IPNetwork
from tempest.lib import exceptions
from tempest.lib.common.utils import data_utils

from nuagetempest.lib.utils import constants as n_constants
from tempest import config

CONF = config.CONF


class VSDManagedNetworksTestJSONML2(
        test_vsd_managed_network.VSDManagedTestNetworks):
    credentials = ['admin']

    def __init__(self, *args, **kwargs):
        super(VSDManagedNetworksTestJSONML2, self).__init__(*args, **kwargs)
        self.failure_type = exceptions.ServerFault

    @classmethod
    def setup_clients(cls):
        cls.os = cls.os_adm
        cls.manager = cls.admin_manager
        super(VSDManagedNetworksTestJSONML2, cls).setup_clients()

    @classmethod
    def create_network(cls, network_name=None):
        """Wrapper utility that returns a test network."""
        name = network_name or data_utils.rand_name('test-network-')
        kwargs = {'name': name, 'provider:network_type': 'vxlan'}
        body = cls.client.create_resource("/networks", {'network': kwargs})
        cls.networks.append(body['network'])
        return body['network']

    @testtools.skip("No netpartition API for ML2")
    def test_create_list_verify_delete_netpartition(self):
        pass

    @testtools.skip("No netpartition API for ML2")
    def test_link_subnet_with_incorrect_netpartition_l2(self):
        pass

    @testtools.skip("ML2 can't detect if user entered gateway or not.")
    def test_link_subnet_with_incorrect_gateway_l3(self):
        pass

    def test_create_port_subnet_l2_managed(self):
        net_name = data_utils.rand_name()
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=net_name, cidr=cidr, gateway='10.10.100.1')
        vsd_l2dom = self.create_vsd_l2domain(name=net_name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])[0]

        network = self.create_network(network_name=net_name)
        subnet = self.create_subnet(
            network, gateway=None, cidr=cidr,
            mask_bits=24, nuagenet=vsd_l2dom['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition,
            enable_dhcp=True)
        self.assertIsNotNone(subnet, "Subnet should be created.")

        port = self.create_port(network)
        nuage_vport = self.nuageclient.get_vport(n_constants.L2_DOMAIN,
                                                 vsd_l2dom['ID'],
                                                 filters='externalID',
                                                 filter_value=port['id'])
        self.assertIsNotNone(nuage_vport, "vport should be created.")

    # HP - Unica scenario with DHCP-options defined in VSD
    def test_link_vsd_sharedsubnet_l3_with_dhcp_option(self):
        name = data_utils.rand_name('shared-l3-')
        cidr = IPNetwork('10.20.0.0/16')
        vsd_shared_l3dom_subnet = self.create_vsd_managed_shared_resource(
            name=name, netmask=str(cidr.netmask), address=str(cidr.ip),
            DHCPManaged=True,
            gateway='10.20.0.1',
            type='PUBLIC')

        self.nuageclient.create_dhcpoption(vsd_shared_l3dom_subnet['ID'],
                                           '03',
                                           ['10.20.0.25'])

        name = data_utils.rand_name('l3dom-with-shared')
        vsd_l3dom_tmplt = self.create_vsd_l3dom_template(
            name=name)
        vsd_l3dom = self.create_vsd_l3domain(name=name,
                                             tid=vsd_l3dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l3dom[0]['name'], name)
        zonename = data_utils.rand_name('Public-zone-')
        extra_params = {'publicZone': True}
        vsd_zone = self.create_vsd_zone(name=zonename,
                                        domain_id=vsd_l3dom[0]['ID'],
                                        extra_params=extra_params)

        name = data_utils.rand_name('l3domain-with-shared')
        data = {
            'name': name,
            'associatedSharedNetworkResourceID': vsd_shared_l3dom_subnet['ID']
        }
        resource = '/zones/' + vsd_zone[0]['ID'] + '/subnets'
        vsd_l3dom_subnet = self.nuageclient.restproxy.rest_call(
            'POST', resource, data)
        vsd_l3_dom_public_subnet = vsd_l3dom_subnet.data[0]
        self.assertEqual(vsd_l3_dom_public_subnet['name'], name)
        self.assertEqual(
            vsd_l3_dom_public_subnet['associatedSharedNetworkResourceID'],
            vsd_shared_l3dom_subnet['ID'])

        # create subnet on OS with nuagenet param set to l3domain UUID
        net_name = data_utils.rand_name('shared-l3-network-')
        network = self.create_network(network_name=net_name)
        subnet = self.create_subnet(
            network, cidr=cidr,
            mask_bits=16,
            nuagenet=vsd_l3_dom_public_subnet['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(
            str(IPNetwork(subnet['cidr']).ip),
            vsd_shared_l3dom_subnet['address'])
        self.assertEqual(subnet['gateway_ip'], '10.20.0.1')
        self.assertEqual(
            subnet['enable_dhcp'],
            vsd_shared_l3dom_subnet['DHCPManaged'])
        self.assertTrue(self._verify_vm_ip(network['id'], net_name))