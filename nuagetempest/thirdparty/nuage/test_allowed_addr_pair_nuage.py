# Copyright 2014 OpenStack Foundation
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

from nuagetempest.lib.utils import constants as n_constants
from nuagetempest.services.nuage_client import NuageRestClient
from tempest.api.network import base
from tempest.common.utils import data_utils
from tempest import config
from tempest import test
from tempest_lib import exceptions
import uuid

CONF = config.CONF


class AllowedAddressPairTestJSON(base.BaseNetworkTest):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(AllowedAddressPairTestJSON, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(AllowedAddressPairTestJSON, cls).resource_setup()
        if not test.is_extension_enabled('allowed-address-pairs', 'network'):
            msg = "Allowed Address Pairs extension not enabled."
            raise cls.skipException(msg)

        cls.network = cls.create_network()
        cls.create_subnet(cls.network)

        cls.ext_net_id = CONF.network.public_network_id
        cls.l3network = cls.create_network()
        cls.l3subnet = cls.create_subnet(cls.l3network)
        cls.router = cls.create_router(data_utils.rand_name('router-'),
                                       external_network_id=cls.ext_net_id)
        cls.create_router_interface(cls.router['id'], cls.l3subnet['id'])

    def test_create_address_pair_on_l2domain(self):
        # Create port with allowed address pair attribute
        addrpair_port = self.create_port(self.network)
        allowed_address_pairs = [{'ip_address':
                                  addrpair_port['fixed_ips'][0]['ip_address'],
                                  'mac_address': addrpair_port['mac_address']}]

        body = self.ports_client.create_port(
            network_id=self.network['id'],
            allowed_address_pairs=allowed_address_pairs)
        port_id = body['port']['id']
        self.addCleanup(self.ports_client.delete_port, port_id)

        # Confirm port was created with allowed address pair attribute
        body = self.ports_client.list_ports()
        ports = body['ports']
        port = [p for p in ports if p['id'] == port_id]
        msg = 'Created port not found in list of ports returned by Neutron'
        self.assertTrue(port, msg)
        ip_address = port[0]['allowed_address_pairs'][0]['ip_address']
        mac_address = port[0]['allowed_address_pairs'][0]['mac_address']
        self.assertEqual(ip_address,
                         addrpair_port['fixed_ips'][0]['ip_address'])
        self.assertEqual(mac_address, addrpair_port['mac_address'])

        # Check address spoofing is disabled on vport in VSD
        nuage_subnet = self.nuage_vsd_client.get_l2domain(
            filters='externalID', filter_value=port[0]['fixed_ips'][0]
            ['subnet_id'])
        nuage_vport = self.nuage_vsd_client.get_vport(n_constants.L2_DOMAIN,
                                                      nuage_subnet[0]['ID'],
                                                      filters='externalID',
                                                      filter_value=port_id)
        self.assertEqual(n_constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])

    def test_create_address_pair_on_l3subnet(self):
        # Create port with allowed address pair attribute
        addrpair_port = self.create_port(self.l3network)
        allowed_address_pairs = [{'ip_address':
                                  addrpair_port['fixed_ips'][0]['ip_address'],
                                  'mac_address': addrpair_port['mac_address']}]

        body = self.ports_client.create_port(
            network_id=self.l3network['id'],
            allowed_address_pairs=allowed_address_pairs)
        port_id = body['port']['id']
        self.addCleanup(self.ports_client.delete_port, port_id)

        # Confirm port was created with allowed address pair attribute
        body = self.ports_client.list_ports()
        ports = body['ports']
        port = [p for p in ports if p['id'] == port_id]
        msg = 'Created port not found in list of ports returned by Neutron'
        self.assertTrue(port, msg)
        ip_address = port[0]['allowed_address_pairs'][0]['ip_address']
        mac_address = port[0]['allowed_address_pairs'][0]['mac_address']
        self.assertEqual(ip_address,
                         addrpair_port['fixed_ips'][0]['ip_address'])
        self.assertEqual(mac_address, addrpair_port['mac_address'])

        # Check VIP is created in VSD
        nuage_domain = self.nuage_vsd_client.get_resource(
            n_constants.DOMAIN,
            filters='externalID',
            filter_value=self.router['id'])
        nuage_subnet = self.nuage_vsd_client.get_domain_subnet(
            n_constants.DOMAIN, nuage_domain[0]['ID'],
            filters='externalID', filter_value=port[0]['fixed_ips'][0]
            ['subnet_id'])
        nuage_vport = self.nuage_vsd_client.get_vport(n_constants.SUBNETWORK,
                                                      nuage_subnet[0]['ID'],
                                                      filters='externalID',
                                                      filter_value=port_id)
        self.assertEqual(n_constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])

        nuage_vip = self.nuage_vsd_client.get_virtual_ip(
            n_constants.VPORT,
            nuage_vport[0]['ID'],
            filters='virtualIP',
            filter_value=str(addrpair_port['fixed_ips'][0]['ip_address']))
        self.assertEqual(addrpair_port['mac_address'], nuage_vip[0]['MAC'])

    def test_update_address_pair_on_l3subnet(self):
        addrpair_port_1 = self.create_port(self.l3network)
        allowed_address_pairs = [
            {'ip_address': addrpair_port_1['fixed_ips'][0]['ip_address'],
             'mac_address': addrpair_port_1['mac_address']}]

        body = self.ports_client.create_port(
            network_id=self.l3network['id'],
            allowed_address_pairs=allowed_address_pairs)
        port_id = body['port']['id']
        self.addCleanup(self.ports_client.delete_port, port_id)

        # Confirm port was created with allowed address pair attribute
        body = self.ports_client.list_ports()
        ports = body['ports']
        port = [p for p in ports if p['id'] == port_id]
        msg = 'Created port not found in list of ports returned by Neutron'
        self.assertTrue(port, msg)
        ip_address = port[0]['allowed_address_pairs'][0]['ip_address']
        mac_address = port[0]['allowed_address_pairs'][0]['mac_address']
        self.assertEqual(ip_address, allowed_address_pairs[0]['ip_address'])
        self.assertEqual(mac_address, allowed_address_pairs[0]['mac_address'])

        # Check VIP is created in VSD
        nuage_domain = self.nuage_vsd_client.get_resource(
            n_constants.DOMAIN,
            filters='externalID',
            filter_value=self.router['id'])
        nuage_subnet = self.nuage_vsd_client.get_domain_subnet(
            n_constants.DOMAIN, nuage_domain[0]['ID'],
            filters='externalID', filter_value=port[0]['fixed_ips'][0]
            ['subnet_id'])
        nuage_vport = self.nuage_vsd_client.get_vport(n_constants.SUBNETWORK,
                                                      nuage_subnet[0]['ID'],
                                                      filters='externalID',
                                                      filter_value=port_id)
        self.assertEqual(n_constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])

        nuage_vip = self.nuage_vsd_client.get_virtual_ip(
            n_constants.VPORT,
            nuage_vport[0]['ID'],
            filters='virtualIP',
            filter_value=str(addrpair_port_1['fixed_ips'][0]['ip_address']))
        self.assertEqual(addrpair_port_1['mac_address'], nuage_vip[0]['MAC'])

        # Update the address pairs
        # Create port with allowed address pair attribute
        addrpair_port_2 = self.create_port(self.l3network)
        allowed_address_pairs = [
            {'ip_address': addrpair_port_2['fixed_ips'][0]['ip_address'],
             'mac_address': addrpair_port_2['mac_address']}]

        port = self.update_port(port[0],
                                allowed_address_pairs=allowed_address_pairs)

        port_id = port['id']

        # Confirm port was created with allowed address pair attribute
        body = self.ports_client.list_ports()
        ports = body['ports']
        port = [p for p in ports if p['id'] == port_id]
        msg = 'Created port not found in list of ports returned by Neutron'
        self.assertTrue(port, msg)
        ip_address = port[0]['allowed_address_pairs'][0]['ip_address']
        mac_address = port[0]['allowed_address_pairs'][0]['mac_address']
        self.assertEqual(ip_address,
                         addrpair_port_2['fixed_ips'][0]['ip_address'])
        self.assertEqual(mac_address, addrpair_port_2['mac_address'])

        # Verify new VIP is created
        nuage_vport = self.nuage_vsd_client.get_vport(n_constants.SUBNETWORK,
                                                      nuage_subnet[0]['ID'],
                                                      filters='externalID',
                                                      filter_value=port_id)
        self.assertEqual(n_constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])

        nuage_vip = self.nuage_vsd_client.get_virtual_ip(
            n_constants.VPORT,
            nuage_vport[0]['ID'],
            filters='virtualIP',
            filter_value=str(addrpair_port_2['fixed_ips'][0]['ip_address']))
        self.assertEqual(addrpair_port_2['mac_address'], nuage_vip[0]['MAC'])

        # Verify old VIP is deleted
        nuage_vip = self.nuage_vsd_client.get_virtual_ip(
            n_constants.VPORT,
            nuage_vport[0]['ID'],
            filters='virtualIP',
            filter_value=str(addrpair_port_1['fixed_ips'][0]['ip_address']))
        self.assertEmpty(nuage_vip)

    def test_create_address_pair_with_same_ip(self):
        # Create a vm
        post_body = {"network_id": self.l3network['id'],
                     "device_owner": 'compute:None',
                     "device_id": str(uuid.uuid1())}
        body = self.ports_client.create_port(**post_body)
        vm_port = body['port']
        self.addCleanup(self.ports_client.delete_port, vm_port['id'])

        # Create another port
        old_name = "Old_Port"
        post_body = {"network_id": self.l3network['id'],
                     "name": old_name}
        body = self.ports_client.create_port(**post_body)
        port = body['port']
        port_id = port['id']
        self.addCleanup(self.ports_client.delete_port, port_id)

        # Create port with allowed address pair attribute
        allowed_address_pairs = [{'ip_address':
                                  vm_port['fixed_ips'][0]['ip_address']}]
        new_name = "New_Port"
        self.assertRaises(exceptions.ServerFault,
                          self.ports_client.update_port,
                          port_id,
                          allowed_address_pairs=allowed_address_pairs,
                          name=new_name
                          )
        body = self.ports_client.list_ports()
        ports = body['ports']
        port = [p for p in ports if p['id'] == port_id]
        self.assertEqual(old_name, port[0]['name'])
