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

from nuagetempest.lib.utils import constants
from nuagetempest.lib import features

from nuagetempest.services.nuage_client import NuageRestClient
from tempest.api.network import test_floating_ips
from tempest.common.utils import data_utils
from tempest import config
from tempest import test
from tempest.lib import exceptions

from testtools.matchers import KeysEqual
import uuid

CONF = config.CONF


class FloatingIPTestJSONNuage(test_floating_ips.FloatingIPTestJSON):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(FloatingIPTestJSONNuage, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(FloatingIPTestJSONNuage, cls).resource_setup()

        # Creating two more ports which will be added in VSD
        for i in range(2):
            post_body = {
                "device_owner": "compute:None", "device_id": str(uuid.uuid1())}
            cls.create_port(cls.network, **post_body)

    def _verify_fip_on_vsd(self, created_floating_ip,
                           router_id, port_id, subnet_id, associated='true'):
        # verifying on Domain level that the floating ip is added
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID',
            filter_value=router_id)
        nuage_domain_fip = self.nuage_vsd_client.get_floatingip(
            constants.DOMAIN, nuage_domain[0]['ID'])
        self.assertEqual(
            nuage_domain_fip[0]['address'],
            created_floating_ip['floating_ip_address'])

        if associated == 'true':
            # verifying on vminterface level that the floating ip is associated
            vsd_subnets = self.nuage_vsd_client.get_domain_subnet(
                None, None, 'externalID', subnet_id)
            nuage_vport = self.nuage_vsd_client.get_vport(constants.SUBNETWORK,
                                                          vsd_subnets[0]['ID'],
                                                          'externalID',
                                                          port_id)
            self.assertEqual(
                nuage_vport[0]['associatedFloatingIPID'],
                nuage_domain_fip[0]['ID'])
        else:
            # verifying the floating is not assigned to any network interface
            self.assertEqual(nuage_domain_fip[0]['assigned'], False)

    @test.attr(type='smoke')
    def test_create_list_show_update_delete_floating_ip(self):
        # Creates a floating IP
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[2]['id'])

        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['tenant_id'])
        self.assertIsNotNone(created_floating_ip['floating_ip_address'])
        self.assertEqual(created_floating_ip['port_id'], self.ports[2]['id'])
        self.assertEqual(created_floating_ip['floating_network_id'],
                         self.ext_net_id)
        self.assertIn(created_floating_ip['fixed_ip_address'],
                      [ip['ip_address'] for ip in self.ports[2]['fixed_ips']])

        # Verifies the details of a floating_ip
        floating_ip = self.floating_ips_client.show_floatingip(
            created_floating_ip['id'])
        shown_floating_ip = floating_ip['floatingip']
        self.assertEqual(shown_floating_ip['id'], created_floating_ip['id'])
        self.assertEqual(shown_floating_ip['floating_network_id'],
                         self.ext_net_id)
        self.assertEqual(shown_floating_ip['tenant_id'],
                         created_floating_ip['tenant_id'])
        self.assertEqual(shown_floating_ip['floating_ip_address'],
                         created_floating_ip['floating_ip_address'])
        self.assertEqual(shown_floating_ip['port_id'], self.ports[2]['id'])

        # VSD Validation
        self._verify_fip_on_vsd(
            created_floating_ip, created_floating_ip['router_id'],
            self.ports[2]['id'], self.subnet['id'], 'true')

        # Verify the floating ip exists in the list of all floating_ips
        floating_ips = self.floating_ips_client.list_floatingips()
        floatingip_id_list = list()
        for f in floating_ips['floatingips']:
            floatingip_id_list.append(f['id'])
        self.assertIn(created_floating_ip['id'], floatingip_id_list)

        # Disassociate floating IP from the port
        floating_ip = self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            port_id=None)
        updated_floating_ip = floating_ip['floatingip']
        self.assertIsNone(updated_floating_ip['port_id'])
        self.assertIsNone(updated_floating_ip['fixed_ip_address'])
        self.assertIsNone(updated_floating_ip['router_id'])

        # Associate floating IP to the other port
        floating_ip = self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            port_id=self.ports[3]['id'])
        updated_floating_ip = floating_ip['floatingip']
        self.assertEqual(updated_floating_ip['port_id'], self.ports[3]['id'])
        self.assertEqual(updated_floating_ip['fixed_ip_address'],
                         self.ports[3]['fixed_ips'][0]['ip_address'])
        self.assertEqual(updated_floating_ip['router_id'], self.router['id'])

        # VSD Validation
        self._verify_fip_on_vsd(
            created_floating_ip, created_floating_ip['router_id'],
            self.ports[3]['id'], self.subnet['id'], 'true')

        # Disassociate floating IP from the port
        floating_ip = self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            port_id=None)
        updated_floating_ip = floating_ip['floatingip']
        self.assertIsNone(updated_floating_ip['port_id'])
        self.assertIsNone(updated_floating_ip['fixed_ip_address'])
        self.assertIsNone(updated_floating_ip['router_id'])

        # VSD Validation
        self._verify_fip_on_vsd(
            created_floating_ip, self.router['id'], None, None, 'false')

    @test.attr(type='smoke')
    def test_create_update_floating_ip(self):
        # Creates a floating IP
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[2]['id'])

        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['tenant_id'])
        self.assertIsNotNone(created_floating_ip['floating_ip_address'])
        self.assertEqual(created_floating_ip['port_id'], self.ports[2]['id'])
        self.assertEqual(created_floating_ip['floating_network_id'],
                         self.ext_net_id)
        self.assertIn(created_floating_ip['fixed_ip_address'],
                      [ip['ip_address'] for ip in self.ports[2]['fixed_ips']])

        # Verifies the details of a floating_ip
        floating_ip = self.floating_ips_client.show_floatingip(
            created_floating_ip['id'])
        shown_floating_ip = floating_ip['floatingip']
        self.assertEqual(shown_floating_ip['id'], created_floating_ip['id'])
        self.assertEqual(shown_floating_ip['floating_network_id'],
                         self.ext_net_id)
        self.assertEqual(shown_floating_ip['tenant_id'],
                         created_floating_ip['tenant_id'])
        self.assertEqual(shown_floating_ip['floating_ip_address'],
                         created_floating_ip['floating_ip_address'])
        self.assertEqual(shown_floating_ip['port_id'], self.ports[2]['id'])

        # VSD Validation
        self._verify_fip_on_vsd(
            created_floating_ip, created_floating_ip['router_id'],
            self.ports[2]['id'], self.subnet['id'], 'true')

        # Verify the floating ip exists in the list of all floating_ips
        floating_ips = self.floating_ips_client.list_floatingips()
        floatingip_id_list = list()
        for f in floating_ips['floatingips']:
            floatingip_id_list.append(f['id'])
        self.assertIn(created_floating_ip['id'], floatingip_id_list)

        # Associate floating IP to the other port
        self.assertRaises(exceptions.ServerFault,
                          self.floating_ips_client.update_floatingip,
                          created_floating_ip['id'],
                          port_id=self.ports[3]['id'])

    @test.attr(type='smoke')
    def test_floating_ip_delete_port(self):
        # Create a floating IP
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id)
        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        # Create a port
        post_body = {
            "device_owner": "compute:None", "device_id": str(uuid.uuid1())}
        port = self.ports_client.create_port(
            network_id=self.network['id'], **post_body)
        created_port = port['port']
        floating_ip = self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            port_id=created_port['id'])

        # VSD Validation
        self._verify_fip_on_vsd(created_floating_ip, self.router['id'],
                                created_port['id'], self.subnet['id'],
                                'true')
        # Delete port
        self.ports_client.delete_port(created_port['id'])
        # Verifies the details of the floating_ip
        floating_ip = self.floating_ips_client.show_floatingip(
            created_floating_ip['id'])
        shown_floating_ip = floating_ip['floatingip']
        # Confirm the fields are back to None
        self.assertEqual(shown_floating_ip['id'], created_floating_ip['id'])
        self.assertIsNone(shown_floating_ip['port_id'])
        self.assertIsNone(shown_floating_ip['fixed_ip_address'])
        self.assertIsNone(shown_floating_ip['router_id'])

    @test.attr(type='smoke')
    def test_floating_ip_update_different_router(self):
        # Associate a floating IP to a port on a router
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[3]['id'])
        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertEqual(created_floating_ip['router_id'], self.router['id'])

        # VSD Validation
        self._verify_fip_on_vsd(
            created_floating_ip, created_floating_ip['router_id'],
            self.ports[3]['id'], self.subnet['id'], 'true')

        network2 = self.create_network()
        subnet2 = self.create_subnet(network2)
        router2 = self.create_router(data_utils.rand_name('router-'),
                                     external_network_id=self.ext_net_id)
        self.create_router_interface(router2['id'], subnet2['id'])
        post_body = {
            "device_owner": "compute:None", "device_id": str(uuid.uuid1())}
        port_other_router = self.create_port(network2, **post_body)
        # Associate floating IP to the other port on another router
        self.assertRaises(exceptions.ServerFault,
                          self.floating_ips_client.update_floatingip,
                          created_floating_ip['id'],
                          port_id=port_other_router['id'])
        # VSD Validation
        self._verify_fip_on_vsd(
            created_floating_ip, created_floating_ip['router_id'],
            self.ports[3]['id'], self.subnet['id'], 'true')

    @test.attr(type='smoke')
    def test_create_floating_ip_specifying_a_fixed_ip_address(self):
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[3]['id'],
            fixed_ip_address=self.ports[3]['fixed_ips'][0]['ip_address'])
        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['id'])
        self.assertEqual(created_floating_ip['fixed_ip_address'],
                         self.ports[3]['fixed_ips'][0]['ip_address'])
        # VSD validation
        self._verify_fip_on_vsd(
            created_floating_ip, created_floating_ip['router_id'],
            self.ports[3]['id'], self.subnet['id'], 'true')

        floating_ip = self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            port_id=None)
        self.assertIsNone(floating_ip['floatingip']['port_id'])

        # VSD Validation
        self._verify_fip_on_vsd(
            created_floating_ip, self.router['id'], None, None, 'false')

    @test.attr(type='smoke')
    def test_create_floatingip_with_rate_limiting(self):
        rate_limit = 10
        # Create port
        post_body = {"network_id": self.network['id']}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])

        # Associate a fip to the port
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=port['id'],
            fixed_ip_address=port['fixed_ips'][0]['ip_address'],
            nuage_fip_rate=rate_limit)
        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['id'])

        fip_id = created_floating_ip['id']
        body = self.floating_ips_client.show_floatingip(fip_id)
        fip = body['floatingip']

        if features.NUAGE_FEATURES.bidrectional_fip_rate_limit:
            self.assertIsNotNone(fip.get('nuage_ingress_fip_rate_kbps'))
            self.assertIsNotNone(fip.get('nuage_egress_fip_rate_kbps'))
            self.assertEqual(str(rate_limit), fip['nuage_egress_fip_rate_kbps'])
            os_fip_rate = fip.get('nuage_fip_rate')

        else:
            os_fip_rate = fip.get('nuage_fip_rate')
            self.assertIsNotNone(os_fip_rate)
            self.assertEqual(str(rate_limit), fip['nuage_fip_rate'])

        # Check vsd
        vsd_subnets = self.nuage_vsd_client.get_domain_subnet(
            None, None, 'externalID', self.subnet['id'])
        self.assertEqual(1, len(vsd_subnets))
        vports = self.nuage_vsd_client.get_vport(constants.SUBNETWORK,
                                                 vsd_subnets[0]['ID'],
                                                 'externalID',
                                                 port['id'])
        self.assertEqual(1, len(vports))
        qos = self.nuage_vsd_client.get_qos(constants.VPORT, vports[0]['ID'])
        self.assertEqual(1, len(qos))
        self.assertEqual(self.nuage_vsd_client.get_vsd_external_id(fip_id), qos[0]['externalID'])
        self.assertEqual(True, qos[0]['FIPRateLimitingActive'])

        if features.NUAGE_FEATURES.bidrectional_fip_rate_limit:
            self.assertEqual(str(rate_limit/1000), qos[0]['FIPPeakInformationRate'])
            self.assertEqual('INFINITY', qos[0]['EgressFIPPeakInformationRate'])
        else:
            self.assertEqual(str(rate_limit), qos[0]['FIPPeakInformationRate'])

    @test.attr(type='smoke')
    def test_create_floatingip_without_rate_limiting(self):
        # Create port
        post_body = {"network_id": self.network['id']}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])

        # Associate a fip to the port
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=port['id'],
            fixed_ip_address=port['fixed_ips'][0]['ip_address'])
        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['id'])

        fip_id = created_floating_ip['id']
        body = self.floating_ips_client.show_floatingip(fip_id)
        fip = body['floatingip']

        if features.NUAGE_FEATURES.bidrectional_fip_rate_limit:
            self.assertIsNotNone(fip.get('nuage_ingress_fip_rate_kbps'))
            self.assertIsNotNone(fip.get('nuage_egress_fip_rate_kbps'))
        else:
            os_fip_rate = fip.get('nuage_fip_rate')
            self.assertIsNotNone(os_fip_rate)

        # Check vsd
        vsd_subnets = self.nuage_vsd_client.get_domain_subnet(
            None, None, 'externalID', self.subnet['id'])
        self.assertEqual(1, len(vsd_subnets))
        vports = self.nuage_vsd_client.get_vport(constants.SUBNETWORK,
                                                 vsd_subnets[0]['ID'],
                                                 'externalID',
                                                 port['id'])
        self.assertEqual(1, len(vports))
        qos = self.nuage_vsd_client.get_qos(constants.VPORT, vports[0]['ID'])
        self.assertEqual(1, len(qos))
        self.assertEqual(self.nuage_vsd_client.get_vsd_external_id(fip_id), qos[0]['externalID'])
        self.assertEqual(True, qos[0]['FIPRateLimitingActive'])

        if features.NUAGE_FEATURES.bidrectional_fip_rate_limit:
            self.assertEqual('INFINITY', qos[0]['FIPPeakInformationRate'])
            self.assertEqual('INFINITY', qos[0]['EgressFIPPeakInformationRate'])
        else:
            self.assertEqual('INFINITY', qos[0]['FIPPeakInformationRate'])

