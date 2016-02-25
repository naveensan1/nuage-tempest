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


import logging
import uuid
from tempest import test

from tempest.lib.common.utils import data_utils

from tempest import config
import nuage_base
from nuagetempest.services import nuage_client

CONF = config.CONF

LOG = logging.getLogger(__name__)


class NeutronGatewayResourcesTest(nuage_base.NuageBaseOrchestrationTest):
    """Basic tests for Heat Nuage gateway resources"""

    @classmethod
    def setup_clients(cls):
        super(NeutronGatewayResourcesTest, cls).setup_clients()
        cls.orchestration_client = cls.os_adm.orchestration_client
        cls.client = cls.orchestration_client

        cls.nuage_vsd_client = nuage_client.NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(NeutronGatewayResourcesTest, cls).resource_setup()

        if not test.is_extension_enabled('nuage-gateway', 'network'):
            msg = "Nuage extension 'nuage-gateway' not enabled."
            raise cls.skipException(msg)

        cls.gateways = []
        cls.gateway_ports = []
        gw_name = data_utils.rand_name('tempest-gw')
        gw = cls.nuage_vsd_client.create_gateway(
            gw_name, str(uuid.uuid4()), 'VRSG', None)
        cls.gateways.append(gw)
        port_name = data_utils.rand_name('tempest-gw-port')
        gw_port = cls.nuage_vsd_client.create_gateway_port(
            port_name, 'test', 'ACCESS', gw[0]['ID'])
        cls.gateway_ports.append(gw_port)

        cls.template = cls.load_template('gateway')
        cls.stack_name = data_utils.rand_name('heat-gateway')
        template = cls.read_template('gateway')

        # create the stack
        cls.stack_identifier = cls.create_stack(
            cls.stack_name,
            template,
            parameters={
                'gw_name': gw_name,
                'gw_port': port_name
            })
        cls.stack_id = cls.stack_identifier.split('/')[1]
        cls.client.wait_for_stack_status(cls.stack_id, 'CREATE_COMPLETE')
        resources = (cls.client.list_resources(cls.stack_identifier)['resources'])

        cls.test_resources = {}
        for resource in resources:
            cls.test_resources[resource['logical_resource_id']] = resource

    @classmethod
    def resource_cleanup(cls):
        super(NeutronGatewayResourcesTest, cls).resource_cleanup()
        for port in cls.gateway_ports:
            try:
                cls.nuage_vsd_client.delete_gateway_port(port[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)

        for gateway in cls.gateways:
            try:
                cls.nuage_vsd_client.delete_gateway(gateway[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)


    def test_created_gateway_resources(self):
        """Verifies created neutron gateway resources."""
        resources = [('gateway', self.template['resources'][
                      'gateway']['type']),
                     ('gateway_port', self.template['resources'][
                      'gateway_port']['type']),
                     ('vlan1', self.template[
                      'resources']['vlan1']['type']),
                     ('vlan2', self.template['resources'][
                      'vlan2']['type'])]
        for resource_name, resource_type in resources:
            resource = self.test_resources.get(resource_name, None)
            self.assertIsInstance(resource, dict)
            self.assertEqual(resource_name, resource['logical_resource_id'])
            self.assertEqual(resource_type, resource['resource_type'])
            self.assertEqual('CREATE_COMPLETE', resource['resource_status'])

