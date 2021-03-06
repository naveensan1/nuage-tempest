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

import os.path
import yaml
import json

from oslo_log import log as logging

from tempest.lib import exceptions as lib_exc

import tempest.test
from tempest import config
from tempest.lib.common.utils import data_utils
from nuagetempest.services import nuage_client

CONF = config.CONF

LOG = logging.getLogger(__name__)


class NuageBaseOrchestrationTest(tempest.test.BaseTestCase):
    """Base test case class for all Nuage Orchestration API tests."""
    credentials = ['primary']

    @classmethod
    def setup_credentials(cls):
        super(NuageBaseOrchestrationTest, cls).setup_credentials()
        stack_owner_role = CONF.orchestration.stack_owner_role
        cls.os = cls.get_client_manager(roles=[stack_owner_role])

    @classmethod
    def skip_checks(cls):
        super(NuageBaseOrchestrationTest, cls).skip_checks()
        if not CONF.service_available.heat:
            raise cls.skipException("Heat support is required")
        if not CONF.service_available.neutron:
            raise cls.skipException("Neutron support is required")

    @classmethod
    def setup_clients(cls):
        super(NuageBaseOrchestrationTest, cls).setup_clients()
        cls.vsd_client = nuage_client.NuageRestClient()

        cls.orchestration_client = cls.os.orchestration_client

        cls.os_adm = cls.get_client_manager(roles=['admin'])

        cls.admin_network_client = cls.os_adm.network_client
        cls.admin_networks_client = cls.os_adm.networks_client
        cls.admin_routers_client = cls.os_adm.routers_client

    @classmethod
    def resource_setup(cls):
        super(NuageBaseOrchestrationTest, cls).resource_setup()

        cls.build_timeout = CONF.orchestration.build_timeout
        cls.build_interval = CONF.orchestration.build_interval

        cls.net_partition_name = CONF.nuage.nuage_default_netpartition
        cls.private_net_name = data_utils.rand_name('heat-network-')

        cls.test_resources = {}
        cls.template_resources = {}

    def launch_stack(self, stack_file_name, stack_parameters):
        stack_name = data_utils.rand_name('heat-' + stack_file_name)
        template = self.read_template(stack_file_name)

        self.launch_stack_template(stack_name, template, stack_parameters)

    def launch_stack_template (self, stack_name, template, stack_parameters):
        LOG.debug("Stack launched: %s", template)
        LOG.debug("Stack parameters: %s", stack_parameters)

        # create the stack
        self.stack_identifier = self.create_stack(
            stack_name,
            template,
            stack_parameters
        )
        self.stack_id = self.stack_identifier.split('/')[1]
        self.orchestration_client.wait_for_stack_status(self.stack_id, 'CREATE_COMPLETE')

        resources = self.orchestration_client.list_resources(self.stack_identifier)
        resources = resources['resources']
        self.test_resources = {}
        for resource in resources:
            self.test_resources[resource['logical_resource_id']] = resource

        # load to dict
        my_dict = yaml.safe_load(template)

        self.template_resources = my_dict['resources']

    # def load_stack_resources(self, stack_file_name):
    #     loaded_template = self.load_template(stack_file_name)
    #     return loaded_template['resources']

    def verify_stack_resources(self, expected_resources, template_resourses, actual_resources):
        for resource_name in expected_resources:
            resource_type = template_resourses[resource_name]['type']
            resource = actual_resources.get(resource_name, None)
            self.assertIsInstance(resource, dict)
            self.assertEqual(resource_name, resource['logical_resource_id'])
            self.assertEqual(resource_type, resource['resource_type'])
            self.assertEqual('CREATE_COMPLETE', resource['resource_status'])

    @classmethod
    def read_template(cls, name, ext='yaml'):
        loc = ["templates", "%s.%s" % (name, ext)]
        fullpath = os.path.join(os.path.dirname(__file__), *loc)

        with open(fullpath, "r") as f:
            content = f.read()
            return content

    @classmethod
    def load_template(cls, name, ext='yaml'):
        loc = ["templates", "%s.%s" % (name, ext)]
        fullpath = os.path.join(os.path.dirname(__file__), *loc)

        with open(fullpath, "r") as f:
            return yaml.safe_load(f)

    def create_stack(self, stack_name, template_data, parameters=None,
                     environment=None, files=None):
        if parameters is None:
            parameters = {}
        body = self.orchestration_client.create_stack(
            stack_name,
            template=template_data,
            parameters=parameters,
            environment=environment,
            files=files)
        stack_id = body.response['location'].split('/')[-1]
        stack_identifier = '%s/%s' % (stack_name, stack_id)
        
        self.addCleanup(self._clear_stack, stack_identifier)
        return stack_identifier

    def _clear_stack(self, stack_identifier):
        try:
            self.orchestration_client.delete_stack(stack_identifier)
        except lib_exc.NotFound:
            pass

        try:
            self.orchestration_client.wait_for_stack_status(
                stack_identifier, 'DELETE_COMPLETE', failure_pattern="DELETE_FAILED")
        except lib_exc.NotFound:
            pass

    # @classmethod
    # def _clear_stacks(self):
    #     for stack_identifier in self.stacks:
    #         try:
    #             self.client.delete_stack(stack_identifier)
    #         except lib_exc.NotFound:
    #             pass
    #
    #     for stack_identifier in self.stacks:
    #         try:
    #             self.client.wait_for_stack_status(
    #                 stack_identifier, 'DELETE_COMPLETE', failure_pattern="DELETE_FAILED")
    #         except lib_exc.NotFound:
    #             pass

    # @classmethod
    # def _create_keypair(cls, name_start='keypair-heat-'):
    #     kp_name = data_utils.rand_name(name_start)
    #     body = cls.keypairs_client.create_keypair(name=kp_name)['keypair']
    #     cls.keypairs.append(kp_name)
    #     return body
    #
    # @classmethod
    # def _clear_keypairs(cls):
    #     for kp_name in cls.keypairs:
    #         try:
    #             cls.keypairs_client.delete_keypair(kp_name)
    #         except Exception:
    #             pass
    #
    # @classmethod
    # def _create_image(cls, name_start='image-heat-', container_format='bare',
    #                   disk_format='iso'):
    #     image_name = data_utils.rand_name(name_start)
    #     body = cls.images_v2_client.create_image(image_name,
    #                                              container_format,
    #                                              disk_format)
    #     image_id = body['id']
    #     cls.images.append(image_id)
    #     return body
    #
    # @classmethod
    # def _clear_images(cls):
    #     for image_id in cls.images:
    #         try:
    #             cls.images_v2_client.delete_image(image_id)
    #         except lib_exc.NotFound:
    #             pass

    @classmethod
    def read_template(cls, name, ext='yaml'):
        loc = ["templates", "%s.%s" % (name, ext)]
        fullpath = os.path.join(os.path.dirname(__file__), *loc)

        with open(fullpath, "r") as f:
            content = f.read()
            return content

    @classmethod
    def load_template(cls, name, ext='yaml'):
        loc = ["templates", "%s.%s" % (name, ext)]
        fullpath = os.path.join(os.path.dirname(__file__), *loc)

        with open(fullpath, "r") as f:
            return yaml.safe_load(f)

    @staticmethod
    def stack_output(stack, output_key):
        """Return a stack output value for a given key."""
        return next((o['output_value'] for o in stack['outputs']
                     if o['output_key'] == output_key), None)

    def assert_fields_in_dict(self, obj, *fields):
        for field in fields:
            self.assertIn(field, obj)

    def list_resources(self, stack_identifier):
        """Get a dict mapping of resource names to types."""
        resources = self.client.list_resources(stack_identifier)['resources']
        self.assertIsInstance(resources, list)
        for res in resources:
            self.assert_fields_in_dict(res, 'logical_resource_id',
                                       'resource_type', 'resource_status',
                                       'updated_time')

        return dict((r['resource_name'], r['resource_type'])
                    for r in resources)

    def get_stack_output(self, stack_identifier, output_key):
        body = self.client.show_stack(stack_identifier)['stack']
        return self.stack_output(body, output_key)

    def verify_created_network(self, resource_name):
        """Verifies created network."""
        resource = self.test_resources.get(resource_name)
        network_id = resource['physical_resource_id']
        body = self.admin_networks_client.show_network(network_id)
        network = body['network']

        # basic verifications
        self.assertIsInstance(network, dict)
        self.assertEqual(network_id, network['id'])

        return network

    def verify_created_subnet(self, resource_name, network):
        """Verifies created network."""
        resource = self.test_resources.get(resource_name)

        subnet_id = resource['physical_resource_id']
        # (waelj) response does no longer report the attribute 'vsd_managed' by default
        # Need to list 'vsd_managed' in the fields list in order to get the attribute
        # format: {'fields': ['id', 'name']}
        body = self.os_adm.subnets_client.show_subnet(subnet_id, fields=['id', 'network_id', 'ip_version',
                                                                         'vsd_managed', 'enable_dhcp', 'cidr',
                                                                         'gateway_ip', 'allocation_pools'])

        subnet = body['subnet']

        # basic verifications
        self.assertIsInstance(subnet, dict)
        self.assertEqual(subnet_id, subnet['id'])
        self.assertEqual(network['id'], subnet['network_id'])

        self.assertTrue(subnet['vsd_managed'])
        #self.assertEqual(4, subnet['ip_version'])

        return subnet

    def verify_created_router(self, resource_name):
        """Verifies created router."""
        resource = self.test_resources.get(resource_name)
        router_id = resource['physical_resource_id']
        body = self.admin_routers_client.show_router(router_id)
        router = body['router']

        # basic verifications
        self.assertIsInstance(router, dict)
        self.assertEqual(router_id, router['id'])

        return router

    def verify_created_security_group(self, resource_name):
        """Verifies created security_group."""
        resource = self.test_resources.get(resource_name)
        security_group_id = resource['physical_resource_id']
        body = self.os_adm.security_groups_client.show_security_group(security_group_id)
        security_group = body['security_group']

        # basic verifications
        self.assertIsInstance(security_group, dict)
        self.assertEqual(security_group_id, security_group['id'])

        return security_group

