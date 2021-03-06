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

from oslo_log import log as logging
import yaml

from tempest import config
from tempest.api.orchestration import base
from tempest.lib.common.utils import data_utils
from nuagetempest.services import nuage_client

CONF = config.CONF

LOG = logging.getLogger(__name__)


class NuageBaseOrchestrationTest(base.BaseOrchestrationTest):
    """Base test case class for all Nuage Orchestration API tests."""
    @classmethod
    def skip_checks(cls):
        super(NuageBaseOrchestrationTest, cls).skip_checks()
        if not CONF.service_available.neutron:
            raise cls.skipException("Neutron support is required")

    @classmethod
    def setup_clients(cls):
        super(NuageBaseOrchestrationTest, cls).setup_clients()
        cls.vsd_client = nuage_client.NuageRestClient()

        cls.os_adm = cls.get_client_manager(roles=['admin'])

        cls.admin_network_client = cls.os_adm.network_client
        cls.admin_networks_client = cls.os_adm.networks_client
        cls.admin_routers_client = cls.os_adm.routers_client

    @classmethod
    def resource_setup(cls):
        super(NuageBaseOrchestrationTest, cls).resource_setup()

        cls.net_partition_name = CONF.nuage.nuage_default_netpartition
        cls.private_net_name = data_utils.rand_name('heat-network-')

        cls.vsd_l2domain_template = []
        cls.vsd_l2domain = []
        cls.vsd_l3domain_template = []
        cls.vsd_l3domain = []
        cls.vsd_zone = []
        cls.vsd_subnet = []

        cls.test_resources = {}
        cls.template_resources = {}

    @classmethod
    def resource_cleanup(cls):
        super(NuageBaseOrchestrationTest, cls).resource_cleanup()

        for vsd_l2domain in cls.vsd_l2domain:
            cls.vsd_client.delete_l2domain(vsd_l2domain[0]['ID'])

        for vsd_l2domain_template in cls.vsd_l2domain_template:
            cls.vsd_client.delete_l2domaintemplate(vsd_l2domain_template[0]['ID'])

        for vsd_subnet in cls.vsd_subnet:
            cls.vsd_client.delete_domain_subnet(vsd_subnet[0]['ID'])

        for vsd_zone in cls.vsd_zone:
            cls.vsd_client.delete_zone(vsd_zone[0]['ID'])

        for vsd_l3domain in cls.vsd_l3domain:
            cls.vsd_client.delete_domain(vsd_l3domain[0]['ID'])

        for vsd_l3domain_template in cls.vsd_l3domain_template:
            cls.vsd_client.delete_l3domaintemplate(vsd_l3domain_template[0]['ID'])

    @classmethod
    def create_vsd_dhcp_managed_l2domain_template(cls, **kwargs):
        params = {
            'DHCPManaged': True,
            'address': str(kwargs['cidr'].ip),
            'netmask': str(kwargs['cidr'].netmask),
            'gateway': kwargs['gateway']
        }
        vsd_l2domain_tmplt = cls.vsd_client.create_l2domaintemplate(
            kwargs['name'] + '-template', extra_params=params)
        cls.vsd_l2domain_template.append(vsd_l2domain_tmplt)
        return vsd_l2domain_tmplt

    @classmethod
    def create_vsd_dhcp_unmanaged_l2domain_template(cls, **kwargs):
        vsd_l2domain_tmplt = cls.vsd_client.create_l2domaintemplate(
            kwargs['name'] + '-template')
        cls.vsd_l2domain_template.append(vsd_l2domain_tmplt)
        return vsd_l2domain_tmplt

    @classmethod
    def create_vsd_l2domain(cls, **kwargs):
        vsd_l2dom = cls.vsd_client.create_l2domain(kwargs['name'],
                                                   templateId=kwargs['tid'])
        cls.vsd_l2domain.append(vsd_l2dom)
        return vsd_l2dom

    @classmethod
    def create_vsd_l3domain_template(cls, **kwargs):
        vsd_l3domain_tmplt = cls.vsd_client.create_l3domaintemplate(
            kwargs['name'] + '-template')
        cls.vsd_l3domain_template.append(vsd_l3domain_tmplt)
        return vsd_l3domain_tmplt

    @classmethod
    def create_vsd_l3domain(cls, **kwargs):
        vsd_l3dom = cls.vsd_client.create_domain(kwargs['name'],
                                                 kwargs['tid'])
        cls.vsd_l3domain.append(vsd_l3dom)
        return vsd_l3dom

    @classmethod
    def create_vsd_zone(cls, **kwargs):
        vsd_zone = cls.vsd_client.create_zone(kwargs['domain_id'],
                                              kwargs['name'])
        cls.vsd_zone.append(vsd_zone)
        return vsd_zone

    @classmethod
    def create_vsd_l3domain_subnet(cls, **kwargs):
        vsd_subnet = cls.vsd_client.create_domain_subnet(kwargs['zone_id'],
                                                         kwargs['name'],
                                                         str(kwargs['cidr'].ip),
                                                         str(kwargs['cidr'].netmask),
                                                         kwargs['gateway'])
        cls.vsd_subnet.append(vsd_subnet)
        return vsd_subnet

    def launch_stack(self, stack_file_name, stack_parameters):
        self.stack_name = data_utils.rand_name('heat-' + stack_file_name)
        template = self.read_template(stack_file_name)

        LOG.debug("Stack launched: %s", template)

        LOG.debug("Stack parameters: %s", stack_parameters)

        # create the stack
        self.stack_identifier = self.create_stack(
            self.stack_name,
            template,
            stack_parameters
        )
        self.stack_id = self.stack_identifier.split('/')[1]
        self.client.wait_for_stack_status(self.stack_id, 'CREATE_COMPLETE')

        resources = self.client.list_resources(self.stack_identifier)
        resources = resources['resources']
        self.test_resources = {}
        for resource in resources:
            self.test_resources[resource['logical_resource_id']] = resource
        self.template_resources = self.load_stack_resources(stack_file_name)

    def load_stack_resources(self, stack_file_name):
        loaded_template = self.load_template(stack_file_name)
        return loaded_template['resources']

    def verify_stack_resources(self, expected_resources, template_resourses, actual_resources):
        for resource_name in expected_resources:
            resource_type = template_resourses[resource_name]['type']
            resource = actual_resources.get(resource_name, None)
            self.assertIsInstance(resource, dict)
            self.assertEqual(resource_name, resource['logical_resource_id'])
            self.assertEqual(resource_type, resource['resource_type'])
            self.assertEqual('CREATE_COMPLETE', resource['resource_status'])

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
        self.assertEqual(4, subnet['ip_version'])

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
