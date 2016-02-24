import logging
from tempest import test

from tempest_lib.common.utils import data_utils
from nuagetempest.services.nuage_network_client import NuageNetworkClientJSON

import nuage_base
from tempest import config

CONF = config.CONF

LOG = logging.getLogger(__name__)


class NeutronAppDesignerResourcesTest(nuage_base.NuageBaseOrchestrationTest):
    """Basic APPDesigner Heat test"""
    @classmethod
    def setup_clients(cls):
        super(NeutronAppDesignerResourcesTest, cls).setup_clients()
        cls.orchestration_client = cls.os_adm.orchestration_client
        cls.client = cls.orchestration_client
        cls.nuage_network_client = NuageNetworkClientJSON(
            cls.os_adm.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os_adm.default_params)

    @classmethod
    def resource_setup(cls):
        super(NeutronAppDesignerResourcesTest, cls).resource_setup()

        if not test.is_extension_enabled('appdesigner', 'network'):
            msg = "Application designer extension 'appdesigner' not enabled."
            raise cls.skipException(msg)

        cls.template = cls.load_template('appdesigner')
        cls.stack_name = data_utils.rand_name('heat-app')
        template = cls.read_template('appdesigner')

        # create the stack 
        cls.stack_identifier = cls.create_stack(
            cls.stack_name,
            template,
            parameters={
                'flavor': '1',
                'image': 'cirros-0.3.4-x86_64-uec'
            })
        cls.stack_id = cls.stack_identifier.split('/')[1]
        cls.client.wait_for_stack_status(cls.stack_id, 'CREATE_COMPLETE')
        resources = cls.client.list_resources(cls.stack_identifier)
        resources = resources['resources']

        cls.test_resources = {}
        for resource in resources:
            cls.test_resources[resource['logical_resource_id']] = resource

    def test_created_app_resources(self):
        """Verifies created neutron application resources."""
        resources = [('app_domain', self.template['resources'][
                      'app_domain']['type']),
                     ('app', self.template['resources'][
                      'app']['type']),
                     ('web_tier', self.template[
                      'resources']['web_tier']['type']),
                     ('db_tier', self.template['resources'][
                      'db_tier']['type']),
                     ('mysql_svc', self.template['resources'][
                      'mysql_svc']['type']),
                     ('flow1', self.template['resources'][
                      'flow1']['type']),
                     ('web_port', self.template['resources'][
                      'web_port']['type']),
                     ('db_port', self.template['resources'][
                      'db_port']['type'])]
        for resource_name, resource_type in resources:
            resource = self.test_resources.get(resource_name, None)
            self.assertIsInstance(resource, dict)
            self.assertEqual(resource_name, resource['logical_resource_id'])
            self.assertEqual(resource_type, resource['resource_type'])
            self.assertEqual('CREATE_COMPLETE', resource['resource_status'])

    def test_created_application_domain(self):
        """Verifies created application domain."""
        domain_id = self.test_resources.get('app_domain')['physical_resource_id']
        body = self.nuage_network_client.show_application_domain(domain_id)
        app_domain = body['application_domain']

        self.assertIsInstance(app_domain, dict)
        self.assertEqual(domain_id, app_domain['id'])
        self.assertEqual(self.template['resources'][
            'app_domain']['properties']['name'], app_domain['name'])
        self.assertEqual(app_domain['applicationDeploymentPolicy'],
                         'ZONE')

    def test_created_application(self):
        """Verifies created application."""
        app_id = self.test_resources.get('app')['physical_resource_id']	
        body = self.nuage_network_client.show_application(app_id)
        app = body['application']
        self.assertIsInstance(app, dict)
        self.assertEqual(app_id, app['id'])
        self.assertEqual(self.template['resources'][
            'app']['properties']['name'], app['name'])
        self.assertEqual(app['associateddomainid'],
                         self.test_resources.get('app_domain')
                         ['physical_resource_id'])

    def test_created_service(self):
        """Verifies created app service."""
        service_id = self.test_resources.get('mysql_svc')[
            'physical_resource_id']
        body = self.nuage_network_client.show_service(service_id)
        service = body['service']
        self.assertIsInstance(service, dict)
        self.assertEqual(service_id, service['id'])
        self.assertEqual(self.template['resources']['mysql_svc'][
            'properties']['name'], service['name'])
        self.assertEqual('REFLEXIVE', service['direction'])
        self.assertEqual('6', service['protocol'])
        self.assertEqual(self.template['resources']['mysql_svc'][
            'properties']['src_port'], service['src_port'])
        self.assertEqual(self.template['resources']['mysql_svc'][
            'properties']['dest_port'], service['dest_port'])

    def test_created_tier(self):
        """Verifies created tier."""
        tier_id = self.test_resources.get('web_tier')['physical_resource_id']
        body = self.nuage_network_client.show_tier(tier_id)
        tier = body['tier']
        self.assertIsInstance(tier, dict)
        self.assertEqual(tier_id, tier['id'])
        self.assertEqual(self.template['resources']['web_tier'][
            'properties']['name'], tier['name'])
        self.assertEqual(
            self.test_resources.get('app')['physical_resource_id'],
            tier['associatedappid'])
        self.assertEqual(self.template['resources']['web_tier'][
            'properties']['type'], tier['type'])

    def test_created_flow(self):
        """Verifies created application flow"""	
        flow_id = self.test_resources.get('flow1')['physical_resource_id']
        body = self.nuage_network_client.show_flow(flow_id)
        flow = body['flow']
        self.assertIsInstance(flow, dict)
        self.assertEqual(flow_id, flow['id'])
        self.assertEqual(self.template['resources']['flow1'][
            'properties']['name'], flow['name'])
        self.assertEqual(self.test_resources.get('web_tier')[
            'physical_resource_id'], flow['origin_tier'])
        self.assertEqual(self.test_resources.get('db_tier')[
            'physical_resource_id'], flow['dest_tier'])	
        self.assertEqual(self.template['resources']['mysql_svc'][
            'properties']['name'], flow['nuage_services'])

    def test_created_appd_port(self):
        """Verifies created application port"""	
        appdport_id = self.test_resources.get('web_port')[
            'physical_resource_id']
        body = self.nuage_network_client.show_appdport(appdport_id)
        appdport = body['appdport']
        self.assertIsInstance(appdport, dict)
        self.assertEqual(appdport_id, appdport['id'])
        self.assertEqual(self.template['resources']['web_port'][
            'properties']['name'], appdport['name'])


