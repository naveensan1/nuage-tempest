# Copyright 2015 Alcatel-Lucent USA Inc.
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
#

from nuagetempest.lib.utils import constants
from nuagetempest.services.nuage_client import NuageRestClient
from oslo_log import log as logging
from tempest.common.utils import data_utils
from tempest import config
from tempest import exceptions
from tempest.lib import exceptions as lib_exceptions
import test_netpartitions


CONF = config.CONF

LOG = logging.getLogger(__name__)


class NuageAppdTestJSON(test_netpartitions.NetPartitionTestJSON):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(NuageAppdTestJSON, cls).setup_clients()
        cls.nuageclient = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(NuageAppdTestJSON, cls).resource_setup()
        cls.def_net_part = CONF.nuage.nuage_default_netpartition
        cls.app_domain = []
        cls.application = []
        cls.tier = []
        cls.flow = []
        cls.appdport = []
        cls.vsd_l3dom_template = []
        cls.service = []

    @classmethod
    def create_default_appd_template(cls):
        name = cls.def_net_part + '_def_appd_L3_Template'
        appd_templ = cls.nuageclient.get_l3domaintemplate(filters='name',
                                                          filter_value=name)
        if not appd_templ:
            appd_templ = cls.nuageclient.\
                create_default_appdomain_template(name)
            cls.vsd_l3dom_template.append(appd_templ)
        return appd_templ

    @classmethod
    def create_app_domain(cls, **kwargs):
        post_body = {'application_domain': kwargs}
        body = cls.client.create_resource('/application-domains', post_body)
        app_domain = body['application_domain']
        cls.app_domain.append(app_domain)
        return app_domain

    @classmethod
    def create_application(cls, **kwargs):
        post_body = {'application': kwargs}
        body = cls.client.create_resource('/applications', post_body)
        application = body['application']
        cls.application.append(application)
        return application

    @classmethod
    def create_tier(cls, **kwargs):
        post_body = {'tier': kwargs}
        body = cls.client.create_resource('/tiers', post_body)
        tier = body['tier']
        cls.tier.append(tier)
        return tier

    @classmethod
    def create_flow(cls, **kwargs):
        post_body = {'flow': kwargs}
        body = cls.client.create_resource('/flows', post_body)
        flow = body['flow']
        cls.flow.append(flow)
        return flow

    @classmethod
    def create_app_port(cls, **kwargs):
        post_body = {'appdport': kwargs}
        body = cls.client.create_resource('/appdports', post_body)
        appdport = body['appdport']
        cls.appdport.append(appdport)
        return appdport

    @classmethod
    def create_vsd_l3dom_template(cls, **kwargs):
        vsd_l3dom_tmplt = cls.nuageclient.create_l3domaintemplate(
            kwargs['name'] + '-template')
        cls.vsd_l3dom_template.append(vsd_l3dom_tmplt)
        return vsd_l3dom_tmplt

    @classmethod
    def create_service(cls, **kwargs):
        post_body = {'service': kwargs}
        body = cls.client.create_resource('/services', post_body)
        service = body['service']
        cls.service.append(service)
        return service

    @classmethod
    def resource_cleanup(cls):
        has_exception = False

        for flow in cls.flow:
            try:
                uri = '/flows/' + flow['id']
                cls.client.delete_resource(uri)
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for appdport in cls.appdport:
            try:
                uri = '/appdports/' + appdport['id']
                cls.client.delete_resource(uri)
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for tier in cls.tier:
            try:
                uri = '/tiers/' + tier['id']
                cls.client.delete_resource(uri)
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for app in cls.application:
            try:
                uri = '/applications/' + app['id']
                cls.client.delete_resource(uri)
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for app_domain in cls.app_domain:
            try:
                uri = '/application-domains/' + app_domain['id']
                cls.client.delete_resource(uri)
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for vsd_l3dom_template in cls.vsd_l3dom_template:
            try:
                cls.nuageclient.delete_l3domaintemplate(
                    vsd_l3dom_template[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for svc in cls.service:
            try:
                uri = '/services/' + svc['id']
                cls.client.delete_resource(uri)
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        if has_exception:
            raise exceptions.TearDownException()

        super(NuageAppdTestJSON, cls).resource_cleanup()

    def _verify_application_properties(self, actual_app, expected_app):
        self.assertEqual(actual_app['name'], expected_app['name'])
        self.assertEqual(actual_app['associateddomainid'],
                         expected_app['associatedDomainID'])

    def _verify_tier_properties(self, actual_tier, expected_tier):
        self.assertEqual(actual_tier['name'], expected_tier['name'])
        self.assertEqual(actual_tier['type'],
                         expected_tier['type'])
        self.assertEqual(actual_tier['associatedappid'],
                         expected_tier['parentID'])

    def _verify_flow_properties(self, actual_flow, expected_flow):
        self.assertEqual(actual_flow['name'], expected_flow['name'])
        self.assertEqual(actual_flow['origin_tier'],
                         expected_flow['originTierID'])
        self.assertEqual(actual_flow['dest_tier'],
                         expected_flow['destinationTierID'])

    def _verify_service_properties(self, actual_svc, expected_svc):
        self.assertEqual(actual_svc['name'], expected_svc['name'])
        self.assertEqual(actual_svc['direction'],
                         expected_svc['direction'])
        self.assertEqual(actual_svc['src_port'],
                         expected_svc['sourcePort'])
        self.assertEqual(actual_svc['dest_port'],
                         expected_svc['destinationPort'])

    def _compare_resource_lists(self, response_list,
                                resource_list, verify_func):
        for item in response_list:
            resource_found = False
            for resource in resource_list:
                if item['id'] == resource['ID']:
                    resource_found = True
                    verify_func(item, resource)
            if not resource_found:
                assert False, (item['name'] + " not found")

    def test_create_application_domain(self):
        name = data_utils.rand_name('app_domain-')
        kwargs = {'name': name}
        appd_domain = self.create_app_domain(**kwargs)
        self.assertEqual(appd_domain['name'], name)
        self.assertEqual(appd_domain['applicationDeploymentPolicy'], 'ZONE')

    def test_create_app_domain_with_rt_rd_fields(self):
        name = data_utils.rand_name('app_domain-')
        kwargs = {'name': name,
                  'rt': '1010:1011',
                  'rd': '2020:2021',
                  'tunnel_type': 'VXLAN'}

        appd_domain = self.create_app_domain(**kwargs)

        self.assertEqual(appd_domain['name'], name)
        self.assertEqual(appd_domain['applicationDeploymentPolicy'], 'ZONE')
        self.assertEqual(appd_domain['rt'], '1010:1011')
        self.assertEqual(appd_domain['rd'], '2020:2021')
        self.assertEqual(appd_domain['tunnel_type'], 'VXLAN')

    def test_create_application_domain_with_template(self):
        name = data_utils.rand_name('app_domain-')
        l3_dom_templ = self.create_vsd_l3dom_template(name=name)
        kwargs = {'name': name,
                  'nuage_domain_template': l3_dom_templ[0]['ID']}
        appd_domain = self.create_app_domain(**kwargs)
        self.assertEqual(appd_domain['name'], name)
        self.assertEqual(appd_domain['applicationDeploymentPolicy'], 'ZONE')

    def test_create_update_show_list_application_in_valid_app_dom(self):
        name = data_utils.rand_name('app_domain-')
        app_name = data_utils.rand_name('app-')
        kwargs = {'name': name}
        appd = self.create_app_domain(**kwargs)
        kwargs = {'name': app_name,
                  'applicationdomain_id': appd['id']}
        app = self.create_application(**kwargs)
        self.assertEqual(app['associateddomainid'], appd['id'])
        self.assertEqual(app['name'], app_name)
        # show_application
        res_path = self.nuageclient.build_resource_path(
            constants.APPLICATION,
            resource_id=app['id'])
        show_vsd_resp = self.nuageclient.get(res_path)
        kwargs = {'id': app['id']}
        show_resp = self.client.show_resource('/applications', **kwargs)
        self._verify_application_properties(show_resp['applications'][0],
                                            show_vsd_resp[0])
        # Update the application name.
        kwargs = {'name': 'updated-app'}
        post_body = {'application': kwargs}
        uri = '/applications/' + app['id']
        self.client.update_resource(uri, post_body)
        show_vsd_resp = self.nuageclient.get(res_path)
        self.assertEqual(show_vsd_resp[0]['name'], 'updated-app')
        # second application creation
        kwargs = {'name': 'second-app',
                  'applicationdomain_id': appd['id']}
        self.create_application(**kwargs)
        # list_applications
        net_part = self.nuageclient.get_net_partition(self.def_net_part)
        res_path = self.nuageclient.build_resource_path(
            constants.NET_PARTITION,
            resource_id=net_part[0]['ID'],
            child_resource=constants.APPLICATION)
        list_vsd_resp = self.nuageclient.get(res_path)
        list_resp = self.client.list_resources('/applications')
        self._compare_resource_lists(list_resp['applications'], list_vsd_resp,
                                     self._verify_application_properties)

    def test_create_update_show_list_std_tier_in_valid_application(self):
        name = data_utils.rand_name('app_domain-')
        app_name = data_utils.rand_name('app-')
        tier_name = data_utils.rand_name('tier-')
        kwargs = {'name': name}
        appd = self.create_app_domain(**kwargs)
        kwargs = {'name': app_name,
                  'applicationdomain_id': appd['id']}
        app = self.create_application(**kwargs)
        kwargs = {'name': tier_name,
                  'app_id': app['id'],
                  'type': 'STANDARD',
                  'cidr': '2.2.2.0/24'}
        tier = self.create_tier(**kwargs)
        self.assertEqual(tier['associatedappid'], app['id'])
        self.assertEqual(tier['type'], 'STANDARD')
        # show_tier
        res_path = self.nuageclient.build_resource_path(
            constants.TIER,
            resource_id=tier['id'])
        show_vsd_resp = self.nuageclient.get(res_path)
        kwargs = {'id': tier['id']}
        show_resp = self.client.show_resource('/tiers', **kwargs)
        self._verify_tier_properties(show_resp['tiers'][0], show_vsd_resp[0])
        # Update tier
        # TODO: tier-update code to be added after VSD-8991 fix
        kwargs = {'name': 'updated-tier'}
        post_body = {'tier': kwargs}
        uri = '/tiers/' + tier['id']
        self.client.update_resource(uri, post_body)
        show_vsd_resp = self.nuageclient.get(res_path)
        self.assertEqual(show_vsd_resp[0]['name'], 'updated-tier')
        # create second tier
        kwargs = {'name': 'second-tier',
                  'app_id': app['id'],
                  'type': 'STANDARD',
                  'cidr': '3.3.3.0/24'}
        self.create_tier(**kwargs)
        # list_tier
        res_path = self.nuageclient.build_resource_path(
            constants.APPLICATION,
            resource_id=app['id'],
            child_resource=constants.TIER)
        list_vsd_resp = self.nuageclient.get(res_path)
        list_resp = self.client.list_tiers(app['id'])
        self._compare_resource_lists(list_resp['tiers'], list_vsd_resp,
                                     self._verify_tier_properties)

    def test_create_update_show_list_flow_in_valid_application(self):
        name = data_utils.rand_name('app_domain-')
        app_name = data_utils.rand_name('app-')
        kwargs = {'name': name}
        appd = self.create_app_domain(**kwargs)
        kwargs = {'name': app_name,
                  'applicationdomain_id': appd['id']}
        app = self.create_application(**kwargs)
        kwargs = {'name': 'tier_1',
                  'app_id': app['id'],
                  'type': 'STANDARD',
                  'cidr': '2.2.2.0/24'}
        tier_1 = self.create_tier(**kwargs)
        kwargs = {'name': 'tier_2',
                  'app_id': app['id'],
                  'type': 'STANDARD',
                  'cidr': '3.3.3.0/24'}
        tier_2 = self.create_tier(**kwargs)
        kwargs = {'name': 'flow',
                  'origin_tier': tier_1['id'],
                  'dest_tier': tier_2['id']}
        flow = self.create_flow(**kwargs)
        self.assertEqual(flow['name'], 'flow')
        self.assertEqual(flow['origin_tier'], tier_1['id'])
        self.assertEqual(flow['dest_tier'], tier_2['id'])
        # show_flow
        res_path = self.nuageclient.build_resource_path(
            constants.FLOW,
            resource_id=flow['id'])
        show_vsd_resp = self.nuageclient.get(res_path)
        kwargs = {'id': flow['id']}
        show_resp = self.client.show_resource('/flows', **kwargs)
        self._verify_flow_properties(show_resp['flows'][0], show_vsd_resp[0])
        # update_flow
        kwargs = {'name': 'updated-flow'}
        post_body = {'flow': kwargs}
        uri = '/flows/' + flow['id']
        self.client.update_resource(uri, post_body)
        show_vsd_resp = self.nuageclient.get(res_path)
        self.assertEqual(show_vsd_resp[0]['name'], 'updated-flow')
        # create second flow
        kwargs = {'name': 'tier_3',
                  'app_id': app['id'],
                  'type': 'STANDARD',
                  'cidr': '4.4.4.0/24'}
        tier_3 = self.create_tier(**kwargs)
        kwargs = {'name': 'second-flow',
                  'origin_tier': tier_1['id'],
                  'dest_tier': tier_3['id']}
        self.create_flow(**kwargs)
        # list_flow
        res_path = self.nuageclient.build_resource_path(
            constants.APPLICATION,
            resource_id=app['id'],
            child_resource=constants.FLOW)
        list_vsd_resp = self.nuageclient.get(res_path)
        list_resp = self.client.list_flows(app['id'])
        self._compare_resource_lists(list_resp['flows'], list_vsd_resp,
                                     self._verify_flow_properties)

    def test_create_update_show_list_application_service(self):
        name = data_utils.rand_name('service-')
        kwargs = {'name': name,
                  'protocol': 'tcp',
                  'src_port': '400',
                  'dest_port': '500'}
        svc = self.create_service(**kwargs)
        self.assertEqual(svc['protocol'], 6)
        self.assertEqual(svc['ethertype'],
                         constants.PROTO_NAME_TO_NUM['IPv4'])
        self.assertEqual(svc['direction'], 'REFLEXIVE')
        self.assertEqual(svc['src_port'], '400')
        self.assertEqual(svc['dest_port'], '500')
        self.assertEqual(svc['dscp'], '*')
        # show service
        res_path = self.nuageclient.build_resource_path(
            constants.SERVICE,
            resource_id=svc['id'])
        show_vsd_resp = self.nuageclient.get(res_path)
        kwargs = {'id': svc['id']}
        show_resp = self.client.show_resource('/services', **kwargs)
        self._verify_service_properties(show_resp['services'][0],
                                        show_vsd_resp[0])
        # update_service
        kwargs = {'name': 'updated-service'}
        post_body = {'service': kwargs}
        uri = '/services/' + svc['id']
        self.client.update_resource(uri, post_body)
        show_vsd_resp = self.nuageclient.get(res_path)
        self.assertEqual(show_vsd_resp[0]['name'], 'updated-service')
        # second service creation
        kwargs = {'name': 'second-service',
                  'protocol': 'udp',
                  'src_port': '*',
                  'dest_port': '*'}
        self.create_service(**kwargs)
        # list_services
        net_part = self.nuageclient.get_net_partition(self.def_net_part)
        res_path = self.nuageclient.build_resource_path(
            constants.NET_PARTITION,
            resource_id=net_part[0]['ID'],
            child_resource=constants.SERVICE)
        list_vsd_resp = self.nuageclient.get(res_path)
        list_resp = self.client.list_resources('/services')
        self._compare_resource_lists(list_resp['services'], list_vsd_resp,
                                     self._verify_service_properties)

    def test_create_update_show_list_appdport(self):
        name = data_utils.rand_name('app_domain-')
        app_name = data_utils.rand_name('app-')
        kwargs = {'name': name}
        appd = self.create_app_domain(**kwargs)
        kwargs = {'name': app_name,
                  'applicationdomain_id': appd['id']}
        app = self.create_application(**kwargs)
        kwargs = {'name': 'tier_1',
                  'app_id': app['id'],
                  'type': 'STANDARD',
                  'cidr': '2.2.2.0/24'}
        tier = self.create_tier(**kwargs)
        kwargs = {'name': 'app-port',
                  'tier_id': tier['id']}
        appdport = self.create_app_port(**kwargs)
        self.assertEqual(appdport['name'], 'app-port')
        self.assertEqual(appdport['device_owner'], 'appd')
        # show appdport
        show_vsd_resp = self.nuageclient.get_vport(constants.TIER, tier['id'])

        kwargs = {}
        show_resp = self.client.show_resource('/appdports/' + appdport['id'], **kwargs)

        self.assertEqual(show_resp['appdport']['name'],
                         show_vsd_resp[0]['name'])
        # update_port
        kwargs = {'name': 'updated-port'}
        post_body = {'appdport': kwargs}
        uri = '/appdports/' + appdport['id']
        show_resp = self.client.update_resource(uri, post_body)

        self.assertEqual(show_resp['appdport']['name'], 'updated-port')
        show_vsd_resp = self.nuageclient.get_vport(constants.TIER,
                                                   tier['id'])
        self.assertEqual(show_vsd_resp[0]['name'],
                         show_resp['appdport']['name'])
        # list_appdport
        res_path = self.nuageclient.build_resource_path(
            constants.TIER,
            resource_id=tier['id'],
            child_resource=constants.VPORT)
        list_vsd_resp = self.nuageclient.get(res_path)

        list_resp = self.client.list_resources('/appdports')

        appdport_ext_id = self.nuageclient.get_vsd_external_id(
            list_resp['appdports'][0]['id'])
        self.assertEqual(appdport_ext_id,
                         list_vsd_resp[0]['externalID'])
        self.assertEqual(list_resp['appdports'][0]['name'],
                         list_vsd_resp[0]['name'])


    def test_create_delete_invalid_application(self):
        name = data_utils.rand_name('app_domain-')
        app_name = data_utils.rand_name('app-')
        kwargs = {'name': name}
        appd = self.create_app_domain(**kwargs)
        kwargs = {'name': app_name,
                  'applicationdomain_id': appd['id']}
        app = self.create_application(**kwargs)
        # Pass invalid application domain
        kwargs = {'name': 'new-app',
                  'applicationdomain_id':
                  '11111111-1111-1111-1111111111111111'}
        post_body = {'application': kwargs}
        self.assertRaises(lib_exceptions.ServerFault,
                          self.client.create_resource,
                          '/applications', post_body)
        # Application with same name as exisiting app.
        kwargs = {'name': app_name,
                  'applicationdomain_id': appd['id']}
        post_body = {'application': kwargs}
        self.assertRaises(lib_exceptions.ServerFault,
                          self.client.create_resource,
                          '/applications', post_body)
        # Delete an app by providing invalid ID
        uri = '/applications/' + '11111111-1111-1111-1111111111111111'
        self.assertRaises(lib_exceptions.NotFound,
                          self.client.delete_resource,
                          uri)

    def test_create_delete_invalid_tier(self):
        name = data_utils.rand_name('app_domain-')
        app_name = data_utils.rand_name('app-')
        tier_name = data_utils.rand_name('tier-')
        kwargs = {'name': name}
        appd = self.create_app_domain(**kwargs)
        kwargs = {'name': app_name,
                  'applicationdomain_id': appd['id']}
        app = self.create_application(**kwargs)
        # create tier with invalid application UUID
        kwargs = {'name': tier_name,
                  'app_id': '11111111-1111-1111-1111-111111111111',
                  'type': 'STANDARD',
                  'cidr': '2.2.2.0/24'}
        self.assertRaises(lib_exceptions.NotFound,
                          self.create_tier,
                          **kwargs)
        # create tier with invalid cidr
        kwargs = {'name': tier_name,
                  'app_id': app['id'],
                  'type': 'STANDARD',
                  'cidr': '2.2.2.0/16'}
        self.assertRaises(lib_exceptions.BadRequest,
                          self.create_tier,
                          **kwargs)
        # create tier with invalid type
        kwargs = {'name': tier_name,
                  'app_id': app['id'],
                  'type': 'standard',
                  'cidr': '2.2.2.0/24'}
        self.assertRaises(lib_exceptions.BadRequest,
                          self.create_tier,
                          **kwargs)
        # delete tier by providing invalid UUID
        uri = '/tiers/' + '11111111-1111-1111-1111111111111111'
        self.assertRaises(lib_exceptions.NotFound,
                          self.client.delete_resource,
                          uri)

    def test_create_delete_invalid_flow(self):
        name = data_utils.rand_name('app_domain-')
        app_name = data_utils.rand_name('app-')
        kwargs = {'name': name}
        appd = self.create_app_domain(**kwargs)
        kwargs = {'name': app_name,
                  'applicationdomain_id': appd['id']}
        app = self.create_application(**kwargs)
        kwargs = {'name': 'tier_1',
                  'app_id': app['id'],
                  'type': 'APPLICATION'}
        tier_1 = self.create_tier(**kwargs)
        kwargs = {'name': 'tier_2',
                  'app_id': app['id'],
                  'type': 'APPLICATION'}
        tier_2 = self.create_tier(**kwargs)
        # create flow with invalid origin tier UUID
        # Issue with Liberty:
        # UUID = <8>-<4>-<4>-<4>-<12> while we used to specify here: <8>-<4>-<4>-<16> : total is the same
        # so for Liberty it is a valid UUID, resulting in NotFound
        # -> make it for sure an invalid UUID (remove some '1's)
        kwargs = {'name': 'flow',
                  'origin_tier': '11111111-1111-1111-1111-111111111111',
                  'dest_tier': tier_2['id']}
        self.assertRaises(lib_exceptions.NotFound,
                          self.create_flow,
                          **kwargs)
        # create flow between two tiers of APPLICATION type
        kwargs = {'name': 'flow',
                  'origin_tier': tier_1['id'],
                  'dest_tier': tier_2['id']}
        self.assertRaises(lib_exceptions.ServerFault,
                          self.create_flow,
                          **kwargs)
        # delete flow by providing invalid UUID
        uri = '/flows/' + '11111111-1111-1111-1111-111111111111'
        self.assertRaises(lib_exceptions.NotFound,
                          self.client.delete_resource,
                          uri)

    def test_create_delete_invalid_service(self):
        name = data_utils.rand_name('service-')
        kwargs = {'name': name,
                  'protocol': 'tcp',
                  'src_port': '400',
                  'dest_port': '500'}
        self.create_service(**kwargs)
        # create second service with same name as another service
        self.assertRaises(lib_exceptions.ServerFault,
                          self.create_service,
                          **kwargs)
        # create service with invalid protocol
        kwargs = {'name': 'service',
                  'protocol': 'tccp',
                  'src_port': '400',
                  'dest_port': '500'}
        self.assertRaises(lib_exceptions.BadRequest,
                          self.create_service,
                          **kwargs)
        # create service without all the mandatory parameters
        kwargs = {'name': 'service',
                  'protocol': 'tcp',
                  'src_port': '400'}
        self.assertRaises(lib_exceptions.ServerFault,
                          self.create_service,
                          **kwargs)
        # delete service by providing invalid UUIDa
        uri = '/services/' + '11111111-1111-1111-1111111111111111'
        self.assertRaises(lib_exceptions.NotFound,
                          self.client.delete_resource,
                          uri)
