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
from nuagetempest.lib.nuage_tempest_test_loader import Release
from nuagetempest.lib.utils import constants as n_constants
from nuagetempest.services.nuage_client import NuageRestClient
from nuagetempest.services.nuage_network_client import NuageNetworkClientJSON

from oslo_log import log as logging

from tempest.api.network import base
from tempest.common.utils import data_utils
from tempest import config
from tempest import exceptions

from tempest.lib.common.utils.data_utils import rand_name
import uuid


CONF = config.CONF
external_id_release = Release(n_constants.EXTERNALID_RELEASE)
conf_release = CONF.nuage_sut.release
current_release = Release(conf_release)

LOG = logging.getLogger(__name__)


class BaseNuageGatewayTest(base.BaseAdminNetworkTest):
    _interface = 'json'

    @classmethod
    def create_gateway(cls, type):
        name = rand_name('tempest-gw')
        gw = cls.nuage_vsd_client.create_gateway(
            name, str(uuid.uuid4()), type, None)
        return gw

    @classmethod
    def create_gateway_group(cls, gw1_id, gw2_id):
        name = rand_name('tempest-gw-grp')
        grp = cls.nuage_vsd_client.create_gateway_redundancy_group(
            name, gw1_id, gw2_id, None)
        return grp

    @classmethod
    def create_gateway_port(cls, gw, name=None):
        if not name:
            name = rand_name('tempest-gw-port')
        gw_port = cls.nuage_vsd_client.create_gateway_port(
            name, 'test', 'ACCESS', gw[0]['ID'])
        return gw_port

    @classmethod
    def create_gateway_vlan(cls, gw_port, value):
        gw_port = cls.nuage_vsd_client.create_gateway_vlan(
            gw_port[0]['ID'], 'test', value)
        return gw_port

    @classmethod
    def create_test_gateway_topology(cls):
        for personality in n_constants.PERSONALITY_LIST:
            gw = cls.create_gateway(personality)
            cls.gateways.append(gw)

        for gateway in cls.gateways:
            for i in range(n_constants.NUMBER_OF_PORTS_PER_GATEWAY):
                gw_port = cls.create_gateway_port(gateway)
                cls.gatewayports.append(gw_port)

        for gw_port in cls.gatewayports:
            for i in range(n_constants.NUMBER_OF_VLANS_PER_PORT):
                gw_vlan = cls.create_gateway_vlan(
                    gw_port, str(
                        n_constants.START_VLAN_VALUE + i))
                cls.gatewayvlans.append(gw_vlan)

    @classmethod
    def setup_clients(cls):
        super(BaseNuageGatewayTest, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()
        # Overriding cls.client with Nuage network client
        cls.client = NuageNetworkClientJSON(
            cls.os.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os.default_params)
        # initialize admin client
        cls.admin_client = NuageNetworkClientJSON(
            cls.os_adm.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os_adm.default_params)

    @classmethod
    def create_router(cls, router_name=None, admin_state_up=False,
                      external_network_id=None, enable_snat=None,
                      **kwargs):
        ext_gw_info = {}
        if external_network_id:
            ext_gw_info['network_id'] = external_network_id
        if enable_snat is not None:
            ext_gw_info['enable_snat'] = enable_snat
        body = cls.admin_routers_client.create_router(
            router_name, external_gateway_info=ext_gw_info,
            admin_state_up=admin_state_up, **kwargs)
        router = body['router']
        cls.routers.append(router)
        return router

    @classmethod
    def create_router_interface(cls, router_id, subnet_id):
        """Wrapper utility that returns a router interface."""
        interface = cls.admin_routers_client.add_router_interface(router_id,
                                                    subnet_id=subnet_id)
        cls.router_interfaces.append(interface)
        return interface

    @classmethod
    def resource_setup(cls):
        super(BaseNuageGatewayTest, cls).resource_setup()

        cls.gateways = []
        cls.gatewayports = []
        cls.gatewayvlans = []
        cls.gatewayvports = []
        cls.router_interfaces = []

        cls.ext_net_id = CONF.network.public_network_id
        cls.network = cls.create_network()

        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(
            data_utils.rand_name('router-'),
            external_network_id=cls.ext_net_id,
            tunnel_type="VXLAN")

        cls.create_router_interface(
            cls.router['id'], cls.subnet['id'])

        # Resource for non-default net-partition
        netpart_body = cls.client.create_netpartition(
            data_utils.rand_name('Enterprise-'))
        cls.nondef_netpart = netpart_body['net_partition'] 
        cls.nondef_network = cls.create_network()
        cls.nondef_subnet = cls.create_subnet(cls.nondef_network,
            net_partition=cls.nondef_netpart['id'])
        cls.nondef_router = cls.create_router(
            data_utils.rand_name('router-'),
            external_network_id=cls.ext_net_id,
            tunnel_type='VXLAN',
            net_partition=cls.nondef_netpart['id'])
        cls.create_router_interface(cls.nondef_router['id'],
            cls.nondef_subnet['id'])


    @classmethod
    def resource_cleanup(cls):
        has_exception = False

        for vport in cls.gatewayvports:
            try:
                if vport['type'] == n_constants.HOST_VPORT:
                    cls.nuage_vsd_client.delete_host_interface(
                        vport['interface'])
                elif vport['type'] == n_constants.BRIDGE_VPORT:
                    cls.nuage_vsd_client.delete_bridge_interface(
                        vport['interface'])
                cls.nuage_vsd_client.delete_host_vport(vport['id'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for vlan in cls.gatewayvlans:
            try:
                if 'id' in vlan:
                    vlan_id = vlan['id']
                else:
                    vlan_id = vlan[0]['ID']
                cls.nuage_vsd_client.delete_vlan_permission(vlan_id)
                cls.nuage_vsd_client.delete_gateway_vlan(vlan_id)
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for port in cls.gatewayports:
            try:
                cls.nuage_vsd_client.delete_gateway_port(port[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for gateway in cls.gateways:
            try:
                cls.nuage_vsd_client.delete_gateway(gateway[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for router_interface in cls.router_interfaces:
            try:
                cls.admin_routers_client.remove_router_interface(router_interface['id'],
                                                         subnet_id=router_interface['subnet_id'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for router in cls.routers:
            try:
                cls.admin_routers_client.delete_router(router['id'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        super(BaseNuageGatewayTest, cls).resource_cleanup()
        try:
            cls.client.delete_netpartition(cls.nondef_netpart['id'])
        except Exception as exc:
            LOG.exception(exc)
            has_exception = True
            
        if has_exception:
            raise exceptions.TearDownException()

    def verify_gateway_properties(self, actual_gw, expected_gw):
        self.assertEqual(actual_gw['ID'], expected_gw['id'])
        self.assertEqual(actual_gw['name'], expected_gw['name'])
        self.assertEqual(actual_gw['personality'], expected_gw['type'])

    def verify_gateway_port_properties(self, actual_port, expected_port):
        self.assertEqual(actual_port['name'], expected_port['name'])
        self.assertEqual(actual_port['ID'], expected_port['id'])

    def verify_vlan_properties(self, actual_vlan, expected_vlan,
                               verify_ext=True):
        self.assertEqual(actual_vlan['ID'], expected_vlan['id'])
        self.assertEqual(actual_vlan['userMnemonic'],
                         expected_vlan['usermnemonic'])
        self.assertEqual(actual_vlan['value'], expected_vlan['value'])
        if external_id_release <= current_release and verify_ext:
            external_id = (expected_vlan['gatewayport'] + "." +
                           str(expected_vlan['value']))
            self.assertEqual(actual_vlan['externalID'],
                             self.nuage_vsd_client.get_vsd_external_id(
                                 external_id))

    def verify_vport_properties(self, actual_vport, expected_vport):
        self.assertEqual(actual_vport['ID'], expected_vport['id'])
        self.assertEqual(actual_vport['type'], expected_vport['type'])
        self.assertEqual(actual_vport['name'], expected_vport['name'])
        if external_id_release <= current_release:
            if expected_vport['type'] == n_constants.BRIDGE_VPORT:
                self.assertEqual(actual_vport['externalID'],
                                 self.nuage_vsd_client.get_vsd_external_id(
                                     expected_vport['subnet']))
            else:
                self.assertEqual(actual_vport['externalID'],
                                 self.nuage_vsd_client.get_vsd_external_id(
                                     expected_vport['port']))
