# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_log import log as logging
import testtools

from tempest import config
from tempest.common.utils import data_utils
from tempest.api.network import base as base

from nuagetempest.lib.test import nuage_test
from nuagetempest.lib.utils import constants as n_constants
from nuagetempest.lib.utils import exceptions as n_exceptions
from nuagetempest.lib.nuage_tempest_test_loader import Release
from nuagetempest.services.nuage_client import NuageRestClient
from nuagetempest.services.nuage_network_client import NuageNetworkClientJSON
from external_id import ExternalId

CONF = config.CONF
LOG = logging.getLogger(__name__)


class ExternalIdForNetworkMacroTest(base.BaseAdminNetworkTest):
    class MatchingVsdNetworkMacro():
        def __init__(self, outer, net_partition):
            """Construct a Vsd_port. """
            self.test = outer
            self.net_partition = net_partition
            self.vsd_network_macro = None

        def get_by_external_id(self):
            vsd_network_macro = self.test.nuage_vsd_client.get_enterprise_net_macro(
                netpart_name=self.net_partition['name'])
            self.test.assertEqual(1, len(vsd_network_macro), "should have network macros")

            vsd_network_macros = self.test.nuage_vsd_client.get_enterprise_net_macro(
                netpart_name=self.net_partition['name'],
                filters='externalID',
                filter_value=ExternalId(self.net_partition['id']).at_openstack())

            # should have exact 1 match
            self.test.assertEqual(1, len(vsd_network_macros))
            self.vsd_network_macro = vsd_network_macros[0]

            # TODO: what should be the name
            # reference = u'5ffc260c-f10d-4cd1-85a3-26e35618e695_0_0'
            # actual    = u'5ffc260c-f10d-4cd1-85a3-26e35618e695'
            # self.test.assertEqual(self.vsd_network_macro['name'], self.net_partition['id'])

            self.test.assertEqual(ExternalId(self.net_partition['id']).at_openstack(),
                                  self.vsd_network_macro['externalID'])
            return self

        def verify_cannot_delete(self):
            # Can't delete NetworkMacro in VSD
            self.test.assertRaisesRegexp(n_exceptions.MultipleChoices,
                                         "Multiple choices",
                                         self.test.nuage_vsd_client.delete_resource,
                                         n_constants.ENTERPRISE_NET_MACRO,
                                         self.vsd_network_macro['ID'])

    @classmethod
    def setup_clients(cls):
        super(ExternalIdForNetworkMacroTest, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()
        cls.nuage_network_client = NuageNetworkClientJSON(
            cls.os.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os.default_params)

    @classmethod
    def _create_netpartition(cls):
        name = data_utils.rand_name('netpartition')

        body = cls.nuage_network_client.create_netpartition(name)
        netpartition = body['net_partition']
        return netpartition

    def _delete_network(self, network):
        # Deleting network also deletes its subnets if exists
        self.networks_client.delete_network(network['id'])
        if network in self.networks:
            self.networks.remove(network)
        for subnet in self.subnets:
            if subnet['network_id'] == network['id']:
                self.subnets.remove(subnet)

    @testtools.skipUnless(Release('4.0R5') <= Release(CONF.nuage_sut.release),
                          'No upgrade testing on network macro')
    @nuage_test.header()
    def test_network_macro_matches_to_enterprise(self):
        # Create a dedicated netpartition
        netpartition_b = self._create_netpartition()
        self.addCleanup(self.nuage_network_client.delete_netpartition, netpartition_b['id'])

        # Create a network 1 in netpartition A
        name = data_utils.rand_name('networkA1')
        network_a1 = self.create_network(network_name=name)
        self.addCleanup(self._delete_network, network_a1)
        subnet_a1 = self.create_subnet(network_a1, net_partition=netpartition_b['name'])
        self.assertIsNotNone(subnet_a1)  # dummy check to use local variable

        network_macros = self.nuage_vsd_client.get_enterprise_net_macro(netpart_name=netpartition_b['name'])
        self.assertEqual(0, len(network_macros), "should not have network macros")

        create_body = self.ports_client.create_port(
            name=name,
            network_id=network_a1['id'])
        port = create_body['port']
        self.addCleanup(self.ports_client.delete_port, port['id'])

        vsd_network_macro = self.MatchingVsdNetworkMacro(self, netpartition_b).get_by_external_id()

        # Delete
        vsd_network_macro.verify_cannot_delete()