# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_log import log as logging

from tempest import config
from tempest.common.utils import data_utils
from tempest.api.network import base as base

from nuagetempest.lib.utils import constants as n_constants
from nuagetempest.lib.nuage_tempest_test_loader import Release
from nuagetempest.services.nuage_client import NuageRestClient
import upgrade_external_id_with_cms_id as upgrade_script

CONF = config.CONF
LOG = logging.getLogger(__name__)

extra_dhcp_opts = [
    {'opt_value': '255.255.255.0', 'opt_name': 'netmask'},
    {'opt_value': '200', 'opt_name': 'time-offset'},
    {'opt_value': '11.33.66.3', 'opt_name': 'router'},
    {'opt_value': '11.33.66.4', 'opt_name': 'time-server'},
    {'opt_value': '11.33.66.6', 'opt_name': 'dns-server'},
    {'opt_value': '11.33.66.7', 'opt_name': 'log-server'}
]

class ExternalIdForVPortTest(base.BaseAdminNetworkTest):
    class MatchingVsdVPort():
        def __init__(self, outer, port, subnet):
            """Construct a Vsd_port. """
            self.test = outer
            self.port = port
            self.subnet = subnet

            self.vsd_vport = None
            self.vsd_l2domain = None

        def get_by_external_id(self):
            vsd_l2domains = self.test.nuage_vsd_client.get_l2domain(
                filters='externalID', filter_value=self.subnet['id'])

            # should have exact 1 match
            self.test.assertEqual(len(vsd_l2domains), 1)
            self.vsd_l2domain = vsd_l2domains[0]

            vsd_vports = self.test.nuage_vsd_client.get_vport(
                    parent=n_constants.L2_DOMAIN,
                    parent_id=self.vsd_l2domain['ID'],
                    filters='externalID',
                    filter_value=self.test.nuage_vsd_client.get_vsd_external_id(self.port['id']))

            # should have exact 1 match
            self.test.assertEqual(len(vsd_vports), 1)
            self.vsd_vport = vsd_vports[0]

            self.test.assertNotEmpty(self.vsd_vport)
            self.test.assertEqual(self.vsd_vport['name'], self.port['id'])
            return self

        def has_dhcp_options(self, with_external_id=None):
            # vsd dhcp_options object has external ID
            vsd_dhcp_options = self.test.nuage_vsd_client.get_dhcpoption(
                parent=n_constants.VPORT,
                parent_id=self.vsd_vport['ID'])
        
            self.test.assertEqual(len(vsd_dhcp_options), len(extra_dhcp_opts),
                                  "dhcp_options not found by VSD parent ID")
        
            if with_external_id is None:
                self.test.assertIsNone(vsd_dhcp_options[0]['externalID'])
            else:
                vsd_dhcp_options = self.test.nuage_vsd_client.get_child_resource(
                    resource=n_constants.VPORT,
                    resource_id=self.vsd_vport['ID'],
                    child_resource=n_constants.DHCPOPTION,
                    filters='externalID',
                    filter_value=self.test.nuage_vsd_client.get_vsd_external_id(
                        with_external_id))
        
                self.test.assertEqual(len(vsd_dhcp_options), len(extra_dhcp_opts),
                                      "dhcp_options not found by ExternalID")
                for vsd_dhcp_option in vsd_dhcp_options:
                    self.test.assertEqual(self.test.nuage_vsd_client.get_vsd_external_id(with_external_id),
                                          vsd_dhcp_option['externalID'])

        def verify_cannot_delete(self):
            # Can't delete vport in VSD
            response = self.test.nuage_vsd_client.delete_resource(n_constants.VPORT, self.vsd_vport['ID'])
            self.test.assertEqual(300, response.status)

    @classmethod
    def skip_checks(cls):
        super(ExternalIdForVPortTest, cls).skip_checks()

        external_id_release = Release('4.0R3')
        current_release = Release(CONF.nuage_sut.release)
        cls.test_upgrade = external_id_release > current_release

    @classmethod
    def setup_clients(cls):
        super(ExternalIdForVPortTest, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()

    def test_port_dhcp_options_matches_to_port(self):
        # Create a network
        name = data_utils.rand_name('network-')
        network = self.create_network(network_name=name)
        self.addCleanup(self.networks_client.delete_network, network['id'])
        subnet = self.create_subnet(network)

        name = data_utils.rand_name('extra-dhcp-opt-port-name')
        create_body = self.ports_client.create_port(
            name=name,
            network_id=network['id'],
            extra_dhcp_opts=extra_dhcp_opts)
        port = create_body['port']
        self.addCleanup(self.ports_client.delete_port, port['id'])

        vsd_vport = None

        if self.test_upgrade:
            vsd_vport = self.MatchingVsdVPort(self, port, subnet).get_by_external_id()
            vsd_vport.has_dhcp_options(with_external_id=port['id'])

            upgrade_script.do_run_upgrade_script()

        vsd_vport.has_dhcp_options(with_external_id=port['id'])

        # Delete
        vsd_vport.verify_cannot_delete()