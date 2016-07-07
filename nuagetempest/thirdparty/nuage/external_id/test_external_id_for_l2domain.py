# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

from oslo_log import log as logging

from tempest.api.network import base
from tempest.common.utils import data_utils
from tempest import config

from nuagetempest.lib.utils import constants as n_constants
from nuagetempest.lib.nuage_tempest_test_loader import Release
from nuagetempest.services.nuage_client import NuageRestClient
import upgrade_external_id_with_cms_id as upgrade_script

CONF = config.CONF
LOG = logging.getLogger(__name__)


class ExternalIdForL2domainTest(base.BaseNetworkTest):
    test_upgrade = False

    class MatchingVsdL2domain():
        def __init__(self, outer, subnet):
            """Construct a Vsd_l2domain. """
            self.test = outer
            self.subnet = subnet
            self.vsd_l2domain = None

        def get_by_external_id(self):
            vsd_l2domains = self.test.nuage_vsd_client.get_l2domain(
                filters='externalID', filter_value=self.subnet['id'])

            # should have exact 1 match
            self.test.assertEqual(len(vsd_l2domains), 1)
            self.vsd_l2domain = vsd_l2domains[0]

            self.test.assertNotEmpty(self.vsd_l2domain)
            self.test.assertEqual(self.vsd_l2domain['name'], self.subnet['id'])
            return self

        def has_permissions(self, with_external_id=None):
            # vsd permissions object has external ID
            vsd_permissions = self.test.nuage_vsd_client.get_permissions(
                parent=n_constants.L2_DOMAIN,
                parent_id=self.vsd_l2domain['ID'])

            self.test.assertEqual(len(vsd_permissions), 1, "VSD Permission not found by parent ID")

            if with_external_id is None:
                self.test.assertIsNone(vsd_permissions[0]['externalID'])
            else:
                # permission object has external ID
                self.test.assertEqual(self.test.nuage_vsd_client.get_vsd_external_id(with_external_id),
                                      vsd_permissions[0]['externalID'])

                # can find vsd permissions by external ID
                vsd_permissions = self.test.nuage_vsd_client.get_permissions(
                    parent=n_constants.L2_DOMAIN,
                    parent_id=self.vsd_l2domain['ID'],
                    filters='externalID', filter_value=with_external_id)
                self.test.assertEqual(len(vsd_permissions), 1, "VSD Permission not found by ExternalID")

        def has_group(self, with_external_id=None):
            # vsd permissions object has external ID
            vsd_groups = self.test.nuage_vsd_client.get_usergroup(
                parent=n_constants.L2_DOMAIN,
                parent_id=self.vsd_l2domain['ID'])

            self.test.assertEqual(len(vsd_groups), 1, "Group not found by VSD parent ID")

            # matching values
            self.test.assertEqual(self.subnet['tenant_id'], vsd_groups[0]['name'])
            self.test.assertEqual("CMS", vsd_groups[0]['managementMode'])

            if with_external_id is None:
                self.test.assertIsNone(vsd_groups[0]['externalID'])
            else:
                vsd_groups = self.test.nuage_vsd_client.get_resource(
                    resource=n_constants.GROUP,
                    filters='externalID',
                    filter_value=self.test.nuage_vsd_client.get_vsd_external_id(
                        self.subnet['tenant_id']))

                self.test.assertEqual(len(vsd_groups), 1, "Group not found by ExternalID")
                self.test.assertEqual(self.test.nuage_vsd_client.get_vsd_external_id(with_external_id),
                                      vsd_groups[0]['externalID'])

        def has_user(self, with_external_id=None):
            # vsd user object has external ID
            vsd_users = self.test.nuage_vsd_client.get_user(
                filters='userName',
                filter_value=self.subnet['tenant_id'])

            self.test.assertEqual(len(vsd_users), 1, "User not found by VSD parent ID")
    
            # matching values
            self.test.assertEqual(self.subnet['tenant_id'], vsd_users[0]['userName'])
            self.test.assertEqual("CMS", vsd_users[0]['managementMode'])

            if with_external_id is None:
                self.test.assertIsNone(vsd_users[0]['externalID'])
            else:
                vsd_users = self.test.nuage_vsd_client.get_resource(
                    resource=n_constants.USER,
                    filters='externalID',
                    filter_value=self.test.nuage_vsd_client.get_vsd_external_id(
                        self.subnet['tenant_id']))
    
                self.test.assertEqual(len(vsd_users), 1, "User not found by ExternalID")
                self.test.assertEqual(self.test.nuage_vsd_client.get_vsd_external_id(with_external_id),
                                      vsd_users[0]['externalID'])

        def has_egress_acl_template(self, with_external_id=None):
            # vsd egress_acl_template object has external ID
            vsd_egress_acl_templates = self.test.nuage_vsd_client.get_egressacl_template(
                parent=n_constants.L2_DOMAIN,
                parent_id=self.vsd_l2domain['ID'])

            self.test.assertEqual(len(vsd_egress_acl_templates), 1, "egress_acl_template not found by VSD parent ID")

            if with_external_id is None:
                self.test.assertIsNone(vsd_egress_acl_templates[0]['externalID'])
            else:
                vsd_egress_acl_templates = self.test.nuage_vsd_client.get_child_resource(
                    resource=n_constants.L2_DOMAIN,
                    resource_id=self.vsd_l2domain['ID'],
                    child_resource=n_constants.EGRESS_ACL_TEMPLATE,
                    filters='externalID',
                    filter_value=self.test.nuage_vsd_client.get_vsd_external_id(
                        with_external_id))

                self.test.assertEqual(len(vsd_egress_acl_templates), 1, "egress_acl_template not found by ExternalID")
                self.test.assertEqual(self.test.nuage_vsd_client.get_vsd_external_id(with_external_id),
                                      vsd_egress_acl_templates[0]['externalID'])

        def has_ingress_acl_template(self, with_external_id=None):
            # vsd ingress_acl_template object has external ID
            vsd_ingress_acl_templates = self.test.nuage_vsd_client.get_ingressacl_template(
                parent=n_constants.L2_DOMAIN,
                parent_id=self.vsd_l2domain['ID'])

            self.test.assertEqual(len(vsd_ingress_acl_templates), 1, "ingress_acl_template not found by VSD parent ID")

            if with_external_id is None:
                self.test.assertIsNone(vsd_ingress_acl_templates[0]['externalID'])
            else:
                vsd_ingress_acl_templates = self.test.nuage_vsd_client.get_child_resource(
                    resource=n_constants.L2_DOMAIN,
                    resource_id=self.vsd_l2domain['ID'],
                    child_resource=n_constants.INGRESS_ACL_TEMPLATE,
                    filters='externalID',
                    filter_value=self.test.nuage_vsd_client.get_vsd_external_id(
                        self.subnet['id']))

                self.test.assertEqual(len(vsd_ingress_acl_templates), 1, "ingress_acl_template not found by ExternalID")
                self.test.assertEqual(self.test.nuage_vsd_client.get_vsd_external_id(with_external_id),
                                      vsd_ingress_acl_templates[0]['externalID'])

        def has_ingress_advanced_forward_acl_template(self, with_external_id=None):
            # vsd ingress_advanced_forward_acl_template object has external ID
            vsd_ingress_advanced_forward_acl_templates = self.test.nuage_vsd_client.get_child_resource(
                resource=n_constants.L2_DOMAIN,
                resource_id=self.vsd_l2domain['ID'],
                child_resource=n_constants.INGRESS_ADV_FWD_TEMPLATE)

            self.test.assertEqual(len(vsd_ingress_advanced_forward_acl_templates), 1, 
                                  "ingress_advanced_forward_acl_template not found by VSD parent ID")

            if with_external_id is None:
                self.test.assertIsNone(vsd_ingress_advanced_forward_acl_templates[0]['externalID'])
            else:
                vsd_ingress_advanced_forward_acl_templates = self.test.nuage_vsd_client.get_child_resource(
                    resource=n_constants.L2_DOMAIN,
                    resource_id=self.vsd_l2domain['ID'],
                    child_resource=n_constants.INGRESS_ADV_FWD_TEMPLATE,
                    filters='externalID',
                    filter_value=self.test.nuage_vsd_client.get_vsd_external_id(
                        with_external_id))

                self.test.assertEqual(len(vsd_ingress_advanced_forward_acl_templates), 1, 
                                      "ingress_advanced_forward_acl_template not found by ExternalID")
                self.test.assertEqual(self.test.nuage_vsd_client.get_vsd_external_id(with_external_id),
                                      vsd_ingress_advanced_forward_acl_templates[0]['externalID'])

        def verify_cannot_delete(self):
            # Can't delete l2 domain in VSD
            response = self.test.nuage_vsd_client.delete_l2domain(self.vsd_l2domain['ID'])
            self.test.assertEqual(300, response.status)

    @classmethod
    def skip_checks(cls):
        super(ExternalIdForL2domainTest, cls).skip_checks()

        external_id_release = Release('4.0R3')
        current_release = Release(CONF.nuage_sut.release)
        cls.test_upgrade = external_id_release > current_release

    @classmethod
    def setup_clients(cls):
        super(ExternalIdForL2domainTest, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()

    def _delete_network(self, network):
        # Deleting network also deletes its subnets if exists
        self.networks_client.delete_network(network['id'])
        if network in self.networks:
            self.networks.remove(network)
        for subnet in self.subnets:
            if subnet['network_id'] == network['id']:
                self.subnets.remove(subnet)

    def test_subnet_matches_to_l2domain(self):
        # Create a network
        name = data_utils.rand_name('network-')
        network = self.create_network(network_name=name)
        self.addCleanup(self._delete_network, network)
        self.assertEqual('ACTIVE', network['status'])

        # Create a subnet
        subnet = self.create_subnet(network)

        if self.test_upgrade:
            vsd_l2domain = self.MatchingVsdL2domain(self, subnet).get_by_external_id()
            vsd_l2domain.has_permissions(with_external_id=None)
            vsd_l2domain.has_group(with_external_id=None)
            vsd_l2domain.has_user(with_external_id=None)
            vsd_l2domain.has_egress_acl_template(with_external_id=None)
            vsd_l2domain.has_ingress_acl_template(with_external_id=None)
            vsd_l2domain.has_ingress_advanced_forward_acl_template(with_external_id=None)

            upgrade_script.do_run_upgrade_script()

        vsd_l2domain = self.MatchingVsdL2domain(self, subnet).get_by_external_id()
        vsd_l2domain.has_permissions(with_external_id=subnet['tenant_id'])
        vsd_l2domain.has_group(with_external_id=subnet['tenant_id'])
        vsd_l2domain.has_user(with_external_id=subnet['tenant_id'])
        vsd_l2domain.has_egress_acl_template(with_external_id=subnet['id'])
        vsd_l2domain.has_ingress_acl_template(with_external_id=subnet['id'])
        vsd_l2domain.has_ingress_advanced_forward_acl_template(with_external_id=subnet['id'])

        # Delete
        vsd_l2domain.verify_cannot_delete()