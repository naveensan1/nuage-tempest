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

from tempest.lib.common.utils import data_utils
from oslo_log import log as logging
from tempest import config
from tempest import test
from tempest.lib import exceptions
from nuagetempest.lib.test import nuage_test

import base_nuage_fip_underlay

CONF = config.CONF


class FIPtoUnderlayTestNuage(base_nuage_fip_underlay.NuageFipUnderlayBase):
    LOG = logging.getLogger(__name__)
    # user order of tests as in this file to avoid unnecessary neutron restart
    #   unittest.TestLoader.sortTestMethodsUsing(None)

    @classmethod
    def resource_setup(cls):
        super(FIPtoUnderlayTestNuage, cls).resource_setup()

    @nuage_test.header()
    def test_create_external_subnet_without_underlay(self):
        """
        Create an external FIP subnet without underlay without nuage_fip+underlay in .ini

        Response must include underlay = False
        """
        self._verify_create_delete_external_subnet_without_underlay()

    @nuage_test.header()
    def test_create_external_subnet_with_underlay_default_none(self):
        """
        Create an external FIP subnet with underlay without nuage_fip+underlay in .ini

        Response must include same underlay status as used in creation
        """
        self._verify_create_external_fip_subnet_with_underlay()

    @nuage_test.header()
    def test_show_external_subnet_without_underlay(self):
        """
        Show an external fip subnet created without underlay without nuage_fip_underlay in .ini

        Response must include underlay = False
        """
        self._verify_show_external_subnet_without_underlay()

    @nuage_test.header()
    def test_show_external_subnet_with_underlay(self):
        """
        Show external fip subnet with underlay without nuage_fip_underlay in .ini file

        Response must include underlay - False
        """
        self._verify_show_external_subnet_with_underlay()

    @nuage_test.header()
    def test_list_external_subnets_underlay(self):
        """
        List external fip subnets with underlay without nuage_fip_underlay in .ini file

        Response must include underlay True for those subnets created with underlay True
        and False otherwise
        """
        self._verify_list_external_subnets_underlay()

    #
    #
    #  Negative test cases
    #
    #
    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_create_external_subnet_with_underlay_invalid_values_neg(self):
        """
        Try to create an external FIP subnet with invalid values for underlay=True/False

        Must fail with proper reason
        """
        ext_network = self._create_network(external=True)
        invalid_underlay_values = ['Ttrue', 'Treu', 'Tru', 'Truet', 'Trrue', 'Truue', 'Truee',
                                   'Flase', 'Falsche', 'Fales', 'Flaes', 'FFalse', 'fFalse']
        subnet_name = data_utils.rand_name('subnet-invalid-underlay-value')
        for underlay in invalid_underlay_values:
            kvargs = {
                'network_id': ext_network['id'],
                'cidr': '135.99.99.0/24',
                'ip_version': self._ip_version,
                'name': subnet_name,
                'underlay': underlay
            }
            self.assertRaises(exceptions.BadRequest,
                              self.admin_subnets_client.create_subnet,
                              **kvargs)
        pass

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_create_internal_subnet_with_underlay_neg(self):
        """
        Try to create an internal subnet while specifying underlay=True/False

        Must fail
        """
        int_network = self.create_network()
        underlay_states = [False, True]
        for underlay in underlay_states:
            subnet_name = data_utils.rand_name('internal-fip-subnet-with-underlay-neg')
            kvargs = {
                'network_id': int_network['id'],
                'cidr': '135.66.66.0/24',
                'ip_version': self._ip_version,
                'name': subnet_name,
                'underlay': underlay
            }
            self.assertRaises(exceptions.BadRequest,
                              self.admin_subnets_client.create_subnet,
                              **kvargs)
        pass

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_update_internal_subnet_with_underlay_neg(self):
        """
        Try to update an internal subnet while specifying underlay=True/False

        Must fail: verifies OPENSTACK-722
        """
        int_network = self.create_network()
        subnet_name = data_utils.rand_name('underlay-update-internal-subnet-not-allowed')
        create_body = self.admin_subnets_client.create_subnet(network_id=int_network['id'],
                                                              cidr="99.97.95.0/24",
                                                              ip_version=self._ip_version,
                                                              name=subnet_name)
        subnet = create_body['subnet']
        new_name = subnet_name + '-updated'
        kvargs = {
            'name': new_name,
            'underlay': True
        }
        self.assertRaises(exceptions.BadRequest,
                          self.admin_subnets_client.update_subnet,
                          subnet['id'],
                          **kvargs)
        self.admin_subnets_client.delete_subnet(subnet['id'])
        pass

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_create_external_subnet_with_underlay_invalid_syntax_neg(self):
        """
        Try to create an external FIP subnet with invalid values for "underlay'

        Must fail with proper reason
        """
        ext_network = self._create_network(external=True)
        underlay_invalid_syntax = ['Underley', 'Overlay', 'under1ay', 'inderlay', 'overlay', 'ollekenbolleke',
                                   'undarlay', 'anderluy', 'etcetera', '...', '***']
        subnet_name = data_utils.rand_name('subnet-invalid-underlay-syntax')
        for underlay in underlay_invalid_syntax:
            kvargs = {
                'network_id': ext_network['id'],
                'cidr': '135.99.99.0/24',
                'ip_version': self._ip_version,
                'name': subnet_name,
                underlay: True
            }
            self.assertRaises(exceptions.BadRequest,
                              self.admin_subnets_client.create_subnet,
                              **kvargs)

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_create_external_subnet_with_gw_nuage_pat_underlay_true_neg(self):
        """
        Try to create an external subnet with gateway while nuage_pat_underlay = True in .ini file

        Must fail
        """
        self.needs_ini_nuage_fip_underlay(True)
        # Todo: checl validity of this test case: not clear as of time of writing
        print "to be completed"

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_update_external_subnet_with_snat_neg(self):
        self._verify_update_external_subnet_with_underlay_neg()

    ## TODO: Hendrik - test needs to run exclusively
    # #
    # #  Scaling tests
    # #
    # #
    # @nuage_test.header()
    # def test_scale_create_external_subnet_with_underlay_gre(self):
    #     self._verify_create_external_subnet_with_underlay_scale('GRE', 32)
    #     # def test_scale_create_external_subnet_with_underlay_VXLAN(self):
    #     #     self._verify_create_external_subnet_with_underlay_scale('VXLAN',400)
