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

from oslo_log import log as logging
from tempest import config
from nuagetempest.lib.test import nuage_test

import base_nuage_fip_underlay

CONF = config.CONF


class FIPtoUnderlayTestNuageConfigurationNone(base_nuage_fip_underlay.NuageFipUnderlayBase):
    LOG = logging.getLogger(__name__)
    # user order of tests as in this file to avoid unnecessary neutron restart
#   unittest.TestLoader.sortTestMethodsUsing(None)

    @classmethod
    def resource_setup(cls):
        super(FIPtoUnderlayTestNuageConfigurationNone, cls).resource_setup()
        cls.needs_ini_nuage_fip_underlay(None)

    @nuage_test.header()
    def test_create_external_subnet_without_underlay_default_none(self):
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
    def test_show_external_subnet_without_underlay_default_none(self):
        """
        Show an external fip subnet created without underlay without nuage_fip_underlay in .ini

        Response must include underlay = False
        """
        self._verify_show_external_subnet_without_underlay()

    @nuage_test.header()
    def test_show_external_subnet_with_underlay_default_none(self):
        """
        Show external fip subnet with underlay without nuage_fip_underlay in .ini file

        Response must include underlay - False
        """
        self._verify_show_external_subnet_with_underlay()

    @nuage_test.header()
    def test_list_external_subnets_underlay_default_none(self):
        """
        List external fip subnets with underlay without nuage_fip_underlay in .ini file

        Response must include underlay True for those subnets created with underlay True
        and False otherwise
        """
        self._verify_list_external_subnets_underlay()

    #
    #  Scaling tests
    #
    #
    # TODO: add check on amount of external networks and then scale to max
    @nuage_test.nuage_skip_because(message="Todo: check external networks before scaling to max")
    @nuage_test.header()
    def test_scale_create_external_subnet_with_underlay_gre(self):
        self._verify_create_external_subnet_with_underlay_scale('GRE', 32)
        # def test_scale_create_external_subnet_with_underlay_VXLAN(self):
        #     self._verify_create_external_subnet_with_underlay_scale('VXLAN',400)


class FIPtoUnderlayTestNuageConfigurationDefaultFalse(base_nuage_fip_underlay.NuageFipUnderlayBase):
    LOG = logging.getLogger(__name__)
    # user order of tests as in this file to avoid unnecessary neutron restart
    #   unittest.TestLoader.sortTestMethodsUsing(None)

    @classmethod
    def resource_setup(cls):
        super(FIPtoUnderlayTestNuageConfigurationDefaultFalse, cls).resource_setup()
        cls.needs_ini_nuage_fip_underlay(False)

    @nuage_test.header()
    def test_create_external_subnet_without_underlay_default_false(self):
        """
        Create an external FIP subnet without underlay without nuage_fip+underlay in .ini

        Response must include underlay = False
        """
        self._verify_create_delete_external_subnet_without_underlay()

    @nuage_test.header()
    def test_create_external_subnet_with_underlay_default_false(self):
        """
        Create an external FIP subnet with underlay without nuage_fip+underlay in .ini

        Response must include same underlay status as used in creation
        """
        self._verify_create_external_fip_subnet_with_underlay()

    @nuage_test.header()
    def test_show_external_subnet_without_underlay_default_false(self):
        """
        Show an external fip subnet created without underlay without nuage_fip_underlay in .ini

        Response must include underlay = False
        """
        self._verify_show_external_subnet_without_underlay()

    @nuage_test.header()
    def test_show_external_subnet_with_underlay_default_false(self):
        """
        Show external fip subnet with underlay without nuage_fip_underlay in .ini file

        Response must include underlay - False
        """
        self._verify_show_external_subnet_with_underlay()

    @nuage_test.header()
    def test_list_external_subnets_underlay_default_false(self):
        """
        List external fip subnets with underlay without nuage_fip_underlay in .ini file

        Response must include underlay True for those subnets created with underlay True
        and False otherwise
        """
        self._verify_list_external_subnets_underlay()

    #
    #  Scaling tests
    #
    #
    # TODO: add check on amount of external networks and then scale to max
    @nuage_test.nuage_skip_because(message="Todo: check external networks before scaling to max")
    @nuage_test.header()
    def test_scale_create_external_subnet_with_underlay_gre(self):
        self._verify_create_external_subnet_with_underlay_scale('GRE', 32)
        # def test_scale_create_external_subnet_with_underlay_VXLAN(self):
        #     self._verify_create_external_subnet_with_underlay_scale('VXLAN',400)


class FIPtoUnderlayTestNuageConfigurationDefaultTrue(base_nuage_fip_underlay.NuageFipUnderlayBase):
    LOG = logging.getLogger(__name__)
    # user order of tests as in this file to avoid unnecessary neutron restart
    #   unittest.TestLoader.sortTestMethodsUsing(None)

    @classmethod
    def resource_setup(cls):
        super(FIPtoUnderlayTestNuageConfigurationDefaultTrue, cls).resource_setup()
        cls.needs_ini_nuage_fip_underlay(True)

    @nuage_test.header()
    def test_create_external_subnet_without_underlay_default_true(self):
        """
        Create an external FIP subnet without underlay without nuage_fip+underlay in .ini

        Response must include underlay = False
        """
        self._verify_create_delete_external_subnet_without_underlay()

    @nuage_test.header()
    def test_create_external_subnet_with_underlay_default_true(self):
        """
        Create an external FIP subnet with underlay without nuage_fip+underlay in .ini

        Response must include same underlay status as used in creation
        """
        self._verify_create_external_fip_subnet_with_underlay()

    @nuage_test.header()
    def test_show_external_subnet_without_underlay_default_true(self):
        """
        Show an external fip subnet created without underlay without nuage_fip_underlay in .ini

        Response must include underlay = False
        """
        self._verify_show_external_subnet_without_underlay()

    @nuage_test.header()
    def test_show_external_subnet_with_underlay_default_true(self):
        """
        Show external fip subnet with underlay without nuage_fip_underlay in .ini file

        Response must include underlay - False
        """
        self._verify_show_external_subnet_with_underlay()

    @nuage_test.header()
    def test_list_external_subnets_underlay_default_true(self):
        """
        List external fip subnets with underlay without nuage_fip_underlay in .ini file

        Response must include underlay True for those subnets created with underlay True
        and False otherwise
        """
        self._verify_list_external_subnets_underlay()

    #
    #  Scaling tests
    #
    #
    # TODO: add check on amount of external networks and then scale to max
    @nuage_test.nuage_skip_because(message="Todo: check external networks before scaling to max")
    @nuage_test.header()
    def test_scale_create_external_subnet_with_underlay_gre(self):
        self._verify_create_external_subnet_with_underlay_scale('GRE', 32)
        # def test_scale_create_external_subnet_with_underlay_VXLAN(self):
        #     self._verify_create_external_subnet_with_underlay_scale('VXLAN',400)
