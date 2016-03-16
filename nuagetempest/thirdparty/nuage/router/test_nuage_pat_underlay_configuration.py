# Copyright 2013 OpenStack Foundation
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

import base_nuage_pat_underlay
from tempest.lib.common.utils import data_utils
from tempest import config
from tempest.lib import exceptions
from nuagetempest.lib.utils import constants
from nuagetempest.lib.test import nuage_test

CONF = config.CONF


class TestNuagePatUnderlayConfigNotAvailable(base_nuage_pat_underlay.NuagePatUnderlayBase):
    _interface = 'json'

    # LOG = logging.getLogger(__name__)

    @classmethod
    def resource_setup(cls):
        super(TestNuagePatUnderlayConfigNotAvailable, cls).resource_setup()
        cls.needs_ini_nuage_pat(constants.NUAGE_PAT_NOTAVAILABLE)

    @classmethod
    def resource_cleanup(cls):
        super(TestNuagePatUnderlayConfigNotAvailable, cls).resource_cleanup()
        # Remove the nuage_pat setting in the .ini file, as not_available is causing troubels for other tests
        cls.needs_ini_nuage_pat(None)

    @nuage_test.header()
    def test_create_router_without_external_gateway_pat_not_available(self):
        self._verify_create_router_without_external_gateway()

    @nuage_test.header()
    def test_create_router_with_external_gateway_without_snat_pat_not_available_neg(self):
        name = data_utils.rand_name('router-without-external-gateway-with-snat-' +
                                    str(constants.NUAGE_PAT_NOTAVAILABLE))
        external_gateway_info = {
            'network_id': CONF.network.public_network_id}
        # Create the router: must fail
        kvargs = {
            'name': name,
            'external_gateway_info': external_gateway_info
        }
        self.assertRaises(exceptions.BadRequest,
                          self.admin_routers_client.create_router,
                          **kvargs)

    @nuage_test.header()
    def test_create_router_without_external_gateway_with_snat_pat_not_available_neg(self):
        self._verify_create_router_without_external_gateway_with_snat_neg()

    @nuage_test.header()
    def test_create_router_with_external_gateway_with_snat_pat_not_available_neg(self):
        """
        Create router with external gateway and enable_snat while nuage_pat = not available

        Must fail as pat is not available: external_gateway mode not supported
        """
        name = data_utils.rand_name('router-with-external-gateway-with-snat-pat-not-available-neg')
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            external_gateway_info = {
                'network_id': CONF.network.public_network_id,
                'enable_snat': enable_snat}
            kvargs = {
                'name': name,
                'external_gateway_info': external_gateway_info
            }
            self.assertRaises(exceptions.BadRequest,
                              self.admin_routers_client.create_router,
                              **kvargs)

    @nuage_test.header()
    def test_show_router_without_external_gateway_pat_not_available(self):
        self._verify_show_router_without_external_gw()


class TestNuagePatUnderlayConfigurationPatNone(base_nuage_pat_underlay.NuagePatUnderlayBase):
    _interface = 'json'

    # LOG = logging.getLogger(__name__)

    @classmethod
    def resource_setup(cls):
        super(TestNuagePatUnderlayConfigurationPatNone, cls).resource_setup()
        cls.needs_ini_nuage_pat(None)

    @nuage_test.header()
    def test_nuage_create_router_without_external_gateway_pat_none(self):
        self._verify_create_router_without_external_gateway()

    @nuage_test.header()
    def test_nuage_create_router_with_external_gateway_without_snat_pat_none(self):
        self._verify_create_router_with_external_gw_without_snat()

    @nuage_test.header()
    def test_nuage_create_router_without_external_gateway_with_snat_pat_none_neg(self):
        self._verify_create_router_without_external_gateway_with_snat_neg()

    @nuage_test.header()
    def test_nuage_create_router_with_external_gateway_with_snat_pat_none(self):
        self._verify_create_router_with_external_gateway_with_snat()

    @nuage_test.header()
    def test_nuage_update_router_with_external_gateway_with_snat_pat_none(self):
        self._verify_update_router_with_external_gateway_with_snat()

    @nuage_test.header()
    def test_nuage_show_router_without_eternal_gateway_pat_none(self):
        self._verify_show_router_without_external_gw()

    @nuage_test.header()
    def test_nuage_show_router_with_external_gateway_with_snat_pat_none(self):
        self._verify_show_router_with_external_gateway_with_snat()

    @nuage_test.header()
    def test_nuage_list_router_with_external_gateway_with_snat_pat_none(self):
        self._verify_list_router_with_gateway_with_snat()


class TestNuagePatUnderlayConfigDefaultDisabled(base_nuage_pat_underlay.NuagePatUnderlayBase):
    _interface = 'json'

    # LOG = logging.getLogger(__name__)

    @classmethod
    def resource_setup(cls):
        super(TestNuagePatUnderlayConfigDefaultDisabled, cls).resource_setup()
        cls.needs_ini_nuage_pat(constants.NUAGE_PAT_DEFAULTDISABLED)

    @nuage_test.header()
    def test_nuage_create_router_without_external_gateway_pat_default_disabled(self):
        self._verify_create_router_without_external_gateway()

    @nuage_test.header()
    def test_nuage_create_router_with_external_gateway_without_snat_pat_default_disabled(self):
        self._verify_create_router_with_external_gw_without_snat()

    @nuage_test.header()
    def test_nuage_create_router_without_external_gateway_with_snat_pat_default_disabled_neg(self):
        self._verify_create_router_without_external_gateway_with_snat_neg()

    @nuage_test.header()
    def test_nuage_create_router_with_external_gateway_with_snat_pat_default_disabled(self):
        self._verify_create_router_with_external_gateway_with_snat()

    @nuage_test.header()
    def test_nuage_update_router_with_external_gateway_with_snat_pat_default_disabled(self):
        self._verify_update_router_with_external_gateway_with_snat()

    @nuage_test.header()
    def test_nuage_show_router_without_eternal_gateway_pat_default_disabled(self):
        self._verify_show_router_without_external_gw()

    @nuage_test.header()
    def test_nuage_show_router_with_external_gateway_with_snat_pat_default_disabled(self):
        self._verify_show_router_with_external_gateway_with_snat()

    @nuage_test.header()
    def test_nuage_list_router_with_external_gateway_with_snat_pat_default_disabled(self):
        self._verify_list_router_with_gateway_with_snat()


class TestNuagePatUnderlayConfigDefaultEnabled(base_nuage_pat_underlay.NuagePatUnderlayBase):
    _interface = 'json'

    # LOG = logging.getLogger(__name__)

    @classmethod
    def resource_setup(cls):
        super(TestNuagePatUnderlayConfigDefaultEnabled, cls).resource_setup()
        cls.needs_ini_nuage_pat(constants.NUAGE_PAT_DEFAULTENABLED)

    @nuage_test.header()
    def test_nuage_create_router_without_external_gateway_pat_default_enabled(self):
        self._verify_create_router_without_external_gateway()

    @nuage_test.header()
    def test_nuage_create_router_with_external_gateway_without_snat_pat_default_enabled(self):
        self._verify_create_router_with_external_gw_without_snat()

    @nuage_test.header()
    def test_nuage_create_router_without_external_gateway_with_snat_pat_default_enabled_neg(self):
        self._verify_create_router_without_external_gateway_with_snat_neg()

    @nuage_test.header()
    def test_nuage_create_router_with_external_gateway_with_snat_pat_default_enabled(self):
        self._verify_create_router_with_external_gateway_with_snat()

    @nuage_test.header()
    def test_nuage_update_router_with_external_gateway_with_snat_pat_default_enabled(self):
        self._verify_update_router_with_external_gateway_with_snat()

    @nuage_test.header()
    def test_nuage_show_router_without_eternal_gateway_pat_default_enabled(self):
        self._verify_show_router_without_external_gw()

    @nuage_test.header()
    def test_nuage_show_router_with_external_gateway_with_snat_pat_default_enabled(self):
        self._verify_show_router_with_external_gateway_with_snat()

    @nuage_test.header()
    def test_nuage_list_router_with_external_gateway_with_snat_pat_default_enabled(self):
        self._verify_list_router_with_gateway_with_snat()

