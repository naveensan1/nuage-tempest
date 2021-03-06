# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from tempest import config
from oslo_log import log as logging
import base_nuage_fip_underlay
from nuagetempest.lib.remote_cli import remote_cli_base_testcase
from nuagetempest.lib.test import nuage_test

CONF = config.CONF


class TestNuageFipUnderlayConfigurationCliNone(remote_cli_base_testcase.RemoteCliBaseTestCase,
                                               base_nuage_fip_underlay.NuageFipUnderlayBase):
    """
    FIP to Underlay tests using Neutron CLI client.
    """
    LOG = logging.getLogger(__name__)

    @classmethod
    def resource_setup(cls):
        super(TestNuageFipUnderlayConfigurationCliNone, cls).resource_setup()
        cls.needs_ini_nuage_fip_underlay(None)

    @nuage_test.header()
    def test_cli_create_delete_external_subnet_without_underlay_default_none(self):
        self._as_admin()
        self._cli_create_delete_external_subnet_without_underlay()

    @nuage_test.header()
    def _test_cli_create_external_fip_subnet_with_underlay_default_none(self):
        self._as_admin()
        self._cli_create_external_fip_subnet_with_underlay()

    @nuage_test.header()
    def test_cli_show_external_subnet_without_underlay_default_none(self):
        self._as_admin()
        self._cli_show_external_subnet_without_underlay()

    @nuage_test.header()
    def test_cli_show_external_subnet_with_underlay_default_none(self):
        self._as_admin()
        self._cli_show_external_subnet_with_underlay()

    @nuage_test.header()
    def test_cli_list_external_subnets_underlay_default_none(self):
        self._as_admin()
        self._cli_list_external_subnets_underlay()


class TestNuageFipUnderlayConfigCliDefaultFalse(remote_cli_base_testcase.RemoteCliBaseTestCase,
                                                       base_nuage_fip_underlay.NuageFipUnderlayBase):
    """
    FIP to Underlay tests using Neutron CLI client.
    """
    LOG = logging.getLogger(__name__)

    @classmethod
    def resource_setup(cls):
        super(TestNuageFipUnderlayConfigCliDefaultFalse, cls).resource_setup()
        cls.needs_ini_nuage_fip_underlay(False)

    @nuage_test.header()
    def test_cli_create_delete_external_subnet_without_underlay_default_false(self):
        self._as_admin()
        self._cli_create_delete_external_subnet_without_underlay()

    @nuage_test.header()
    def _test_cli_create_external_fip_subnet_with_underlay_default_false(self):
        self._as_admin()
        self._cli_create_external_fip_subnet_with_underlay()

    @nuage_test.header()
    def test_cli_show_external_subnet_without_underlay_default_false(self):
        self._as_admin()
        self._cli_show_external_subnet_without_underlay()

    @nuage_test.header()
    def test_cli_show_external_subnet_with_underlay_default_false(self):
        self._as_admin()
        self._cli_show_external_subnet_with_underlay()

    @nuage_test.header()
    def test_cli_list_external_subnets_underlay_default_false(self):
        self._as_admin()
        self._cli_list_external_subnets_underlay()


class TestNuageFipUnderlayConfigCliDefaultTrue(remote_cli_base_testcase.RemoteCliBaseTestCase,
                                                      base_nuage_fip_underlay.NuageFipUnderlayBase):
    """
    FIP to Underlay tests using Neutron CLI client.
    """
    LOG = logging.getLogger(__name__)

    @classmethod
    def resource_setup(cls):
        super(TestNuageFipUnderlayConfigCliDefaultTrue, cls).resource_setup()
        cls.needs_ini_nuage_fip_underlay(True)

    @nuage_test.header()
    def test_cli_create_delete_external_subnet_without_underlay_default_true(self):
        self._as_admin()
        self._cli_create_delete_external_subnet_without_underlay()

    @nuage_test.header()
    def _test_cli_create_external_fip_subnet_with_underlay_default_true(self):
        self._as_admin()
        self._cli_create_external_fip_subnet_with_underlay()

    @nuage_test.header()
    def test_cli_show_external_subnet_without_underlay_default_true(self):
        self._as_admin()
        self._cli_show_external_subnet_without_underlay()

    @nuage_test.header()
    def test_cli_show_external_subnet_with_underlay_default_true(self):
        self._as_admin()
        self._cli_show_external_subnet_with_underlay()

    @nuage_test.header()
    def test_cli_list_external_subnets_underlay_default_true(self):
        self._as_admin()
        self._cli_list_external_subnets_underlay()
