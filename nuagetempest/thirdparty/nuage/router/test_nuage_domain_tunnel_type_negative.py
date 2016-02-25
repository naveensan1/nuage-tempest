# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.
#

from tempest import config
from tempest import test
from tempest.lib import exceptions

from nuagetempest.lib.test import nuage_test

import base_nuage_domain_tunnel_type

CONF = config.CONF


class NuageDomainTunnelTypeNegativeTest(base_nuage_domain_tunnel_type.NuageDomainTunnelTypeBase):
    """
    Negative tests for the per Domain Tunnel Type based on the neutron REST API.

    """

    @classmethod
    def resource_setup(cls):
        super(NuageDomainTunnelTypeNegativeTest, cls).resource_setup()

    def _do_test_invalid_value(self, invalid_value):
        self.assertRaisesRegexp(exceptions.BadRequest,
                                "Invalid input for tunnel_type. Reason: '%s' is not in" % invalid_value,
                                self._do_create_router_with_domain_tunnel_type, invalid_value)

    def _do_test_no_value(self, invalid_value):
        self.assertRaisesRegexp(exceptions.BadRequest,
                                "Invalid input for tunnel_type. Reason: 'None' is not in "
                                "\['VXLAN', 'vxlan', 'GRE', 'gre', 'DEFAULT', 'default'\].",
                                self._do_create_router_with_domain_tunnel_type, invalid_value)

    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_create_with_invalid_value(self):
        self._do_test_invalid_value("BAD CHOICE")

    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_create_with_no_value(self):
        self._do_test_no_value("")

    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_create_with_leading_or_trailing_spaces(self):
        self._do_test_invalid_value(" GRE ")

    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_create_with_invalid_attribute(self):
        self.assertRaisesRegexp(exceptions.BadRequest,
                                "Unrecognized attribute",
                                self._create_router,
                                tunnnnnel_type="GRE")

    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_create_with_camel_cased_attribute(self):
        self.assertRaisesRegexp(exceptions.BadRequest,
                                "Unrecognized attribute",
                                self._create_router,
                                tunnelType="GRE")

    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_create_with_mixed_case_attribute(self):
        self.assertRaisesRegexp(exceptions.BadRequest,
                                "Unrecognized attribute",
                                self._create_router,
                                Tunnel_Type="GRE")
