# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.
#

from tempest import config
from tempest import test
from tempest.lib import exceptions as lib_exc

from nuagetempest.lib.utils import constants
from nuagetempest.lib.test import nuage_test

import base_nuage_bidirectional_fip_rate_limit

CONF = config.CONF


MSG_INVALID_INPUT_IN = "'nuage_ingress_fip_rate_kbps' should be a number higher than 0, -1 for unlimited or 'default' for the configured default value."
MSG_INVALID_INPUT_EG = "'nuage_egress_fip_rate_kbps' should be a number higher than 0, -1 for unlimited or 'default' for the configured default value."
MSG_INVALID_INPUT2 = "Nuage API: Error in REST call to VSD: fipPir\(NaN\) must be a valid Integer greater than zero or set to INFINITY"


MSG_INVALID_INPUT_FOR_OPERATION = "Invalid input for operation: " + \
                                  "'nuage_fip_rate' should be a number higher than 0, -1 for unlimited " + \
                                  "or 'default' for the configured default value.."


class TestNuageBidiFipRateLimitBaseCreateNegative(base_nuage_bidirectional_fip_rate_limit.NuageBidirectionalFipRateLimitBase):
    """
    Negative tests for the per FIP rate limiting based on the neutron REST API.

    Creation of the FIP with rate limiting

    """

    @classmethod
    def resource_setup(cls):
        super(TestNuageBidiFipRateLimitBaseCreateNegative, cls).resource_setup()
        cls.port = cls.ports[0]

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_below_min_value(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_IN,
                                self._create_fip_with_fip_rate_limit, self.port, ingress_rate_limit=-2, egress_rate_limit=-2)

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_invalid_value(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_IN,
                                self._create_fip_with_fip_rate_limit, self.port, 'NaN', 'NaN')

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_no_value(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_IN,
                                self._create_fip_with_fip_rate_limit, self.port, '', '')


    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_below_min_value_ingress(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_IN,
                                self._create_fip_with_fip_rate_limit, self.port, ingress_rate_limit=-2)

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_invalid_value_ingress(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_IN,
                                self._create_fip_with_fip_rate_limit, self.port, ingress_rate_limit='NaN')

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_no_value_ingress(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_IN,
                                self._create_fip_with_fip_rate_limit, self.port, ingress_rate_limit='')
        
    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_below_min_value_egress(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_EG,
                                self._create_fip_with_fip_rate_limit, self.port, egress_rate_limit=-2)

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_invalid_value_egress(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_EG,
                                self._create_fip_with_fip_rate_limit, self.port, egress_rate_limit='NaN')

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_no_value_egress(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_EG,
                                self._create_fip_with_fip_rate_limit, self.port, egress_rate_limit='')

class TestNuageBidiFipRateLimitBaseUpdateNegative(base_nuage_bidirectional_fip_rate_limit.NuageBidirectionalFipRateLimitBase):
    """
    Negative tests for the per FIP rate limiting based on the neutron REST API.

    Update of the FIP with rate limiting

    """

    @classmethod
    def resource_setup(cls):
        super(TestNuageBidiFipRateLimitBaseUpdateNegative, cls).resource_setup()
        cls.port = cls.ports[1]
        cls.fip = cls._create_fip_for_port_with_rate_limit(cls.port['id'], ingress_rate_limit=456, egress_rate_limit=456)

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_below_min_value(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_IN,
                                self._update_fip_with_fip_rate_limit, self.port, self.fip, ingress_rate_limit=-2, egress_rate_limit=-2)

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_invalid_value(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_IN,
                                self._update_fip_with_fip_rate_limit, self.port, self.fip, 'NaN', 'NaN')

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_no_value(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_IN,
                                self._update_fip_with_fip_rate_limit, self.port, self.fip, '', '')

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_below_min_value_ingress(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_IN,
                                self._update_fip_with_fip_rate_limit, self.port, self.fip, ingress_rate_limit=-2)

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_invalid_value_ingress(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_IN,
                                self._update_fip_with_fip_rate_limit, self.port, self.fip, ingress_rate_limit='NaN')

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_no_value_ingress(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_IN,
                                self._update_fip_with_fip_rate_limit, self.port, self.fip, ingress_rate_limit='')
    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_below_min_value_egress(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_EG,
                                self._update_fip_with_fip_rate_limit, self.port, self.fip, egress_rate_limit=-2)

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_invalid_value_egress(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_EG,
                                self._update_fip_with_fip_rate_limit, self.port, self.fip, egress_rate_limit='NaN')

    @nuage_test.header()
    @test.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_no_value_egress(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                MSG_INVALID_INPUT_EG,
                                self._update_fip_with_fip_rate_limit, self.port, self.fip, egress_rate_limit='')

class TestNuageBidiFRLBaseAssociationNegative(base_nuage_bidirectional_fip_rate_limit.NuageBidirectionalFipRateLimitBase):

    """
    Negative tests for the per FIP rate limiting based on the neutron REST API.

    Create/Update of the FIP with rate limiting without port association

    """

    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_fail_to_create_floatingip_with_rate_limit_wo_port_association(self):
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                "Rate limiting requires the floating ip to be associated to a port.",
                                self.floating_ips_client.create_floatingip,
                                floating_network_id=self.ext_net_id,
                                nuage_ingress_fip_rate_kbps=321)

    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_fail_to_update_floatingip_with_rate_limit_without_port_association(self):
        fip2 = self._do_create_fip_for_port_with_rate_limit(self.ports[1]['id'], 456)

        # Disassociate the port
        self.floating_ips_client.update_floatingip(fip2['id'], port_id=None)
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                "Bad floatingip request: " +
                                "Rate limiting requires the floating ip to be associated to a port.",
                                self.floating_ips_client.update_floatingip,
                                fip2['id'],
                                nuage_ingress_fip_rate_kbps=321)

    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_fail_to_update_floatingip_with_rate_limit_and_port_disassociation(self):
        fip2 = self._do_create_fip_for_port_with_rate_limit(self.ports[1]['id'], 456)
        self.assertRaisesRegexp(lib_exc.BadRequest,
                                "Bad floatingip request: " +
                                "Rate limiting requires the floating ip to be associated to a port.",
                                self.floating_ips_client.update_floatingip,
                                fip2['id'],
                                port_id=None,
                                nuage_ingress_fip_rate_kbps=321)