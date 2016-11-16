# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from tempest.api.network import base
from tempest import config
from tempest import test
from tempest.lib.common.utils import data_utils
from oslo_log import log as logging
from nuagetempest.lib import service_mgmt
from nuagetempest.lib.utils import constants
from nuagetempest.lib.test import nuage_test
from nuagetempest.services import nuage_client

CONF = config.CONF


class TestNuageBidiFRLConfigurationBase(base.BaseNetworkTest):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(TestNuageBidiFRLConfigurationBase, cls).setup_clients()
        cls.nuage_vsd_client = nuage_client.NuageRestClient()

        cls.service_manager = service_mgmt.ServiceManager()

        if not cls.service_manager.is_service_running(constants.NEUTRON_SERVICE):
            cls.service_manager.set_configuration_attribute(
                CONF.nuage_sut.nuage_plugin_configuration,
                constants.FIP_RATE_GROUP,
                constants.BIDIRECTIONAL_FIP_RATE_DEFAULT_INGRESS,
                str(-1))
            cls.service_manager.set_configuration_attribute(
                CONF.nuage_sut.nuage_plugin_configuration,
                constants.FIP_RATE_GROUP,
                constants.BIDIRECTIONAL_FIP_RATE_DEFAULT_EGRESS,
                str(-1))
            cls.service_manager.start_service(constants.NEUTRON_SERVICE)
            cls.service_manager.wait_for_service_status(constants.NEUTRON_SERVICE)

    @classmethod
    def skip_checks(cls):
        super(TestNuageBidiFRLConfigurationBase, cls).skip_checks()
        if not test.is_extension_enabled('router', 'network'):
            msg = "router extension not enabled."
            raise cls.skipException(msg)

        if not test.is_extension_enabled('nuage-floatingip', 'network'):
            msg = "Extension nuage_floatingip not enabled."
            raise cls.skipException(msg)

        if not CONF.service_available.neutron:
            msg = "Skipping all Neutron cli tests because it is not available"
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TestNuageBidiFRLConfigurationBase, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id

    @classmethod
    def resource_cleanup(cls):
        if not cls.service_manager.is_service_running(constants.NEUTRON_SERVICE):
            cls.service_manager.set_configuration_attribute(
                CONF.nuage_sut.nuage_plugin_configuration,
                constants.FIP_RATE_GROUP,
                constants.BIDIRECTIONAL_FIP_RATE_DEFAULT_INGRESS,
                str(-1))
            cls.service_manager.set_configuration_attribute(
                CONF.nuage_sut.nuage_plugin_configuration,
                constants.FIP_RATE_GROUP,
                constants.BIDIRECTIONAL_FIP_RATE_DEFAULT_EGRESS,
                str(-1))
            cls.service_manager.start_service(constants.NEUTRON_SERVICE)
            cls.service_manager.wait_for_service_status(constants.NEUTRON_SERVICE)

        super(TestNuageBidiFRLConfigurationBase, cls).resource_cleanup()

    def must_have_configuration_attribute(self, config_file, config_group, config_key, value):
        original_value = self.service_manager.get_configuration_attribute(config_file, config_group, config_key)

        if original_value != value:
            self.service_manager.stop_service(constants.NEUTRON_SERVICE)
            if value is None:
                self.service_manager.comment_configuration_attribute(config_file, config_group, config_key)
            else:
                self.service_manager.set_configuration_attribute(config_file, config_group, config_key, value)

            self.service_manager.start_service(constants.NEUTRON_SERVICE)
            self.service_manager.wait_for_service_status(constants.NEUTRON_SERVICE)


class TestNuageBidiFRLConfigurationJSON(TestNuageBidiFRLConfigurationBase):
    _interface = 'json'

    """
    Tests the following operations in the Neutron API using the REST client for
    Neutron:

    v2.0 of the Neutron API is assumed. It is also assumed that the following
    options are defined in the [network] section of etc/tempest.conf:

        public_network_id which is the id for the external network present
    """

    LOG = logging.getLogger(__name__)

    @classmethod
    def resource_setup(cls):
        super(TestNuageBidiFRLConfigurationJSON, cls).resource_setup()

        # Create network, subnet, router and add interface
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(data_utils.rand_name('router-'),
                                       external_network_id=cls.ext_net_id)

        cls.create_router_interface(cls.router['id'], cls.subnet['id'])

        # Create two ports one each for Creation and Updating of floatingIP
        for i in range(2):
            cls.create_port(cls.network)

            # os = cls.get_client_manager()
            # cls.nuage_vsd_client = os.nuage_vsd_client

    def _do_create_fip_with_default_rate_limit(self):
        # When I try to create a floating IP
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[0]['id'])

        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        return created_floating_ip

    def _do_get_floating_ip(self, floating_ip_id):
        body = self.floating_ips_client.show_floatingip(
            floating_ip_id)

        floating_ip = body['floatingip']
        return floating_ip
    
    def _convert_mbps_to_kbps(self, value):
        return float(value) * 1000

    def _verify_fip_openstack(self, created_floating_ip, ingress_rate_limit=None, egress_rate_limit=None, backward=False):
        # Then it should be created
        # for the admin tenant id
        self.assertIsNotNone(created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['tenant_id'])
        self.assertIsNotNone(created_floating_ip['floating_ip_address'])
        self.assertEqual(created_floating_ip['port_id'], self.ports[0]['id'])
        self.assertEqual(created_floating_ip['floating_network_id'],
                         self.ext_net_id)
        self.assertIn(created_floating_ip['fixed_ip_address'],
                      [ip['ip_address'] for ip in self.ports[0]['fixed_ips']])
        self.LOG.info("Ingress FIP Rate limit %s", created_floating_ip['nuage_ingress_fip_rate_kbps'])
        self.LOG.info("Egress FIP Rate limit %s", created_floating_ip['nuage_egress_fip_rate_kbps'])
        if ingress_rate_limit is not None:
            self.assertEqual(float(created_floating_ip['nuage_ingress_fip_rate_kbps']), float(ingress_rate_limit))
        if egress_rate_limit is not None and backward is False:
            self.assertEqual(float(created_floating_ip['nuage_egress_fip_rate_kbps']), float(egress_rate_limit))
        else:
            self.assertEqual(float(created_floating_ip['nuage_egress_fip_rate_kbps']), float(egress_rate_limit*1000))

    def _verify_fip_vsd(self, created_floating_ip, ingress_rate_limit=None, egress_rate_limit=None, backward=False):
        # verifying on Domain level that the floating ip is added
        external_id = self.nuage_vsd_client.get_vsd_external_id(created_floating_ip['router_id'])
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID',
            filter_value=external_id)
        nuage_domain_fip = self.nuage_vsd_client.get_floatingip(
            constants.DOMAIN, nuage_domain[0]['ID'])

        # The VSD FIP has same IP address than OpenStack FIP
        self.assertIn(created_floating_ip['floating_ip_address'],
                      [nuage_fip['address'] for nuage_fip in nuage_domain_fip])

        # The VSD externalID for FIP matches the OpenStack ID
        external_id = self.nuage_vsd_client.get_vsd_external_id(created_floating_ip['id'])
        self.assertIn(external_id,
                      [nuage_fip['externalID'] for nuage_fip in nuage_domain_fip])

        # Check vsd
        vsd_subnets = self.nuage_vsd_client.get_domain_subnet(None, None,
                                                              'externalID',
                                                              self.nuage_vsd_client.get_vsd_external_id(
                                                                  self.subnet['id']))
        self.assertEqual(1, len(vsd_subnets))
        vports = self.nuage_vsd_client.get_vport(constants.SUBNETWORK,
                                                 vsd_subnets[0]['ID'],
                                                 'externalID',
                                                 self.nuage_vsd_client.get_vsd_external_id(self.ports[0]['id']))
        self.assertEqual(1, len(vports))
        qos = self.nuage_vsd_client.get_qos(constants.VPORT, vports[0]['ID'])
        self.assertEqual(1, len(qos))
        self.assertEqual(True, qos[0]['FIPRateLimitingActive'])

        self.LOG.info("OpenStack Egress FIP Rate limit %s", qos[0]['FIPPeakInformationRate'])
        self.LOG.info("OpenStack Ingress FIP Rate limit %s", qos[0]['EgressFIPPeakInformationRate'])
        if ingress_rate_limit is not None:
            self.assertEqual(float(ingress_rate_limit), self._convert_mbps_to_kbps(qos[0]['EgressFIPPeakInformationRate']))
        if egress_rate_limit is not None and backward is False:
            self.assertEqual(float(egress_rate_limit), self._convert_mbps_to_kbps(qos[0]['FIPPeakInformationRate']))
        else:
            self.assertEqual(float(egress_rate_limit), float(qos[0]['FIPPeakInformationRate']))

        self.assertEqual(self.nuage_vsd_client.get_vsd_external_id(created_floating_ip['id']), qos[0]['externalID'])

    def _create_fip_with_default_fip_rate_limit(self, ingress_default_rate_limit=None, egress_default_rate_limit=None, default_fip_rate=None):
        if egress_default_rate_limit:
            self.must_have_configuration_attribute(
                CONF.nuage_sut.nuage_plugin_configuration,
                constants.FIP_RATE_GROUP, constants.BIDIRECTIONAL_FIP_RATE_DEFAULT_EGRESS, str(egress_default_rate_limit))
        if ingress_default_rate_limit:
            self.must_have_configuration_attribute(
                CONF.nuage_sut.nuage_plugin_configuration,
                constants.FIP_RATE_GROUP, constants.BIDIRECTIONAL_FIP_RATE_DEFAULT_INGRESS, str(ingress_default_rate_limit))
        if default_fip_rate:
            self.must_have_configuration_attribute(
                CONF.nuage_sut.nuage_plugin_configuration,
                constants.FIP_RATE_GROUP, constants.FIP_RATE_DEFAULT, str(default_fip_rate))
        if egress_default_rate_limit is None:
            self.must_have_configuration_attribute(
                CONF.nuage_sut.nuage_plugin_configuration,
                constants.FIP_RATE_GROUP, constants.BIDIRECTIONAL_FIP_RATE_DEFAULT_EGRESS, None)
        # When I create a fip with default rate limit
        created_floating_ip = self._do_create_fip_with_default_rate_limit()
        show_floating_ip = self._do_get_floating_ip(created_floating_ip['id'])
        # Then I got a valid OpenStack FIP with the default rate limit
        if default_fip_rate and egress_default_rate_limit:
            self._verify_fip_openstack(show_floating_ip, ingress_default_rate_limit, egress_default_rate_limit)
        elif default_fip_rate is None and egress_default_rate_limit:
            self._verify_fip_openstack(show_floating_ip, ingress_default_rate_limit, egress_default_rate_limit)
        else:
            self._verify_fip_openstack(show_floating_ip, ingress_default_rate_limit, default_fip_rate, backward=True)

        # Then I got a valid VSD FIP with the default rate limit
        if ingress_default_rate_limit == -1:
            ingress_vsd_fip_rate = "INFINITY"
        else:
            ingress_vsd_fip_rate = str(ingress_default_rate_limit)
        
        if egress_default_rate_limit == -1:
            egress_vsd_fip_rate = "INFINITY"
        else:
            egress_vsd_fip_rate = str(egress_default_rate_limit)
            
        if default_fip_rate == -1:
            default_vsd_fip_rate = "INFINITY"
        else:
            default_vsd_fip_rate = str(default_fip_rate)

        if default_fip_rate and egress_default_rate_limit:
            self._verify_fip_vsd(created_floating_ip, ingress_vsd_fip_rate, egress_vsd_fip_rate)
        elif default_fip_rate is None and egress_default_rate_limit:
            self._verify_fip_vsd(created_floating_ip, ingress_vsd_fip_rate, egress_vsd_fip_rate)
        else:
            self._verify_fip_vsd(created_floating_ip, ingress_vsd_fip_rate, default_vsd_fip_rate, backward=True)

    @test.attr(type='smoke')
    @nuage_test.header()
    def test_create_fip_with_no_default_rate_limit_in_configuration(self):
        """
        Test configuration parameters in the nuage_plugin.ini for FIP rate limiting

        By default, the nuage_plugin.ini has no setting for default_fip_rate
        On creation of a floating ip, the default nuage_fip_rate = -1 (Infinite).
        """
        self.must_have_configuration_attribute(
            CONF.nuage_sut.nuage_plugin_configuration,
            constants.FIP_RATE_GROUP, constants.BIDIRECTIONAL_FIP_RATE_DEFAULT_EGRESS, None)
        self.must_have_configuration_attribute(
            CONF.nuage_sut.nuage_plugin_configuration,
            constants.FIP_RATE_GROUP, constants.BIDIRECTIONAL_FIP_RATE_DEFAULT_INGRESS, None)
        self.must_have_configuration_attribute(
            CONF.nuage_sut.nuage_plugin_configuration,
            constants.FIP_RATE_GROUP, constants.FIP_RATE_DEFAULT, None)
        # When I create a fip with default rate limit
        created_floating_ip = self._do_create_fip_with_default_rate_limit()
        show_floating_ip = self._do_get_floating_ip(created_floating_ip['id'])
        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(show_floating_ip, -1, -1)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(created_floating_ip, "INFINITY", "INFINITY")

    @nuage_test.header()
    def test_create_fip_with_default_rate_limit_normal_value(self):
        self._create_fip_with_default_fip_rate_limit(123, 123)

    @nuage_test.header()
    def test_create_fip_with_default_rate_limit_infinite_value(self):
        self._create_fip_with_default_fip_rate_limit(-1, -1)

    @nuage_test.header()
    def test_create_fip_with_default_rate_limit_min_value(self):
        self._create_fip_with_default_fip_rate_limit('0', '0')

    @nuage_test.header()
    def test_create_fip_with_default_rate_limit_max_value(self):
        self._create_fip_with_default_fip_rate_limit(2147483647, 2147483647)
        
    @nuage_test.header()
    def test_create_fip_with_default_rate_limit_backward_compatibility_both(self):
        self._create_fip_with_default_fip_rate_limit(123, 123, 5000)

    @nuage_test.header()
    def test_create_fip_with_default_rate_limit_backward_compatibility_old(self):
        self._create_fip_with_default_fip_rate_limit(123, default_fip_rate=5000)

    @nuage_test.header()
    def test_create_update_fip_rate_limit_with_keyword_default(self):
        default_fip_rate = 123
        self.must_have_configuration_attribute(
            CONF.nuage_sut.nuage_plugin_configuration,
            constants.FIP_RATE_GROUP, constants.BIDIRECTIONAL_FIP_RATE_DEFAULT_EGRESS, str(default_fip_rate))
        self.must_have_configuration_attribute(
            CONF.nuage_sut.nuage_plugin_configuration,
            constants.FIP_RATE_GROUP, constants.BIDIRECTIONAL_FIP_RATE_DEFAULT_INGRESS, str(default_fip_rate))

        # create using 'default' keyword
        ################################

        # When I try to create a floating IP
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[0]['id'],
            nuage_ingress_fip_rate_kbps='default',
            nuage_egress_fip_rate_kbps='default')

        created_floating_ip = body['floatingip']
        show_floating_ip = self._do_get_floating_ip(created_floating_ip['id'])
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(show_floating_ip, default_fip_rate, default_fip_rate)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(created_floating_ip, default_fip_rate, default_fip_rate)

        # Update to non-default value
        ################################
        rate_limit = 321
        body = self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            nuage_ingress_fip_rate_kbps=rate_limit,
            nuage_egress_fip_rate_kbps=rate_limit)

        updated_floating_ip = body['floatingip']
        show_floating_ip = self._do_get_floating_ip(created_floating_ip['id'])
        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(show_floating_ip, rate_limit, rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(updated_floating_ip, rate_limit, rate_limit)

        # Update using keyword 'default'
        ################################
        body = self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            nuage_ingress_fip_rate_kbps='default',
            nuage_egress_fip_rate_kbps='default')

        updated_floating_ip = body['floatingip']
        show_floating_ip = self._do_get_floating_ip(created_floating_ip['id'])
        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(show_floating_ip, default_fip_rate, default_fip_rate)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(updated_floating_ip, default_fip_rate, default_fip_rate)

