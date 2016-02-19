# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from tempest.api.network import base
from tempest import config
from tempest import test
from tempest_lib.common.utils import data_utils
from oslo_log import log as logging
from nuagetempest.lib import service_mgmt
from nuagetempest.lib.utils import constants
from nuagetempest.lib.test import nuage_test
import services.nuage_client as nuage_client

CONF = config.CONF


class TestNuageFipRateLimitConfigurationBase(base.BaseNetworkTest):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(TestNuageFipRateLimitConfigurationBase, cls).setup_clients()
        cls.nuage_vsd_client = nuage_client.NuageRestClient()

        cls.service_manager = service_mgmt.ServiceManager()

        if not cls.service_manager.is_service_running(constants.NEUTRON_SERVICE):
            cls.service_manager.set_configuration_attribute(
                CONF.nuage_sut.nuage_plugin_configuration,
                constants.FIP_RATE_GROUP,
                constants.FIP_RATE_DEFAULT,
                str(-1))
            cls.service_manager.start_service(constants.NEUTRON_SERVICE)
            cls.service_manager.wait_for_service_status(constants.NEUTRON_SERVICE)

    @classmethod
    def skip_checks(cls):
        super(TestNuageFipRateLimitConfigurationBase, cls).skip_checks()
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
        super(TestNuageFipRateLimitConfigurationBase, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id

    @classmethod
    def resource_cleanup(cls):
        if not cls.service_manager.is_service_running(constants.NEUTRON_SERVICE):
            cls.service_manager.set_configuration_attribute(
                CONF.nuage_sut.nuage_plugin_configuration,
                constants.FIP_RATE_GROUP,
                constants.FIP_RATE_DEFAULT,
                str(-1))
            cls.service_manager.start_service(constants.NEUTRON_SERVICE)
            cls.service_manager.wait_for_service_status(constants.NEUTRON_SERVICE)

        super(TestNuageFipRateLimitConfigurationBase, cls).resource_cleanup()

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


class TestNuageFipRateLimitConfigurationJSON(TestNuageFipRateLimitConfigurationBase):
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
        super(TestNuageFipRateLimitConfigurationJSON, cls).resource_setup()

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

    def _verify_fip_openstack(self, created_floating_ip, default_rate_limit):
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

        self.LOG.info("FIP Rate limit %s", created_floating_ip['nuage_fip_rate'])

        self.assertEqual(created_floating_ip['nuage_fip_rate'], default_rate_limit)

    def _verify_fip_vsd(self, created_floating_ip, default_rate_limit):
        # verifying on Domain level that the floating ip is added
        external_id = self.nuage_vsd_client.get_vsd_external_id(created_floating_ip['router_id'])

        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID',
            filter_value=external_id)
        nuage_domain_fip = self.nuage_vsd_client.get_floatingip(
            constants.DOMAIN, nuage_domain[0]['ID'])

        # The VSD FIP has same IP address than OpenStack FIP
        self.assertEqual(
            nuage_domain_fip[0]['address'],
            created_floating_ip['floating_ip_address'])

        # The VSD externalID for FIP matches the OpenStack ID
        external_id = self.nuage_vsd_client.get_vsd_external_id(created_floating_ip['id'])
        self.assertEqual(
            nuage_domain_fip[0]['externalID'],
            external_id)

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

        self.LOG.info("FIP Rate limit %s", qos[0]['FIPPeakInformationRate'])
        self.assertEqual(str(default_rate_limit), qos[0]['FIPPeakInformationRate'])

    def _create_fip_with_default_fip_rate_limit(self, default_fip_rate):
        self.must_have_configuration_attribute(
            CONF.nuage_sut.nuage_plugin_configuration,
            constants.FIP_RATE_GROUP, constants.FIP_RATE_DEFAULT, str(default_fip_rate))

        # When I create a fip with default rate limit
        created_floating_ip = self._do_create_fip_with_default_rate_limit()

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(created_floating_ip, default_fip_rate)

        # Then I got a valid VSD FIP with the default rate limit
        if default_fip_rate == -1:
            vsd_fip_rate = "INFINITY"
        else:
            vsd_fip_rate = str(default_fip_rate)

        self._verify_fip_vsd(created_floating_ip, vsd_fip_rate)

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
            constants.FIP_RATE_GROUP, constants.FIP_RATE_DEFAULT, None)

        # When I create a fip with default rate limit
        created_floating_ip = self._do_create_fip_with_default_rate_limit()

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(created_floating_ip, -1)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(created_floating_ip, "INFINITY")

    @nuage_test.header()
    def test_create_fip_with_default_rate_limit_normal_value(self):
        self._create_fip_with_default_fip_rate_limit(123)

    @nuage_test.header()
    def test_create_fip_with_default_rate_limit_infinite_value(self):
        self._create_fip_with_default_fip_rate_limit(-1)

    @nuage_test.header()
    def test_create_fip_with_default_rate_limit_min_value(self):
        self._create_fip_with_default_fip_rate_limit(0)

    @nuage_test.header()
    def test_create_fip_with_default_rate_limit_max_value(self):
        self._create_fip_with_default_fip_rate_limit(2147483647)

    @nuage_test.header()
    def test_create_update_fip_rate_limit_with_keyword_default(self):
        default_fip_rate = 123
        self.must_have_configuration_attribute(
            CONF.nuage_sut.nuage_plugin_configuration,
            constants.FIP_RATE_GROUP, constants.FIP_RATE_DEFAULT, str(default_fip_rate))

        # create using 'default' keyword
        ################################

        # When I try to create a floating IP
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[0]['id'],
            nuage_fip_rate='default')

        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(created_floating_ip, default_fip_rate)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(created_floating_ip, default_fip_rate)

        # Update to non-default value
        ################################
        rate_limit = 321
        body = self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            nuage_fip_rate=rate_limit)

        updated_floating_ip = body['floatingip']

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(updated_floating_ip, rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(updated_floating_ip, rate_limit)

        # Update using keyword 'default'
        ################################
        body = self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            nuage_fip_rate='default')

        updated_floating_ip = body['floatingip']

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(updated_floating_ip, default_fip_rate)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(updated_floating_ip, default_fip_rate)

