# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from netaddr import IPNetwork

from tempest import config
from tempest import test
from tempest.lib.common.utils import data_utils
from oslo_log import log as logging
import base_nuage_pat_underlay
from nuagetempest.lib.remote_cli import remote_cli_base_testcase
from nuagetempest.lib.test import nuage_test
from tempest.lib import exceptions

CONF = config.CONF


class TestNuagePatUnderlayCLI(remote_cli_base_testcase.RemoteCliBaseTestCase,
                              base_nuage_pat_underlay.NuagePatUnderlayBase):
    LOG = logging.getLogger(__name__)

    @classmethod
    def resource_setup(cls):
        super(TestNuagePatUnderlayCLI, cls).resource_setup()
        nuage_pat = cls.read_nuage_pat_value_ini()
        if nuage_pat == '':
            nuage_pat = None
        cls.nuage_pat_ini = nuage_pat

    @nuage_test.header()
    def test_cli_create_router_without_external_gateway(self):
        self._as_admin()
        self._cli_create_router_without_external_gateway_neg()

    @nuage_test.header()
    def test_cli_create_router_with_external_gateway_without_snat(self):
        self._as_admin()
        self._cli_create_router_with_external_gateway_without_snat()

    @nuage_test.header()
    def test_cli_create_router_without_external_gateway_with_snat_neg(self):
        self._as_admin()
        self._cli_create_router_without_external_gateway_with_snat_neg()

    @nuage_test.header()
    def test_cli_create_router_with_external_gateway_with_snat(self):
        self._as_admin()
        self._verify_create_router_with_external_gateway_with_snat()

    @nuage_test.header()
    def test_cli_update_router_with_external_gateway_with_snat(self):
        self._as_admin()
        self._cli_update_router_with_external_gateway_with_snat()

    @nuage_test.header()
    def test_cli_show_router_without_eternal_gateway(self):
        self._as_admin()
        self._cli_show_router_without_external_gw()

    @nuage_test.header()
    def test_cli_show_router_with_external_gateway_with_snat(self):
        self._as_admin()
        self._cli_show_router_with_external_gw_with_snat()

    @nuage_test.header()
    def test_cli_list_router_with_external_gateway_with_snat(self):
        self._as_admin()
        self._cli_list_router_with_gateway_with_snat()

    @nuage_test.header()
    def test_cli_list_router_without_external_gateway(self):
        self._as_admin()
        self._cli_list_router_without_gateway()

    @nuage_test.header()
    def test_cli_add_os_subnet_to_existing_external_gateway_with_snat(self):
        self._as_admin()
        self._cli_add_subnet_to_existing_external_gateway_with_snat()

    @nuage_test.header()
    def test_cli_create_router_with_snat_invalid_value_neg(self):
        """
        Create router with external gateway with invalid values for 'enable_snat'

        Must fail
        """
        # Create a router enabling snat attributes
        self._as_admin()
        enable_snat_states = ['Ttrue', 'Treu', 'Tru', 'Truet', 'Trrue', 'Truue', 'Truee', '=True',
                              'Flase', 'Falsche', 'Fales', 'Flaes', 'FFalse', 'fFalse', '=False']
        name = data_utils.rand_name('router-with-snat-invalid-fail')
        self.network = self.create_network_with_args(name, ' --router:external')
        for enable_snat in enable_snat_states:
            external_gateway_info_cli = '--external_gateway_info type=dict network_id=' + \
                                        self.network['id'] + ',enable_snat=' + str(enable_snat)
            exp_message = "Invalid input for operation: '" + enable_snat + "' cannot be converted to boolean."
            self.LOG.info("exp_message = " + exp_message)
            self.assertRaisesRegexp(exceptions.SSHExecCommandFailed,
                                    exp_message,
                                    self.create_router_with_args, name, external_gateway_info_cli)

        #     @nuage_test.header()
        #     def test_create_router_with_snat_invalid_syntax_neg(self):
        #         """
        #         Create router with external gateway with invalid syntax for 'enable_snat'
        #
        #         Must fail
        #         """
        #         self._as_admin()
        #         name = data_utils.rand_name('snat-router-invalid-syntax')
        #         enable_snat_typos = ['enabel_snat', 'enablesnat', 'enable-snat', 'Enable_Snat', 'enable_sant',
        #                              'eeeennnnnaaaabahajhjakjakfjhadkfjhadkjfhadkjfhakdfhakdjfhakdjfhkadjk']
        #         self.network = self.create_network_with_args(name, ' --router:external')
        #         for enable_snat in enable_snat_typos:
        #             external_gateway_info_cli = '--external_gateway_info type=dict network_id=' + \
        #                                         self.network['id'] + ',' + enable_snat + '=True'
        #             exp_message = \
        #                   "Invalid input for external_gateway_info. Reason: Validation of dictionary's keys failed. \
        #                           Expected keys: set(['network_id']) Provided keys: set([u'" + \
        #                           enable_snat + "', u'network_id'])."
        #             self.LOG.info("exp_message = " + exp_message)
        #             self.assertRaisesRegexp(exceptions.SSHExecCommandFailed,
        #                                     exp_message,
        #                                     self.create_router_with_args, name, external_gateway_info_cli)
        #         pass

    @test.requires_ext(extension='ext-gw-mode', service='network')
    @test.attr(type='smoke')
    @nuage_test.header()
    def test_cli_create_router_with_gateway_with_non_existing_ext_network_neg(self):
        """
        Try to create router with external gateway with a non-existing external network uuid

        Must fail
        """
        self._as_admin()
        name = data_utils.rand_name('router-with-external-gateway-non-existing-network')

        # reverse the existing external network id, unlikely that this exists ;-)
        bad_network_id = "11111111-1111-1111-1111-11111111"
        external_gateway_info_cli = '--external_gateway_info type=dict network_id=' + \
                                    bad_network_id + ',enable_snat=True'
        exp_message = "Invalid input for external_gateway_info. Reason: '" + bad_network_id + "' is not a valid UUID."
        self.LOG.info("exp_message = " + exp_message)
        self.assertRaisesRegexp(exceptions.SSHExecCommandFailed,
                                exp_message,
                                self.create_router_with_args, name, external_gateway_info_cli)

    @test.requires_ext(extension='ext-gw-mode', service='network')
    @test.attr(type='smoke')
    @nuage_test.header()
    def test_cli_create_router_with_external_gateway_with_vsd_managed_subnet_neg(self):
        """
        Create router with external gateway, using a VSD managed subnet

        Should fail, as PAT is only for OS managed networks
        """
        self._as_admin()
        name = data_utils.rand_name('vsd-l2domain-')
        cidr = IPNetwork('10.10.99.0/24')
        params = {
            'DHCPManaged': True,
            'address': str(cidr.ip),
            'netmask': str(cidr.netmask),
            'gateway': '10.10.99.1'
        }
        # Create VSD managed subnet
        vsd_l2dom_template = self.nuage_vsd_client.create_l2domaintemplate(
            name=name + '-template',
            extra_params=params)
        template_id = vsd_l2dom_template[0]['ID']
        vsd_l2domain = self.nuage_vsd_client.create_l2domain(name=name,
                                                             templateId=template_id)
        self.assertEqual(vsd_l2domain[0][u'name'], name)
        # Try to create subnet on OS with nuagenet param set to l2domain UUID
        # Must fails with message = exp+message
        network_name = data_utils.rand_name('ext-pat-network')
        self.network = self.create_network_with_args(network_name, ' --router:external')
        exp_message = "Bad request: VSD-Managed Subnet create not allowed on external network"
        self.LOG.info("exp_message = " + exp_message)
        self.assertRaisesRegexp(exceptions.SSHExecCommandFailed,
                                exp_message,
                                self.create_subnet_with_args,
                                self.network['name'],
                                str(cidr.cidr),
                                '--name subnet-VSD-managed '
                                '--net-partition', CONF.nuage.nuage_default_netpartition,
                                '--nuagenet', vsd_l2domain[0][u'ID'])
        # Delete the VSD manged subnet
        self.nuage_vsd_client.delete_l2domain(vsd_l2domain[0]['ID'])
        self.nuage_vsd_client.delete_l2domaintemplate(vsd_l2dom_template[0]['ID'])

    @nuage_test.header()
    def test_cli_create_router_with_internal_network_neg(self):
        """
        Try to create a router with external_gateway_info and enable_snat, using an internal network

        Must fails, as an external network is required
        """
        self._as_admin()
        self.network = self.create_network()
        name = "pat-router-with-internal-network-neg"
        external_gateway_info_cli = '--external_gateway_info type=dict network_id=' + \
                                    self.network['id'] + ',enable_snat=True'
        exp_message = "Bad router request: Network " + self.network['id'] + " is not an external network"
        print "exp_message = " + exp_message
        self.LOG.info("exp_message = " + exp_message)
        self.assertRaisesRegexp(exceptions.SSHExecCommandFailed,
                                exp_message,
                                self.create_router_with_args, name, external_gateway_info_cli)

    # Needs adaptations in the json file
    # @nuage_test.header()
    # def test_cli_list_routers_other_tenants_neg(self):
    #     """
    #     Try to list routers from another tenant
    #
    #     May not succeed
    #     """
    #     # Create router as admin from admin tenant
    #     self._as_admin()
    #     network_name = data_utils.rand_name('ext-pat-network-admin')
    #     router_name = data_utils.rand_name('ext-pat-router-admin')
    #     self.network = self.create_network_with_args(network_name, ' --router:external')
    #     external_gateway_info_cli = '--external_gateway_info type=dict network_id=' + \
    #                                 self.network['id'] + ',enable_snat=True'
    #     router_admin = self.create_router_with_args(router_name,
    #                                                 external_gateway_info_cli)
    #     self._as_tenant()
    #     # Create a router as tenant ro have at least one router in the list
    #     # router_name = data_utils.rand_name('ext-pat-router-tenant')
    #     # router_tenant = self.create_router(router_name)
    #     router_list = self.parser.listing(self.list_routers())
    #     for router in router_list:
    #         router_admin_id = router_admin['id']
    #         tenant_router_id = router['id']
    #         # id of the admin router may not be in our list
    #         self.assertNotEqual(router_admin_id, tenant_router_id,
    #                             "Non-admin tenant can see other admin tenants in router-list")
    #     pass

    @nuage_test.header()
    def test_cli_add_subnet_to_existing_pat_router(self):
        """
        Add a subnet to an existing external router with snat enabled

        Must succeed
        """
        self._as_admin()
        cidr = IPNetwork('10.10.100.0/24')
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            network_name = data_utils.rand_name('ext-pat-network-admin')
            router_name = data_utils.rand_name('ext-pat-router-admin')
            self.network = self.create_network_with_args(network_name, ' --router:external')
            external_gateway_info_cli = '--external_gateway_info type=dict network_id=' + \
                                        self.network['id'] + ',enable_snat=' + str(enable_snat)
            router = self.create_router_with_args(router_name,
                                                  external_gateway_info_cli)
            compare_snat_str = '"enable_snat": ' + str(enable_snat)
            self.assertIn(compare_snat_str.lower(), router['external_gateway_info'])
            # Now create a subnet and add it to the external network
            subnet_name = data_utils.rand_name("os-subnet")
            self.subnet = self.create_subnet_with_args(self.network['id'],
                                                       str(cidr.cidr),
                                                       '--name ', subnet_name)
            show_router = self.show_router(router['id'])
            self.assertIn(compare_snat_str.lower(), show_router['external_gateway_info'])
            cidr = cidr.next(1)
        pass

    @nuage_test.header()
    def test_cli_non_admin_add_os_subnet_to_existing_gw_other_tenant(self):
        self._cli_add_subnet_to_other_tenant_existing_external_gateway_with_snat()

    @nuage_test.header()
    def test_cli_create_router_with_external_gateway(self):
        self._cli_tenant_create_router_with_external_gateway()

