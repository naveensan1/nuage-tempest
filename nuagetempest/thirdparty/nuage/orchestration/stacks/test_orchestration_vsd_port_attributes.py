# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

import logging

from netaddr import *
from tempest.lib.common.utils import data_utils
from tempest import config
from tempest import test
from nuagetempest.lib.test import nuage_test
import nuage_base
from nuagetempest.thirdparty.nuage.vsd_managed import base_vsd_managed_networks
from nuagetempest.thirdparty.nuage.vsd_managed import base_vsd_managed_port_attributes
from nuagetempest.thirdparty.nuage.vsd_managed.base_vsd_managed_port_attributes import BaseVSDManagedPortAttributes
from nuagetempest.lib.utils import constants
from nuagetempest.services.nuage_network_client import NuageNetworkClientJSON
from nuagetempest.services import nuage_client
from tempest.scenario import manager
from tempest.api.network import base

CONF = config.CONF

LOG = logging.getLogger(__name__)

VSD_HEAT_L2__MGD_CIDR = IPNetwork('22.22.22.0/24')
VALID_MAC_ADDRESS = 'fa:fa:3e:e8:e8:c0'

class HeatVsdManagedPortAttributesTest(base_vsd_managed_port_attributes.BaseVSDManagedPortAttributes,
                                       base_vsd_managed_networks.BaseVSDManagedNetwork,
                                       nuage_base.NuageBaseOrchestrationTest):


    @classmethod
    def setup_clients(cls):
        super(base_vsd_managed_port_attributes.BaseVSDManagedPortAttributes, cls).setup_clients()
        super(base_vsd_managed_networks.BaseVSDManagedNetwork, cls).setup_clients()
        super(nuage_base.NuageBaseOrchestrationTest, cls).setup_clients()
    # #     # cls.base = BaseVSDManagedPortAttributes()
    # #     super(HeatVsdManagedPortAttributesTest, cls).setup_clients()
    # #     # cls.orchestration_client = cls.os_adm.orchestration_client
    # #     # cls.client = cls.orchestration_client
    # #     pass
    # #     super(base_vsd_managed_network.BaseVSDManagedNetworksTest, cls).setup_clients()
    #     cls.nuage_vsd_client = nuage_client.NuageRestClient()
    #     cls.admin_client = cls.os_adm.network_client
    #
    #     cls.nuage_network_client = NuageNetworkClientJSON(
    #         cls.os.auth_provider,
    #         CONF.network.catalog_type,
    #         CONF.network.region or CONF.identity.region,
    #         endpoint_type=CONF.network.endpoint_type,
    #         build_interval=CONF.network.build_interval,
    #         build_timeout=CONF.network.build_timeout,
    #         **cls.os.default_params)
        pass

    @classmethod
    def resource_setup(cls):
        super(nuage_base.NuageBaseOrchestrationTest, cls).resource_setup()
        super(base_vsd_managed_networks.BaseVSDManagedNetwork, cls).resource_setup()
        super(HeatVsdManagedPortAttributesTest, cls).resource_setup()

        if not test.is_extension_enabled('nuage-redirect-target', 'network'):
            msg = "Nuage extension 'nuage-redirect-target' not enabled."
            raise cls.skipException(msg)
        # cls.base = BaseVSDManagedPortAttributes()

        # cls.template = cls.load_template('redirect')
        # cls.stack_name = data_utils.rand_name('redirecttarget')
        # template = cls.read_template('redirect')
        #
        # # create the stack
        # cls.stack_identifier = cls.create_stack(
        #     cls.stack_name,
        #     template)
        # cls.stack_id = cls.stack_identifier.split('/')[1]
        # cls.client.wait_for_stack_status(cls.stack_id, 'CREATE_COMPLETE')
        # resources = (cls.client.list_resources(cls.stack_identifier)['resources'])
        #
        # cls.test_resources = {}
        # for resource in resources:
        #     cls.test_resources[resource['logical_resource_id']] = resource

    # def _local_check_port_in_policy_group(self, port_id, pg_id):
    #     port_found = False
    #     show_pg = self.nuage_network_client.show_nuage_policy_group(pg_id)
    #     for id in show_pg['nuage_policy_group']['ports']:
    #         if id == port_id:
    #             port_found = True
    #             break
    #     return port_found

    def test_heat_vsd_managed_l2_port_attributes(self):
        # Prepare all the stuff whcih can be created only on VSD
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('13.13.100.0/24')

        vsd_l2domain_template = self.create_vsd_dhcp_managed_l2domain_template(
            name=name, cidr=cidr, gateway=str(cidr[1]))
        vsd_l2domain = self.create_vsd_l2domain(name=name,
                                            tid=vsd_l2domain_template[0]['ID'])
        self.assertIsInstance(vsd_l2domain, list)
        self.assertEqual(vsd_l2domain[0][u'name'], name)
        # network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        policy_group = self.vsd_client.create_policygroup(
            constants.L2_DOMAIN,
            vsd_l2domain[0]['ID'],
            name='myHEAT-VSD-pg-1',
            type='SOFTWARE',
            extra_params=None)


        # template = self.load_template('port_attributes')
        stack_name = 'port_attributes'
        port_fixed_ip = str(IPAddress(cidr) + 10)
        aap_fixed_ip = str(IPAddress(port_fixed_ip) + 5)
        aap_mac_address = VALID_MAC_ADDRESS
        # addrpair_port = self.create_port(network, **kwargs)

        stack_parameters = {
            'vsd_L2_subnet_id': vsd_l2domain[0]['ID'],
            'netpartition_name': CONF.nuage.nuage_default_netpartition,
            'l2_net_name': data_utils.rand_name('l2-net'),
            'l2_subnet_name': data_utils.rand_name('l2-subnet'),
            'l2_net_cidr': str(cidr.cidr),
            'policy_group_id': policy_group[0]['ID'],
            'fixed_ip_address': port_fixed_ip,
            'aap_ip_address': aap_fixed_ip,
            'aap_mac_address': aap_mac_address
        }
        self.launch_stack(stack_name, stack_parameters)
        self.client.wait_for_stack_status(self.stack_id, 'CREATE_COMPLETE')
        checkje = base_vsd_managed_port_attributes.OS_CONNECTING_NW_CIDR

        expected_resources = ['l2_port',]
        self.verify_stack_resources(expected_resources, self.template_resources, self.test_resources)

        port_id = self.test_resources['l2_port']['physical_resource_id']
        show_port = self.ports_client.show_port(port_id)
        rt_id = self.test_resources['rt_l2']['physical_resource_id']
        show_rt = self.nuage_network_client.show_redirection_target(rt_id)
        port_present = self._check_port_in_show_redirect_target(show_port['port'], show_rt)

        # port_present = self._local_check_port_in_policy_group(port_id, policy_group[0]['ID'])
        # self.assertTrue(port_present, "Port(%s) assiociated to policy group (%s) is not present" %
        #                 (port_id, policy_group[0]['ID']))
        port_present = self._check_port_in_policy_group(port_id, policy_group[0]['ID'])
        # port_present = base_vsd_managed_port_attributes._check_port_in_policy_group(port_id, policy_group[0]['ID'])
        # self.assertTrue(port_present, "Port(%s) assiociated to policy group (%s) is not present" %
        #                 (port_id, policy_group[0]['ID']))

        pass


    def test_created_redirecttarget_resources(self):
        """Verifies created redirect target resources."""
        resources = [('secgrp', self.template['resources'][
            'secgrp']['type']),
                     ('rt_l2', self.template['resources'][
                         'rt_l2']['type']),
                     ('rtr_l2', self.template[
                         'resources']['rtr_l2']['type']),
                     ('rt_l3', self.template['resources'][
                         'rt_l3']['type']),
                     ('rtr_l3', self.template[
                         'resources']['rtr_l3']['type']),
                     ('vip_l3', self.template['resources'][
                         'vip_l3']['type'])]
        for resource_name, resource_type in resources:
            resource = self.test_resources.get(resource_name, None)
            self.assertIsInstance(resource, dict)
            self.assertEqual(resource_name, resource['logical_resource_id'])
            self.assertEqual(resource_type, resource['resource_type'])
            self.assertEqual('CREATE_COMPLETE', resource['resource_status'])

        @test.attr(type='slow')
        @nuage_test.header()
        def test_link_subnet_to_vsd_l2domain_dhcp_managed_minimal(self):
            """ Test heat creation of a private VSD managed network from dhcp-managed l2 domain template


        OpenStack network is created with minimal attributes.
        """
        # Create the VSD l2 domain from a template
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')

        vsd_l2domain_template = self.create_vsd_dhcp_managed_l2domain_template(
            name=name, cidr=cidr, gateway=str(cidr[1]))
        vsd_l2domain = self.create_vsd_l2domain(name=name,
                                                tid=vsd_l2domain_template[0]['ID'])

        self.assertIsInstance(vsd_l2domain, list)
        self.assertEqual(vsd_l2domain[0][u'name'], name)

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_minimal'
        stack_parameters = {
            'vsd_subnet_id': vsd_l2domain[0]['ID'],
            'netpartition_name': self.net_partition_name,
            'private_net_name': self.private_net_name,
            'private_net_cidr': str(cidr)}
        self.launch_stack(stack_file_name, stack_parameters)

        # Verifies created resources
        expected_resources = ['private_net', 'private_subnet']
        self.verify_stack_resources(expected_resources, self.template_resources, self.test_resources)

        # Test network
        network = self.verify_created_network('private_net')
        subnet = self.verify_created_subnet('private_subnet', network)

        self.assertTrue(subnet['enable_dhcp'], "Shall have DHCP enabled from the l2 domain template")
        self.assertEqual(str(cidr), subnet['cidr'], "Shall get the CIDR from the l2 domain")
        self.assertEqual(str(cidr[1]), subnet['allocation_pools'][0]['start'],
                         "Shall start allocation pool at first address in l2 domain")
        self.assertEqual(str(cidr[-2]), subnet['allocation_pools'][0]['end'],
                         "Shall start allocation pool at last address in l2 domain")
        pass

    @test.attr(type='slow')
    @nuage_test.header()
    def test_link_subnet_to_vsd_l2domain_dhcp_managed(self):
        """ Test heat creation of a private VSD managed network from dhcp-managed l2 domain template

        OpenStack network is created with maximal attributes.
        """
        # TODO: Add all possible attributes (DNS servers,....)

        # Create the VSD l2 domain from a template
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')

        vsd_l2domain_template = self.create_vsd_dhcp_managed_l2domain_template(
            name=name, cidr=cidr, gateway=str(cidr[1]))
        vsd_l2domain = self.create_vsd_l2domain(name=name,
                                                tid=vsd_l2domain_template[0]['ID'])

        self.assertIsInstance(vsd_l2domain, list)
        self.assertEqual(vsd_l2domain[0][u'name'], name)

        # launch a heat stack
        stack_file_name = 'port_attributes'
        stack_parameters = {
            'vsd_subnet_id': vsd_l2domain[0]['ID'],
            'netpartition_name': self.net_partition_name,
            'private_net_name': self.private_net_name,
            'private_net_cidr': str(cidr),
            'private_net_dhcp': True,
            'private_net_pool_start': str(cidr[+1]),
            'private_net_pool_end': str(cidr[-2])}

        # TODO: verify the usage of gateway_ip for vsd-managed networks
        # Nuage client expect gateway_ip=None in case DHCP is true
        # This can not be realized with the command line or REST API
        # 'private_net_gateway': str(cidr[1])

        self.launch_stack(stack_file_name, stack_parameters)

        # Verifies created resources
        expected_resources = ['private_net', 'private_subnet']
        self.verify_stack_resources(expected_resources, self.template_resources, self.test_resources)

        # Test network
        network = self.verify_created_network('private_net')
        subnet = self.verify_created_subnet('private_subnet', network)

        # TODO: to check: there is no gateway IP in the response !!!
        self.assertTrue(subnet['enable_dhcp'], "Shall have DHCP enabled from the l2 domain template")
        self.assertEqual(str(cidr), subnet['cidr'], "Shall get the CIDR from the l2 domain")
        self.assertEqual(str(cidr[1]), subnet['allocation_pools'][0]['start'],
                         "Shall start allocation pool at first address in l2 domain")
        self.assertEqual(str(cidr[-2]), subnet['allocation_pools'][0]['end'],
                         "Shall start allocation pool at last address in l2 domain")

        pass

    @test.attr(type='slow')
    @nuage_test.header()
    def test_link_subnet_to_vsd_l2domain_dhcp_unmanaged(self):
        """ Test heat creation of a private VSD managed network from dhcp-unmanaged l2 domain template
        """
        # Create the VSD l2 domain from a template
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        gateway_ip = str(cidr[1])

        vsd_l2domain_template = self.create_vsd_dhcp_unmanaged_l2domain_template(
            name=name, cidr=cidr, gateway=gateway_ip)
        vsd_l2domain = self.create_vsd_l2domain(name=name,
                                                tid=vsd_l2domain_template[0]['ID'])

        self.assertIsInstance(vsd_l2domain, list)
        self.assertEqual(vsd_l2domain[0][u'name'], name)

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network'
        stack_parameters = {
            'vsd_subnet_id': vsd_l2domain[0]['ID'],
            'netpartition_name': self.net_partition_name,
            'private_net_name': self.private_net_name,
            'private_net_cidr': str(cidr),
            'private_net_dhcp': False,
            'private_net_pool_start': str(cidr[+2]),
            'private_net_pool_end': str(cidr[-2])}
        self.launch_stack(stack_file_name, stack_parameters)

        # Verifies created resources
        expected_resources = ['private_net', 'private_subnet']
        self.verify_stack_resources(expected_resources, self.template_resources, self.test_resources)

        # Test network
        network = self.verify_created_network('private_net')
        subnet = self.verify_created_subnet('private_subnet', network)

        self.assertFalse(subnet['enable_dhcp'], "Shall have DHCP enabled from the l2 domain template")
        self.assertEqual(str(cidr), subnet['cidr'], "Shall get the CIDR from the l2 domain")
        self.assertIsNone(subnet['gateway_ip'], "Shall get null")
        self.assertEqual(str(cidr[2]), subnet['allocation_pools'][0]['start'],
                         "Shall start allocation pool at first address in l2 domain")
        self.assertEqual(str(cidr[-2]), subnet['allocation_pools'][0]['end'],
                         "Shall start allocation pool at last address in l2 domain")
        pass

    @test.attr(type='slow')
    @nuage_test.header()
    def test_link_subnet_to_vsd_l3domain(self):
        """ Test heat creation of a private VSD managed network from l3 domain template
        """
        # Create the VSD l3 domain from a template
        name = data_utils.rand_name('l3domain-')
        cidr = IPNetwork('10.10.100.0/24')
        gateway_ip = str(cidr[1])
        pool_start_ip = str(cidr[+2])
        pool_end_ip = str(cidr[-2])

        vsd_l3domain_template = self.create_vsd_l3domain_template(
            name=name)
        vsd_l3domain = self.create_vsd_l3domain(name=name,
                                                tid=vsd_l3domain_template[0]['ID'])

        self.assertIsInstance(vsd_l3domain, list)
        self.assertEqual(vsd_l3domain[0][u'name'], name)

        zone_name = data_utils.rand_name('l3domain-zone-')
        vsd_zone = self.create_vsd_zone(name=zone_name,
                                        domain_id=vsd_l3domain[0]['ID'])
        self.assertEqual(vsd_zone[0]['name'], zone_name)

        subnet_name = data_utils.rand_name('l3domain-sub-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_domain_subnet = self.create_vsd_l3domain_subnet(
            name=subnet_name,
            zone_id=vsd_zone[0]['ID'],
            cidr=cidr,
            gateway=gateway_ip)
        self.assertEqual(vsd_domain_subnet[0]['name'], subnet_name)

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network'
        stack_parameters = {
            'vsd_subnet_id': vsd_domain_subnet[0]['ID'],
            'netpartition_name': self.net_partition_name,
            'private_net_name': self.private_net_name,
            'private_net_cidr': str(cidr),
            'private_net_dhcp': True,
            'private_net_pool_start': pool_start_ip,
            'private_net_pool_end': pool_end_ip}
        self.launch_stack(stack_file_name, stack_parameters)

        # Verifies created resources
        expected_resources = ['private_net', 'private_subnet']
        self.verify_stack_resources(expected_resources, self.template_resources, self.test_resources)

        # Test network
        network = self.verify_created_network('private_net')
        subnet = self.verify_created_subnet('private_subnet', network)

        self.assertTrue(subnet['enable_dhcp'], "Shall have DHCP enabled from the l2 domain template")
        self.assertEqual(str(cidr), subnet['cidr'], "Shall get the CIDR from the l2 domain")
        self.assertEqual(gateway_ip, subnet['gateway_ip'], "Shall get the gateway IP from the l2 domain")
        self.assertEqual(pool_start_ip, subnet['allocation_pools'][0]['start'],
                         "Shall start allocation pool at first address in l2 domain")
        self.assertEqual(pool_end_ip, subnet['allocation_pools'][0]['end'],
                         "Shall start allocation pool at last address in l2 domain")

