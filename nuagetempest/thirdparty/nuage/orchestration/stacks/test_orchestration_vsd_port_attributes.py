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
                                       # base_vsd_managed_networks.BaseVSDManagedNetwork,
                                       nuage_base.NuageBaseOrchestrationTest):


    @classmethod
    def setup_clients(cls):
        super(base_vsd_managed_port_attributes.BaseVSDManagedPortAttributes, cls).setup_clients()
        # super(base_vsd_managed_networks.BaseVSDManagedNetwork, cls).setup_clients()
        super(nuage_base.NuageBaseOrchestrationTest, cls).setup_clients()
        pass

    @classmethod
    def resource_setup(cls):
        super(HeatVsdManagedPortAttributesTest, cls).resource_setup()
        super(nuage_base.NuageBaseOrchestrationTest, cls).resource_setup()
        # super(base_vsd_managed_networks.BaseVSDManagedNetwork, cls).resource_setup()

        if not test.is_extension_enabled('nuage-redirect-target', 'network'):
            msg = "Nuage extension 'nuage-redirect-target' not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_cleanup(cls):
        super(nuage_base.NuageBaseOrchestrationTest, cls).resource_cleanup()
        super(base_vsd_managed_port_attributes.BaseVSDManagedPortAttributes, cls).resource_cleanup()
        pass

    def test_heat_vsd_managed_l2_port_attributes(self):
        # Prepare all the stuff whcih can be created only on VSD
        l2_cidr = base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR
        l3_cidr = base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR
        vsd_l2_subnet, l2_domtmpl = self._create_vsd_l2_managed_subnet()
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        # Policy group on L2/L3
        l2_policy_group = self.vsd_client.create_policygroup(
            constants.L2_DOMAIN,
            vsd_l2_subnet[0]['ID'],
            name='myHEAT-VSD-L2-pg-1',
            type='SOFTWARE',
            extra_params=None)
        l3_policy_group = self.vsd_client.create_policygroup(
            constants.DOMAIN,
            vsd_l3_domain[0]['ID'],
            name='myHEAT-VSD-pg-L3-1',
            type='SOFTWARE',
            extra_params=None)
        # FIP pool for L3
        self.vsd_fip_pool = self._create_vsd_floatingip_pool()
        claimed_fip = self.nuage_vsd_client.claim_floatingip(vsd_l3_domain[0]['ID'], self.vsd_fip_pool[0]['ID'])

        stack_name = 'port_attributes'
        l2_port_fixed_ip = str(IPAddress(l2_cidr) + 10)
        l2_aap_fixed_ip = str(IPAddress(l2_port_fixed_ip) + 5)
        l2_aap_mac_address = VALID_MAC_ADDRESS

        l3_port_fixed_ip = str(IPAddress(l3_cidr) + 10)
        l3_aap_fixed_ip = str(IPAddress(l3_port_fixed_ip) + 5)
        l3_aap_mac_address = VALID_MAC_ADDRESS

        stack_parameters = {
            'vsd_l2_subnet_id': vsd_l2_subnet[0]['ID'],
            'netpartition_name': CONF.nuage.nuage_default_netpartition,
            'l2_net_name': data_utils.rand_name('l2-net'),
            'l2_subnet_name': data_utils.rand_name('l2-subnet'),
            'l2_net_cidr': str(l2_cidr.cidr),
            'l2_policy_group_id': l2_policy_group[0]['ID'],
            'l2_fixed_ip_address': l2_port_fixed_ip,
            'l2_aap_ip_address': l2_aap_fixed_ip,
            'l2_aap_mac_address': l2_aap_mac_address,
            'vsd_l3_subnet_id': vsd_l3_subnet[0]['ID'],
            'l3_net_name': data_utils.rand_name('l3-net'),
            'l3_subnet_name': data_utils.rand_name('l3-subnet'),
            'l3_net_cidr': str(l3_cidr.cidr),
            'l3_policy_group_id': l3_policy_group[0]['ID'],
            'l3_fixed_ip_address': l3_port_fixed_ip,
            'l3_aap_ip_address': l3_aap_fixed_ip,
            'l3_aap_mac_address': l3_aap_mac_address,
            'claimed_fip_id': claimed_fip[0]['ID']
        }
        self.launch_stack(stack_name, stack_parameters)
        self.client.wait_for_stack_status(self.stack_id, 'CREATE_COMPLETE')

        expected_resources = ['l2_port', 'l3_port']
        # expected_resources = ['l2_port']
        self.verify_stack_resources(expected_resources, self.template_resources, self.test_resources)

        l2_port_id = self.test_resources['l2_port']['physical_resource_id']
        l2_show_port = self.ports_client.show_port(l2_port_id)
        l2_rt_id = self.test_resources['rt_l2']['physical_resource_id']
        l2_show_rt = self.nuage_network_client.show_redirection_target(l2_rt_id)
        port_present_rt = self._check_port_in_show_redirect_target(l2_show_port['port'], l2_show_rt)
        self.assertTrue(port_present_rt,
                        "Associated port not present in show nuage redirect target response")

        port_present = self._check_port_in_policy_group(l2_port_id, l2_policy_group[0]['ID'])
        self.assertTrue(port_present, "Port(%s) assiociated to policy group (%s) is not present" %
                        (l2_port_id, l2_policy_group[0]['ID']))
        # port_present = base_vsd_managed_port_attributes._check_port_in_policy_group(port_id, policy_group[0]['ID'])
        # self.assertTrue(port_present, "Port(%s) assiociated to policy group (%s) is not present" %
        #                 (port_id, policy_group[0]['ID']))

        pass


    # def test_created_redirecttarget_resources(self):
    #     """Verifies created redirect target resources."""
    #     resources = [('secgrp', self.template['resources'][
    #         'secgrp']['type']),
    #                  ('rt_l2', self.template['resources'][
    #                      'rt_l2']['type']),
    #                  ('rtr_l2', self.template[
    #                      'resources']['rtr_l2']['type']),
    #                  ('rt_l3', self.template['resources'][
    #                      'rt_l3']['type']),
    #                  ('rtr_l3', self.template[
    #                      'resources']['rtr_l3']['type']),
    #                  ('vip_l3', self.template['resources'][
    #                      'vip_l3']['type'])]
    #     for resource_name, resource_type in resources:
    #         resource = self.test_resources.get(resource_name, None)
    #         self.assertIsInstance(resource, dict)
    #         self.assertEqual(resource_name, resource['logical_resource_id'])
    #         self.assertEqual(resource_type, resource['resource_type'])
    #         self.assertEqual('CREATE_COMPLETE', resource['resource_status'])

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

    # @test.attr(type='slow')
    # @nuage_test.header()
    # def test_link_subnet_to_vsd_l2domain_dhcp_managed(self):
    #     """ Test heat creation of a private VSD managed network from dhcp-managed l2 domain template
    #
    #     OpenStack network is created with maximal attributes.
    #     """
    #     # TODO: Add all possible attributes (DNS servers,....)
    #
    #     # Create the VSD l2 domain from a template
    #     name = data_utils.rand_name('l2domain-')
    #     cidr = IPNetwork('10.10.100.0/24')
    #
    #     vsd_l2domain_template = self.create_vsd_dhcp_managed_l2domain_template(
    #         name=name, cidr=cidr, gateway=str(cidr[1]))
    #     vsd_l2domain = self.create_vsd_l2domain(name=name,
    #                                             tid=vsd_l2domain_template[0]['ID'])
    #
    #     self.assertIsInstance(vsd_l2domain, list)
    #     self.assertEqual(vsd_l2domain[0][u'name'], name)
    #
    #     # launch a heat stack
    #     stack_file_name = 'port_attributes'
    #     stack_parameters = {
    #         'vsd_subnet_id': vsd_l2domain[0]['ID'],
    #         'netpartition_name': self.net_partition_name,
    #         'private_net_name': self.private_net_name,
    #         'private_net_cidr': str(cidr),
    #         'private_net_dhcp': True,
    #         'private_net_pool_start': str(cidr[+1]),
    #         'private_net_pool_end': str(cidr[-2])}
    #
    #     # TODO: verify the usage of gateway_ip for vsd-managed networks
    #     # Nuage client expect gateway_ip=None in case DHCP is true
    #     # This can not be realized with the command line or REST API
    #     # 'private_net_gateway': str(cidr[1])
    #
    #     self.launch_stack(stack_file_name, stack_parameters)
    #
    #     # Verifies created resources
    #     expected_resources = ['private_net', 'private_subnet']
    #     self.verify_stack_resources(expected_resources, self.template_resources, self.test_resources)
    #
    #     # Test network
    #     network = self.verify_created_network('private_net')
    #     subnet = self.verify_created_subnet('private_subnet', network)
    #
    #     # TODO: to check: there is no gateway IP in the response !!!
    #     self.assertTrue(subnet['enable_dhcp'], "Shall have DHCP enabled from the l2 domain template")
    #     self.assertEqual(str(cidr), subnet['cidr'], "Shall get the CIDR from the l2 domain")
    #     self.assertEqual(str(cidr[1]), subnet['allocation_pools'][0]['start'],
    #                      "Shall start allocation pool at first address in l2 domain")
    #     self.assertEqual(str(cidr[-2]), subnet['allocation_pools'][0]['end'],
    #                      "Shall start allocation pool at last address in l2 domain")
    #
    #     pass

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

