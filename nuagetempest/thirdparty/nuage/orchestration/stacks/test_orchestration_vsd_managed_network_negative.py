# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

import logging

from netaddr import *
from tempest.lib.common.utils import data_utils
from tempest import config
from tempest import exceptions
from tempest import test
from nuagetempest.lib.test import nuage_test
import nuage_base

CONF = config.CONF

LOG = logging.getLogger(__name__)


class VsdManagedNetworkTest(nuage_base.NuageBaseOrchestrationTest):
    @test.attr(type=['negative', 'slow'])
    @nuage_test.header()
    def test_link_subnet_to_vsd_l2domain_without_net_partition(self):
        """ Test heat creation should raise exception for a private VSD managed network without net-partition

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
            'private_net_name': self.private_net_name,
            'private_net_cidr': str(cidr)}

        if CONF.nuage_sut.nuage_plugin_mode == 'ml2':
            msg = "is in CREATE_FAILED status due to 'Resource CREATE failed: InternalServerError: resources.private_subnet: create_subnet_postcommit failed.'"
        else:
            msg = "Bad subnet request: In advance mode, net-partition name must be provided"

        # Small difference between El7 and Ubuntu heat results in different output: check the neutron output only
        self.assertRaisesRegexp(exceptions.StackBuildErrorException,
                                # "Resource CREATE failed: BadRequest: resources.private_subnet: Bad subnet request:
                                # In advance mode, net-partition name must be provided",
                                # "Bad subnet request: In advance mode, net-partition name must be provided",
                                msg,
                                self.launch_stack,
                                stack_file_name,
                                stack_parameters)
        pass

    @test.attr(type=['negative', 'slow'])
    @nuage_test.header()
    def test_link_subnet_to_vsd_l2domain_without_valid_vsd_l2domain(self):
        """ Test heat creation should raise exception for a private VSD managed network without valid l2_domain id

        """
        cidr = IPNetwork('10.10.100.0/24')

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_minimal'
        stack_parameters = {
            'vsd_subnet_id': 'not a valid UUID',
            'netpartition_name': self.net_partition_name,
            'private_net_name': self.private_net_name,
            'private_net_cidr': str(cidr)}

        # Small difference between El7 and Ubuntu heat results in different output: check the neutron output only
        self.assertRaisesRegexp(exceptions.StackBuildErrorException,
                                # "'Resource CREATE failed: BadRequest: resources.private_subnet:
                                #  Invalid input for nuagenet. Reason: 'not a valid UUID' is not a valid UUID.",
                                "Invalid input for nuagenet. Reason: 'not a valid UUID' is not a valid UUID.",
                                self.launch_stack,
                                stack_file_name,
                                stack_parameters)

    @test.attr(type=['negative', 'slow'])
    @nuage_test.header()
    def test_link_subnet_to_vsd_l2domain_without_existing_vsd_l2domain(self):
        """ Test heat creation should raise exception for a private VSD managed network without valid l2_domain id

        """
        cidr = IPNetwork('10.10.100.0/24')

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_minimal'
        stack_parameters = {
            'vsd_subnet_id': data_utils.rand_uuid(),
            'netpartition_name': self.net_partition_name,
            'private_net_name': self.private_net_name,
            'private_net_cidr': str(cidr)}

        # Small difference between El7 and Ubuntu heat results in different output: check the neutron output only
        self.assertRaisesRegexp(exceptions.StackBuildErrorException,
                                # "Resource CREATE failed: InternalServerError: resources.private_subnet:
                                # Nuage API: Error in REST call to VSD: Cannot find l2domain with ID",
                                "Nuage API: Error in REST call to VSD: Cannot find l2domain with ID",
                                self.launch_stack,
                                stack_file_name,
                                stack_parameters)

