# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

import logging

from netaddr import *
from tempest.lib.common.utils import data_utils
from tempest import config
from tempest import test
from nuagetempest.lib.test import nuage_test

from nuagetempest.thirdparty.nuage.ipv6.base_nuage_orchestration import NuageBaseOrchestrationTest
from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import VsdTestCaseMixin
from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import NetworkTestCaseMixin

CONF = config.CONF

LOG = logging.getLogger(__name__)


class OrchestrationDualStackScaleTest(NuageBaseOrchestrationTest,
                                         VsdTestCaseMixin,
                                         NetworkTestCaseMixin):
    @classmethod
    def resource_setup(cls):
        if CONF.nuage_sut.nuage_plugin_mode == 'ml2':
            # create default netpartition if it is not there
            netpartition_name = cls.vsd_client.def_netpart_name
            net_partition = cls.vsd_client.get_net_partition(netpartition_name)
            if not net_partition:
                net_partition = cls.vsd_client.create_net_partition(netpartition_name,
                                                                     fip_quota=100,
                                                                     extra_params=None)
        super(OrchestrationDualStackScaleTest, cls).resource_setup()
        cls.cidr4 = IPNetwork('1.2.3.0/24')
        cls.mask_bits = cls.cidr4._prefixlen
        cls.gateway4 = str(IPAddress(cls.cidr4) + 1)

        cls.cidr6 = IPNetwork(CONF.network.tenant_network_v6_cidr)
        cls.gateway6 = str(IPAddress(cls.cidr6) + 1)

    @test.attr(type='slow')
    @nuage_test.header()
    def test_link_subnet_to_vsd_l2domain_dhcp_managed_scale_ports(self):
        """ Test heat creation of a private VSD managed network from dhcp-managed l2 domain template


        OpenStack network is created with minimal attributes.
        """
        # create l2domain on VSD
        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=self.cidr4,
            cidr6=self.cidr6,
            gateway=self.gateway4,
            gateway6=self.gateway6)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=self.cidr4,
                                           cidr6=self.cidr6,
                                           IPv6Gateway=self.gateway6,
                                           gateway=self.gateway4)

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
        self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_dualstack'
        stack_name = data_utils.rand_name('heat-' + stack_file_name)
        template = self.read_template(stack_file_name)

        ports_template = ""
        port_template = """  port%s:
    type: OS::Neutron::Port
    properties:
      network: { get_resource: dualstack_net }
      name: 'dualstack-port'
      fixed_ips: [ { subnet: { get_resource: subnet4 } }, { subnet: { get_resource: subnet6 } }  ]
"""
        for i in range(1, 50):
            ports_template = ports_template + (port_template % i)

        template = template + ports_template

        stack_parameters = {
            'vsd_subnet_id': vsd_l2domain['ID'],
            'netpartition_name': self.net_partition_name,
            'net_name': self.private_net_name,
            'cidr4': str(self.cidr4),
            'gateway4': self.gateway4,
            'maskbits4': self.mask_bits,
            'cidr6': str(self.cidr6),
            'gateway6': self.gateway6,
            'maskbits6': IPNetwork(vsd_l2domain_template['IPv6Address'])._prefixlen
        }
        self.launch_stack_template(stack_name, template, stack_parameters)

        # Verifies created resources
        expected_resources = ['dualstack_net', 'subnet4', 'subnet6']
        self.verify_stack_resources(expected_resources, self.template_resources, self.test_resources)

        # Test network
        network = self.verify_created_network('dualstack_net')
        subnet4 = self.verify_created_subnet('subnet4', network)
        subnet6 = self.verify_created_subnet('subnet6', network)

        pass

    @test.attr(type='slow')
    @nuage_test.header()
    def test_link_subnet_to_vsd_l2domain_dhcp_managed_scale_vm_in_net(self):
        """ Test heat creation of a private VSD managed network from dhcp-managed l2 domain template


        OpenStack network is created with minimal attributes.
        """
        # create l2domain on VSD
        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=self.cidr4,
            cidr6=self.cidr6,
            gateway=self.gateway4,
            gateway6=self.gateway6)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=self.cidr4,
                                           cidr6=self.cidr6,
                                           IPv6Gateway=self.gateway6,
                                           gateway=self.gateway4)

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
        self._verify_vsd_l2domain_with_template(vsd_l2domain, vsd_l2domain_template)

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_dualstack_vm_in_net'
        stack_name = data_utils.rand_name('heat-' + stack_file_name)
        template = self.read_template(stack_file_name)

        extra_template = ""
        _template = """

  instance%s:
    type: OS::Nova::Server
    depends_on: [subnet4, subnet6]
    properties:
      flavor: m1.tiny
      image: cirros
      networks:
        - network: { get_resource: dualstack_net }
      user_data: |
        #!/bin/sh
        echo "Hello, World!"
      user_data_format: RAW

"""

        for i in range(1, 100):
            extra_template = extra_template + (_template % i)

        template = template + extra_template

        stack_parameters = {
            'vsd_subnet_id': vsd_l2domain['ID'],
            'netpartition_name': self.net_partition_name,
            'net_name': self.private_net_name,
            'cidr4': str(self.cidr4),
            'gateway4': self.gateway4,
            'maskbits4': self.mask_bits,
            'cidr6': str(self.cidr6),
            'gateway6': self.gateway6,
            'maskbits6': IPNetwork(vsd_l2domain_template['IPv6Address'])._prefixlen
        }
        self.launch_stack_template(stack_name, template, stack_parameters)

        # Verifies created resources
        expected_resources = ['dualstack_net', 'subnet4', 'subnet6']
        self.verify_stack_resources(expected_resources, self.template_resources, self.test_resources)

        # Test network
        network = self.verify_created_network('dualstack_net')
        subnet4 = self.verify_created_subnet('subnet4', network)
        subnet6 = self.verify_created_subnet('subnet6', network)

        pass

    @test.attr(type='slow')
    @nuage_test.header()
    def test_link_subnet_to_vsd_l3domain_dhcp_managed__scale_ports(self):
        """ Test heat creation of a private VSD managed network from dhcp-managed l3 domain

        """

        name = data_utils.rand_name('l3domain-')
        vsd_l3domain_template = self.create_vsd_l3dom_template(
            name=name)
        vsd_l3domain = self.create_vsd_l3domain(name=name,
                                                tid=vsd_l3domain_template['ID'])

        self.assertEqual(vsd_l3domain['name'], name)
        zone_name = data_utils.rand_name('zone-')
        extra_params = None
        vsd_zone = self.create_vsd_zone(name=zone_name,
                                        domain_id=vsd_l3domain['ID'],
                                        extra_params=extra_params)

        subnet_name = data_utils.rand_name('l3domain-subnet-')
        subnet_cidr = IPNetwork('10.10.100.0/24')
        subnet_gateway = str(IPAddress(subnet_cidr) + 1)

        subnet_ipv6_cidr = IPNetwork("2001:5f74:c4a5:b82e::/64")
        subnet_ipv6_gateway = str(IPAddress(subnet_ipv6_cidr) + 1)

        vsd_l3domain_subnet = self.create_vsd_l3domain_dualstack_subnet(
            zone_id=vsd_zone['ID'],
            subnet_name=subnet_name,
            cidr=subnet_cidr,
            gateway=subnet_gateway,
            cidr6=subnet_ipv6_cidr,
            gateway6=subnet_ipv6_gateway)

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_dualstack_vm_on_port'
        stack_name = data_utils.rand_name('heat-' + stack_file_name)
        template = self.read_template(stack_file_name)

        ports_template = ""
        port_template = """  port%s:
    type: OS::Neutron::Port
    properties:
      network: { get_resource: dualstack_net }
      name: 'dualstack-port'
      fixed_ips: [ { subnet: { get_resource: subnet4 } }, { subnet: { get_resource: subnet6 } }  ]
"""
        for i in range(1, 50):
            ports_template = ports_template + (port_template % i)

        template = template + ports_template

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_dualstack_vm_on_port'
        stack_parameters = {
            'vsd_subnet_id': vsd_l3domain_subnet['ID'],
            'netpartition_name': self.net_partition_name,
            'net_name': self.private_net_name,
            'cidr4': str(subnet_cidr),
            'gateway4': subnet_gateway,
            'maskbits4': subnet_cidr.prefixlen,
            'cidr6': str(subnet_ipv6_cidr),
            'gateway6': subnet_ipv6_gateway,
            'maskbits6': IPNetwork(vsd_l3domain_subnet['IPv6Address']).prefixlen
        }
        self.launch_stack_template(stack_name, template, stack_parameters)

        # Verifies created resources
        expected_resources = ['dualstack_net', 'subnet4', 'subnet6']
        self.verify_stack_resources(expected_resources, self.template_resources, self.test_resources)

        # Test network
        network = self.verify_created_network('dualstack_net')
        subnet4 = self.verify_created_subnet('subnet4', network)
        subnet6 = self.verify_created_subnet('subnet6', network)

        pass

    @test.attr(type='slow')
    @nuage_test.header()
    def test_link_subnet_to_vsd_l3domain_dhcp_managed__scale_vm_in_net(self):
        """ Test heat creation of a private VSD managed network from dhcp-managed l3 domain

        """
        name = data_utils.rand_name('l3domain-')
        vsd_l3domain_template = self.create_vsd_l3dom_template(
            name=name)
        vsd_l3domain = self.create_vsd_l3domain(name=name,
                                                tid=vsd_l3domain_template['ID'])

        self.assertEqual(vsd_l3domain['name'], name)
        zone_name = data_utils.rand_name('zone-')
        extra_params = None
        vsd_zone = self.create_vsd_zone(name=zone_name,
                                        domain_id=vsd_l3domain['ID'],
                                        extra_params=extra_params)

        subnet_name = data_utils.rand_name('l3domain-subnet-')
        subnet_cidr = IPNetwork('10.10.100.0/24')
        subnet_gateway = str(IPAddress(subnet_cidr) + 1)

        subnet_ipv6_cidr = IPNetwork("2001:5f74:c4a5:b82e::/64")
        subnet_ipv6_gateway = str(IPAddress(subnet_ipv6_cidr) + 1)

        vsd_l3domain_subnet = self.create_vsd_l3domain_dualstack_subnet(
            zone_id=vsd_zone['ID'],
            subnet_name=subnet_name,
            cidr=subnet_cidr,
            gateway=subnet_gateway,
            cidr6=subnet_ipv6_cidr,
            gateway6=subnet_ipv6_gateway)

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_dualstack_vm_in_net'
        stack_name = data_utils.rand_name('heat-' + stack_file_name)
        template = self.read_template(stack_file_name)

        extra_template = ""
        _template = """

  instance%s:
    type: OS::Nova::Server
    depends_on: [subnet4, subnet6]
    properties:
      flavor: m1.tiny
      image: cirros
      networks:
        - network: { get_resource: dualstack_net }
      user_data: |
        #!/bin/sh
        echo "Hello, World!"
      user_data_format: RAW

"""

        for i in range(1, 100):
            extra_template = extra_template + (_template % i)

        template = template + extra_template

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_dualstack_vm_on_port'
        stack_parameters = {
            'vsd_subnet_id': vsd_l3domain_subnet['ID'],
            'netpartition_name': self.net_partition_name,
            'net_name': self.private_net_name,
            'cidr4': str(subnet_cidr),
            'gateway4': subnet_gateway,
            'maskbits4': subnet_cidr.prefixlen,
            'cidr6': str(subnet_ipv6_cidr),
            'gateway6': subnet_ipv6_gateway,
            'maskbits6': IPNetwork(vsd_l3domain_subnet['IPv6Address']).prefixlen
        }
        self.launch_stack_template(stack_name, template, stack_parameters)

        # Verifies created resources
        expected_resources = ['dualstack_net', 'subnet4', 'subnet6']
        self.verify_stack_resources(expected_resources, self.template_resources, self.test_resources)

        # Test network
        network = self.verify_created_network('dualstack_net')
        subnet4 = self.verify_created_subnet('subnet4', network)
        subnet6 = self.verify_created_subnet('subnet6', network)

        pass
