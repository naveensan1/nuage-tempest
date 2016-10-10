# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import time

from tempest import config
from nuagetempest.lib.utils import constants
from nuagetempest.thirdparty.nuage.vsd_managed import base_vsd_managed_port_attributes
from nuagetempest.thirdparty.nuage.scenario import base_nuage_network_scenario_test
from nuagetempest.lib.test import nuage_test

CONF = config.CONF


class PolicyGroupsScenarioTest(base_vsd_managed_port_attributes.BaseVSDManagedPortAttributes,
                               base_nuage_network_scenario_test.NuageNetworkScenarioTest):

    @nuage_test.header()
    def test_e2e_l2_vm_connectivity_port_to_policygroup(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a VSD creeated policy group
        vsd_l2_subnet, l2_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        policy_group = self.nuage_vsd_client.create_policygroup(constants.L2_DOMAIN,
                                                                vsd_l2_subnet[0]['ID'],
                                                                name='myVSD-l2-pg',
                                                                type='SOFTWARE',
                                                                extra_params=None)
        self.addCleanup(self.nuage_vsd_client.delete_resource, constants.POLICYGROUP,
                        policy_group[0]['ID'],
                        responseChoice=True)  # enforce deletion of underlying ACL rules/vPorts

        # And the policy group has and ingress/egress policy with rules allowing PING
        self._prepare_l2_security_group_entries(policy_group[0]['ID'], vsd_l2_subnet[0]['ID'])
        # When I retrieve the VSD-L2-Managed-Subnet
        policy_group_list = self.nuage_network_client.list_nuage_policy_group_for_subnet(subnet['id'])
        # I expect the policyGroup in my list
        pg_present = self._check_policy_group_in_list(policy_group[0]['ID'], policy_group_list)
        self.assertTrue(pg_present, "Did not find vsd policy group in policy group list")
        # And it has no external ID
        self.assertIsNone(policy_group[0]['externalID'],
                          "Policy Group has an external ID, while it should not")

        show_pg = self.nuage_network_client.show_nuage_policy_group(policy_group[0]['ID'])

        # When I create 2 ports in the subnet
        port1 = self.create_port(network)
        port2 = self.create_port(network)
        # And I associate all ports with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-pg'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        # Then I expext all ports in the show policy group response
        port_present = self._check_port_in_policy_group(port1['id'], policy_group[0]['ID'])
        self.assertTrue(port_present, "Port(%s) assiociated to policy group (%s) is not present" %
                        (port1['id'], policy_group[0]['ID']))
        port_present = self._check_port_in_policy_group(port2['id'], policy_group[0]['ID'])
        self.assertTrue(port_present, "Port(%s) assiociated to policy group (%s) is not present" %
                        (port2['id'], policy_group[0]['ID']))
        # create connectivity VM
        vm_conn = self._create_connectivity_VM(public_network_id=CONF.network.public_network_id,
                                               vsd_l2_subnet=vsd_l2_subnet,
                                               vsd_l2_port=port2)
        floating_ip, the_server = self.floating_ip_tuple

        rslt = self._configure_eth1_server(vm_conn, floating_ip.floating_ip_address)

        # When I spin a VM with this port
        vm1 = self._create_server(name='vm1', network_id=network['id'], port_id=port1['id'])
        vm1_ip_addr = vm1['addresses'][network['name']][0]['addr']
        # These Vm's have connectivity
        # for i in range(5):
        time.sleep(3)  # add a delay
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 10)
        self.assertTrue(connectivity, msg="No ping connectivity in policy group while expected (1)")
        # When I disassociate all ports from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg-1st'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        time.sleep(3)  # add a delay to allow propagation of the rules

        # Then these VM's have no more connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 1)
        self.assertFalse(connectivity, msg="Ping connectivity in policy group while NOT expected (1)")
        # When I re-associate all ports with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-pg-2nd'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        time.sleep(3)  # add a delay to allow propagation of the rules

        # Then these VM's have again connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 10)
        self.assertTrue(connectivity, msg="No ping connectivity in policy group while expected (2)")
        # When I disassociate 1 port from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg-2nd'
        }
        self.update_port(port1, **kwargs)
        # self.update_port(port2, **kwargs)
        time.sleep(3)  # add a delay to allow propagation of the rules

        # Then these VM's have no more connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 1)
        self.assertFalse(connectivity, msg="Ping connectivity in policy group while NOT expected (2)")
        # When I re-associate that port with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-3rd'
        }
        self.update_port(port1, **kwargs)
        # self.update_port(port2, **kwargs)
        time.sleep(3)  # add a delay to allow propagation of the rules

        # Then these VM's have again connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 10)
        self.assertTrue(connectivity, msg="No ping connectivity in policy group while expected (3)")
        # When I disassociate the other port from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg-2nd'
        }
        # self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        # Then these VM's have no more connectivity
        time.sleep(3)  # add a delay to allow propagation of the rules
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 1)
        self.assertFalse(connectivity, msg="Ping connectivity in policy group while NOT expected (3)")
        # When I re-associate that port with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-3rd'
        }
        # self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        time.sleep(5)  # add a delay to allow propagation of the rules

        # Then these VM's have again connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 10)
        self.assertTrue(connectivity, msg="No ping connectivity in policy group while expected (3)")
        #
        #end for loop
        the_floating_ip = self.floating_ips.pop()
        self.floating_ips_client.delete_floatingip(the_floating_ip['id'])

        # self.servers_client.delete_server(vm_conn['id'])
        # self.servers_client.delete_server(vm1['id'])
        self._clear_connectivity_vm_interfaces(self.conn_router_id, self.conn_subnet_id, self.conn_port_id)

    @nuage_test.header()
    def test_e2e_l3_vm_connectivity_port_to_policygroup(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a VSD creeated policy group
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        policy_group = self.nuage_vsd_client.create_policygroup(constants.DOMAIN,
                                                                vsd_l3_domain[0]['ID'],
                                                                name='myVSD-l3-policygrp',
                                                                type='SOFTWARE',
                                                                extra_params=None)
        self.addCleanup(self.nuage_vsd_client.delete_resource, constants.POLICYGROUP,
                        policy_group[0]['ID'],
                        responseChoice=True)  # enforce deletion of underlying ACL rules/vPorts

        # And the policy group has and ingress/egress policy with rules allowing PING
        self._prepare_l3_security_group_entries(policy_group[0]['ID'],
                                                vsd_l3_domain[0]['ID'],
                                                defaultAllowIP=False)
        # When I retrieve the VSD-L2-Managed-Subnet
        policy_group_list = self.nuage_network_client.list_nuage_policy_group_for_subnet(subnet['id'])
        # I expect the policyGroup in my list
        pg_present = self._check_policy_group_in_list(policy_group[0]['ID'], policy_group_list)
        self.assertTrue(pg_present, "Did not find vsd policy group in policy group list")
        # And it has no external ID
        self.assertIsNone(policy_group[0]['externalID'],
                          "Policy Group has an external ID, while it should not")

        show_pg = self.nuage_network_client.show_nuage_policy_group(policy_group[0]['ID'])

        # When I create 2 ports in the subnet
        port1 = self.create_port(network)
        port2 = self.create_port(network)
        # port3 = self.create_port(network)
        # public_network = self.admin_client.show_network(CONF.network.public_network_id)
        # port4 = self.create_port(public_network['network'])
        # And I associate the port with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-pg'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        # Then I expext the port in the show policy group response
        time.sleep(3)  # add a delay to allow propagation of the rules

        if CONF.nuage_sut.nuage_plugin_mode != 'ml2':
            port_present = self._check_port_in_policy_group(port1['id'], policy_group[0]['ID'])
            self.assertTrue(port_present, "Port(%s) assiociated to policy group (%s) is not present" %
                            (port1['id'], policy_group[0]['ID']))
            port_present = self._check_port_in_policy_group(port2['id'], policy_group[0]['ID'])
            self.assertTrue(port_present, "Port(%s) assiociated to policy group (%s) is not present" %
                            (port2['id'], policy_group[0]['ID']))

        # create connectivity VM
        vm_conn = self._create_connectivity_VM(public_network_id=CONF.network.public_network_id,
                                               vsd_l2_subnet=vsd_l3_subnet,
                                               vsd_l2_port=port2)
        floating_ip, the_server = self.floating_ip_tuple

        rslt = self._configure_eth1_server(vm_conn, floating_ip.floating_ip_address)

        # When I spin a VM with this port
        vm1 = self._create_server(name='vm1', network_id=network['id'], port_id=port1['id'])
        # vm2 = self._create_server(name='vm2', network_id=network['id'], port_id=port2['id'])
        # These Vm's have connectivity
        vm1_ip_addr = vm1['addresses'][network['name']][0]['addr']

        time.sleep(10)  # wait for boot complete

        # for i in range(5):
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 10)
        self.assertTrue(connectivity, msg="No ping connectivity in policy group while expected (1)")

        # When I disassociate the port from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg-1st'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        time.sleep(3)  # add a delay to allow propagation of the rules

        # Then these VM's have no more connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 1)
        self.assertFalse(connectivity, msg="Ping connectivity in policy group while NOT expected (1)")

        # When I re-associate the port with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-pg-2nd'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)

        # Then these VM's have again connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 10)
        self.assertTrue(connectivity, msg="No ping connectivity in policy group while expected (2)")

        # When I disassociate the port from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg-2nd'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        time.sleep(3)  # add a delay to allow propagation of the rules

        # Then these VM's have no more connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 1)
        self.assertFalse(connectivity, msg="Ping connectivity in policy group while NOT expected (3)")

        # When I re-associate the port with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-3rd'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        time.sleep(3)  # add a delay to allow propagation of the rules

        # Then these VM's have again connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 10)
        self.assertTrue(connectivity, msg="No ping connectivity in policy group while expected (4)")

        # When I disassociate the port from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg-2nd'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)

        time.sleep(3)  # add a delay to allow propagation of the rules

        # Then these VM's have no more connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 1)
        self.assertFalse(connectivity, msg="Ping connectivity in policy group while NOT expected (5)")
        # When I re-associate the port with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-3rd'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)

        the_floating_ip = self.floating_ips.pop()
        self.floating_ips_client.delete_floatingip(the_floating_ip['id'])
        # the_server = self.servers.pop()
        self.servers_client.delete_server(vm_conn['id'])
        self.servers_client.delete_server(vm1['id'])
        self._clear_connectivity_vm_interfaces(self.conn_router_id, self.conn_subnet_id, self.conn_port_id)
