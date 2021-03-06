# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import *

from oslo_log import log as logging
from tempest import config
from tempest import test
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

from nuagetempest.lib.utils import constants
from nuagetempest.lib.test import nuage_test
from nuagetempest.lib.remote_cli import remote_cli_base_testcase

from nuagetempest.services.nuage_network_client import NuageNetworkClientJSON
from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks import VsdTestCaseMixin
from nuagetempest.thirdparty.nuage.ipv6.base_nuage_networks_cli import BaseNuageNetworksCLITestCase

CONF = config.CONF
LOG = logging.getLogger(__name__)

# Constants used in this file
SEVERAL_REDIRECT_TARGETS = 3
EXPECT_NO_MULTIPLE_RT_MSG = "Bad request: Multiple redirect targets on a port not supported"
SEVERAL_POLICY_GROUPS = 3
SEVERAL_PORTS = 3
SEVERAL_VSD_FIP_POOLS = 3
SEVERAL_VSD_CLAIMED_FIPS = 3

VALID_MAC_ADDRESS = 'fa:fa:3e:e8:e8:c0'


######################################################################################################################
######################################################################################################################
# PolicyGroups
######################################################################################################################
######################################################################################################################
class VSDManagedPolicyGroupsCLITest(BaseNuageNetworksCLITestCase, VsdTestCaseMixin):

    @classmethod
    def setup_clients(cls):
        super(VSDManagedPolicyGroupsCLITest, cls).setup_clients()
        cls.nuage_network_client = NuageNetworkClientJSON(
            cls.os.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os.default_params)

    def _check_port_in_policy_group(self, port_id, pg_id):
        port_found = False
        show_pg = self.nuage_network_client.show_nuage_policy_group(pg_id)
        for id in show_pg['nuage_policy_group']['ports']:
            if id == port_id:
                port_found = True
                break
        return port_found

    def _check_policy_group_in_show_port(self, pg_id, show_port):
        pg_present = False
        for show_pg_id in show_port['port']['nuage_policy_groups']:
            if pg_id == show_pg_id:
                pg_present = True
                break
        return pg_present

    def _check_all_policy_groups_in_show_port(self, pg_id_list, show_port):
        groups_present = True
        for pg_id in show_port['port']['nuage_policy_groups']:
            if not pg_id in pg_id_list:
                groups_present = False
                break
        return groups_present

    @nuage_test.header()
    def test_cli_l2_associate_port_to_policygroup(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a VSD created policy group
        cidr4 = IPNetwork('1.1.20.0/24')
        cidr6 = IPNetwork("2001:5f74:c4a5:b82e::/64")
        vsd_l2_subnet = self._given_vsd_l2domain(cidr4=cidr4, cidr6=cidr6, dhcp_managed=True )
        cli_network, cli_subnet4, cli_subnet6 = self._cli_create_os_l2_vsd_managed_dualstack_subnet(vsd_l2_subnet)
        policy_group = self.nuage_vsd_client.create_policygroup(
            constants.L2_DOMAIN,
            vsd_l2_subnet['ID'],
            name='cli-myVSDpg-1',
            type='SOFTWARE',
            extra_params=None)

        # When I retrieve the VSD-L2-Managed-Subnet

        # I expect the policy group in my list
        policy_group_list4 = self.list_nuage_policy_group_for_subnet(cli_subnet4['id'])
        pg_present = self._cli_check_policy_group_in_list(policy_group[0]['ID'], policy_group_list4)
        self.assertTrue(pg_present, "Did not find vsd policy group in policy group list")

        policy_group_list6 = self.list_nuage_policy_group_for_subnet(cli_subnet6['id'])
        pg_present = self._cli_check_policy_group_in_list(policy_group[0]['ID'], policy_group_list6)
        self.assertTrue(pg_present, "Did not find vsd policy group in policy group list")

        # And it has no external ID
        self.assertIsNone(policy_group[0]['externalID'],
                          "Policy Group has an external ID, while it should not")

        # When I create a port in the subnet
        port = self.create_port(cli_network)
        self.addCleanup(self._delete_port, port['id'])
        self.ports.remove(port)

        # And I associate the port with the policy group
        self.cli_associate_port_with_policy_group(port, policy_group)

        # Then I expect the port in the show policy group response
        port_present = self.cli_check_port_in_show_policy_group(port['id'], policy_group[0]['ID'])
        self.assertTrue(port_present, "Port(%s) assiociated to policy group (%s) is not present" %
                        (port['id'], policy_group[0]['ID']))
        # When I disassociate the port from the policy group
        self.cli_disassociate_port_from_policy_group(port['id'])
        # Then I do NOT expect the port in the show plicy group response
        port_present = self._check_port_in_policy_group(port['id'], policy_group[0]['ID'])
        self.assertFalse(port_present, "Port(%s) disassiociated to policy group (%s) is still present" %
                         (port['id'], policy_group[0]['ID']))

    @nuage_test.header()
    def test_cli_l2_associate_multiple_ports_to_policygroups(self):
        policy_groups = []
        ports = []
        # Given I have a VSD-L2-Managed-Subnet
        cidr4 = IPNetwork('1.1.20.0/24')
        cidr6 = IPNetwork("2001:5f74:c4a5:b82e::/64")
        vsd_l2_subnet = self._given_vsd_l2domain(cidr4=cidr4, cidr6=cidr6, dhcp_managed=True)
        cli_network, cli_subnet4, cli_subnet6 = self._cli_create_os_l2_vsd_managed_dualstack_subnet(vsd_l2_subnet)

        # And I have multiple policy_groups
        for i in range(SEVERAL_POLICY_GROUPS):
            policy_groups.append(self.nuage_vsd_client.create_policygroup(constants.L2_DOMAIN,
                                                                          vsd_l2_subnet['ID'],
                                                                          name='myVSDpg-%s' % i,
                                                                          type='SOFTWARE',
                                                                          extra_params=None))
        for i in range(SEVERAL_PORTS):
            # When I create multiple ports
            port = self.create_port(cli_network)
            ports.append(port)
            self.addCleanup(self._delete_port, port['id'])
            self.ports.remove(port)

        # And associate each port with all these policy groups
        pg_id_list = []
        for i in range(SEVERAL_POLICY_GROUPS):
            pg_id_list.append(policy_groups[i][0]['ID'])
        for i in range(SEVERAL_PORTS):
            self.cli_associate_port_with_multiple_policy_group(ports[i], pg_id_list)
        # When I retrieve each port
        for i in range(SEVERAL_PORTS):
            show_port = self.show_port(ports[i]['id'])
            # Then I expect all policy groups in the response
            if CONF.nuage_sut.nuage_plugin_mode != 'ml2':
                all_pg_present = self._cli_check_all_policy_groups_in_show_port(pg_id_list, show_port)
                self.assertTrue(all_pg_present, "Port does not contain all associated policy groups")
        # When I retrieve each policy group
        for i in range(SEVERAL_POLICY_GROUPS):
            # Then I expect the response to contain all the ports
            for j in range(SEVERAL_PORTS):
                port_present = self.cli_check_port_in_show_policy_group(ports[j]['id'], policy_groups[i][0]['ID'])
                self.assertTrue(port_present, "Port(%s) not present in policy group(%s)" %
                                (ports[j]['id'], policy_groups[i][0]['ID']))
        # When I disassociate all policy groups from each port
        for i in range(SEVERAL_PORTS):
            self.cli_disassociate_port_from_policy_group(ports[i]['id'])
            # Then I do NOT expect the policy Groups in the show port response
            show_port = self.show_port(ports[i]['id'])

            if CONF.nuage_sut.nuage_plugin_mode != 'ml2':
                self.assertEmpty(show_port['nuage_policy_groups'],
                                 "Port-show list disassociated ports")

            # And I do not expect this port in any of the policy groups
            for j in range(SEVERAL_POLICY_GROUPS):
                port_present = self.cli_check_port_in_show_policy_group(ports[i]['id'], policy_groups[j][0]['ID'])
                self.assertFalse(port_present, 'disassociated port (%s) still present in policy group(%s)' %
                                 (ports[i]['id'], policy_groups[j][0]['ID']))
        pass

    @nuage_test.header()
    def test_cli_list_l2_policy_groups_subnet_only(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a VSD created policy group
        cidr4 = IPNetwork('1.1.20.0/24')
        cidr6 = IPNetwork("2001:5f74:1111:b82e::/64")
        vsd_l2_subnet_x = self._given_vsd_l2domain(cidr4=cidr4, cidr6=cidr6, dhcp_managed=True)
        cli_network_x, cli_subnet4_x, cli_subnet6_x = self._cli_create_os_l2_vsd_managed_dualstack_subnet(vsd_l2_subnet_x)

        policy_group_x = self.nuage_vsd_client.create_policygroup(
            constants.L2_DOMAIN,
            vsd_l2_subnet_x['ID'],
            name='myVSDpg-X',
            type='SOFTWARE',
            extra_params=None)

        cidr4 = IPNetwork('1.2.20.0/24')
        cidr6 = IPNetwork("2001:5f74:2222:b82e::/64")
        vsd_l2_subnet_y = self._given_vsd_l2domain(cidr4=cidr4, cidr6=cidr6, dhcp_managed=True )
        cli_network_y, cli_subnet4_y, cli_subnet6_y = self._cli_create_os_l2_vsd_managed_dualstack_subnet(vsd_l2_subnet_y)

        policy_group_y = self.nuage_vsd_client.create_policygroup(
            constants.L2_DOMAIN,
            vsd_l2_subnet_y['ID'],
            name='myVSDpg-2',
            type='SOFTWARE',
            extra_params=None)
        # When I retrieve the policy groups of  VSD-L2-Managed-Subnet_x
        policy_group_list_x = self.list_nuage_policy_group_for_subnet(cli_subnet4_x['id'])
        # I expect policyGroup_x in my list
        pg_present = self._cli_check_policy_group_in_list(policy_group_x[0]['ID'], policy_group_list_x)
        self.assertTrue(pg_present, "Did not find vsd policy group in policy group list")
        # And I do NOT expect policyGroup_y in my list
        pg_present = self._cli_check_policy_group_in_list(policy_group_y[0]['ID'], policy_group_list_x)
        self.assertFalse(pg_present, "Found policgroup (%s) of another subnet (%s) in this subnet (%s)" %
                         (policy_group_y[0]['ID'],  cli_subnet4_y['id'], cli_subnet4_x['id']))
        self.assertFalse(pg_present, "Found policgroup (%s) of another subnet (%s) in this subnet (%s)" %
                         (policy_group_y[0]['ID'],  cli_subnet6_y['id'], cli_subnet6_x['id']))

        # And vice versa
        # When I retrieve the polic groups of VSD-L2-Managed-Subnet_y
        policy_group_list_y = self.list_nuage_policy_group_for_subnet(cli_subnet4_y['id'])
        # I expect policyGroup_y in my list
        pg_present = self._cli_check_policy_group_in_list(policy_group_y[0]['ID'], policy_group_list_y)
        self.assertTrue(pg_present, "Did not find vsd policy group in policy group list")
        # And I do NOT expect policyGroup_x in my list
        pg_present = self._cli_check_policy_group_in_list(policy_group_x[0]['ID'], policy_group_list_y)
        self.assertFalse(pg_present, "Found policgroup (%s) of another subnet (%s) in this subnet (%s)" %
                         (policy_group_x[0]['ID'],  cli_subnet4_x['id'], cli_subnet4_y['id']))
        self.assertFalse(pg_present, "Found policgroup (%s) of another subnet (%s) in this subnet (%s)" %
                         (policy_group_x[0]['ID'],  cli_subnet6_x['id'], cli_subnet6_y['id']))
        pass

    @nuage_test.header()
    def test_cli_list_l3_policy_groups_subnet_only(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a VSD creeated policy group

        cidr4 = IPNetwork('1.1.20.0/24')
        cidr6 = IPNetwork("2001:5f74:1111:b82e::/64")
        vsd_l3_domain_x, vsd_l3_subnet_x = self._given_vsd_l3subnet(cidr4=cidr4, cidr6=cidr6, dhcp_managed=True)
        cli_network_x, cli_subnet4_x, cli_subnet6_x = self._cli_create_os_l2_vsd_managed_dualstack_subnet(vsd_l3_subnet_x)

        policy_group_x = self.nuage_vsd_client.create_policygroup(constants.DOMAIN,
                                                                  vsd_l3_domain_x['ID'],
                                                                  name='myVSD-L3-pg-X',
                                                                  type='SOFTWARE',
                                                                  extra_params=None)

        cidr4 = IPNetwork('1.1.30.0/24')
        cidr6 = IPNetwork("2001:5f74:2222:b82e::/64")
        vsd_l3_domain_y, vsd_l3_subnet_y = self._given_vsd_l3subnet(cidr4=cidr4, cidr6=cidr6 )
        cli_network_y, cli_subnet4_y, cli_subnet6_y = self._cli_create_os_l2_vsd_managed_dualstack_subnet(vsd_l3_subnet_y)
        policy_group_y = self.nuage_vsd_client.create_policygroup(constants.DOMAIN,
                                                                  vsd_l3_domain_y['ID'],
                                                                  name='myVSD-L3-pg-Y',
                                                                  type='SOFTWARE',
                                                                  extra_params=None)

        # When I retrieve the policy groups of  VSD-L2-Managed-Subnet_x
        policy_group_list_x = self.list_nuage_policy_group_for_subnet(cli_subnet4_x['id'])
        # policy_group_list_x = self.client.list_available_nuage_policy_group(subnet_x['id'])
        # I expect policyGroup_x in my list
        pg_present = self._cli_check_policy_group_in_list(policy_group_x[0]['ID'], policy_group_list_x)
        self.assertTrue(pg_present, "Did not find vsd policy group in policy group list")
        # And I do NOT expect policyGroup_y in my list
        pg_present = self._cli_check_policy_group_in_list(policy_group_y[0]['ID'], policy_group_list_x)
        self.assertFalse(pg_present, "Found policgroup (%s) of another subnet (%s) in this subnet (%s)" %
                         (policy_group_y[0]['ID'],  cli_subnet4_y['id'], cli_subnet4_x['id']))

        # idem for subnet6

        # When I retrieve the policy groups of  VSD-L2-Managed-Subnet_x
        policy_group_list_x = self.list_nuage_policy_group_for_subnet(cli_subnet6_x['id'])
        # policy_group_list_x = self.client.list_available_nuage_policy_group(subnet_x['id'])
        # I expect policyGroup_x in my list
        pg_present = self._cli_check_policy_group_in_list(policy_group_x[0]['ID'], policy_group_list_x)
        self.assertTrue(pg_present, "Did not find vsd policy group in policy group list")
        # And I do NOT expect policyGroup_y in my list
        pg_present = self._cli_check_policy_group_in_list(policy_group_y[0]['ID'], policy_group_list_x)
        self.assertFalse(pg_present, "Found policgroup (%s) of another subnet (%s) in this subnet (%s)" %
                         (policy_group_y[0]['ID'],  cli_subnet6_y['id'], cli_subnet6_x['id']))


        # And vice versa
        # When I retrieve the polic groups of VSD-L2-Managed-Subnet_y
        # policy_group_list_y = self.client.list_available_nuage_policy_group(subnet_y['id'])
        policy_group_list_y = self.list_nuage_policy_group_for_subnet(cli_subnet4_y['id'])
        # I expect policyGroup_y in my list
        pg_present = self._cli_check_policy_group_in_list(policy_group_y[0]['ID'], policy_group_list_y)
        self.assertTrue(pg_present, "Did not find vsd policy group in policy group list")
        # And I do NOT expect policyGroup_x in my list
        pg_present = self._cli_check_policy_group_in_list(policy_group_x[0]['ID'], policy_group_list_y)
        self.assertFalse(pg_present, "Found policgroup (%s) of another subnet (%s) in this subnet (%s)" %
                         (policy_group_x[0]['ID'],  cli_subnet4_x['id'], cli_subnet4_y['id']))

        policy_group_list_y = self.list_nuage_policy_group_for_subnet(cli_subnet6_y['id'])
        # I expect policyGroup_y in my list
        pg_present = self._cli_check_policy_group_in_list(policy_group_y[0]['ID'], policy_group_list_y)
        self.assertTrue(pg_present, "Did not find vsd policy group in policy group list")
        # And I do NOT expect policyGroup_x in my list
        pg_present = self._cli_check_policy_group_in_list(policy_group_x[0]['ID'], policy_group_list_y)
        self.assertFalse(pg_present, "Found policgroup (%s) of another subnet (%s) in this subnet (%s)" %
                         (policy_group_x[0]['ID'],  cli_subnet6_x['id'], cli_subnet6_y['id']))

    @nuage_test.header()
    def test_cli_l3_associate_multiple_ports_to_policygroups(self):
        policy_groups = []
        ports = []

        # Given I have a VSD-L3-Managed-Subnet
        cidr4 = IPNetwork('1.1.20.0/24')
        cidr6 = IPNetwork("2001:5f74:1111:b82e::/64")
        vsd_l3_domain, vsd_l3_subnet = self._given_vsd_l3subnet(cidr4=cidr4, cidr6=cidr6, dhcp_managed=True)
        cli_network, cli_subnet4, cli_subnet6 = self._cli_create_os_l2_vsd_managed_dualstack_subnet(vsd_l3_subnet)

        # And I have multiple policy_groups
        for i in range(SEVERAL_POLICY_GROUPS):
            policy_groups.append(self.nuage_vsd_client.create_policygroup(constants.DOMAIN,
                                                                       vsd_l3_domain['ID'],
                                                                       name='my-L3-VSDpg-%s' % i,
                                                                       type='SOFTWARE',
                                                                       extra_params=None))

        for i in range(SEVERAL_PORTS):
            # When I create multiple ports
            port = self.create_port(cli_network)
            ports.append(port)
            self.addCleanup(self._delete_port, port['id'])
            self.ports.remove(port)

        # And associate each port with all these policy groups
        pg_id_list = []
        for i in range(SEVERAL_POLICY_GROUPS):
            pg_id_list.append(policy_groups[i][0]['ID'])
        for i in range(SEVERAL_PORTS):
            self.cli_associate_port_with_multiple_policy_group(ports[i], pg_id_list)
        # When I retrieve each port
        for i in range(SEVERAL_PORTS):
            show_port = self.show_port(ports[i]['id'])
            # Then I expect all policy groups in the response
            if CONF.nuage_sut.nuage_plugin_mode != 'ml2':
                all_pg_present = self._cli_check_all_policy_groups_in_show_port(pg_id_list, show_port)
                self.assertTrue(all_pg_present, "Port does not contain all associated policy groups")

        # When I retrieve each policy group
        for i in range(SEVERAL_POLICY_GROUPS):
            # Then I expect the response to contain all the ports
            for j in range(SEVERAL_PORTS):
                port_present = self.cli_check_port_in_show_policy_group(ports[j]['id'], policy_groups[i][0]['ID'])
                self.assertTrue(port_present, "Port(%s) not present in policy group(%s)" %
                                (ports[j]['id'], policy_groups[i][0]['ID']))
        # When I disassociate all policy groups from each port
        for i in range(SEVERAL_PORTS):
            self.cli_disassociate_port_from_policy_group(ports[i]['id'])

            # Then I do NOT expect the policy Groups in the show port response
            show_port = self.show_port(ports[i]['id'])
            if CONF.nuage_sut.nuage_plugin_mode != 'ml2':
                self.assertEmpty(show_port['nuage_policy_groups'],
                                 "Port-show list disassociated ports")

            # And I do not expect this port in any of the policy groups
            for j in range(SEVERAL_POLICY_GROUPS):
                port_present = self.cli_check_port_in_show_policy_group(ports[i]['id'], policy_groups[j][0]['ID'])
                self.assertFalse(port_present, 'disassociated port (%s) still present in policy group(%s)' %
                                 (ports[i]['id'], policy_groups[j][0]['ID']))

    @nuage_test.header()
    def test_cli_l2_associate_multiple_ports_to_policygroups_dhcp_managed(self):
        policy_groups = []
        ports = []
        # Given I have a VSD-L2-Managed-Subnet
        cidr4 = IPNetwork('1.1.20.0/24')
        cidr6 = IPNetwork("2001:5f74:c4a5:b82e::/64")
        vsd_l2_subnet = self._given_vsd_l2domain(cidr4=cidr4, cidr6=cidr6,dhcp_managed=True )
        cli_network, cli_subnet4, cli_subnet6 = self._cli_create_os_l2_vsd_managed_dualstack_subnet(vsd_l2_subnet)

        # And I have multiple policy_groups
        for i in range(SEVERAL_POLICY_GROUPS):
            policy_groups.append(self.nuage_vsd_client.create_policygroup(constants.L2_DOMAIN,
                                                                          vsd_l2_subnet['ID'],
                                                                          name='myVSDpg-%s' % i,
                                                                          type='SOFTWARE',
                                                                          extra_params=None))
        for i in range(SEVERAL_PORTS):
            # When I create multiple ports
            port = self.create_port(cli_network)
            ports.append(port)
            self.addCleanup(self._delete_port, port['id'])
            self.ports.remove(port)

        # And associate each port with all these policy groups
        pg_id_list = []
        for i in range(SEVERAL_POLICY_GROUPS):
            pg_id_list.append(policy_groups[i][0]['ID'])
        for i in range(SEVERAL_PORTS):
            self.cli_associate_port_with_multiple_policy_group(ports[i], pg_id_list)
        # When I retrieve each port
        for i in range(SEVERAL_PORTS):
            show_port = self.show_port(ports[i]['id'])
            # Then I expect all policy groups in the response
            if CONF.nuage_sut.nuage_plugin_mode != 'ml2':
                all_pg_present = self._cli_check_all_policy_groups_in_show_port(pg_id_list, show_port)
                self.assertTrue(all_pg_present, "Port does not contain all associated policy groups")
        # When I retrieve each policy group
        for i in range(SEVERAL_POLICY_GROUPS):
            # Then I expect the response to contain all the ports
            for j in range(SEVERAL_PORTS):
                port_present = self.cli_check_port_in_show_policy_group(ports[j]['id'], policy_groups[i][0]['ID'])
                self.assertTrue(port_present, "Port(%s) not present in policy group(%s)" %
                                (ports[j]['id'], policy_groups[i][0]['ID']))
        # When I disassociate all policy groups from each port
        for i in range(SEVERAL_PORTS):
            self.cli_disassociate_port_from_policy_group(ports[i]['id'])
            # Then I do NOT expect the policy Groups in the show port response
            show_port = self.show_port(ports[i]['id'])

            if CONF.nuage_sut.nuage_plugin_mode != 'ml2':
                self.assertEmpty(show_port['nuage_policy_groups'],
                                 "Port-show list disassociated ports")

            # And I do not expect this port in any of the policy groups
            for j in range(SEVERAL_POLICY_GROUPS):
                port_present = self.cli_check_port_in_show_policy_group(ports[i]['id'], policy_groups[j][0]['ID'])
                self.assertFalse(port_present, 'disassociated port (%s) still present in policy group(%s)' %
                                 (ports[i]['id'], policy_groups[j][0]['ID']))
        pass
