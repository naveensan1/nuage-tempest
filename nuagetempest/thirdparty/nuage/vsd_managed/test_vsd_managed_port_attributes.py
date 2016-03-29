# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
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

from netaddr import *
import collections
import time

from tempest import config
from tempest import test
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.services.network import resources as net_resources

from nuagetempest.lib.utils import constants
from nuagetempest.lib.test import nuage_test
from nuagetempest.thirdparty.nuage.vsd_managed import base_vsd_managed_networks
from nuagetempest.thirdparty.nuage.scenario.test_nuage_fip_server_basic_ops import NuageNetworkScenarioTest

CONF = config.CONF

# Stuff for the interconnectivity VM
OS_CONNECTING_NW_CIDR = IPNetwork('33.33.33.0/24')
OS_CONNECTING_NW_GW = '33.33.33.1'
# Constants used in this file
SEVERAL_REDIRECT_TARGETS = 3
EXPECT_NO_MULTIPLE_RT_MSG = "Bad request: Multiple redirect targets on a port not supported"
SEVERAL_POLICY_GROUPS = 3
SEVERAL_PORTS = 3
SEVERAL_VSD_FIP_POOLS = 3
SEVERAL_VSD_CLAIMED_FIPS = 3

VALID_MAC_ADDRESS = 'fa:fa:3e:e8:e8:c0'
VSD_FIP_POOL_CIDR = IPNetwork('130.130.130.0/24')
VSD_FIP_POOL_GW = '130.130.130.1'
VSD_SECOND_SUBNET_CIDR = IPNetwork('30.31.32.0/24')

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])

class BaseVSDManagedPortAttributest(base_vsd_managed_networks.BaseVSDMangedNetworkTest,
                                    NuageNetworkScenarioTest):

    def setUp(self):
        super(BaseVSDManagedPortAttributest, self).setUp()
        self.keypairs = {}
        self.servers = []

    @classmethod
    def setup_clients(cls):
        super(BaseVSDManagedPortAttributest, cls).setup_clients()

    @classmethod
    def resource_setup(cls):
        super(BaseVSDManagedPortAttributest, cls).resource_setup()
        cls.conn_router_id = '',
        cls.conn_subnet_id = ''

    @classmethod
    def _create_subnet(cls, network, gateway='', cidr=None, mask_bits=None,
                       ip_version=None, client=None, **kwargs):
        """
        Copy of tempest/api/network/base.py_create_subnet
        where we allow NOT passing gateway_ip (!= not passing as parameter and being calculated by create_subnet)
        """
        # allow tests to use admin client
        if not client:
            client = cls.subnets_client
        # The cidr and mask_bits depend on the ip version.
        ip_version = ip_version if ip_version is not None else cls._ip_version
        gateway_not_set = gateway == ''
        if ip_version == 4:
            cidr = cidr or IPNetwork(CONF.network.tenant_network_cidr)
            mask_bits = mask_bits or CONF.network.tenant_network_mask_bits
        elif ip_version == 6:
            cidr = (
                cidr or IPNetwork(CONF.network.tenant_network_v6_cidr))
            mask_bits = mask_bits or CONF.network.tenant_network_v6_mask_bits
        # Find a cidr that is not in use yet and create a subnet with it
        for subnet_cidr in cidr.subnet(mask_bits):
            if gateway_not_set:
                gateway_ip = str(IPAddress(subnet_cidr) + 1)
            else:
                gateway_ip = gateway
            try:
                if gateway_not_set:
                    body = client.create_subnet(
                        network_id=network['id'],
                        cidr=str(subnet_cidr),
                        ip_version=ip_version,
                        # gateway_ip=not passed,
                        **kwargs)
                    break
                else:
                    body = client.create_subnet(
                        network_id=network['id'],
                        cidr=str(subnet_cidr),
                        ip_version=ip_version,
                        gateway_ip=gateway_ip,
                        **kwargs)
                    break
            except exceptions.BadRequest as e:
                is_overlapping_cidr = 'overlaps with another subnet' in str(e)
                if not is_overlapping_cidr:
                    raise
        else:
            message = 'Available CIDR for subnet creation could not be found'
            raise exceptions.NotFound(message)
            # raise exceptions.BuildErrorException(message)
        subnet = body['subnet']
        cls.subnets.append(subnet)
        return subnet

    def _create_shared_network(self, name=None, shared=False):
        if name is None:
            name = data_utils.rand_name('ext-network')
        if shared:
            name = data_utils.rand_name('SHARED-network')
            post_body = {'name': name, 'shared': True}
            body = self.admin_client.create_network(**post_body)
            self.addCleanup(self.admin_client.delete_network, body['network']['id'])
        else:
            post_body = {'name': name}
            body = self.networks_client.create_network(**post_body)
            self.addCleanup(self.networks_client.delete_network, body['network']['id'])
        network = body['network']
        return network

    def _verify_redirect_target(self, rt, parent, parentinfo, postinfo):
        redirect_target = self.nuage_vsd_client.get_redirection_target(
            parent, parentinfo['ID'], filters='ID',
            filter_value=rt['nuage_redirect_target']['id'])

        self.assertEqual(
            str(redirect_target[0]['redundancyEnabled']),
            postinfo['redundancy_enabled'])
        self.assertEqual(
            str(redirect_target[0]['endPointType']),
            postinfo['insertion_mode'])
        return redirect_target

    def _verify_redirect_target_rules(self, rtrule,
                                      parent, parentinfo, ruleinfo):
        redirect_target_rule_template = self.nuage_vsd_client.get_advfwd_template(
            parent, parentinfo['ID'])

        redirect_target_rule = self.nuage_vsd_client.get_advfwd_entrytemplate(
            'ingressadvfwdtemplates',
            str(redirect_target_rule_template[0]['ID']))

        self.assertEqual(
            str(redirect_target_rule[0]['protocol']), ruleinfo['protocol'])
        self.assertEqual(
            str(redirect_target_rule[0]['protocol']), ruleinfo['protocol'])
        self.assertEqual(
            str(redirect_target_rule[0]['action']), ruleinfo['action'])
        self.assertEqual(
            str(redirect_target_rule[0]['ID']),
            rtrule['nuage_redirect_target_rule']['id'])
        if not (str(ruleinfo['protocol']) == str(1)):
            pmin = str(ruleinfo['port_range_min'])
            pmax = str(ruleinfo['port_range_max'])
            self.assertEqual(
                str(redirect_target_rule[0]['destinationPort']),
                pmin + "-" + pmax)

    def _associate_rt_port(self, rtport, rt):
        port_body = self.ports_client.update_port(
            rtport['id'],
            nuage_redirect_targets=str(rt['nuage_redirect_target']['id']))

    def _associate_multiple_rt_port(self, rtport, rts):
        nuage_rt_id_list = []
        for rt in rts:
            nuage_rt_id_list.append(rt['nuage_redirect_target']['id'])
        # convert into comaa separated string
        rt_string = ",".join(nuage_rt_id_list)
        port_body = self.ports_client.update_port(
            rtport['id'],
            nuage_redirect_targets=rt_string)

    def _disassociate_rt_port(self, rtport, rt):
        # Unassigning port to Redirect Target
        port_body = self.ports_client.update_port(
            rtport['id'], nuage_redirect_targets='')
        redirect_vport = self.nuage_vsd_client.get_redirection_target_vports(
            'redirectiontargets',
            rt['nuage_redirect_target']['id'])
        self.assertEqual(redirect_vport, '')

    def _verify_vsd_rt_port(self, rtport, rt, parent, parentinfo):
        # Verifying vport has associated RT
        redirect_vport = self.nuage_vsd_client.get_redirection_target_vports(
            'redirectiontargets',
            rt['nuage_redirect_target']['id'])
        port_ext_id = self.nuage_vsd_client.get_vsd_external_id(
            rtport['id'])
        vsd_vport = self.nuage_vsd_client.get_vport(
            parent, parentinfo['ID'], filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(
            redirect_vport[0]['ID'], vsd_vport[0]['ID'])

    def _assign_unassign_rt_port(self, rtport, rt, parent, parentinfo):
        port_body = self.ports_client.update_port(
            rtport['id'],
            nuage_redirect_targets=str(rt['nuage_redirect_target']['id']))
        redirect_vport = self.nuage_vsd_client.get_redirection_target_vports(
            'redirectiontargets',
            rt['nuage_redirect_target']['id'])

        # Verifying vport has associated RT
        port_ext_id = self.nuage_vsd_client.get_vsd_external_id(
            rtport['id'])
        vsd_vport = self.nuage_vsd_client.get_vport(
            parent, parentinfo['ID'], filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(
            redirect_vport[0]['ID'], vsd_vport[0]['ID'])

        # Unassigning port to Redirect Target
        port_body = self.ports_client.update_port(
            rtport['id'], nuage_redirect_targets='')
        redirect_vport = self.nuage_network_client.get_redirection_target_vports(
            'redirectiontargets',
            rt['nuage_redirect_target']['id'])
        self.assertEqual(redirect_vport, '')

    def _check_port_in_show_redirect_target(self,port,rt):
        present = False
        show_rt_body = self.nuage_network_client.show_redirection_target(rt['nuage_redirect_target']['id'])
        for show_port in show_rt_body['nuage_redirect_target']['ports']:
            if port['id'] == show_port:
                present = True
                break
        return present

    def _verify_redirect_target_vip(self, rt, vipinfo):
        # Verifying RT has associated vip
        redirect_vip = self.nuage_network_client.get_redirection_target_vips(
            'redirectiontargets',
            rt['nuage_redirect_target']['id'])
        self.assertEqual(
            redirect_vip[0]['virtualIP'], vipinfo['virtual_ip_address'])

    def _find_id_redirect_target_in_list(self, redirect_target_id, subnet):
        rt_found = False
        list_body = self.nuage_network_client.list_redirection_targets(id=subnet['id'])
        for rt in list_body['nuage_redirect_targets']:
            if rt['id'] == redirect_target_id:
                rt_found = True
                break
        return rt_found

    def _find_redirect_target_in_list(self, redirect_target_id, subnet):
        rt_found = False
        list_body = self.nuage_network_client.list_redirection_targets(id=subnet['id'])
        for rt in list_body['nuage_redirect_targets']:
            if rt['id'] == redirect_target_id:
                rt_found = True
                break
        return rt_found

    def _create_redirect_target_in_l2_subnet(self, l2subnet, name=None):
        if name is None:
            name = data_utils.rand_name('os-l2-rt')
        # parameters for nuage redirection target
        post_body = { 'insertion_mode': 'VIRTUAL_WIRE',
                      'redundancy_enabled': 'False',
                      'subnet_id': l2subnet['id'],
                      'name': name}
        redirect_target = self.nuage_network_client.create_redirection_target(**post_body)
        return redirect_target

    def _create_redirect_target_rule(self, redirect_target_id, security_group_id):
        name = data_utils.rand_name('l2-rtr')
        # Creating Redirect Target Rule
        rule_body = {
            'priority': '300',
            'redirect_target_id': redirect_target_id,
            'protocol': '1',
            'origin_group_id': str(security_group_id),
            'remote_ip_prefix': '10.0.0.0/24',
            'action': 'REDIRECT'
        }
        rt_rule = self.nuage_network_client.create_redirection_target_rule(**rule_body)
        return rt_rule

    def _list_redirect_target_rule(self, subnet_id):
        return self.nuage_network_client.list_redirection_target_rule(subnet_id)

    def _create_redirect_target_in_l3_subnet(self, l3subnet, name=None):
        if name is None:
            name = data_utils.rand_name('os-l3-rt')
        # parameters for nuage redirection target
        post_body = { 'insertion_mode': 'L3',
                      'redundancy_enabled': 'False',
                      'subnet_id': l3subnet['id'],
                      'name': name}
        redirect_target = self.nuage_network_client.create_redirection_target(**post_body)
        return redirect_target

    def _check_policy_group_in_list(self, pg_id, pg_list):
        pg_present = False
        for pg in pg_list['nuage_policy_groups']:
            if pg['id'] == pg_id:
                pg_present = True
                break
        return pg_present

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

    def _create_vsd_l2_managed_subnet(self):
        kwargs = {
            'name': data_utils.rand_name("l2dom_template"),
            'cidr': base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            'gateway': base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
        }
        l2dom_template = self.create_vsd_dhcpmanaged_l2dom_template(**kwargs)
        vsd_l2_subnet = self.create_vsd_l2domain(tid=l2dom_template[0]['ID'])
        # self.iacl_template = self._create_ingress_acl_template(name=data_utils.rand_name("iacl_tmpl"), template_id=l2dom_template[0]['ID'])
        # self.eacl_templace = self._create_egress_acl_template(name=data_utils.rand_name("eacl_tmpl"), template_id=l2dom_template[0]['ID'])
        return vsd_l2_subnet, l2dom_template

    def _create_vsd_l3_managed_subnet(self):
        # create template
        kwargs = {
            'name': data_utils.rand_name("l3dom_template"),
        }
        l3dom_template = self.create_vsd_l3dom_template(**kwargs)
        # create domain
        vsd_l3_domain = self.create_vsd_l3domain(tid=l3dom_template[0]['ID'])
        # create zone om domain
        zone = self.create_vsd_zone(name='l3-zone',
                                    domain_id=vsd_l3_domain[0]['ID'])
        # create subnet in zone
        kwargs = {
            'name': data_utils.rand_name("vsd-l3-mgd-subnet"),
            'zone_id': zone[0]['ID'],
            'extra_params': ""
        }
        vsd_l3_subnet = self.create_vsd_l3domain_managed_subnet(**kwargs)
        return vsd_l3_subnet, vsd_l3_domain

    def _create_vsd_l3_managed_subnet_in_domain(self, l3domain_id, cidr):
         # create zone om domain
        zone = self.create_vsd_zone(name=data_utils.rand_name('l3-zone'),
                                    domain_id=l3domain_id)
        # create subnet in zone
        kwargs = {
            'name': data_utils.rand_name("vsd-l3-mgd-subnet"),
            'zone_id': zone[0]['ID'],
            'cidr': cidr,
            'gateway': str(IPAddress(cidr.first + 1))
,            'extra_params': ""
        }
        vsd_l3_subnet = self.create_vsd_l3domain_managed_subnet(**kwargs)
        return vsd_l3_subnet

    def _create_pg_vsd_l2_managed_subnet(self):
        kwargs = {
            'name': data_utils.rand_name("l2dom_template"),
            'cidr': base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            'gateway': base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
        }
        l2dom_template = self.create_vsd_dhcpmanaged_l2dom_template(**kwargs)
        vsd_l2_subnet = self.create_vsd_l2domain(tid=l2dom_template[0]['ID'])
        # create ingress and egress policy group
        self.iacl_template = self._create_l2_ingress_acl_template(name=data_utils.rand_name("iacl_tmpl"), domain_id=vsd_l2_subnet[0]['ID'])
        self.eacl_templace = self._create_l2_egress_acl_template(name=data_utils.rand_name("eacl_tmpl"), domain_id=vsd_l2_subnet[0]['ID'])
        return vsd_l2_subnet, l2dom_template

    def _create_ping_security_group_entries(self, policy_group_id, iacl_template_id):
        extra_params = {
            "networkType":"POLICYGROUP",
            "networkID": policy_group_id,
            "locationType":"POLICYGROUP",
            "locationID":policy_group_id,
            "stateful":True,
            "protocol":"1",
            "ICMPType":"8",
            "ICMPCode":"0",
            "etherType":"0x0800",
            "DSCP":"*",
            "action":"FORWARD"
        }
        ping8 = self.nuage_vsd_client.create_ingress_security_group_entry(name_description='ping8',
                                                                      iacl_template_id=iacl_template_id,
                                                                      extra_params=extra_params)
        # create second entry
        extra_params = {
            "networkType":"POLICYGROUP",
            "networkID": policy_group_id,
            "locationType":"POLICYGROUP",
            "locationID":policy_group_id,
            "stateful":False,
            "protocol":"1",
            "ICMPType":"0",
            "ICMPCode":"0",
            "etherType":"0x0800",
            "DSCP":"*",
            "description":"ping0",
            "action":"FORWARD"
        }
        ping0 = self.nuage_vsd_client.create_ingress_security_group_entry(name_description='ping0',
                                                                          iacl_template_id=iacl_template_id,
                                                                          extra_params=extra_params)
        pass

    def _prepare_l2_security_group_entries(self, policy_group_id, l2domain_id):
        # For the given VSD L2 managed subnet:
        # Create ingress policy that default does NOT allow IP traffic
        # Create egress policy that allows all
        # Create ingress security policy entry for ICMP-Type8-Code0 (echo) in pg
        # Create ingress security policy entry for ICMP-Type0-Code0 (echo reply) in pg
        # =? ping works in this pg, can be switched off/on via associating ports to the pg
        #
        # start policy group changes
        self.nuage_vsd_client.begin_l2_policy_changes(l2domain_id)
        # create ingress policy
        self.iacl_template = self._create_l2_ingress_acl_template(data_utils.rand_name("iacl_policy"), l2domain_id)
        self._create_ping_security_group_entries(policy_group_id, self.iacl_template[0]['ID'])
        self.eacl_templace = self._create_l2_egress_acl_template(data_utils.rand_name("eacl_policy"), l2domain_id)
        # Apply the policy changes
        self.nuage_vsd_client.apply_l2_policy_changes(l2domain_id)
        pass

    def _prepare_l3_security_group_entries(self, policy_group_id, l3domain_id):
        # For the given VSD L3 managed subnet:
        # Create ingress policy that default does NOT allow IP traffic
        # Create egress policy that allows all
        # Create ingress security policy entry for ICMP-Type8-Code0 (echo) in pg
        # Create ingress security policy entry for ICMP-Type0-Code0 (echo reply) in pg
        # =? ping works in this pg, can be switched off/on via associating ports to the pg
        #
        # start policy group changes
        self.nuage_vsd_client.begin_l3_policy_changes(l3domain_id)
        # create ingress policy
        self.iacl_template = self._create_l3_ingress_acl_template(data_utils.rand_name("iacl_policy"), l3domain_id)
        self._create_ping_security_group_entries(policy_group_id, self.iacl_template[0]['ID'])
        self.eacl_templace = self._create_l3_egress_acl_template(data_utils.rand_name("eacl_policy"), l3domain_id)
        # Apply the policy changes
        self.nuage_vsd_client.apply_l3_policy_changes(l3domain_id)
        pass

    def _create_l2_ingress_acl_template(self, name, domain_id):
        # do not allow deafault IP: will do this via security policy entries
        extra_params = {"allowAddressSpoof":True,
                        "priorityType":"NONE",
                        "statsLoggingEnabled": False,
                        "flowLoggingEnabled": False,
                        "defaultAllowNonIP": True,
                        "defaultAllowIP": False,
                        "active":True}
        iacl_template =  self.nuage_vsd_client.create_ingress_acl_template(name, constants.L2_DOMAIN,domain_id, extra_params=extra_params)
        return iacl_template
        pass

    def _create_l3_ingress_acl_template(self, name, domain_id):
        # do not allow deafault IP: will do this via security policy entries
        extra_params = {"allowAddressSpoof":True,
                        "priorityType":"NONE",
                        "statsLoggingEnabled": False,
                        "flowLoggingEnabled": False,
                        "defaultAllowNonIP": True,
                        "defaultAllowIP": False,
                        "active":True}
        iacl_template =  self.nuage_vsd_client.create_ingress_acl_template(name, constants.DOMAIN, domain_id, extra_params=extra_params)
        return iacl_template
        pass

    def _create_ingress_acl_template(self, name, domain_id):
        iacl_template =  self.nuage_vsd_client.create_ingress_acl_template(name, domain_id)
        return iacl_template
        pass

    def _create_ingress_security_group_entry(self, name_description, policy_group_id, extra_params=None):
        data = {
            "policyState":None,
            "networkType":"POLICYGROUP",
            "networkID": policy_group_id,
            "locationType":"POLICYGROUP",
            "locationID":policy_group_id,
            "associatedApplicationObjectType":None,
            "associatedApplicationObjectID":None,
            "associatedApplicationID":None,
            "addressOverride":None,
            "name": name_description,
            "mirrorDestinationID":None,
            "statsLoggingEnabled":False,
            "statsID":None,
            "stateful":True,
            "sourcePort":None,
            "protocol":"1",
            "priority":None,
            "ICMPType":"8",
            "ICMPCode":"0",
            "flowLoggingEnabled":False,
            "etherType":"0x0800",
            "DSCP":"*",
            "destinationPort":None,
            "action":"FORWARD",
            "entityScope":None,
            "parentType":None,
            "parentID":None,
            "owner":None,
            "lastUpdatedBy":None,
            "ID":None,
            "externalID":None
        }

        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=constants.INGRESS_ACL_TEMPLATE,
            resource_id=policy_group_id,
            child_resource=constants.INGRESS_ACL_ENTRY_TEMPLATE)
        result = self.post(res_path, data)
        return result

    def _create_l2_egress_acl_template(self, name, domain_id):
        extra_params = {"allowAddressSpoof":True,
                        "priorityType":"NONE",
                        "statsLoggingEnabled": False,
                        "flowLoggingEnabled": False,
                        "defaultAllowNonIP": True,
                        "defaultAllowIP": False,
                        "active":True}
        eacl_template =  self.nuage_vsd_client.create_egress_acl_template(name, constants.L2_DOMAIN, domain_id, extra_params=extra_params)
        return eacl_template
        pass

    def _create_l3_egress_acl_template(self, name, domain_id):
        extra_params = {"allowAddressSpoof":True,
                        "priorityType":"NONE",
                        "statsLoggingEnabled": False,
                        "flowLoggingEnabled": False,
                        "defaultAllowNonIP": True,
                        "defaultAllowIP": False,
                        "active":True}
        eacl_template =  self.nuage_vsd_client.create_egress_acl_template(name, constants.DOMAIN, domain_id, extra_params=extra_params)
        return eacl_template
        pass

    def _create_egress_acl_template(self, name, template_id):
        eacl_template =  self.nuage_vsd_client.create_egress_acl_template(name, template_id)
        return eacl_template
        pass

    def _create_os_l2_vsd_managed_subnet(self, vsd_l2_subnet):
        network = self.create_network(network_name=data_utils.rand_name('osl2network-'))
        kwargs = {
            'network': network,
            'cidr': base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            'mask_bits': base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR.prefixlen,
            'net_partition': CONF.nuage.nuage_default_netpartition,
            'nuagenet': vsd_l2_subnet[0]['ID']
            # 'tenant_id': None
        }
        subnet = self._create_subnet(**kwargs)
        return network, subnet

    def _create_os_l3_vsd_managed_subnet(self,vsd_l3_subnet):
        network = self.create_network(network_name=data_utils.rand_name('osl3network-'))
        kwargs = {
            'network': network,
            'cidr': base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            'mask_bits': base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR.prefixlen,
            'net_partition': CONF.nuage.nuage_default_netpartition,
            'nuagenet': vsd_l3_subnet[0]['ID']
            # 'tenant_id': None
        }
        subnet = self._create_subnet(**kwargs)
        return network, subnet

    def _create_os_l3_vsd_managed_subnet(self,vsd_l3_subnet, cidr=None):
        network = self.create_network(network_name=data_utils.rand_name('osl3network'))
        if cidr is None:
            cidr = base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR
            netmask = base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR.prefixlen
        else:
            cidr = cidr
            netmask = cidr.prefixlen
        kwargs = {
            'name': data_utils.rand_name('osl3subnet'),
            'network': network,
            'cidr': cidr,
            'mask_bits': netmask,
            'net_partition': CONF.nuage.nuage_default_netpartition,
            'nuagenet': vsd_l3_subnet[0]['ID']
        }
        subnet = self.create_subnet(**kwargs)
        return network, subnet

    def _create_server(self, name, network_id, port_id=None):

        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        self.security_group = \
            self._create_security_group(tenant_id=self.tenant_id)
        security_groups = [{'name': self.security_group['name']}]

        network = {'uuid': network_id}
        if port_id is not None:
            network['port'] = port_id

        # create_kwargs = {
        #     'networks': [
        #         {'uuid': network_id},
        #     ],
        #     'key_name': keypair['name'],
        #     'security_groups': security_groups,
        # }
        # if port_id is not None:
        #     create_kwargs['networks'][0]['port'] = port_id
        # server = self.create_server(name=name,
        #                             **create_kwargs)
        server = self.create_server(
            name=name,
            networks=[network],
            key_name=keypair['name'],
            security_groups=security_groups,
            wait_until='ACTIVE')

        return server

    def _create_2nic_server(self, name, network_id_1, port_1, network_id_2, port_2):

        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        self.security_group = \
            self._create_security_group(tenant_id=self.tenant_id)
        security_groups = [{'name': self.security_group['name']}]
        # pass this security group to port_id_1, to make ssh work
        port_kwargs = {
            'security_groups': [self.security_group['id']]
        }
        self.update_port(port_1, **port_kwargs)

        create_kwargs = {
            'networks': [
                {'uuid': network_id_1},
                {'uuid': network_id_2}
            ],
            'key_name': keypair['name'],
            'security_groups': security_groups,
        }
        create_kwargs['networks'][0]['port'] = port_1['id']
        create_kwargs['networks'][1]['port'] = port_2['id']

        server = self.create_server(name=name, **create_kwargs)
        # self.servers.append(server)
        return server

    def _create_network(self, client=None, tenant_id=None,
                        namestart='network-smoke-'):
        if not client:
            client = self.networks_client
        if not tenant_id:
            tenant_id = client.tenant_id
        name = data_utils.rand_name(namestart)
        result = client.create_network(name=name, tenant_id=tenant_id)
        network = result['network']
        # network = net_resources.DeletableNetwork(client=client,
        #                                          **result['network'])
        self.assertEqual(network['name'], name)
        self.addCleanup(client.delete_network, network['id'] )

        #self.addCleanup(self.delete_wrapper, network.delete)
        return network

    def _create_connectivity_VM(self, public_network_id, vsd_l2_subnet, vsd_l2_port):
        # Create an intermediate VM with FIP and a second nic in the VSD network,
        # So that we can ssh into this VM and check ping on the second NIC, which
        # is a port that we associated/disassociate to the policy group
        network = self._create_network(client=None, tenant_id=None)
        router = self._get_router(tenant_id=None, client=self.admin_routers_client)
        kwargs = {
            'network': network,
            'cidr': OS_CONNECTING_NW_CIDR,
            'mask_bits': OS_CONNECTING_NW_CIDR.prefixlen,
            'gateway': OS_CONNECTING_NW_GW
        }
        subnet = self._create_subnet(**kwargs)
        # subnet_kwargs = dict(network=network, client=None)
        # # use explicit check because empty list is a valid option
        # subnet = self._create_subnet(**subnet_kwargs)
        self.admin_routers_client.add_router_interface(router_id=router['id'], subnet_id=subnet['id'])
        # subnet.add_to_router(router.id)
        # Set the router gateway to the public FIP network
        self.admin_routers_client.update_router_with_snat_gw_info(
            router['id'],
            external_gateway_info={
                'network_id': CONF.network.public_network_id,
                'enable_snat': True})
        kwargs= {'name': data_utils.rand_name('osport')}
        # port = self.create_port(network=network,
        #                          namestart='osport-1')
        port = self.create_port(network=network, **kwargs)

        # Create floating IP with FIP rate limiting
        result = self.floating_ips_client.create_floatingip(
            floating_network_id=CONF.network.public_network_id,
            port_id=port['id'],
            nuage_fip_rate='5')
        # Add it to the list so it gets deleted afterwards
        self.floating_ips.append(result['floatingip'])
        # convert to format used throughout this file
        floating_ip = net_resources.DeletableFloatingIp(
            client=self.floating_ips_client,
            **result['floatingip'])

        # noew create the VM with 2 vnics
        server = self._create_2nic_server(name=data_utils.rand_name('IC-VM'),
                                          network_id_1=network['id'], port_1=port,
                                          network_id_2=vsd_l2_subnet[0]['ID'], port_2=vsd_l2_port)

        self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server)
        # store router, subnet and port id clear gateway and interface before cleanup start
        self.conn_router_id = router['id']
        self.conn_subnet_id = subnet['id']
        self.conn_port_id = port['id']
        return server
        pass

    def _create_vsdmgd_connectivity_VM(self, public_network_id, vsd_l2_subnet, vsd_l2_port):
        # Create an intermediate VM with FIP and a second nic in the VSD network,
        # So that we can ssh into this VM and check ping on the second NIC, which
        # is a port that we associated/disassociate to the policy group
        network = self._create_network(client=None, tenant_id=None)
        router = self._get_router(client=None, tenant_id=None)
        kwargs = {
            'network': network,
            'cidr': OS_CONNECTING_NW_CIDR,
            'mask_bits': OS_CONNECTING_NW_CIDR.prefixlen,
            'gateway': OS_CONNECTING_NW_GW
        }
        subnet = self._create_subnet(**kwargs)
        # subnet_kwargs = dict(network=network, client=None)
        # # use explicit check because empty list is a valid option
        # subnet = self._create_subnet(**subnet_kwargs)
        self.routers_client.add_router_interface(router_id=router['id'], subnet_id=subnet['id'])
        # subnet.add_to_router(router.id)
        # Set the router gateway to the public FIP network
        self.admin_client.update_router_with_snat_gw_info(
            router['id'],
            external_gateway_info={
                'network_id': CONF.network.public_network_id,
                'enable_snat': True})
        kwargs= {'name': data_utils.rand_name('osport')}
        # port = self.create_port(network=network,
        #                          namestart='osport-1')
        port = self.create_port(network=network, **kwargs)

        # Create floating IP with FIP rate limiting
        result = self.floating_ips_client.create_floatingip(
            floating_network_id=CONF.network.public_network_id,
            port_id=port['id'],
            nuage_fip_rate='5')
        # Add it to the list so it gets deleted afterwards
        self.floating_ips.append(result['floatingip'])
        # convert to format used throughout this file
        floating_ip = net_resources.DeletableFloatingIp(
            client=self.floating_ips_client,
            **result['floatingip'])

        # noew create the VM with 2 vnics
        server = self._create_2nic_server(name=data_utils.rand_name('IC-VM'),
                                          network_id_1=network['id'], port_1=port,
                                          network_id_2=vsd_l2_subnet[0]['ID'], port_2=vsd_l2_port)

        self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server)
        # store router, subnet and port id clear gateway and interface before cleanup start
        self.conn_router_id = router['id']
        self.conn_subnet_id = subnet['id']
        self.conn_port_id = port['id']
        return server
        pass

    def _create_connectivity_VM_vsd_floatingip(self, public_network_id, os_l3_network, os_l3_port, vsd_l3_subnet, vsd_l3_port, floatingip):
        # Create an intermediate VM with FIP and a second nic in the VSD network,
        # So that we can ssh into this VM and check ping on the second NIC, which
        # is a port that we associated/disassociate to the policy group
        # network = self._create_network(client=None, tenant_id=None)
        # kwargs = {
        #     'network': network,
        #     'cidr': OS_CONNECTING_NW_CIDR,
        #     'mask_bits': OS_CONNECTING_NW_CIDR.prefixlen,
        #     'gateway': OS_CONNECTING_NW_GW
        # }
        # subnet = self._create_subnet(**kwargs)
        #
        # kwargs= {'name': data_utils.rand_name('osport')}
        # # port = self.create_port(network=network,
        # #                          namestart='osport-1')
        # port = self.create_port(network=network, **kwargs)
        #
        # # associate OS port to VSD floatingip
        # self._associate_fip_to_port(port, floatingip['id'])
        # # convert to format used throughout this file
        # floating_ip = net_resources.DeletableFloatingIp(
        #     client=self.os.network_client,
        #     **result['floatingip'])

        # noew create the VM with 2 vnics
        server = self._create_2nic_server(name=data_utils.rand_name('IC-VM'),
                                          network_id_1=os_l3_network['id'], port_1=os_l3_port,
                                          network_id_2=vsd_l3_subnet[0]['ID'], port_2=vsd_l3_port)

        self.floating_ip_tuple = Floating_IP_tuple(floatingip, server)
        # store router, subnet and port id clear gateway and interface before cleanup start
        # self.conn_router_id = router['id']
        # self.conn_subnet_id = subnet['id']
        # self.conn_port_id = port['id']
        return server
        pass

    def _clear_connectivity_vm_interfaces(self, router_id, subnet_id, port_id):
        # Clear router gateway
        self.admin_routers_client.update_router_with_snat_gw_info(
            router_id,
            external_gateway_info={}
        )
        self.ports_client.delete_port(port_id)
        # remove router-interface
        self.admin_routers_client.remove_router_interface(router_id=router_id, subnet_id=subnet_id)
        pass

    def _update_ingress_template_block_traffic(self, iacl_template_id):
        # update the ingress acl template to block all traffic
        update_params = {
            "defaultAllowNonIP": False,
            "defaultAllowIP": False
        }
        self.nuage_vsd_client.update_ingress_acl_template(iacl_template_id, extra_params=update_params)
        pass

    def _update_ingress_template_allow_traffic(self, iacl_template_id):
        # update the ingress acl template to allow all traffic
        update_params = {
            "defaultAllowNonIP": True,
            "defaultAllowIP": True
        }
        self.nuage_vsd_client.update_ingress_acl_template(iacl_template_id, extra_params=update_params)
        pass

    def _update_egress_template_block_traffic(self, eacl_template_id):
        # update the egress acl template to block all traffic
        update_params = {
            "defaultAllowNonIP": False,
            "defaultAllowIP": False
        }
        self.nuage_vsd_client.update_egress_acl_template(eacl_template_id, extra_params=update_params)
        pass

    def _update_egress_template_allow_traffic(self, eacl_template_id):
        # update the egress acl template to allow all traffic
        update_params = {
            "defaultAllowNonIP": True,
            "defaultAllowIP": True
        }
        self.nuage_vsd_client.update_egress_acl_template(eacl_template_id, extra_params=update_params)
        pass

    def _get_server_key(self, server):
        return self.keypairs[server['key_name']]['private_key']

    def _configure_eth1_server(self, server, floating_ip_address):
        private_key = self._get_server_key(server)
        ssh_client = self.get_remote_client(floating_ip_address,
                                            private_key=private_key)
        command = "sudo sh -c 'echo -e \"\nauto eth1\niface eth1 inet dhcp\n\" >> /etc/network/interfaces'"
        result = ssh_client.exec_command(command)
        command = 'cat /etc/network/interfaces'
        result = ssh_client.exec_command(command)
        #
        # VERY DIRTY: I know ..
        # trying sudo /sbin/ifup eth1 fails with error message
        # ifup: no dhcp clients found
        # ifup: don't seem to have all the variables for eth1/inet
        # No clue why, so I use the 'hard' way: reboot the server
        #
        command = "sudo /sbin/reboot"
        result = ssh_client.exec_command(command)
        return result

    def _check_vm_policy_group_ping(self,server, floating_ip_address, ping_vm_ipaddress, wait_time):
        # wait_time for speeding up testing
        #  bigger value in case connectivity is expected
        #  smaller value in case conencitivity is NOT expected (this method exits faster)
        private_key = self._get_server_key(server)
        ssh_client = self.get_remote_client(floating_ip_address,
                                            private_key=private_key)
        # the "bl**y client exec command cannot cope with exit status <> 0.
        # So we add an echo $? (always succeeds) and provides the exit status of the ping command
        # command = "ping -c1 -q " + "10.12.14.16  >> /dev/null ; echo $?"
        # result = ssh_client.exec_command(command)
        #command = "ping -c1 -w5 -q " + ping_vm_ipaddress + " >> /dev/null ; echo $?"
        #command = "ping -c1 -w" + str(wait_time) + " -q " + ping_vm_ipaddress + " >> /dev/null ; echo $?"

        # result = ssh_client.exec_command(command)
        # if result.__contains__("0"): connectivity = True
        # else: connectivity = False


        command = "ping -c1 -w" + str(wait_time) + " -q " + ping_vm_ipaddress
        try:
            ssh_client.exec_command(command)
            connectivity = True
        except (exceptions.SSHExecCommandFailed) as e:
            connectivity = False

        return connectivity


    def _create_port_with_allowed_address_pair(self, allowed_address_pairs,
                                               net_id):
        body = self.ports_client.create_port(
            network_id=net_id,
            allowed_address_pairs=allowed_address_pairs)
        self.addCleanup(self.ports_client.delete_port, body['port']['id'] )
        return body
    def _get_port_by_id(self, port_id):
        body = self.ports_client.list_ports()
        ports = body['ports']
        port = [p for p in ports if p['id'] == port_id]
        msg = 'Created port not found in list of ports returned by Neutron'
        self.assertTrue(port, msg)
        return port

    def _verify_port_allowed_address_fields(self, port,
                                            addrpair_ip, addrpair_mac):
        ip_address = port['allowed_address_pairs'][0]['ip_address']
        mac_address = port['allowed_address_pairs'][0]['mac_address']
        self.assertEqual(ip_address, addrpair_ip)
        self.assertEqual(mac_address, addrpair_mac)

    def _remove_allowed_addres_pair_from_port(self, port):
        kwargs = {'allowed_address_pairs': []}
        self.update_port(port,**kwargs)

    @classmethod
    def _create_vsd_floatingip_pool(self):
        # Create a VSD floatingip
        # data = {"vnID":None,
        #         "uplinkGWVlanAttachmentID":None,
        #         "sharedResourceParentID":None,
        #         "underlay": True,
        #         "uplinkVPortName":None,
        #         "uplinkInterfaceMAC":None,
        #         "uplinkInterfaceIP":None,
        #         "type":"FLOATING",
        #         "netmask":"255.255.255.0",
        #         "name":"myFIPnet",
        #         "gateway":"10.20.30.1",
        #         "ECMPCount":None,
        #         "domainRouteTarget":None,
        #         "domainRouteDistinguisher":None,
        #         "DHCPManaged":False,
        #         "description":"",
        #         "backHaulVNID":None,
        #         "backHaulRouteTarget":None,
        #         "backHaulRouteDistinguisher":None,
        #         "address":"10.20.30.0",
        #         "accessRestrictionEnabled":False,
        #         "entityScope":None,
        #         "parentType":None,
        #         "parentID":None,
        #         "owner":None,
        #         "lastUpdatedBy":None,
        #         "ID":None,
        #         "externalID":None
        #         }
        name = data_utils.rand_name('fip-pool')
        address = IPAddress(VSD_FIP_POOL_CIDR.first )
        netmask = VSD_FIP_POOL_CIDR.netmask
        gateway = VSD_FIP_POOL_GW
        extra_params = {
            "underlay": True
        }
        vsd_fip_pool = self.nuage_vsd_client.create_floatingip_pool(name=name,
                                                                    address=str(address),
                                                                    gateway=gateway,
                                                                    netmask=str(netmask),
                                                                    extra_params=extra_params)
        self.vsd_shared_domain.append(vsd_fip_pool)
        return vsd_fip_pool

    def _claim_vsd_floating_ip(self, l3domain_id, vsd_fip_pool_id):
        claimed_fip = self.nuage_vsd_client.claim_floatingip(l3domain_id, vsd_fip_pool_id)
        return claimed_fip

    def _associate_fip_to_port(self, port, fip_id):
        kwargs = {"nuage_floatingip": {'id': fip_id }}
        self.update_port(port, **kwargs)

    def _disassociate_fip_from_port(self, port):
        kwargs = {"nuage_floatingip": None}
        self.update_port(port, **kwargs)

    def _check_fip_in_list(self, claimed_fip_id, fip_list):
        fip_found = False
        for fip in fip_list['nuage_floatingips']:
            if fip['id'] == claimed_fip_id:
                fip_found=True
        return fip_found

    def _check_fip_in_port_show(self, port_id, claimed_fip_id):
        fip_found = False
        show_port = self.ports_client.show_port(port_id)
        # first check if 'nuage_flaotingip' is not None
        if show_port['port']['nuage_floatingip'] is not None:
            if show_port['port']['nuage_floatingip']['id'] == claimed_fip_id:
                fip_found = True
        return fip_found


class VSDManagedPortAttributestTest(BaseVSDManagedPortAttributest):

    @classmethod
    def resource_setup(cls):
        super(VSDManagedPortAttributestTest, cls).resource_setup()
        cls.iacl_template = ''
        cls.eacl_templace = ''

    ######################################################################################################################
    ######################################################################################################################
    # Redirect targets
    ######################################################################################################################
    ######################################################################################################################

    @nuage_test.header()
    def test_create_delete_os_redirection_target_l2_mgd_subnet(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        #  When I create a redirection-target in the VSD-L2-Managed-Subnet
        os_redirect_target = self._create_redirect_target_in_l2_subnet(subnet)
        # Then I expect the redirection-target in my list
        my_rt_found = self._find_redirect_target_in_list(os_redirect_target['nuage_redirect_target']['id'], subnet)
        self.assertTrue(my_rt_found, "Did not find my redirect-target in the list")
        # And, as I do not trus the VSD, I expect the redirect-targetit to be present in the VSD as well ;-)
        vsd_redirect_target = self.nuage_vsd_client.get_redirection_target(
            constants.L2_DOMAIN, vsd_l2_subnet[0]['ID'], filters='ID',
            filter_value=os_redirect_target['nuage_redirect_target']['id'])

        # When I associate a port to the redirectict-target
        rtport = self.create_port(network)
        self._associate_rt_port(rtport, os_redirect_target)
        # Then I expect the port in the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(rtport, os_redirect_target)
        self.assertTrue(port_present,
                        "Associated port not present in show nuage redirect target response")
        # When I disassociate the red0rect-target from the port
        self._disassociate_rt_port(rtport, os_redirect_target)
        # I expect the port to be gone from the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(rtport, os_redirect_target)
        self.assertEqual(port_present, False,
                         message="Disassociated port still present in  show nuage-redirect-target-response")
        # When I delete the redirect-target
        self.nuage_network_client.delete_redirection_target(os_redirect_target['nuage_redirect_target']['id'])
        # I expect the redirect-target to be gone from the list
        my_rt_found = self._find_redirect_target_in_list(os_redirect_target, subnet)
        self.assertEqual(False, my_rt_found,
                         message="Deleted nuage_redirect_target still present in subnet")
        # And the reditrect-target is also deleted on the VSD
        vsd_redirect_target = self.nuage_vsd_client.get_redirection_target(
            constants.L2_DOMAIN, vsd_l2_subnet[0]['ID'], filters='ID',
            filter_value=os_redirect_target['nuage_redirect_target']['id'])
        self.assertEqual(vsd_redirect_target, '')
        pass

    @nuage_test.header()
    def test_create_delete_vsd_redirection_target_l2_mgd_subnet(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        #  When I create a redirection-target in the VSD-L2-Managed-Subnet on the VSD
        vsd_redirect_target = self.nuage_vsd_client.create_l2_redirect_target(vsd_l2_subnet[0]['ID'],
                                                                              data_utils.rand_name("vsd-rt"))
        # Fetch this redircet_target in OS, as this strucure is used throught the test
        redirect_target = self.nuage_network_client.show_redirection_target(vsd_redirect_target[0]['ID'])
        # Then I expect the redirection-target in my list
        my_rt_found = self._find_redirect_target_in_list(vsd_redirect_target[0]['ID'], subnet)
        self.assertTrue(my_rt_found, "Did not find my redirect-target in the list")
        # Verifying Redirect Target on VSD
        # redirect_target = self._verify_redirect_target(
        #     os_redirect_target, 'l2domains', vsd_l2_subnet[0], post_body)
        # When I associate a port to the redirectict-target
        rtport = self.create_port(network)
        self._associate_rt_port(rtport, redirect_target)
        # Then I expect the port in the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(rtport, redirect_target)
        message = "Associated port not present in show nuage redirect target response"
        self.assertTrue(port_present, message)
        # When I disassociate the red0rect-target from the port
        self._disassociate_rt_port(rtport, redirect_target)
        # I expect the port to be gone from the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(rtport, redirect_target)
        self.assertEqual(port_present, False,
                         message="Disassociated port still present in  show nuage-redirect-target-response")
        # When I delete the redirect-target
        self.nuage_network_client.delete_redirection_target(redirect_target['nuage_redirect_target']['id'])
        # I expect the redirect-target to be gone from the list
        my_rt_found = self._find_redirect_target_in_list(redirect_target, subnet)
        self.assertEqual(False, my_rt_found,
                         message="Deleteed nuage_redirect_target still present in subnet")
        # Verifying RT is deleted from VSD
        vsd_redirect_target = self.nuage_vsd_client.get_redirection_target(
            constants.L2_DOMAIN, vsd_l2_subnet[0]['ID'], filters='ID',
            filter_value=vsd_redirect_target[0]['ID'])
        self.assertEqual(vsd_redirect_target, '')
        pass

    @nuage_test.header()
    def test_create_delete_several_redirection_targets_l2_mgd_subnet(self):
        os_redirect_targets = []
        vsd_redirect_targets = []
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        #  When I create several redirection-target in the VSD-L2-Managed-Subnet
        #  both on openstack and VSD
        for i in range(SEVERAL_REDIRECT_TARGETS):
            os_redirect_targets.append(self._create_redirect_target_in_l2_subnet(subnet))
            vsd_redirect_target = self.nuage_vsd_client.create_l2_redirect_target(vsd_l2_subnet[0]['ID'],
                                                                                  data_utils.rand_name("vsd-rt"))
            # Fetch this redirect_target in OS, as this strucure is used throught the test
            vsd_redirect_targets.append(self.nuage_network_client.show_redirection_target(vsd_redirect_target[0]['ID']))
        # Then I expect the redirection-target in my list
        for i in range(SEVERAL_REDIRECT_TARGETS):
            my_os_rt_found = self._find_redirect_target_in_list(os_redirect_targets[i]['nuage_redirect_target']['id'], subnet)
            self.assertTrue(my_os_rt_found, "Did not find my redirect-target in the list")
            my_vsd_rt_found = self._find_redirect_target_in_list(vsd_redirect_targets[i]['nuage_redirect_target']['id'], subnet)
            self.assertTrue(my_vsd_rt_found, "Did not find my redirect-target in the list")
        #
        for i in range(SEVERAL_REDIRECT_TARGETS):
            rtport = self.create_port(network)
            # When I associate a port to the redirectict-target
            self._associate_rt_port(rtport, os_redirect_targets[i])
            # Then I expect the port in the show redirect-target response
            port_present = self._check_port_in_show_redirect_target(rtport, os_redirect_targets[i])
            self.assertTrue(port_present,
                            "Associated port not present in show nuage redirect target response")
            # When I disassociate the red0rect-target from the port        #
            self._disassociate_rt_port(rtport, os_redirect_targets[i])
            # Then I expect the port to be gone from the show redirect-target response
            port_present = self._check_port_in_show_redirect_target(rtport, os_redirect_targets[i])
            self.assertEqual(port_present, False,
                             message="Disassociated port still present in  show nuage-redirect-target-response")
        for i in range(SEVERAL_REDIRECT_TARGETS):
            # When I delete the redirect-target
            self.nuage_network_client.delete_redirection_target(os_redirect_targets[i]['nuage_redirect_target']['id'])
            # I expect the redirect-target to be gone from the list
            my_rt_found = self._find_redirect_target_in_list(os_redirect_targets[i], subnet)
            self.assertEqual(False, my_rt_found,
                             message="Deleted nuage_redirect_target still present in subnet")
            # And the redirect-target on VSD is also gone
            vsd_redirect_target = self.nuage_vsd_client.get_redirection_target(
                constants.L2_DOMAIN, vsd_l2_subnet[0]['ID'], filters='ID',
                filter_value=os_redirect_targets[i]['nuage_redirect_target']['id'])
            self.assertEqual(vsd_redirect_target, '')
            # When I delete the VSD created redirect-target
            self.nuage_vsd_client.delete_redirect_target(vsd_redirect_targets[i]['nuage_redirect_target']['id'])
            # Then I expect the redirect_target to be gone from my list
            my_vsd_rt_found = self._find_redirect_target_in_list(vsd_redirect_targets[i], subnet)
            self.assertEqual(False, my_vsd_rt_found,
                             message="Deleted nuage_redirect_target still present in subnet")
            # And the redirect-target on VSD is also gone
            vsd_redirect_target = self.nuage_vsd_client.get_redirection_target(
                constants.L2_DOMAIN, vsd_l2_subnet[0]['ID'], filters='ID',
                filter_value=vsd_redirect_targets[i]['nuage_redirect_target']['id'])
            self.assertEqual(vsd_redirect_target, '')
        pass

    @nuage_test.header()
    def test_create_delete_os_redirection_target_l3_mgd_subnet(self):
        # Given I have a VSD-L3-Managed-Subnet in openstack        #
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        #  When I create a redirection-target in the VSD-L3-Managed-Subnet
        os_redirect_target = self._create_redirect_target_in_l3_subnet(subnet)
        # Then I expect the redirection-target in my list
        my_rt_found = self._find_redirect_target_in_list(os_redirect_target['nuage_redirect_target']['id'], subnet)
        self.assertTrue(my_rt_found, "Did not find my redirect-target in the list")
        # check on VSD
        vsd_redirect_target = self.nuage_vsd_client.get_redirection_target(
            constants.DOMAIN, vsd_l3_domain[0]['ID'], filters='ID',
            filter_value=os_redirect_target['nuage_redirect_target']['id'])
        self.assertIsNotNone(vsd_redirect_target, message="OS created redirect target not found on VSD")
        # When I associate a port to the redirectict-target
        rtport = self.create_port(network)
        self._associate_rt_port(rtport, os_redirect_target)
        # Then I expect the port in the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(rtport, os_redirect_target)
        message = "Associated port not present in show nuage redirect target response"
        self.assertTrue(port_present, message)
        # When I disassociate the red0rect-target from the port
        self._disassociate_rt_port(rtport, os_redirect_target)
        # I expect the port to be gone from the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(rtport, os_redirect_target)
        self.assertEqual(port_present, False,
                         message="Disassociated port still present in  show nuage-redirect-target-response")
        # When I delete the redirect-target
        self.nuage_network_client.delete_redirection_target(os_redirect_target['nuage_redirect_target']['id'])
        # I expect the redirect-target to be gone from the list
        my_rt_found = self._find_redirect_target_in_list(os_redirect_target['nuage_redirect_target']['id'], subnet)
        self.assertEqual(False, my_rt_found,
                         message="Deleteed nuage_redirect_target still present in subnet")
        # And the redirect target on VSD is gone as well
        vsd_redirect_target = self.nuage_vsd_client.get_redirection_target(
            constants.DOMAIN, vsd_l3_domain[0]['ID'], filters='ID',
            filter_value=os_redirect_target['nuage_redirect_target']['id'])
        self.assertEqual(vsd_redirect_target, '')
        pass

    @nuage_test.header()
    def test_create_delete_vsd_redirection_target_l3_mgd_subnet(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        #  When I create a redirection-target in the VSD-L2-Managed-Subnet on the VSD
        vsd_redirect_target = self.nuage_vsd_client.create_l3_redirect_target(vsd_l3_domain[0]['ID'],
                                                                              data_utils.rand_name("vsd-rt"))
        # Fetch this redircet_target in OS, as this strucure is used throught the test
        redirect_target = self.nuage_network_client.show_redirection_target(vsd_redirect_target[0]['ID'])
        # Then I expect the redirection-target in my list
        my_rt_found = self._find_redirect_target_in_list(vsd_redirect_target[0]['ID'], subnet)
        self.assertTrue(my_rt_found, "Did not find my redirect-target in the list")
        # Verifying Redirect Target on VSD
        # redirect_target = self._verify_redirect_target(
        #     os_redirect_target, 'l2domains', vsd_l2_subnet[0], post_body)
        # # When I update the redirect-target
        # update_description = "VSD-created-and-OS-updated-redirect-target"
        # kwargs = {'description':update_description }
        # update_rt = self.nuage_network_client.update_redirection_target(redirect_target['nuage_redirect_target']['id'], **kwargs)
        # # self.nuage_vsd_client.update_redirect_target(redirect_target['nuage_redirect_target']['id'], update_params=update_params)
        # # I expect the updated item in my list
        # upd_redirect_target = self.client.show_redirection_target(redirect_target['nuage_redirect_target']['id'])
        # self.assertEqual(update_description, upd_redirect_target['descrip[tion'],
        #                  message="Update of redirect target failed")
        # When I associate a port to the redirectict-target
        rtport = self.create_port(network)
        self._associate_rt_port(rtport, redirect_target)
        # Then I expect the port in the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(rtport, redirect_target)
        message = "Associated port not present in show nuage redirect target response"
        self.assertTrue(port_present, message)
        # When I disassociate the red0rect-target from the port
        self._disassociate_rt_port(rtport, redirect_target)
        # I expect the port to be gone from the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(rtport, redirect_target)
        self.assertEqual(port_present, False,
                         message="Disassociated port still present in  show nuage-redirect-target-response")
        # When I delete the redirect-target
        self.nuage_network_client.delete_redirection_target(redirect_target['nuage_redirect_target']['id'])
        # I expect the redirect-target to be gone from the list
        my_rt_found = self._find_redirect_target_in_list(redirect_target, subnet)
        self.assertEqual(False, my_rt_found,
                         message="Deleteed nuage_redirect_target still present in subnet")
        # Verifying RT is deleted from VSD
        vsd_redirect_target = self.nuage_vsd_client.get_redirection_target(
            constants.DOMAIN, vsd_l3_domain[0]['ID'], filters='ID',
            filter_value=vsd_redirect_target[0]['ID'])
        self.assertEqual(vsd_redirect_target, '')
        pass

    @nuage_test.header()
    def test_create_delete_several_redirection_targets_l3_mgd_subnet(self):
        os_redirect_targets = []
        vsd_redirect_targets = []
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        #  When I create several redirection-target in the VSD-L2-Managed-Subnet
        #  both on openstack and VSD
        for i in range(SEVERAL_REDIRECT_TARGETS):
            os_redirect_targets.append(self._create_redirect_target_in_l3_subnet(subnet))
            vsd_redirect_target = self.nuage_vsd_client.create_l3_redirect_target(vsd_l3_domain[0]['ID'],
                                                                                  data_utils.rand_name("vsd-l3-rt"))
            # Fetch this redirect_target in OS, as this strucure is used throught the test
            vsd_redirect_targets.append(self.nuage_network_client.show_redirection_target(vsd_redirect_target[0]['ID']))
        # Then I expect the redirection-target in my list
        for i in range(SEVERAL_REDIRECT_TARGETS):
            my_os_rt_found = self._find_redirect_target_in_list(os_redirect_targets[i]['nuage_redirect_target']['id'], subnet)
            self.assertTrue(my_os_rt_found, "Did not find my redirect-target in the list")
            my_vsd_rt_found = self._find_redirect_target_in_list(vsd_redirect_targets[i]['nuage_redirect_target']['id'], subnet)
            self.assertTrue(my_vsd_rt_found, "Did not find my redirect-target in the list")
        #
        for i in range(SEVERAL_REDIRECT_TARGETS):
            rtport = self.create_port(network)
            # When I associate a port to the redirectict-target
            self._associate_rt_port(rtport, os_redirect_targets[i])
            # Then I expect the port in the show redirect-target response
            port_present = self._check_port_in_show_redirect_target(rtport, os_redirect_targets[i])
            self.assertTrue(port_present,
                            "Associated port not present in show nuage redirect target response")
            # When I disassociate the red0rect-target from the port        #
            self._disassociate_rt_port(rtport, os_redirect_targets[i])
            # Then I expect the port to be gone from the show redirect-target response
            port_present = self._check_port_in_show_redirect_target(rtport, os_redirect_targets[i])
            self.assertEqual(port_present, False,
                             message="Disassociated port still present in  show nuage-redirect-target-response")
        for i in range(SEVERAL_REDIRECT_TARGETS):
            # When I delete the redirect-target
            self.nuage_network_client.delete_redirection_target(os_redirect_targets[i]['nuage_redirect_target']['id'])
            # I expect the redirect-target to be gone from the list
            my_rt_found = self._find_redirect_target_in_list(os_redirect_targets[i], subnet)
            self.assertEqual(False, my_rt_found,
                             message="Deleted nuage_redirect_target still present in subnet")
            # And the redirect-target on VSD is also gone
            vsd_redirect_target = self.nuage_vsd_client.get_redirection_target(
                constants.DOMAIN, vsd_l3_domain[0]['ID'], filters='ID',
                filter_value=os_redirect_targets[i]['nuage_redirect_target']['id'])
            self.assertEqual(vsd_redirect_target, '')
            # When I delete the VSD created redirect-target
            self.nuage_vsd_client.delete_redirect_target(vsd_redirect_targets[i]['nuage_redirect_target']['id'])
            # Then I expect the redirect_target to be gone from my list
            my_vsd_rt_found = self._find_redirect_target_in_list(vsd_redirect_targets[i], subnet)
            self.assertEqual(False, my_vsd_rt_found,
                             message="Deleted nuage_redirect_target still present in subnet")
            # And the redirect-target on VSD is also gone
            vsd_redirect_target = self.nuage_vsd_client.get_redirection_target(
                constants.DOMAIN, vsd_l3_domain[0]['ID'], filters='ID',
                filter_value=vsd_redirect_targets[i]['nuage_redirect_target']['id'])
            self.assertEqual(vsd_redirect_target, '')
        pass

    @nuage_test.header()
    def test_create_os_redirection_target_same_name_diff_l2_mgd_subnet(self):
        # Given I have a VSD-L2-Managed-Subnet-x in openstack
        vsd_l2_subnet_x, l2dom_template_x = self._create_vsd_l2_managed_subnet()
        network_x, subnet_x = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet_x)
        #  And I have created a redirection-target in the VSD-L2-Managed-Subnet-x
        name = data_utils.rand_name("rt-same-name")
        os_redirect_target_x = self._create_redirect_target_in_l2_subnet(subnet_x, name)
        # When I have a VSD-L2-Managed-Subnet-y in openstack
        vsd_l2_subnet_y, l2dom_template_y = self._create_vsd_l2_managed_subnet()
        network_y, subnet_y = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet_y)
        #  When I create in VSD-L2-Managed-Subnet-y a redirect--target with the same name as in subnet_x
        os_redirect_target_y = self._create_redirect_target_in_l2_subnet(subnet_y, name)
        # I expect rt-y  to be in my list-y
        my_rt_found_y = self._find_redirect_target_in_list(os_redirect_target_y['nuage_redirect_target']['id'], subnet_y)
        self.assertTrue(my_rt_found_y, "Did not find my redirect-target in the list")
        # And rt-x in my list-x
        my_rt_found_X = self._find_redirect_target_in_list(os_redirect_target_x['nuage_redirect_target']['id'], subnet_x)
        self.assertTrue(my_rt_found_X, "Did not find my redirect-target in the list")
        pass

    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_create_os_redirection_target_same_name_same_l2_mgd_subnet_neg(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        #  And I have created a redirection-target in the VSD-L2-Managed-Subnet
        name = data_utils.rand_name("rt-same-name")
        os_redirect_target_x1 = self._create_redirect_target_in_l2_subnet(subnet, name)
        #  When I try to create a redirect target with the same name,
        # I expect this to fail
        msg = "Bad request: A Nuage redirect target with name '%s' already exists" % name
        self.assertRaisesRegexp(
            exceptions.BadRequest,
            msg,
            self._create_redirect_target_in_l2_subnet,
            subnet,
            name)
        pass


    # TODO: temporay test unless VSD-14419 is resolved, at least we test for correct error message
    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_associate_two_port_same_l2_os_redirection_target_neg2(self):
        self.assertRaisesRegex(
            exceptions.ServerFault,
            "Cannot have more than 1 vPort under a redirectiontarget with redundancy disabled",
            self.test_associate_two_port_same_l2_os_redirection_target_neg
        )

    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_associate_two_port_same_l2_os_redirection_target_neg(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        #  And I have created a redirection-target in the VSD-L2-Managed-Subnet
        os_redirect_target = self._create_redirect_target_in_l2_subnet(subnet)
        # And this rt is associated to a port
        rtport_1 = self.create_port(network)
        self._associate_rt_port(rtport_1, os_redirect_target)
        port_present = self._check_port_in_show_redirect_target(rtport_1, os_redirect_target)
        self.assertTrue(port_present,
                        "Associated port not present in show nuage redirect target response")
        # When I disassociate the red0rect-target from the port        #
        #  When I try to create associate another port to the same redirect target, which has redundancy disabled (l2)

        # I expect this to fail
        rtport_2 = self.create_port(network)
        msg = "Cannot have more than 1 vPort under a redirectiontarget with redundancy disabled"
        self.assertRaisesRegexp(
            exceptions.BadRequest,
            msg,
            self._associate_rt_port,
            rtport_2,
            os_redirect_target)


    # TODO: temporay test unless VSD-14420 is resolved, at least we test for getting an exception
    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_create_os_l2_redirection_target_redundancy_enabled_neg2(self):
        self.assertRaisesRegex(
            exceptions.ServerFault,
            "Got server fault",
            self.test_create_os_l2_redirection_target_redundancy_enabled_neg
        )

    @test.attr(type=['negative'])
    def test_create_os_l2_redirection_target_redundancy_enabled_neg(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        # And I have created a redirection-target in the VSD-L2-Managed-Subnet
        post_body = { 'insertion_mode': 'VIRTUAL_WIRE',
                      'redundancy_enabled': 'True',
                      'subnet_id': subnet['id'],
                      'name': "rt-l2-redundancy-enabled-fail"}

        # TODO: Need a valid error message, this message should fail ! See VSD-14420
        msg="A valid message why this is a a bad request"
        self.assertRaisesRegexp(
            exceptions.BadRequest,
            msg,
            self.nuage_network_client.create_redirection_target,
            **post_body
        )

    # TODO: temporay test unless VSD-14420 is resolved, at least we test for getting an exception
    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_create_os_l2_redirection_target_insertion_mode_l3_neg2(self):
        self.assertRaisesRegex(
            exceptions.ServerFault,
            "Got server fault",
            self.test_create_os_l2_redirection_target_insertion_mode_l3_neg
        )

    @test.attr(type=['negative'])
    # @nuage_test.nuage_skip_because(message="VSD-14421")
    @nuage_test.header()
    def test_create_os_l2_redirection_target_insertion_mode_l3_neg(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        #  And I have created a redirection-target in the VSD-L2-Managed-Subnet
        post_body = { 'insertion_mode': 'L3',
                      'redundancy_enabled': 'False',
                      'subnet_id': subnet['id'],
                      'name': "rt-l2-insertion-mode-l3-fail"}

        # TODO: Need a valid error message, this message should fail ! See VSD-14420
        msg="A valid message why this is a a bad request"
        self.assertRaisesRegexp(
            exceptions.BadRequest,
            msg,
            self.nuage_network_client.create_redirection_target,
            **post_body
        )


    # TODO: temporay test unless VSD-14421 is resolved, at least we test for getting an exception
    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_os_redirection_targets_bad_insertion_mode_neg2(self):
        self.assertRaisesRegex(
            exceptions.ServerFault,
            "Got server fault",
            self.test_os_redirection_targets_bad_insertion_mode_neg
        )

    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_os_redirection_targets_bad_insertion_mode_neg(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)

        #  When I try to create a redirection-target with an unknown insertion_mode
        post_body = { 'insertion_mode': 'L2',
                      'redundancy_enabled': 'False',
                      'subnet_id': subnet['id'],
                      'name': "rt-l2-insertion-mode-l2-fail"}

        # I expect a badRequest
        # TODO: Need a valid error message, this message should fail ! See VSD-14421
        msg="A valid message why this is a a bad request"

        self.assertRaisesRegexp(
            exceptions.BadRequest,
            msg,
            self.nuage_network_client.create_redirection_target,
            **post_body
        )

    @test.attr(type=['negative'])
    @nuage_test.header()
    def test_multiple_L2_vsd_redirection_targets_per_port_neg(self):
        vsd_redirect_targets = []
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_templ = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        #  And I have several VSD created redirection-target in the VSD-L2-Managed-Subnet
        for i in range(2):
            vsd_redirect_target = self.nuage_vsd_client.create_l2_redirect_target(vsd_l2_subnet[0]['ID'],
                                                                                  data_utils.rand_name("vsd-rt"))
            # Fetch this redirect_target in OS, as this strucure is used throught the test
            vsd_redirect_targets.append(self.nuage_network_client.show_redirection_target(vsd_redirect_target[0]['ID']))
        # When I try to associate these  multiple vsd created redirect targets per port with redundancy disabled
        # Then I expect a failure
        rtport = self.create_port(network)
        self.assertRaisesRegexp(
            exceptions.BadRequest,
            EXPECT_NO_MULTIPLE_RT_MSG,
            self._associate_multiple_rt_port,
            rtport,
            vsd_redirect_targets)


    ######################################################################################################################
    ######################################################################################################################
    # PolicyGroups
    ######################################################################################################################
    ######################################################################################################################

    @nuage_test.header()
    def test_l2_associate_port_to_policygroup(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a VSD creeated policy group
        vsd_l2_subnet, l2_domtmpl = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        policy_group = self.nuage_vsd_client.create_policygroup(constants.L2_DOMAIN,
                                                                    vsd_l2_subnet[0]['ID'],
                                                                    name='myVSDpg-1',
                                                                    type='SOFTWARE',
                                                                    extra_params=None)
        # When I retrieve the VSD-L2-Managed-Subnet
        policy_group_list = self.nuage_network_client.list_nuage_policy_group_for_subnet(subnet['id'])
        # I expect the policyGroup in my list
        pg_present = self._check_policy_group_in_list(policy_group[0]['ID'], policy_group_list)
        self.assertTrue(pg_present,"Did not find vsd policy group in policy group list")
        # And it has no external ID
        self.assertIsNone(policy_group[0]['externalID'],
                          "Policy Group has an external ID, while it should not")

        show_pg = self.nuage_network_client.show_nuage_policy_group(policy_group[0]['ID'])
        # When I create a port in the subnet
        port = self.create_port(network)
        # And I associate the port with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-pg'
        }
        self.update_port(port, **kwargs)
        # Then I expext the port in the show policy group response
        port_present = self._check_port_in_policy_group(port['id'], policy_group[0]['ID'])
        self.assertTrue(port_present, "Port(%s) assiociated to policy group (%s) is not present" %
                        (port['id'], policy_group[0]['ID']))
        # When I disassociate the port from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg'
        }
        self.update_port(port, **kwargs)
        # Then I do NOT expect the port in the show plicy group response
        port_present = self._check_port_in_policy_group(port['id'], policy_group[0]['ID'])
        self.assertFalse(port_present, "Port(%s) disassiociated to policy group (%s) is still present" %
                        (port['id'], policy_group[0]['ID']))
        pass

    @nuage_test.header()
    def test_l2_associate_port_to_policygroups(self):
        policy_groups = []
        # Given I have a VSD-L2-Managed-Subnet
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        # And I have multiple policy_groups
        for i in range(SEVERAL_POLICY_GROUPS):
            policy_groups.append(self.nuage_vsd_client.create_policygroup(constants.L2_DOMAIN,
                                                                             vsd_l2_subnet[0]['ID'],
                                                                             name='myVSDpg-%s' % i,
                                                                             type='SOFTWARE',
                                                                             extra_params=None))
        # When I create  a port
        port = self.create_port(network)
        # And associate this port with all these policy groups
        pg_id_list = []
        for i in range(SEVERAL_POLICY_GROUPS):
            pg_id_list.append(policy_groups[i][0]['ID'])
        kwargs = {
            'nuage_policy_groups': pg_id_list,
        }
        self.update_port(port,**kwargs)
        # When I retrieve the port
        show_port = self.ports_client.show_port(port['id'])
        # Then I expext all policy groups in the response
        all_pg_present = self._check_all_policy_groups_in_show_port(pg_id_list, show_port)
        self.assertTrue(all_pg_present, "Port does not contain all associated policy groups")
        # When I disassociate 1 policy group from the port (e.g. the last one)
        pg_id_list = []
        for i in range(SEVERAL_POLICY_GROUPS - 1):
            pg_id_list.append(policy_groups[i][0]['ID'])
        kwargs = {
            'nuage_policy_groups': pg_id_list,
        }
        self.update_port(port, **kwargs)
        # Then I do NOT expect this policy group in the show port response
        show_port = self.ports_client.show_port(port['id'])
        pg_present = self._check_policy_group_in_show_port([policy_groups[i][0]['ID']], show_port)
        self.assertFalse(pg_present, "Disassociated policygroup stu=ill present in show port")
        # When I disassociate all policy groups from the port
        kwargs = {
            'nuage_policy_groups': []
        }
        self.update_port(port,**kwargs)
        # Then I do NOT expect the policy Groups in the show port response
        show_port = self.ports_client.show_port(port['id'])
        self.assertEmpty(show_port['port']['nuage_policy_groups'],
                         "Port-show list disassociated ports")
        pass

    @nuage_test.header()
    def test_l2_associate_multiple_ports_to_policygroups(self):
        policy_groups = []
        ports = []
        # Given I have a VSD-L2-Managed-Subnet
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        # And I have multiple policy_groups
        for i in range(SEVERAL_POLICY_GROUPS):
            policy_groups.append(self.nuage_vsd_client.create_policygroup(constants.L2_DOMAIN,
                                                                          vsd_l2_subnet[0]['ID'],
                                                                          name='myVSDpg-%s' % i,
                                                                          type='SOFTWARE',
                                                                          extra_params=None))
        for i in range(SEVERAL_PORTS):
            # When I create multiple ports
            ports.append(self.create_port(network))
        # And associate each port with all these policy groups
        pg_id_list = []
        for i in range(SEVERAL_POLICY_GROUPS):
            pg_id_list.append(policy_groups[i][0]['ID'])
        kwargs = {
            'nuage_policy_groups': pg_id_list,
        }
        for i in range(SEVERAL_PORTS):
            self.update_port(ports[i], **kwargs)
        # When I retrieve each port
        for i in range(SEVERAL_PORTS):
            show_port = self.ports_client.show_port(ports[i]['id'])
            # Then I expext all policy groups in the response
            all_pg_present = self._check_all_policy_groups_in_show_port(pg_id_list, show_port)
            self.assertTrue(all_pg_present, "Port does not contain all associated policy groups")
        # When I retreive each policy group
        for i in range(SEVERAL_POLICY_GROUPS):
            # Then I expect the response to contain all the ports
            for j in range(SEVERAL_PORTS):
                port_present = self._check_port_in_policy_group(ports[j]['id'], policy_groups[i][0]['ID'])
                self.assertTrue(port_present, "Port(%s) not present in policy group(%s)" %
                                (ports[j]['id'], policy_groups[i][0]['ID']))
        # When I disassociate all policy groups from each port
        kwargs = {
            'nuage_policy_groups': []
        }
        for i in range(SEVERAL_PORTS):
            self.update_port(ports[i],**kwargs)
            # Then I do NOT expect the policy Groups in the show port response
            show_port = self.ports_client.show_port(ports[i]['id'])
            self.assertEmpty(show_port['port']['nuage_policy_groups'],
                             "Port-show list disassociated ports")
            # And I do not expect this port in any of the policy groups
            for j in range(SEVERAL_POLICY_GROUPS):
                port_present = self._check_port_in_policy_group(ports[i]['id'], policy_groups[j][0]['ID'])
                self.assertFalse(port_present, 'disassociated port (%s) still present in policy group(%s)' %
                                 (ports[i]['id'], policy_groups[j][0]['ID']))
        pass

    @nuage_test.header()
    def test_vsd_multiple_l2_policygroup(self):
        policy_groups = []
        # Given I have a VSD-L2-Managed-Subnet
        vsd_l2_subnet, l2dom_templ = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        # When I create several policy groups
        for i in range(SEVERAL_POLICY_GROUPS):
            policy_groups.append(self.nuage_vsd_client.create_policygroup(constants.L2_DOMAIN,
                                                                              vsd_l2_subnet[0]['ID'],
                                                                              name='myVSDpg-%s' % i,
                                                                              type='SOFTWARE',
                                                                              extra_params=None))
        # When I list the policy groups of the VSD-L2-Managed-Subnet
        policy_group_list = self.nuage_network_client.list_nuage_policy_group_for_subnet(subnet['id'])
        # I expect the policyGroup in my list
        for i in range(SEVERAL_POLICY_GROUPS):
            pg_present = self._check_policy_group_in_list(policy_groups[i][0]['ID'], policy_group_list)
            self.assertTrue(pg_present,"Did not find vsd policy group in policy group list")
            # And it has no external ID
            self.assertIsNone(policy_groups[i][0]['externalID'],
                          "Policy Group has an external ID, while it should not")
        # When I delete the (first) policy group on the VSD
        self.nuage_vsd_client.delete_policygroup(policy_groups[0][0]['ID'])
        # Then I expect this policy group to be gone from my list
        policy_group_list = self.nuage_network_client.list_nuage_policy_group_for_subnet(subnet['id'])
        pg_present = self._check_policy_group_in_list(policy_groups[0][0]['ID'], policy_group_list)
        self.assertFalse(pg_present, "Deleted policy group(%s) still present in the ser polic group list" %
                         policy_groups[0][0]['ID'])
        pass

    @nuage_test.header()
    def test_list_l2_policy_groups_subnet_only(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a VSD creeated policy group
        vsd_l2_subnet_x, l2dom_templ_x = self._create_vsd_l2_managed_subnet()
        network_x, subnet_x = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet_x)
        policy_group_x = self.nuage_vsd_client.create_policygroup(constants.L2_DOMAIN,
                                                                    vsd_l2_subnet_x[0]['ID'],
                                                                    name='myVSDpg-X',
                                                                    type='SOFTWARE',
                                                                    extra_params=None)
        vsd_l2_subnet_y, l2dom_templ_y = self._create_vsd_l2_managed_subnet()
        network_y, subnet_y = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet_y)
        policy_group_y = self.nuage_vsd_client.create_policygroup(constants.L2_DOMAIN,
                                                                     vsd_l2_subnet_y[0]['ID'],
                                                                     name='myVSDpg-2',
                                                                     type='SOFTWARE',
                                                                     extra_params=None)
        # When I retrieve the policy groups of  VSD-L2-Managed-Subnet_x
        policy_group_list_x = self.nuage_network_client.list_nuage_policy_group_for_subnet(subnet_x['id'])
        # I expect policyGroup_x in my list
        pg_present = self._check_policy_group_in_list(policy_group_x[0]['ID'], policy_group_list_x)
        self.assertTrue(pg_present,"Did not find vsd policy group in policy group list")
        # And I do NOT expect policyGroup_y in my list
        pg_present = self._check_policy_group_in_list(policy_group_y[0]['ID'], policy_group_list_x)
        self.assertFalse(pg_present,"Found policgroup (%s) of another subnet (%s) in this subnet (%s)" %
                         (policy_group_y[0]['ID'],  subnet_y['id'], subnet_x['id']))

        # And vice versa
        # When I retrieve the polic groups of VSD-L2-Managed-Subnet_y
        policy_group_list_y = self.nuage_network_client.list_nuage_policy_group_for_subnet(subnet_y['id'])
        # I expect policyGroup_y in my list
        pg_present = self._check_policy_group_in_list(policy_group_y[0]['ID'], policy_group_list_y)
        self.assertTrue(pg_present,"Did not find vsd policy group in policy group list")
        # And I do NOT expect policyGroup_x in my list
        pg_present = self._check_policy_group_in_list(policy_group_x[0]['ID'], policy_group_list_y)
        self.assertFalse(pg_present,"Found policgroup (%s) of another subnet (%s) in this subnet (%s)" %
                         (policy_group_x[0]['ID'],  subnet_x['id'], subnet_y['id']))
        pass

    # @nuage_test.nuage_skip_because(message="Speedup")
    def test_e2e_l2_vm_connectivity_port_to_policygroup(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a VSD creeated policy group
        vsd_l2_subnet, l2_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        policy_group = self.nuage_vsd_client.create_policygroup(constants.L2_DOMAIN,
                                                                vsd_l2_subnet[0]['ID'],
                                                                name='myVSD-l2-pg',
                                                                type='SOFTWARE',
                                                                extra_params=None)
        # And the policy group has and ingress/egress policy with rules allowing PING
        self._prepare_l2_security_group_entries(policy_group[0]['ID'], vsd_l2_subnet[0]['ID'])
        # When I retrieve the VSD-L2-Managed-Subnet
        policy_group_list = self.nuage_network_client.list_nuage_policy_group_for_subnet(subnet['id'])
        # I expect the policyGroup in my list
        pg_present = self._check_policy_group_in_list(policy_group[0]['ID'], policy_group_list)
        self.assertTrue(pg_present,"Did not find vsd policy group in policy group list")
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
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 10)
        self.assertTrue(connectivity,msg="No ping connectivity in policy group while expected (1)")
        # When I disassociate all ports from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg-1st'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        # Then these VM's have no more connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr,1)
        self.assertFalse(connectivity, msg="Ping connectivity in policy group while NOT expected (1)")
        # When I re-associate all ports with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-pg-2nd'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        # Then these VM's have again connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 10)
        self.assertTrue(connectivity,msg="No ping connectivity in policy group while expected (2)")
        # When I disassociate 1 port from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg-2nd'
        }
        self.update_port(port1, **kwargs)
        # self.update_port(port2, **kwargs)
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
        # Then these VM's have again connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 10)
        self.assertTrue(connectivity,msg="No ping connectivity in policy group while expected (3)")
        # When I disassociate the other port from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg-2nd'
        }
        # self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        # Then these VM's have no more connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 1)
        self.assertFalse(connectivity, msg="Ping connectivity in policy group while NOT expected (3)")
        # When I re-associate that port with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-3rd'
        }
        # self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        # Then these VM's have again connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 10)
        self.assertTrue(connectivity,msg="No ping connectivity in policy group while expected (3)")
        #
        the_floating_ip = self.floating_ips.pop()
        self.floating_ips_client.delete_floatingip(the_floating_ip['id'])

        # self.servers_client.delete_server(vm_conn['id'])
        # self.servers_client.delete_server(vm1['id'])
        self._clear_connectivity_vm_interfaces(self.conn_router_id, self.conn_subnet_id, self.conn_port_id)
        # pass

    @nuage_test.header()
    def test_l3_associate_port_to_policygroup(self):
        # Given I have a VSD-L3-Managed-Subnet in openstack with a VSD creeated policy group
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        policy_group = self.nuage_vsd_client.create_policygroup(constants.DOMAIN,
                                                                vsd_l3_domain[0]['ID'],
                                                                name='myVSDpg-1',
                                                                type='SOFTWARE',
                                                                extra_params=None)
        # When I retrieve the VSD-L2-Managed-Subnet
        policy_group_list = self.nuage_network_client.list_nuage_policy_group_for_subnet(subnet['id'])
        # I expect the policyGroup in my list
        pg_present = self._check_policy_group_in_list(policy_group[0]['ID'], policy_group_list)
        self.assertTrue(pg_present,"Did not find vsd policy group in policy group list")
        # And it has no external ID
        self.assertIsNone(policy_group[0]['externalID'],
                          "Policy Group has an external ID, while it should not")

        show_pg = self.nuage_network_client.show_nuage_policy_group(policy_group[0]['ID'])
        # When I create a port in the subnet
        port = self.create_port(network)
        # And I associate the port with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-pg'
        }
        self.update_port(port, **kwargs)
        # Then I expext the port in the show policy group response
        port_present = self._check_port_in_policy_group(port['id'], policy_group[0]['ID'])
        self.assertTrue(port_present, "Port(%s) assiociated to policy group (%s) is not present" %
                        (port['id'], policy_group[0]['ID']))
        # When I disassociate the port from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg'
        }
        self.update_port(port, **kwargs)
        # Then I do NOT expect the port in the show plicy group response
        port_present = self._check_port_in_policy_group(port['id'], policy_group[0]['ID'])
        self.assertFalse(port_present, "Port(%s) disassiociated to policy group (%s) is still present" %
                         (port['id'], policy_group[0]['ID']))
        pass

    def test_list_l3_policy_groups_subnet_only(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a VSD creeated policy group
        vsd_l3_subnet_x, vsd_l3_domain_x = self._create_vsd_l3_managed_subnet()
        network_x, subnet_x = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet_x)
        policy_group_x = self.nuage_vsd_client.create_policygroup(constants.DOMAIN,
                                                                  vsd_l3_domain_x[0]['ID'],
                                                                  name='myVSD-L3-pg-X',
                                                                  type='SOFTWARE',
                                                                  extra_params=None)
        vsd_l3_subnet_y, vsd_l3_domain_y = self._create_vsd_l3_managed_subnet()
        network_y, subnet_y = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet_y)
        policy_group_y = self.nuage_vsd_client.create_policygroup(constants.DOMAIN,
                                                                  vsd_l3_domain_y[0]['ID'],
                                                                  name='myVSD-L3-pg-Y',
                                                                  type='SOFTWARE',
                                                                  extra_params=None)
        # When I retrieve the policy groups of  VSD-L2-Managed-Subnet_x
        policy_group_list_x = self.nuage_network_client.list_nuage_policy_group_for_subnet(subnet_x['id'])
        # policy_group_list_x = self.client.list_available_nuage_policy_group(subnet_x['id'])
        # I expect policyGroup_x in my list
        pg_present = self._check_policy_group_in_list(policy_group_x[0]['ID'], policy_group_list_x)
        self.assertTrue(pg_present,"Did not find vsd policy group in policy group list")
        # And I do NOT expect policyGroup_y in my list
        pg_present = self._check_policy_group_in_list(policy_group_y[0]['ID'], policy_group_list_x)
        self.assertFalse(pg_present,"Found policgroup (%s) of another subnet (%s) in this subnet (%s)" %
                         (policy_group_y[0]['ID'],  subnet_y['id'], subnet_x['id']))

        # And vice versa
        # When I retrieve the polic groups of VSD-L2-Managed-Subnet_y
        # policy_group_list_y = self.client.list_available_nuage_policy_group(subnet_y['id'])
        policy_group_list_y = self.nuage_network_client.list_nuage_policy_group_for_subnet(subnet_y['id'])
        # I expect policyGroup_y in my list
        pg_present = self._check_policy_group_in_list(policy_group_y[0]['ID'], policy_group_list_y)
        self.assertTrue(pg_present,"Did not find vsd policy group in policy group list")
        # And I do NOT expect policyGroup_x in my list
        pg_present = self._check_policy_group_in_list(policy_group_x[0]['ID'], policy_group_list_y)
        self.assertFalse(pg_present,"Found policgroup (%s) of another subnet (%s) in this subnet (%s)" %
                         (policy_group_x[0]['ID'],  subnet_x['id'], subnet_y['id']))
        pass

    def test_l3_associate_multiple_ports_to_policygroups(self):
        policy_groups = []
        ports = []
        # Given I have a VSD-L3-Managed-Subnet
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        # And I have multiple policy_groups
        for i in range(SEVERAL_POLICY_GROUPS):
            policy_groups.append(self.nuage_vsd_client.create_policygroup(constants.DOMAIN,
                                                                          vsd_l3_domain[0]['ID'],
                                                                          name='my-L3-VSDpg-%s' % i,
                                                                          type='SOFTWARE',
                                                                          extra_params=None))
        for i in range(SEVERAL_PORTS):
            # When I create multiple ports
            ports.append(self.create_port(network))
        # And associate each port with all these policy groups
        pg_id_list = []
        for i in range(SEVERAL_POLICY_GROUPS):
            pg_id_list.append(policy_groups[i][0]['ID'])
        kwargs = {
            'nuage_policy_groups': pg_id_list,
        }
        for i in range(SEVERAL_PORTS):
            self.update_port(ports[i], **kwargs)
        # When I retrieve each port
        for i in range(SEVERAL_PORTS):
            show_port = self.ports_client.show_port(ports[i]['id'])
            # Then I expext all policy groups in the response
            all_pg_present = self._check_all_policy_groups_in_show_port(pg_id_list, show_port)
            self.assertTrue(all_pg_present, "Port does not contain all associated policy groups")

        # When I retreive each policy group
        for i in range(SEVERAL_POLICY_GROUPS):
            # Then I expect the response to contain all the ports
            for j in range(SEVERAL_PORTS):
                port_present = self._check_port_in_policy_group(ports[j]['id'], policy_groups[i][0]['ID'])
                self.assertTrue(port_present, "Port(%s) not present in policy group(%s)" %
                                (ports[j]['id'], policy_groups[i][0]['ID']))
        # When I disassociate all policy groups from each port
        kwargs = {
            'nuage_policy_groups': []
        }
        for i in range(SEVERAL_PORTS):
            self.update_port(ports[i],**kwargs)
            # Then I do NOT expect the policy Groups in the show port response
            show_port = self.ports_client.show_port(ports[i]['id'])
            self.assertEmpty(show_port['port']['nuage_policy_groups'],
                             "Port-show list disassociated ports")
            # And I do not expect this port in any of the policy groups
            for j in range(SEVERAL_POLICY_GROUPS):
                port_present = self._check_port_in_policy_group(ports[i]['id'], policy_groups[j][0]['ID'])
                self.assertFalse(port_present, 'disassociated port (%s) still present in policy group(%s)' %
                                 (ports[i]['id'], policy_groups[j][0]['ID']))
        pass

    # @nuage_test.nuage_skip_because(message="Speedup")
    def test_e2e_l3_vm_connectivity_port_to_policygroup(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a VSD creeated policy group
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        policy_group = self.nuage_vsd_client.create_policygroup(constants.DOMAIN,
                                                                vsd_l3_domain[0]['ID'],
                                                                name='myVSD-l3-policygrp',
                                                                type='SOFTWARE',
                                                                extra_params=None)
        # And the policy group has and ingress/egress policy with rules allowing PING
        self._prepare_l3_security_group_entries(policy_group[0]['ID'], vsd_l3_domain[0]['ID'])
        # When I retrieve the VSD-L2-Managed-Subnet
        policy_group_list = self.nuage_network_client.list_nuage_policy_group_for_subnet(subnet['id'])
        # I expect the policyGroup in my list
        pg_present = self._check_policy_group_in_list(policy_group[0]['ID'], policy_group_list)
        self.assertTrue(pg_present,"Did not find vsd policy group in policy group list")
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
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 10)
        self.assertTrue(connectivity,msg="No ping connectivity in policy group while expected (1)")
        # When I disassociate the port from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg-1st'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        # Then these VM's have no more connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr,1)
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
        self.assertTrue(connectivity,msg="No ping connectivity in policy group while expected (2)")
        # When I disassociate the port from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg-2nd'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        # Then these VM's have no more connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 1)
        self.assertFalse(connectivity, msg="Ping connectivity in policy group while NOT expected (2)")
        # When I re-associate the port with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-3rd'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        # Then these VM's have again connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 10)
        self.assertTrue(connectivity,msg="No ping connectivity in policy group while expected (3)")
        # When I disassociate the port from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg-2nd'
        }
        self.update_port(port1, **kwargs)
        self.update_port(port2, **kwargs)
        # Then these VM's have no more connectivity
        connectivity = self._check_vm_policy_group_ping(vm_conn, floating_ip.floating_ip_address, vm1_ip_addr, 1)
        self.assertFalse(connectivity, msg="Ping connectivity in policy group while NOT expected (3)")
        the_floating_ip = self.floating_ips.pop()
        self.floating_ips_client.delete_floatingip(the_floating_ip['id'])
        # the_server = self.servers.pop()
        self.servers_client.delete_server(vm_conn['id'])
        self.servers_client.delete_server(vm1['id'])
        self._clear_connectivity_vm_interfaces(self.conn_router_id, self.conn_subnet_id, self.conn_port_id)
        pass

    @nuage_test.header()
    def test_l2_list_policy_group_no_security_group_neg(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a VSD created policy group
        vsd_l2_subnet, l2_domtmpl = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        policy_group = self.nuage_vsd_client.create_policygroup(constants.L2_DOMAIN,
                                                                vsd_l2_subnet[0]['ID'],
                                                                name='myVSDpg-1',
                                                                type='SOFTWARE',
                                                                extra_params=None)
        # And I have created a security group on the OS subnet
        security_group = self._create_security_group()
        # And I have a redirect target
        os_redirect_target = self._create_redirect_target_in_l2_subnet(subnet)
        advfw_template = self.nuage_vsd_client.create_advfwd_entrytemplate(
            constants.L2_DOMAIN,
            vsd_l2_subnet[0]['ID']
        )
        # When I try to use this security group in a redirect-target-rule-creation
        # rt_rule = self._create_redirect_target_rule(os_redirect_target['nuage_redirect_target']['id'],
        #                                             security_group['id'])
        rt_rule = self._create_redirect_target_rule(os_redirect_target['nuage_redirect_target']['id'],
                                                     policy_group[0]['ID'])
        # When I retrieve the VSD-L2-Managed-Subnet
        policy_group_list = self.nuage_network_client.list_nuage_policy_group_for_subnet(subnet['id'])
        # I expect the only the policyGroup in my list: length may not be greater than one
        self.assertEqual(1,len(policy_group_list['nuage_policy_groups']),
                         message="Security groups are also in the policy group list")

    ################################################################################################################
    ################################################################################################################
    # MultiVIP . allowed address pairsallowable address pairs)
    ################################################################################################################
    ################################################################################################################


    def test_create_address_pair_l2domain_no_mac(self):
        # Given I have a VSD-L2-Managed subnet
        vsd_l2_subnet, l2_domtmpl = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        # When I create a port in this VSD-L2-Managed-Subnet with
        # - fixed-IP address
        # - allowed-address-pair with
        #     IP@ = fixed-IP+5
        #     no MAC address
        port_fixed_ip = str(IPAddress(base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW) + 10)
        aap_fixed_ip = str(IPAddress(port_fixed_ip) + 5)
        kwargs = {
            'fixed_ips': [{
                'subnet_id': subnet['id'],
                'ip_address': str(port_fixed_ip)
            }],
            'allowed_address_pairs': [{
                'ip_address':  aap_fixed_ip
            }]
        }
        addrpair_port = self.create_port(network, **kwargs)
        # Then I expect the allowed-address-pair the port-show response
        # And the allowed-address-pair MACaddress == port MACaddress
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self._verify_port_allowed_address_fields(show_port['port'],
                                                 aap_fixed_ip,
                                                 addrpair_port['mac_address'])
        # And no corresponding MultiVIP on the VSD
        port_ext_id = self.nuage_vsd_client.get_vsd_external_id(addrpair_port['id'])
        nuage_vport = self.nuage_vsd_client.get_vport(constants.L2_DOMAIN,
                                                      vsd_l2_subnet[0]['ID'],
                                                      filters='externalID',
                                                      filter_value=port_ext_id)
        self.assertIsNone(nuage_vport[0]['multiNICVPortID'], "multiNICVPortID is not empty while it should be")
        # And address address spoofing is disabled on vport in VSD
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        # When I delete the allowed address  pair from the port
        self._remove_allowed_addres_pair_from_port(addrpair_port)
        # I expect it ot be gone fro the show port response
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self.assertEmpty(show_port['port']['allowed_address_pairs'],
                         "Removed allowed-address-pair stil present in port (%s)" % addrpair_port['id'])
        pass

    def test_create_address_pair_l2domain_with_mac(self):
        # Given I have a VSD-L2-Managed subnet
        vsd_l2_subnet, l2_domtmpl = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        # When I create a port in this VSD-L2-Managed-Subnet with
        # - fixed-IP address
        # - allowed-address-pair with
        #     IP@ = fixed-IP+5
        #     valid MAC address (<> port MAC address)
        port_fixed_ip = str(IPAddress(base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW) + 100)
        aap_fixed_ip = str(IPAddress(port_fixed_ip) + 5)
        kwargs = {
            'fixed_ips': [{
                'subnet_id': subnet['id'],
                'ip_address': str(port_fixed_ip)
            }],
            'allowed_address_pairs': [{
                'ip_address':  aap_fixed_ip,
                'mac_address': VALID_MAC_ADDRESS
            }]
        }
        addrpair_port = self.create_port(network, **kwargs)
        # Then I expect the allowed-address-pair the port-show response
        # And the allowed-address-pair MACaddress == port MACaddress
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self._verify_port_allowed_address_fields(show_port['port'],
                                                 aap_fixed_ip,
                                                 VALID_MAC_ADDRESS)
        # And no corresponding MultiVIP on the VSD
        port_ext_id = self.nuage_vsd_client.get_vsd_external_id(addrpair_port['id'])
        nuage_vport = self.nuage_vsd_client.get_vport(constants.L2_DOMAIN,
                                                      vsd_l2_subnet[0]['ID'],
                                                      filters='externalID',
                                                      filter_value=port_ext_id)
        self.assertIsNone(nuage_vport[0]['multiNICVPortID'], "multiNICVPortID is not empty while it should be")
        # And address address spoofing is disabled on vport in VSD
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        # When I delete the allowed address  pair from the port
        self._remove_allowed_addres_pair_from_port(addrpair_port)
        # I expect it ot be gone fro the show port response
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self.assertEmpty(show_port['port']['allowed_address_pairs'],
                         "Removed allowed-address-pair stil present in port (%s)" % addrpair_port['id'])
        pass

    def test_create_address_pair_l3_subnet_no_mac(self):
        # Given I have a VSD-L3-Managed subnet
        vsd_l3_subnet, l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        # When I create a port in this VSD-L3-Managed-Subnet with
        # - fixed-IP address
        # - allowed-address-pair with
        #     IP@ = fixed-IP+5
        #     no MAC address
        port_fixed_ip = str(IPAddress(base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW) + 10)
        aap_fixed_ip = str(IPAddress(port_fixed_ip) + 5)
        kwargs = {
            'fixed_ips': [{
                'subnet_id': subnet['id'],
                'ip_address': str(port_fixed_ip)
            }],
            'allowed_address_pairs': [{
                'ip_address':  aap_fixed_ip
            }]
        }
        addrpair_port = self.create_port(network, **kwargs)
        # Then I expect the allowed-address-pair the port-show response
        # And the allowed-address-pair MACaddress == port MACaddress
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self._verify_port_allowed_address_fields(show_port['port'],
                                                 aap_fixed_ip,
                                                 addrpair_port['mac_address'])
        # And no corresponding MultiVIP on the VSD
        port_ext_id = self.nuage_vsd_client.get_vsd_external_id(addrpair_port['id'])
        nuage_vport = self.nuage_vsd_client.get_vport(constants.SUBNETWORK,
                                                      vsd_l3_subnet[0]['ID'],
                                                      filters='externalID',
                                                      filter_value=port_ext_id)
        self.assertIsNone(nuage_vport[0]['multiNICVPortID'], "multiNICVPortID is not empty while it should be")
        # # And address address spoofing is disabled on vport in VSD
        # self.assertEqual(constants.ENABLED,
        #                  nuage_vport[0]['addressSpoofing'])
        # When I delete the allowed address  pair from the port
        self._remove_allowed_addres_pair_from_port(addrpair_port)
        # I expect it ot be gone fro the show port response
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self.assertEmpty(show_port['port']['allowed_address_pairs'],
                         "Removed allowed-address-pair stil present in port (%s)" % addrpair_port['id'])
        pass

    def test_create_address_pair_l3domain_with_mac(self):
        # Given I have a VSD-L2-Managed subnet
        vsd_l3_subnet, l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        # When I create a port in this VSD-L3-Managed-Subnet with
        # - fixed-IP address
        # - allowed-address-pair with
        #     IP@ = fixed-IP+5
        #     valid MAC address (<> port MAC address)
        port_fixed_ip = str(IPAddress(base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW) + 100)
        aap_fixed_ip = str(IPAddress(port_fixed_ip) + 5)
        kwargs = {
            'fixed_ips': [{
                'subnet_id': subnet['id'],
                'ip_address': str(port_fixed_ip)
            }],
            'allowed_address_pairs': [{
                'ip_address':  aap_fixed_ip,
                'mac_address': VALID_MAC_ADDRESS
            }]
        }
        addrpair_port = self.create_port(network, **kwargs)
        # Then I expect the allowed-address-pair the port-show response
        # And the allowed-address-pair MACaddress == port MACaddress
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self._verify_port_allowed_address_fields(show_port['port'],
                                                 aap_fixed_ip,
                                                 VALID_MAC_ADDRESS)
        # And no corresponding MultiVIP on the VSD
        port_ext_id = self.nuage_vsd_client.get_vsd_external_id(addrpair_port['id'])
        nuage_vport = self.nuage_vsd_client.get_vport(constants.SUBNETWORK,
                                                      vsd_l3_subnet[0]['ID'],
                                                      filters='externalID',
                                                      filter_value=port_ext_id)
        self.assertIsNone(nuage_vport[0]['multiNICVPortID'], "multiNICVPortID is not empty while it should be")
        # And address address spoofing is disabled on vport in VSD
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])
        # When I delete the allowed address  pair from the port
        self._remove_allowed_addres_pair_from_port(addrpair_port)
        # I expect it ot be gone fro the show port response
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self.assertEmpty(show_port['port']['allowed_address_pairs'],
                         "Removed allowed-address-pair stil present in port (%s)" % addrpair_port['id'])
        pass

    ################################################################################################################
    ################################################################################################################
    # associate FIP testcases
    ################################################################################################################
    ################################################################################################################


class VSDManagedAssociateFIPTest(BaseVSDManagedPortAttributest):

    @classmethod
    def resource_setup(cls):
        super(VSDManagedAssociateFIPTest, cls).resource_setup()
        cls.vsd_fip_pool = cls._create_vsd_floatingip_pool()

    @nuage_test.header()
    def test_create_list_associate_vsd_floatingip(self):
        # Given I have a VSD-FloatingIP-pool
        vsd_fip_pool = self.vsd_fip_pool
        # And VSD-L3-Domain with a VSD-L3-Managed-Subnet
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        # And I have claimed a VSD-FloatingIP in the VSD-L3-Domain
        claimed_fip = self.nuage_vsd_client.claim_floatingip(vsd_l3_domain[0]['ID'], vsd_fip_pool[0]['ID'])
        # When I retreive the nuage-floatingIP-list of the VSD-L3-Managed-Subnet
        fip_list = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet['id'])
        # I expect the VSD-floatingIP in my list
        fip_present = self._check_fip_in_list(claimed_fip[0]['ID'], fip_list)
        self.assertTrue(fip_present, msg="nuage floatingip not present in list, while expected to be")
        # When I create a port in the subnet
        port = self.create_port(network)
        # And I associate this port to the claimed floating ip (via update)
        self._associate_fip_to_port(port, claimed_fip[0]['ID'])
        # Then I expect the claimed floating ip in the port show response
        fip_present = self._check_fip_in_port_show(port['id'], claimed_fip[0]['ID'])
        self.assertTrue(fip_present,
                       msg="associated VSD claimed FIP (%s) not found in port (%s)" %
                           (claimed_fip[0]['ID'], port['id']))
        # When I disassociate the claimed fip from the port
        self._disassociate_fip_from_port(port)
        # Then I no longer expect the claimed floating ip in the port show response
        fip_present = self._check_fip_in_port_show(port['id'], claimed_fip[0]['ID'])
        self.assertFalse(fip_present,
                         msg="disassociated VSD claimed FIP (%s) still found in port (%s)" %
                             (claimed_fip[0]['ID'], port['id']))
        pass

    @nuage_test.header()
    def test_create_list_associate_several_vsd_floatingip(self):
        ports = []
        claimed_fips = []
        # Given I have a several VSD-FloatingIP-pools
        vsd_fip_pool = self.vsd_fip_pool
        # And VSD-L3-Domain with a VSD-L3-Managed-Subnet
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        # And I have claimed several VSD-FloatingIP in the VSD-L3-Domain
        for i in range(SEVERAL_VSD_CLAIMED_FIPS):
            claimed_fip = self.nuage_vsd_client.claim_floatingip(vsd_l3_domain[0]['ID'], vsd_fip_pool[0]['ID'])
            claimed_fips.append(claimed_fip)
        # When I retreive the nuage-floatingIP-list of the VSD-L3-Managed-Subnet
        fip_list = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet['id'])
        # I expect all VSD-floatingIP in my list
        for i in range(SEVERAL_VSD_CLAIMED_FIPS):
            fip_present = self._check_fip_in_list(claimed_fips[i][0]['ID'], fip_list)
            self.assertTrue(fip_present, msg="nuage floatingip not present in list, while expected to be")
        # When I create several ports in the subnet
        for i in range (SEVERAL_VSD_CLAIMED_FIPS):
            port = self.create_port(network)
            ports.append((port))
        # And I associate this port to the claimed floating ip (via update)
        for i in range(SEVERAL_VSD_CLAIMED_FIPS):
            self._associate_fip_to_port(ports[i], claimed_fips[i][0]['ID'])
        for i in range(SEVERAL_VSD_CLAIMED_FIPS):
            # Then I expect the claimed floating ip in the port show response
            fip_present = self._check_fip_in_port_show(ports[i]['id'], claimed_fips[i][0]['ID'])
            self.assertTrue(fip_present,
                        msg="associated VSD claimed FIP (%s) not found in port (%s)" %
                            (claimed_fips[i][0]['ID'], ports[i]['id']))
            # When I disassociate the claimed fip from the port
            self._disassociate_fip_from_port(ports[i])
            # Then I no longer expect the claimed floating ip in the port show response
            fip_present = self._check_fip_in_port_show(ports[i]['id'], claimed_fips[i][0]['ID'])
            self.assertFalse(fip_present,
                         msg="disassociated VSD claimed FIP (%s) still found in port (%s)" %
                             (claimed_fip[0]['ID'], port['id']))
        pass

    def test_subnets_same_domain_associate_vsd_floatingip(self):
        # Given I have a VSD-FloatingIP-pool
        vsd_fip_pool = self.vsd_fip_pool
        # And I have claimed a VSD-FloatingIp-X in VSD-L3-Managed-Subnet-X
        # And I have claimed a VSD-FloatingIP-Y  in VD-L3-Managed-Subnet-Y
        # And they are in the same  VSD-L3-domain
        vsd_l3_subnet_x, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network_x, subnet_x = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet_x)
        vsd_l3_subnet_y = self._create_vsd_l3_managed_subnet_in_domain(vsd_l3_domain[0]['ID'],
                                                                       VSD_SECOND_SUBNET_CIDR)
        network_y, subnet_y = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet_y,cidr=VSD_SECOND_SUBNET_CIDR)
        claimed_fip_x = self.nuage_vsd_client.claim_floatingip(vsd_l3_domain[0]['ID'], vsd_fip_pool[0]['ID'])
        claimed_fip_y = self.nuage_vsd_client.claim_floatingip(vsd_l3_domain[0]['ID'], vsd_fip_pool[0]['ID'])

        # When I retreive the nuage-floatingip-list from VSD-L3-Managed-Subnet-X
        fip_list_x = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet_x['id'])
        # I expect both VSD-FloatingIP's in the list
        fip_present_x = self._check_fip_in_list(claimed_fip_x[0]['ID'], fip_list_x)
        self.assertTrue(fip_present_x, msg="nuage floatingip not present in list, while expected to be")
        fip_present_y = self._check_fip_in_list(claimed_fip_y[0]['ID'], fip_list_x)
        self.assertTrue(fip_present_y, msg="nuage floatingip not present in list, while expected to be")
        # When I retreive the nuage-floatingip-list from VSD-L3-Managed-Subnet-B
        fip_list_y = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet_y['id'])
        # I expect both VSD-floatingIP's in the list
        fip_present = self._check_fip_in_list(claimed_fip_x[0]['ID'], fip_list_y)
        self.assertTrue(fip_present, msg="nuage floatingip not present in list, while expected to be")
        fip_present = self._check_fip_in_list(claimed_fip_y[0]['ID'], fip_list_y)
        self.assertTrue(fip_present, msg="nuage floatingip not present in list, while expected to be")
        # When I associate VSD-FloatingIp-X to port_x
        port_x = self.create_port(network_x)
        self._associate_fip_to_port(port_x, claimed_fip_x[0]['ID'])
        # I expect this VSD-FloatingIp-X to be gone from the lists (no longer available)
        fip_list_x = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet_x['id'])
        fip_present_x =  self._check_fip_in_list(claimed_fip_x[0]['ID'], fip_list_x)
        self.assertFalse(fip_present_x,
                         msg="associated VSD claimed FIP (%s) still found as available in subnet-list (%s)" %
                             (claimed_fip_x[0]['ID'], subnet_x['id']))
        fip_list_y = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet_y['id'])
        fip_present_x =  self._check_fip_in_list(claimed_fip_x[0]['ID'], fip_list_y)
        self.assertFalse(fip_present_x,
                         msg="associated VSD claimed FIP (%s) still found as available in subnet-list (%s)" %
                             (claimed_fip_x[0]['ID'], subnet_y['id']))
        # And VSD-FloatingIp-Y still present in that list
        fip_present_y =  self._check_fip_in_list(claimed_fip_y[0]['ID'], fip_list_x)
        self.assertTrue(fip_present_y, msg="nuage floatingip not present in list, while expected to be")
        # When I associate VSD-FloatingIp-Y to port_y
        port_y = self.create_port(network_y)
        self._associate_fip_to_port(port_y, claimed_fip_y[0]['ID'])
        # Then I expect VSD-FloatingIp-Y to be gone from the list (as no longer available)
        fip_list_y = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet_y['id'])
        fip_present_y =  self._check_fip_in_list(claimed_fip_y[0]['ID'], fip_list_y)
        self.assertFalse(fip_present_y,
                         msg="associated VSD claimed FIP (%s) still found as available in subnet-list (%s)" %
                             (claimed_fip_y[0]['ID'], subnet_y['id']))
        # When I disassociate VSD-FloatingIp-X from port-X
        self._disassociate_fip_from_port(port_x)
        # Then VSD_FloatingIp-X is again available in the list of subnet-X
        fip_list_x = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet_x['id'])
        fip_present_x = self._check_fip_in_list(claimed_fip_x[0]['ID'], fip_list_x)
        self.assertTrue(fip_present_x, msg="nuage floatingip not present in list, while expected to be")
        # And is is also available in the list of subnet-Y
        fip_list_y = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet_y['id'])
        fip_present_y = self._check_fip_in_list(claimed_fip_x[0]['ID'], fip_list_y)
        self.assertTrue(fip_present_y, msg="nuage floatingip not present in list, while expected to be")
        # When I disassociate VSD-FloatingIp-Y from port-Y
        self._disassociate_fip_from_port(port_y)
        # Then VSD_FloatingIp-Y is again available in the list of subnet-X
        fip_list_x = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet_x['id'])
        fip_present_x = self._check_fip_in_list(claimed_fip_y[0]['ID'], fip_list_x)
        self.assertTrue(fip_present_x, msg="nuage floatingip not present in list, while expected to be")
        # And is is also available in the list of subnet-Y
        fip_list_y = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet_y['id'])
        fip_present_y = self._check_fip_in_list(claimed_fip_y[0]['ID'], fip_list_y)
        self.assertTrue(fip_present_y, msg="nuage floatingip not present in list, while expected to be")
        pass

    def test_subnets_other_domain_associate_vsd_floatingip(self):
        # Given I have a VSD-FloatingIP-pool
        vsd_fip_pool = self.vsd_fip_pool
        # And I have claimed a VSD-FloatingIp-X in VSD-L3-Managed-Subnet-X
        vsd_l3_subnet_x, vsd_l3_domain_x = self._create_vsd_l3_managed_subnet()
        network_x, subnet_x = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet_x)
        claimed_fip_x = self.nuage_vsd_client.claim_floatingip(vsd_l3_domain_x[0]['ID'], vsd_fip_pool[0]['ID'])
        # And I have claimed a VSD-FloatingIP-Y in VD-L3-Managed-Subnet-Y
        # And they are in different VSD-L3-domains
        vsd_l3_subnet_y, vsd_l3_domain_y = self._create_vsd_l3_managed_subnet()
        network_y, subnet_y = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet_y)
        claimed_fip_y = self.nuage_vsd_client.claim_floatingip(vsd_l3_domain_y[0]['ID'], vsd_fip_pool[0]['ID'])
        # When I retreive the nuage-floatingip-list from VSD-L3-Managed-Subnet-X
        fip_list_x = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet_x['id'])
        # I expect only VSD-FloatingIP-X in the list, not VSD-FloatingIP-y
        self.assertTrue(self._check_fip_in_list(claimed_fip_x[0]['ID'], fip_list_x),
                        msg="nuage floatingip not present in list, while expected to be")
        fip_present = self._check_fip_in_list(claimed_fip_y[0]['ID'], fip_list_x)
        self.assertFalse(fip_present, msg="nuage floatingip present in list, while expected not to be")
        # When I retreive the nuage-floatingip-list from VSD-L3-Managed-Subnet-Y
        fip_list_y = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet_y['id'])
        # I expect only VSD-floatingIP-Y in the list
        fip_present = self._check_fip_in_list(claimed_fip_x[0]['ID'], fip_list_y)
        self.assertFalse(fip_present, msg="nuage floatingip not present in list, while expected to be")
        fip_present = self._check_fip_in_list(claimed_fip_y[0]['ID'], fip_list_y)
        self.assertTrue(fip_present, msg="nuage floatingip not present in list, while expected to be")
        # When I associate VSD-FloatingIp-x to port-x
        port_x = self.create_port(network_x)
        self._associate_fip_to_port(port_x, claimed_fip_x[0]['ID'])
        # Then VSD-FloatingIp-x is no longer present in the list for subnet-x
        fip_list_x = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet_x['id'])
        self.assertFalse(self._check_fip_in_list(claimed_fip_x[0]['ID'], fip_list_x),
                        msg="nuage floatingip not present in list, while expected to be")
        # When I associate VSD-FloatingIp-y to port-y
        port_y = self.create_port(network_y)
        self._associate_fip_to_port(port_y, claimed_fip_y[0]['ID'])
        # Then VSD-FloatingIp-y is no longer present in the list for subnet-y
        fip_list_y = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet_y['id'])
        self.assertFalse(self._check_fip_in_list(claimed_fip_y[0]['ID'], fip_list_y),
                         msg="nuage floatingip not present in list, while expected to be")
    pass

    # def test_e2e_vsd_managed_subnet_floating_ip_connectivity(self):
    #     # Use the by default availabe FIP pool (public network)
    #     vsd_fip_pool = self._create_vsd_floatingip_pool()
    #     # And I have associated a VSD-FloatingIp-X to a port-X in VSD-L3-Managed-Subnet-X
    #     vsd_l3_subnet_x, vsd_l3_domain_x = self._create_vsd_l3_managed_subnet()
    #     network_x, subnet_x = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet_x)
    #     claimed_fip_x = self.nuage_vsd_client.claim_floatingip(vsd_l3_domain_x[0]['ID'], vsd_fip_pool[0]['ID'])
    #     port_x = self.create_port(network_x)
    #     self._associate_fip_to_port(port_x, claimed_fip_x[0]['ID'])
    #     # self._create_connectivity_VM_vsd_floatingip(self, public_network_id, vsd_l3_subnet, vsd_l3_port, floatingip):

    ################################################################################################################
    ################################################################################################################
    # Negative testcases
    ################################################################################################################
    ################################################################################################################

    ######################################################################################################################
    # Negative Redirect targets
    ######################################################################################################################


    ######################################################################################################################
    # Negative Redirect targets
    ######################################################################################################################

    ######################################################################################################################
    # Negative Policy Groups targets
    ######################################################################################################################

    ######################################################################################################################
    # Negative Multi VIp (allowable address pairs)
    ######################################################################################################################

    ######################################################################################################################
    # Negative associate FIP
    ######################################################################################################################
    @nuage_test.header()
    def test_create_associate_vsd_floatingip_twice_neg(self):
        # Given I have a VSD-FloatingIP-pool
        vsd_fip_pool = self.vsd_fip_pool
        # And VSD-L3-Domain with a VSD-L3-Managed-Subnet
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        # And I have claimed a VSD-FloatingIP in the VSD-L3-Domain
        claimed_fip = self.nuage_vsd_client.claim_floatingip(vsd_l3_domain[0]['ID'], vsd_fip_pool[0]['ID'])
        # When I retreive the nuage-floatingIP-list of the VSD-L3-Managed-Subnet
        fip_list = self.nuage_network_client.list_nuage_floatingip_by_subnet(subnet['id'])
        # I expect the VSD-floatingIP in my list
        fip_present = self._check_fip_in_list(claimed_fip[0]['ID'], fip_list)
        self.assertTrue(fip_present, msg="nuage floatingip not present in list, while expected to be")
        # When I create a port in the subnet
        port_1 = self.create_port(network)
        # And I associate this port to the claimed floating ip (via update)
        self._associate_fip_to_port(port_1, claimed_fip[0]['ID'])
        self._associate_fip_to_port(port_1, claimed_fip[0]['ID'])
        # kwargs = {"nuage_floatingip": {'id': claimed_fip[0]['ID']}}
        # self.update_port(port_1, **kwargs)
        # Then I expect the claimed floating ip in the port show response
        fip_present = self._check_fip_in_port_show(port_1['id'], claimed_fip[0]['ID'])
        self.assertTrue(fip_present,
                        msg="associated VSD claimed FIP (%s) not found in port (%s)" %
                            (claimed_fip[0]['ID'], port_1['id']))
        # When I try to associate the same claimed flaoting IP to another port
        port_2 = self.create_port(network)
        # I expect a failure
        msg = 'Bad request: Floating IP %s is already in use' % claimed_fip[0]['address']
        # self.update_port(port_2, **kwargs)
        # kwargs = {"nuage_floatingip": {'id': claimed_fip[0]['ID']}}
        # Todo: figure out why next line refuses to work
        # self.assertRaisesRegexp(
        #     exceptions.BadRequest,
        #     msg,
        #     self._associate_fip_to_port,
        #     port_2,
        #     claimed_fip[0]['ID'])
        pass
