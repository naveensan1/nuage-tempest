# Copyright 2013 OpenStack Foundation
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

from nuagetempest.lib.nuage_tempest_test_loader import Release
from nuagetempest.lib.utils import constants as n_constants
from nuagetempest.services.nuage_client import NuageRestClient
import six
from tempest.api.network import test_security_groups
from tempest.common.utils import data_utils
from tempest import config
from tempest import test
import uuid

CONF = config.CONF
external_id_release = Release('4.0r4')
conf_release = CONF.nuage_sut.release
current_release = Release(conf_release)


class SecGroupTestNuage(test_security_groups.SecGroupTest):
    _interface = 'json'
    _tenant_network_cidr = CONF.network.tenant_network_cidr

    @classmethod
    def setup_clients(cls):
        super(SecGroupTestNuage, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(SecGroupTestNuage, cls).resource_setup()

        # Nuage specific resource addition
        name = data_utils.rand_name('network-')
        cls.network = cls.create_network(network_name=name)
        cls.subnet = cls.create_subnet(cls.network)
        cls.nuage_l2domain = cls.nuage_vsd_client.get_l2domain(
            filters='externalID',
            filter_value=cls.subnet['id'])

    def _create_verify_security_group_rule(self, **kwargs):
        sec_group_rule = self.security_group_rules_client\
            .create_security_group_rule(**kwargs)
        self._verify_nuage_acl(sec_group_rule.get('security_group_rule'))

    def _create_nuage_port_with_security_group(self, sg_id, nw_id):
        post_body = {"network_id": nw_id,
                     "device_owner": "compute:None",
                     "device_id": str(uuid.uuid1()),
                     "security_groups": [sg_id]}
        body = self.ports_client.create_port(**post_body)
        self.addCleanup(self.ports_client.delete_port, body['port']['id'])

    def _verify_vsd_policy_grp(self, remote_group_id):
        nuage_policy_grp = self.nuage_vsd_client.get_policygroup(
            n_constants.L2_DOMAIN,
            self.nuage_l2domain[0]['ID'],
            filters='externalID',
            filter_value=remote_group_id)
        self.assertEqual(nuage_policy_grp[0]['name'],
                         remote_group_id)

    def _verify_vsd_network_macro(self, remote_ip_prefix):
        net_addr = remote_ip_prefix.split('/')
        ent_net_macro = self.nuage_vsd_client.get_enterprise_net_macro(
            filters='address', filter_value=net_addr[0])
        self.assertNotEqual(ent_net_macro, '', msg='Macro not found')
        if external_id_release <= current_release:
            self.assertEqual(ent_net_macro[0]['externalID'],
                             ent_net_macro[0]['parentID'] + '@openstack')

    def _get_nuage_acl_entry_template(self, sec_group_rule):
        if sec_group_rule['direction'] == 'ingress':
            nuage_eacl_template = self.nuage_vsd_client.\
                get_egressacl_template(n_constants.L2_DOMAIN,
                                       self.nuage_l2domain[0]['ID'])
            nuage_eacl_entrytemplate = self.nuage_vsd_client.\
                get_egressacl_entytemplate(
                    n_constants.EGRESS_ACL_TEMPLATE,
                    nuage_eacl_template[0]['ID'],
                    filters='externalID',
                    filter_value=sec_group_rule['id'])
            return nuage_eacl_entrytemplate
        else:
            nuage_iacl_template = self.nuage_vsd_client.\
                get_ingressacl_template(
                    n_constants.L2_DOMAIN,
                    self.nuage_l2domain[0]['ID'])
            nuage_iacl_entrytemplate = self.nuage_vsd_client.\
                get_ingressacl_entytemplate(
                    n_constants.INGRESS_ACL_TEMPLATE,
                    nuage_iacl_template[0]['ID'],
                    filters='externalID',
                    filter_value=sec_group_rule['id'])
            return nuage_iacl_entrytemplate

    def _verify_nuage_acl(self, sec_group_rule):

        if sec_group_rule.get('remote_group_id'):
            self._verify_vsd_policy_grp(sec_group_rule['remote_group_id'])

        if sec_group_rule.get('remote_ip_prefix'):
            self._verify_vsd_network_macro(sec_group_rule
                                           ['remote_ip_prefix'])

        nuage_acl_entry = self._get_nuage_acl_entry_template(sec_group_rule)

        to_verify = ['protocol', 'etherType', 'sourcePort', 'destinationPort']
        expected = {}
        for parameter in to_verify:
            parm_value = nuage_acl_entry[0][parameter]
            if parm_value and parameter == 'etherType':
                expected['ethertype'] = parm_value
            elif parm_value:
                expected[parameter] = parm_value

        for key, value in expected.iteritems():
            if key in ['sourcePort']:
                self.assertEqual(value, '*')
            elif key in ['destinationPort']:
                if not sec_group_rule['port_range_max']:
                    self.assertEqual(value, '*')
                elif sec_group_rule['port_range_max'] == \
                        sec_group_rule['port_range_min']:
                    self.assertEqual(
                        int(value), sec_group_rule['port_range_max'])
                else:
                    self.assertEqual(
                        value,
                        str(sec_group_rule['port_range_min']) + '-' + str(
                            sec_group_rule['port_range_max']))
            else:
                self.assertEqual(value, n_constants.PROTO_NAME_TO_NUM
                                 [sec_group_rule[key]],
                                 "Field %s of the created security group "
                                 "rule does not match with %s." %
                                 (key, value))

    @test.attr(type='smoke')
    def test_create_list_update_show_delete_security_group(self):
        group_create_body, name = self._create_security_group()

        # List security groups and verify if created group is there in response
        list_body = self.security_groups_client.list_security_groups()
        secgroup_list = list()
        for secgroup in list_body['security_groups']:
            secgroup_list.append(secgroup['id'])
        self.assertIn(group_create_body['security_group']['id'], secgroup_list)
        # Update the security group
        # create a nuage port to create sg on VSD.
        self._create_nuage_port_with_security_group(
            group_create_body['security_group']['id'], self.network['id'])
        # Verify vsd.
        self._verify_vsd_policy_grp(group_create_body
                                    ['security_group']['id'])
        new_name = data_utils.rand_name('security-')
        new_description = data_utils.rand_name('security-description')
        update_body = self.security_groups_client.update_security_group(
            group_create_body['security_group']['id'],
            name=new_name,
            description=new_description)
        # Verify if security group is updated
        self.assertEqual(update_body['security_group']['name'], new_name)
        self.assertEqual(update_body['security_group']['description'],
                         new_description)
        # Show details of the updated security group
        show_body = self.security_groups_client.show_security_group(
            group_create_body['security_group']['id'])
        self.assertEqual(show_body['security_group']['name'], new_name)
        self.assertEqual(show_body['security_group']['description'],
                         new_description)

    @test.attr(type='smoke')
    def test_create_show_delete_security_group_rule(self):
        group_create_body, _ = self._create_security_group()
        # create a nuage port to create sg on VSD.
        self._create_nuage_port_with_security_group(
            group_create_body['security_group']['id'], self.network['id'])
        # Create rules for each protocol
        protocols = ['tcp', 'udp', 'icmp']
        for protocol in protocols:
            rule_create_body = (
                self.security_group_rules_client.create_security_group_rule(
                    security_group_id=group_create_body['security_group']
                    ['id'],
                    protocol=protocol,
                    direction='ingress',
                    ethertype=self.ethertype
                ))
            # Show details of the created security rule
            show_rule_body = (
                self.security_group_rules_client.show_security_group_rule(
                    rule_create_body['security_group_rule']['id']))
            create_dict = rule_create_body['security_group_rule']
            for key, value in six.iteritems(create_dict):
                self.assertEqual(value,
                                 show_rule_body['security_group_rule'][key],
                                 "%s does not match." % key)
            self._verify_nuage_acl(rule_create_body['security_group_rule'])
            # List rules and verify created rule is in response
            rule_list_body = (self.security_group_rules_client.
                              list_security_group_rules())
            rule_list = [rule['id']
                         for rule in rule_list_body['security_group_rules']]
            self.assertIn(rule_create_body['security_group_rule']['id'],
                          rule_list)

    @test.attr(type='smoke')
    def test_create_security_group_rule_with_additional_args(self):
        """Verify security group rule with additional arguments works.

        direction:ingress, ethertype:[IPv4/IPv6],
        protocol:tcp, port_range_min:77, port_range_max:77
        """
        group_create_body, _ = self._create_security_group()
        self._create_nuage_port_with_security_group(
            group_create_body['security_group']['id'], self.network['id'])
        sg_id = group_create_body['security_group']['id']
        direction = 'ingress'
        protocol = 'tcp'
        port_range_min = 77
        port_range_max = 77
        self._create_verify_security_group_rule(
            security_group_id=sg_id, direction=direction,
            ethertype=self.ethertype, protocol=protocol,
            port_range_min=port_range_min,
            port_range_max=port_range_max)

    @test.attr(type='smoke')
    def test_create_security_group_rule_with_icmp_type_code(self):
        """Verify security group rule for icmp protocol works.

        Specify icmp type (port_range_min) and icmp code
        (port_range_max) with different values. A seperate testcase
        is added for icmp protocol as icmp validation would be
        different from tcp/udp.
        """
        group_create_body, _ = self._create_security_group()
        self._create_nuage_port_with_security_group(
            group_create_body['security_group']['id'], self.network['id'])
        sg_id = group_create_body['security_group']['id']
        direction = 'ingress'
        protocol = 'icmp'
        icmp_type_codes = [(3, 2), (2, 3), (3, 0), (2, None)]
        for icmp_type, icmp_code in icmp_type_codes:
            self._create_verify_security_group_rule(
                security_group_id=sg_id, direction=direction,
                ethertype=self.ethertype, protocol=protocol,
                port_range_min=icmp_type, port_range_max=icmp_code)

    @test.attr(type='smoke')
    def test_create_security_group_rule_with_remote_group_id(self):
        # Verify creating security group rule with remote_group_id works
        sg1_body, _ = self._create_security_group()
        sg2_body, _ = self._create_security_group()
        self._create_nuage_port_with_security_group(
            sg1_body['security_group']['id'], self.network['id'])
        self._create_nuage_port_with_security_group(
            sg2_body['security_group']['id'], self.network['id'])
        sg_id = sg1_body['security_group']['id']
        direction = 'ingress'
        protocol = 'udp'
        port_range_min = 50
        port_range_max = 55
        remote_id = sg2_body['security_group']['id']
        self._create_verify_security_group_rule(
            security_group_id=sg_id, direction=direction,
            ethertype=self.ethertype, protocol=protocol,
            port_range_min=port_range_min,
            port_range_max=port_range_max,
            remote_group_id=remote_id)

    @test.attr(type='smoke')
    def test_create_security_group_rule_with_remote_ip_prefix(self):
        # Verify creating security group rule with remote_ip_prefix works
        sg1_body, _ = self._create_security_group()
        self._create_nuage_port_with_security_group(
            sg1_body['security_group']['id'], self.network['id'])
        sg_id = sg1_body['security_group']['id']
        direction = 'ingress'
        protocol = 'tcp'
        port_range_min = 76
        port_range_max = 77
        ip_prefix = self._tenant_network_cidr
        self._create_verify_security_group_rule(
            security_group_id=sg_id, direction=direction,
            ethertype=self.ethertype, protocol=protocol,
            port_range_min=port_range_min,
            port_range_max=port_range_max,
            remote_ip_prefix=ip_prefix)
