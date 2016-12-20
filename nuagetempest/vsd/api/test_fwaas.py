from tempest import config
from oslo_log import log as logging
from nuagetempest.lib import base
from nuagetempest.lib import test_base
from tempest import test
import re
import unittest
import sys
from nuagetempest.tests import nuage_ext


CONF = config.CONF

LOG = logging.getLogger(__name__)

class FWaaSExtensionTestJSON():
    
    def __init__(self):
        pass
        
    def _get_def_ent_obj(self, obj):
        return obj.TB.vsd_1.get_enterprise(
            filter='name == "%s"' % obj.def_net_partition)
        
    def _populate_vsd_data_to_obj_fw_rule(self, name, obj):
        ext_id = test_base.get_external_id(
            obj.os_data.get_resource(name).os_data['id'])
        fw_acl = obj.TB.vsd_1.get_firewallrule(self._get_def_ent_obj(obj),
                    filter=test_base.get_filter_str('externalID', ext_id))
        obj.os_data.get_resource(name).vsd_data = fw_acl
    
    def _verify_fw_rule(self, name, obj):
        
        VSD_TO_OS_ACTION = {
            'allow': "FORWARD",
            'deny': "DROP"
        }
        
        self._populate_vsd_data_to_obj_fw_rule(name, obj)
        firewall_acl_os = (
            obj.os_data.get_resource(name).os_data
        )
        firewall_acl_vsd = (
            obj.os_data.get_resource(name).vsd_data
        )
        firewall_acl_vsd = firewall_acl_vsd.to_dict()
        #Protocol and externalID cannot be verified VSD-18219
        obj.assertEqual(firewall_acl_os['name'], firewall_acl_vsd['description'])
        if firewall_acl_os['action'] == "allow":
            obj.assertEqual(firewall_acl_vsd['stateful'], True)
        else:
            obj.assertEqual(firewall_acl_vsd['stateful'], False)
        if firewall_acl_vsd['sourcePort']:
            firewall_acl_vsd['sourcePort'] = firewall_acl_vsd['sourcePort'].replace('-', ':')
        if firewall_acl_vsd['destinationPort']:
            firewall_acl_vsd['destinationPort'] = firewall_acl_vsd['destinationPort'].replace('-', ':')
        obj.assertEqual(firewall_acl_os['source_port'], firewall_acl_vsd['sourcePort'])
        obj.assertEqual(firewall_acl_os['destination_port'], firewall_acl_vsd['destinationPort'])
        obj.assertEqual(firewall_acl_os['source_ip_address'], firewall_acl_vsd['addressOverride'])
        obj.assertEqual(firewall_acl_os['destination_ip_address'], firewall_acl_vsd['networkID'])
        obj.assertEqual(VSD_TO_OS_ACTION.get(firewall_acl_os['action']), firewall_acl_vsd['action'])
        if firewall_acl_os['firewall_policy_id'] is not None:
            obj.assertEqual(firewall_acl_vsd['associatedfirewallACLID'], not None)
        
    class _list_firewall_rules():
        def __init__(self):
            self.fwaas_api_tests = FWaaSExtensionTestJSON()
            pass

        def verify_firewall_rule(self, obj):
            self.fwaas_api_tests._verify_fw_rule('fw-rule-1', obj)
    
    class _create_update_delete_firewall_rule():
        def __init__(self):
            self.fwaas_api_tests = FWaaSExtensionTestJSON()
            pass

        def verify_firewall_rule(self, obj):
            self.fwaas_api_tests._verify_fw_rule('fw-rule-2', obj)
            
    class _create_update_delete_firewall_rule_all_attributes():
        def __init__(self):
            self.fwaas_api_tests = FWaaSExtensionTestJSON()
            pass

        def verify_firewall_rule(self, obj):
            self.fwaas_api_tests._verify_fw_rule('fw-rule-3', obj)
            
    class _create_firewall_rule_different_protocol_types_and_actions():
        def __init__(self):
            self.fwaas_api_tests = FWaaSExtensionTestJSON()
            pass

        def verify_firewall_rules_all(self, obj):
            self.fwaas_api_tests._verify_fw_rule('fw-rule-4', obj)
            self.fwaas_api_tests._verify_fw_rule('fw-rule-5', obj)
            self.fwaas_api_tests._verify_fw_rule('fw-rule-6', obj)
            self.fwaas_api_tests._verify_fw_rule('fw-rule-7', obj)

