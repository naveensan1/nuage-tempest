from nuagetempest.lib import test_base as base
import re
import unittest
import sys
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

class IpAntiSpoofingTestScenarioBase():
    def __init__(self):
        pass

    def _get_table_entry(self, table_entries, key):
        out_dict = {}
        if table_entries[0]:
            for table_entry in table_entries[0]:
                if re.search(key, table_entry):
                    return table_entry;
        return None
        
class IpAntiSpoofingTestScenario(IpAntiSpoofingTestScenarioBase):

    def __init__(self):
        pass

    class _vm_in_sec_disabled_port_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTestScenario()
        def verify_vm_in_sec_disabled_port_l2domain(self, obj):
            vm_osc = obj.os_data.get_resource('scn-port1-vm-1').os_data
            # get the address details of to compare
            vm_address = vm_osc['addresses'].values()[0][0]['addr']
            vm_vrs = base.poll_for_vm_boot(obj.TB.vrs_1.cmd, vm_address, 30)
            obj.assertEqual(vm_vrs['anti_spoof'], 'Disabled')
            obj.assertEqual(vm_vrs['ip'], vm_address)
            obj.assertNotEqual(vm_vrs['evpn_id'], 0)


    class _vm_in_sec_disabled_port_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTestScenario()
        def verify_vm_in_sec_disabled_port_l3domain(self, obj):
            vm_osc = obj.os_data.get_resource('scn-port11-vm-1').os_data
            # get the address details of to compare
            vm_address = vm_osc['addresses'].values()[0][0]['addr']
            vm_vrs = base.poll_for_vm_boot(obj.TB.vrs_1.cmd, vm_address, 30)
            obj.assertEqual(vm_vrs['anti_spoof'], 'Disabled')
            obj.assertEqual(vm_vrs['ip'], vm_address)
            obj.assertNotEqual(vm_vrs['evpn_id'], 0)
            obj.assertNotEqual(vm_vrs['vrf_id'], 0)

    class _vm_with_port_parameters_1_0_0_1_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTestScenario()
        def verify_vm_vip_and_anit_spoof_l3domain(self, obj):
            vm_osc = obj.os_data.get_resource('scn-port12-vm-1').os_data
            vm_address = vm_osc['addresses'].values()[0][0]['addr']
            vm_vrs = base.poll_for_vm_boot(obj.TB.vrs_1.cmd, vm_address, 30)
            #vm_vrs = TB.vrs_1.cmd.vmportshow()[0]
            obj.assertEqual(vm_vrs['anti_spoof'], 'Enabled')
            obj.assertEqual(vm_vrs['ip'], vm_address)
            obj.assertNotEqual(vm_vrs['evpn_id'], 0)
            obj.assertNotEqual(vm_vrs['vrf_id'], 0)
            table_entries = obj.TB.vrs_1.cmd(
                'ovs-appctl bridge/dump-flows alubr0 | grep table_id=60')
            table_entry = self.ip_anti_spoof._get_table_entry(table_entries,
                                                              '30.30.30.100')
            if table_entry is None:
                LOG.error("No table entry for VIP available on VRS")

