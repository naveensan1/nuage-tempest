from nuagetempest.lib import base
import re
import unittest
import sys

class IpAntiSpoofingTestScenarioBase():
    def __init__(self):
        pass

    def _get_vm_details_in_vsc(self, vm):
        # Get the VM details on VSC
        out_dict = {}
        # Parse the VM details output
        for vm_data in vm:
            if vm_data:
                entry = vm_data.split(':', 1)
                if len(entry) > 1:
                    out_dict[entry[0]] = entry[1]

        # Get rid of redundant space in output dictionary
        vm_dict = {}
        for key,value in out_dict.iteritems():
            vm_dict[key.strip()] = value.strip()
        return vm_dict

class IpAntiSpoofingTestScenario(IpAntiSpoofingTestScenarioBase):

    def __init__(self):
        pass

    class _vm_in_sec_disabled_port_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTestScenario()
        def verify_vm_in_sec_disabled_port_l2domain(self, obj):
            vm_osc = obj.os_data.get_resource('scn-port1-vm-1').os_data
            vm_vsc = obj.TB.vsc_1.cmd('show vswitch-controller vports type vm detail')
            vm_dict = self.ip_anti_spoof._get_vm_details_in_vsc(vm_vsc)
            obj.assertEqual(vm_dict['Anti Spoof Enabled'], 'false')

    class _vm_in_sec_disabled_port_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTestScenario()
        def verify_vm_in_sec_disabled_port_l3domain(self, obj):
            vm_osc = obj.os_data.get_resource('scn-port11-vm-1').os_data
            vm_vsc = obj.TB.vsc_1.cmd('show vswitch-controller vports type vm detail')
            vm_dict = self.ip_anti_spoof._get_vm_details_in_vsc(vm_vsc)
            obj.assertEqual(vm_dict['Anti Spoof Enabled'], 'false')

    class _vm_with_port_parameters_1_0_0_1_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTestScenario()
            pass
        def verify_vm_vip_and_anit_spoof_l3domain(self, obj):
            vm_osc = obj.os_data.get_resource('scn-port12-vm-1').os_data
            vm_vsc = obj.TB.vsc_1.cmd('show vswitch-controller vports type vm detail')
            vm_dict = self.ip_anti_spoof._get_vm_details_in_vsc(vm_vsc)
            obj.assertEqual(vm_dict['Anti Spoof Enabled'], 'true')
            obj.assertEqual(vm_dict['No. of Virtual IP'], '1')


