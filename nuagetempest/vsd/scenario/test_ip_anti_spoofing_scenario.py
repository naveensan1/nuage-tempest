from nuagetempest.lib import topology
from nuagetempest.lib import base
from nuagetempest.vsd.api import test_ip_anti_spoofing as antispoof
from tempest import test
import re
import unittest
import sys

TB = topology.testbed

class IpAntiSpoofingTestScenario(antispoof.IpAntiSpoofingVSDBase):

    def __init__(self):
        pass

    class _vm_in_sec_disabled_port_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTestScenario()
            pass
        def verify_vm_in_sec_disabled_port_l2domain(self, obj):
            l2domain = obj.os_data.get_resource('l2dom3-1').os_data                          
            port = obj.os_data.get_resource('port3-1').os_data
            vm   = obj.os_data.get_resource('vm').os_data 
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(                 
                                     l2domain, port)
            vsd_vm = vsd_l2domain.vms.get_first()
            vsd_vm_inf = vsd_vm.interfaces.pop()
            obj.assertEqual(vsd_vm_inf['IPAddress'], 
                            port['fixed_ips'][0]['ip_address'])
            obj.assertEqual(vsd_vm_inf['MAC'], port['mac_address'])
            obj.assertEqual(vsd_vm.status, 'RUNNING')
