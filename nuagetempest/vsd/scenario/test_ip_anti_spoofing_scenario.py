from testtools.matchers import MatchesAny
from testtools.matchers import Equals
from nuagetempest.vsd.api import test_ip_anti_spoofing as antispoof


class IpAntiSpoofingTestScenario(antispoof.IpAntiSpoofingVSDBase):

    def __init__(self):
        pass


    class _vm_in_sec_disabled_port_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTestScenario()
            pass
        def verify_vm_in_sec_disabled_port_l2domain(self, obj):
            l2domain = obj.os_data.get_resource('scn-l2dom1-1').os_data                          
            port = obj.os_data.get_resource('scn-port1-1').os_data
            vm   = obj.os_data.get_resource('scn-port1-vm-1').os_data 
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(                 
                                     l2domain, port, obj)

            obj.os_data.get_resource('scn-port1-1').vsd_data = vsd_port

            vsd_vm = vsd_l2domain.vms.get_first()
            vsd_vm_inf = vsd_vm.interfaces.pop()
            obj.assertEqual(vsd_vm_inf['IPAddress'], 
                            port['fixed_ips'][0]['ip_address'])
            obj.assertEqual(vsd_vm_inf['MAC'], port['mac_address'])
            obj.assertThat(vsd_vm.status, MatchesAny(Equals('RUNNING'), Equals('INIT')))


    class _vm_in_sec_disabled_port_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTestScenario()
            pass
        def verify_vm_in_sec_disabled_port_l3domain(self, obj):
            router = obj.os_data.get_resource('scn-router11-1').os_data
            subnet = obj.os_data.get_resource('scn-subnet11-1').os_data
            port = obj.os_data.get_resource('scn-port11-1').os_data
            vm   = obj.os_data.get_resource('scn-port11-vm-1').os_data 
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port, obj)

            obj.os_data.get_resource('scn-port11-1').vsd_data = vsd_port

            vsd_vm = vsd_l3dom.vms.get_first()
            vsd_vm_inf = vsd_vm.interfaces.pop()
            obj.assertEqual(vsd_vm_inf['IPAddress'], 
                            port['fixed_ips'][0]['ip_address'])
            obj.assertEqual(vsd_vm_inf['MAC'], port['mac_address'])
            obj.assertThat(vsd_vm.status, MatchesAny(Equals('RUNNING'), Equals('INIT')))


    class _vm_with_port_parameters_1_0_0_1_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTestScenario()
            pass
        def verify_vm_vip_and_anit_spoof_l3domain(self, obj):
            router = obj.os_data.get_resource('scn-router12-1').os_data
            subnet = obj.os_data.get_resource('scn-subnet12-1').os_data
            port = obj.os_data.get_resource('scn-port12-1').os_data
            vm   = obj.os_data.get_resource('scn-port12-vm-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port, obj)

            obj.os_data.get_resource('scn-port12-1').vsd_data = vsd_port

            vip_params = ('1', '0', '0', '1')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing(
                port, vsd_port, vip_params, obj)
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port, obj)
            vsd_vm = vsd_l3dom.vms.get_first()
            vsd_vm_inf = vsd_vm.interfaces.pop()
            obj.assertEqual(vsd_vm_inf['IPAddress'],
                            port['fixed_ips'][0]['ip_address'])
            obj.assertEqual(vsd_vm_inf['MAC'], port['mac_address'])
            obj.assertThat(vsd_vm.status, MatchesAny(Equals('RUNNING'), Equals('INIT')))
