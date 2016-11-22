import time
from testtools.matchers import Equals

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
        for key, value in out_dict.iteritems():
            vm_dict[key.strip()] = value.strip()
        return vm_dict


class IpAntiSpoofingTestScenario(IpAntiSpoofingTestScenarioBase):

    def __init__(self):
        pass

    class _vm_in_sec_disabled_port_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTestScenario()

        def verify_vm_in_sec_disabled_port_l2domain(self, obj):
            vsd_port = obj.os_data.get_resource('scn-port1-1').vsd_data

            time.sleep(10)
            vports_vsc = obj.TB.vsc_1.cmd.vswitchctrl_vport_vm_detail()
            obj.assertIsNotNone(vports_vsc)
            obj.assertGreaterEqual(len(vports_vsc), 1)

            vport_vsc = next (x for x in vports_vsc if x['vsd_vp_uuid'] == vsd_port.id)
            obj.assertIsNotNone(vport_vsc)
            obj.assertThat(vport_vsc['anti_spoof_enabled'], Equals('false'))

    class _vm_in_sec_disabled_port_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTestScenario()

        def verify_vm_in_sec_disabled_port_l3domain(self, obj):
            vsd_port = obj.os_data.get_resource('scn-port11-1').vsd_data

            time.sleep(10)
            vports_vsc = obj.TB.vsc_1.cmd.vswitchctrl_vport_vm_detail()
            obj.assertIsNotNone(vports_vsc)
            obj.assertGreaterEqual(len(vports_vsc), 1)

            vport_vsc = next (x for x in vports_vsc if x['vsd_vp_uuid'] == vsd_port.id)
            obj.assertIsNotNone(vport_vsc)
            obj.assertThat(vport_vsc['anti_spoof_enabled'], Equals('false'))

    class _vm_with_port_parameters_1_0_0_1_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTestScenario()
            pass

        def verify_vm_vip_and_anit_spoof_l3domain(self, obj):
            vsd_port = obj.os_data.get_resource('scn-port12-1').vsd_data

            time.sleep(5)
            vports_vsc = obj.TB.vsc_1.cmd.vswitchctrl_vport_vm_detail()
            obj.assertIsNotNone(vports_vsc)
            obj.assertGreaterEqual(len(vports_vsc), 1)

            vport_vsc = next (x for x in vports_vsc if x['vsd_vp_uuid'] == vsd_port.id)
            obj.assertIsNotNone(vport_vsc)
            obj.assertThat(vport_vsc['anti_spoof_enabled'], Equals('true'))
            obj.assertThat(vport_vsc['vips_count'], Equals(1))


