from libduts import topology
from libduts import linux

path_to_esrcalls = "/opt/stack/esrcalls.tcl"
testbed = 'mvdcdev53'
testbed_user = 'mvdcdev53'

class Testbed():

    def __init__(self):
        T = topology.Topology(path_to_esrcalls)
        self.testbed = linux.Linux(testbed, id='testbed')
        self.vsd = T.make_dut('vsd-1')
        self.osc = T.make_dut('osc-1')
        self.ovs_1 = T.make_dut('ovs-1')
        self.ovs_2 = T.make_dut('ovs-2')
        self.ovs_3 = T.make_dut('ovs-3')
        self.ovs_4 = T.make_dut('ovs-4')
        self.dut_g = T.make_dut('Dut-G')
        self.dut_h = T.make_dut('Dut-H')
        self.duts = {
            'testbed': self.testbed,
            'vsd-1': self.vsd,
            'osc-1': self.osc,
            'ovs-1': self.ovs_1,
            'ovs-2': self.ovs_2,
            'ovs-3': self.ovs_3,
            'ovs-4': self.ovs_4,
            'Dut-G': self.dut_g,
            'Dut-H': self.dut_h,
        }
        self.vrses = {
            'ovs-1': self.ovs_1,
            'ovs-2': self.ovs_2,
            'ovs-3': self.ovs_3,
            'ovs-4': self.ovs_4
        }
        self.vsces = {
            'Dut-G': self.dut_g,
            'Dut-H': self.dut_h          
        }

layer = Testbed()
for k,v in layer.duts.iteritems():
    v.ssh.open()