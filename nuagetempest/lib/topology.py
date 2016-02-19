import itertools
import threading
from libduts import sros, linux
import re

class Topology(object):

    def __init__(self, path_to_esrcalls):
        self.esrcalls = path_to_esrcalls
        self.duts_list = self.parse_esrcalls()
        self.make_testbed()

    def open_ssh_sessions(self):

        def _open_ssh_session(dut):
            try:
                dut.ssh.open()
            except:
                exc = ''.join(traceback.format_exception(*sys.exc_info()))
                dut.ssh.log.error(exc)
                failed.append(dut)

        threads = []
        failed = []
        for dut in self.duts.values():
            t = threading.Thread(target=_open_ssh_session, args=(dut,))
            t.is_daemon = True
            t.start()
            threads.append(t)

        [thread.join() for thread in threads]

    @property
    def vrs(self):
        vrs = {}
        for dutname, dut in self.duts.iteritems():
            if isinstance(dut, linux.VRS):
                vrs[dutname] = dut
        return vrs

    def parse_esrcalls(self):

        def parse_line(line):
            line = line.split()
            try:
                if line[0] == 'None':
                    return (None, None, None, None)
                elif re.search('component', line[len(line)-2]):
                    return (line[0], line[1], line[2], line[len(line)-1])
                return (line[0], line[1], line[2], None)
            except:
                return (None, None, None, None)

        duts_list = []
        with open(self.esrcalls, 'r') as esrcalls_file:
            for line in esrcalls_file.readlines():
                dut_type, dut_name, dut_ip, component = parse_line(line)
                if dut_type in ['LINUX', 'ESR']:
                    duts_list.append({
                        'name': dut_name,
                        'type': dut_type,
                        'ip': dut_ip,
                        'component': component
                    })
        return duts_list

    def get_dut_from_esrcalls(self, name):
        for d in self.duts_list:
            if d['name'] == name:
                return d
        raise Exception('{} not found in {}'.format(name, self.path_to_esrcalls))

    @staticmethod
    def _is_sros(component):
        if re.match('7750', component):
            return True
        return False

    @staticmethod
    def _is_vsc(component):
        if re.match('VSC', component):
            return True
        return False

    @staticmethod
    def _is_7750(component):
        if re.match('7750', component):
            return True
        return False

    @staticmethod
    def _is_vsd(component):
        if re.match('VSD', component):
            return True
        return False

    @staticmethod
    def _is_ovs(component):
        if re.match('VRS', component):
            return True
        return False

    @staticmethod
    def _is_osc(component):
        if re.match('OSC', component):
            return True
        return False

    @staticmethod
    def _is_util(component):
        if re.match('UTILS', component):
            return True
        return False

    @staticmethod
    def _is_vsg(component):
        if re.match('VSG', component):
            return True
        return False

    @staticmethod
    def _is_nsg(component):
        if re.match('NSG', component):
            return True
        return False

    @staticmethod
    def _is_traffic(component):
        if component == 'TRAFFIC':
            return True
        return False

    def make_dut(self, name):

        dut = self.get_dut_from_esrcalls(name)
        ip = dut['ip']
        component = dut['component']

        if self._is_ovs(component):
            return linux.VRS(ip, id=name)

        if self._is_vsd(component):
            api = linux.ApiClient(dut['ip'])
            return linux.VSD(ip, api=api, id=name)

        if self._is_7750(component):
            return sros.SROS(ip, name, id=name)

        if self._is_vsg(component):
            return sros.VSG(ip, name, id=name)

        if self._is_vsc(component):
            return sros.VSC(ip, name, id=name)

        if self._is_util(component):
            return linux.Linux(ip, password='Alcateldc', id=name)

        if self._is_nsg(component):
            return linux.NSG(ip, id=name)

        if self._is_osc(component):
            return linux.OSC(ip, id=name)

        err = 'Cannot find a class corresponding to {}'.format(name)
        raise Exception(err)

    def make_testbed(self):
        self.vrs_counter = itertools.count()
        self.vsc_counter = itertools.count()
        self.vsd_counter = itertools.count()
        self.osc_counter = itertools.count()
        self.duts = {}
        self.vsces = {}
        self.vrses = {}
        self.vsdes = {}
        self.osces = {}
        for dut in self.duts_list:
            if dut['component'] is not None:
                switcher = {
                    'VSC': self.make_testbed_vsc,
                    'VRS': self.make_testbed_vrs,
                    'VSD': self.make_testbed_vsd,
                    'OSC': self.make_testbed_osc,
                }
                func = switcher.get(dut['component'], None)
                if func:
                    func(dut)

    def make_testbed_vrs(self, dut):
        dut_count = self.vrs_counter.next()
        self.vrses['vrs-{}'.format(dut_count)] = self.make_dut(dut['name'])
        self.duts['vrs-{}'.format(dut_count)] = self.vrses['vrs-{}'.format(dut_count)]

    def make_testbed_vsc(self, dut):
        dut_count = self.vsc_counter.next()
        self.vsces['vsc-{}'.format(dut_count)] = self.make_dut(dut['name'])
        self.duts['vsc-{}'.format(dut_count)] = self.vsces['vsc-{}'.format(dut_count)]
        
    def make_testbed_vsd(self, dut):
        dut_count = self.vsd_counter.next()
        self.vsdes['vsd-{}'.format(dut_count)] = self.make_dut(dut['name'])
        self.duts['vsd-{}'.format(dut_count)] = self.vsdes['vsd-{}'.format(dut_count)]
        
    def make_testbed_osc(self, dut):
        dut_count = self.osc_counter.next()
        self.osces['osc-{}'.format(dut_count)] = self.make_dut(dut['name'])
        self.duts['osc-{}'.format(dut_count)] = self.osces['osc-{}'.format(dut_count)]
