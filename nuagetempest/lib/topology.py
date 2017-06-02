import itertools
import sys
import traceback
import threading

import libVSD
from tempest import config

from libduts.linux import Linux
from libduts.sros import SROS
from libduts.sros.vsc import VSC
from libduts.sros.vsg import VSG
from libduts.linux import OSC
from libduts.linux.vrs import VRS

from nuagetempest.lib.openstackcli import openstackcli_base
from nuagetempest.lib.openstackapi import openstackapi_base
import re
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

CONF = config.CONF


class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Topology(object):
    __metaclass__ = Singleton

    def __init__(self):
        testbed = CONF.nuagext.exec_server
        testbed_user = CONF.nuagext.exec_server_user
        self.nuage_components = CONF.nuagext.nuage_components
        self.topologyfile = CONF.nuagext.topologyfile
        self.duts_list = self.parse_topologyfile()
        self.make_testbed()

    @property
    def _vrs(self):
        vrs = {}
        for dutname, dut in self.duts.iteritems():
            if isinstance(dut, VRS):
                vrs[dutname] = dut

    def parse_topologyfile(self):

        def parse_line(line):
            line = line.split()
            try:
                if line[0] == 'None':
                    return (None, None, None, None, None, None)
                elif '-component' in line and '-username' in line and '-password' in line:
                    idx = line.index('-component') + 1
                    idx_u = line.index('-username') + 1
                    idx_p = line.index('-password') + 1
                    return (line[0], line[1], line[2], line[idx], line[idx_u], line[idx_p])
                return (line[0], line[1], line[2], None, None, None)
            except:
                return (None, None, None, None, None, None)

        duts_list = []
        try:
            topo_file = open(self.topologyfile, 'r')
            content = topo_file.readlines()
        except IOError:
            if any(comp in CONF.nuagext.nuage_components for comp in ('vsc', 'vrs')):
                raise Exception('Testbed topo file or exec server is not provided')
            elif 'vsd' in CONF.nuagext.nuage_components:
                vsd_dut = {}
                vsd_dut['component'] = 'VSD'
                vsd_dut['name'] = 'vsd-1'
                vsd_dut['ip'] = 'vsd-1'
                duts_list.append(vsd_dut)
            else:
                raise Exception('Testbed topo file or exec server is not provided')
        else:
            with topo_file:
                for line in content:
                    dut_type, dut_name, dut_ip, component, username, password = parse_line(line)
                    if dut_type in ['LINUX', 'ESR']:
                        duts_list.append({
                            'name': dut_name,
                            'type': dut_type,
                            'ip': dut_ip,
                            'component': component,
                            'username': username,
                            'password': password
                        })
        return duts_list

    def get_dut_from_topologyfile(self, name):
        for d in self.duts_list:
            if d['name'] == name:
                return d
        raise Exception('{} not found in {}'.format(name, self.topologyfile))

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

    @staticmethod
    def _base_uri_to_version(base_uri):
        pattern = re.compile(r'(\d+_\d+)')
        match =  pattern.search(base_uri)
        version = match.group()
        version = str(version).replace('_','.')
        return version

    def make_dut(self, name):

        dut = self.get_dut_from_topologyfile(name)
        ip = dut['ip']
        component = dut['component']

        if self._is_ovs(component):
            return VRS(ip, id=name, password=dut['password'], user=dut['username'])

        if self._is_vsd(component):
            vsd_ip = CONF.nuage.nuage_vsd_server.split(':')[0]
            vsd_port = CONF.nuage.nuage_vsd_server.split(':')[1]
            vsd_api_version = self._base_uri_to_version(CONF.nuage.nuage_base_uri)

            api = libVSD.client.ApiClient(vsd_ip, port=vsd_port, version=vsd_api_version)
            helper = libVSD.helpers.VSDHelpers(api)
            setattr(helper, 'api', api)
            return helper

        if self._is_7750(component):
            return SROS(ip, name, id=name, password=dut['password'], user=dut['username'])

        if self._is_vsg(component):
            return VSG(ip, name, id=name, password=dut['password'], user=dut['username'])

        if self._is_vsc(component):
            return VSC(ip, name, id=name, password=dut['password'], user=dut['username'])

        if self._is_osc(component):
            osc = OSC(ip, id=name, password=dut['password'], user=dut['username'])
            setattr(osc, 'cli', openstackcli_base.OpenstackCliClient(osc))
            setattr(osc, 'api', openstackapi_base.OpenstackAPIClient())
            return osc

        err = 'Cannot find a class corresponding to {}'.format(name)
        raise Exception(err)

    def make_testbed(self):
        vrs_counter = itertools.count()
        vrs_counter.next()
        vsc_counter = itertools.count()
        vsc_counter.next()
        vsd_counter = itertools.count()
        vsd_counter.next()
        osc_counter = itertools.count()
        osc_counter.next()
        testbed = CONF.nuagext.exec_server
        self.testbed = Linux(testbed, id='testbed')
        self.duts = {}
        for dut in self.duts_list:
            if dut['component'] == "VRS" and 'vrs' in CONF.nuagext.nuage_components:
                dutobjname = 'vrs_' + str(vrs_counter.next())
                dutobj = self.make_dut(dut['name'])
                setattr(self, dutobjname, dutobj)
                self.duts[dutobjname] = getattr(self, dutobjname)
            elif dut['component'] == "VSC" and 'vsc' in CONF.nuagext.nuage_components:
                dutobjname = 'vsc_' + str(vsc_counter.next())
                dutobj = self.make_dut(dut['name'])
                setattr(self, dutobjname, dutobj)
                self.duts[dutobjname] = getattr(self, dutobjname)
            elif dut['component'] == "VSD" and 'vsd' in CONF.nuagext.nuage_components:
                dutobjname = 'vsd_' + str(vsd_counter.next())
                dutobj = self.make_dut(dut['name'])
                setattr(self, dutobjname, dutobj)
                self.duts[dutobjname] = getattr(self, dutobjname)
            elif dut['component'] == "OSC":
                dutobjname = 'osc_' + str(osc_counter.next())
                dutobj = self.make_dut(dut['name'])
                setattr(self, dutobjname, dutobj)
                self.duts[dutobjname] = getattr(self, dutobjname)

# def open_session(TB):
#     for dut in dir(TB):
#         if dut.split('_')[0] in CONF.nuagext.nuage_components + ['osc']:
#             if dut.split('_')[0] == 'vsd':
#                 obj = getattr(TB, dut)
#                 obj.api.new_session()
#                 obj.update_vsd_session()
#             else:
#                 obj = getattr(TB, dut)
#                 obj.ssh.open()


def open_session(TB, timeout=1):

    def _open_ssh_session(dut):
        try:
            dut.ssh.open()
        except:
            exc = ''.join(traceback.format_exception(*sys.exc_info()))
            dut.ssh.log.error(exc)
            failed.append(dut)

    threads = []
    failed = []
    for dut in dir(TB):
        if dut.split('_')[0] in CONF.nuagext.nuage_components + ['osc']:
            if dut.split('_')[0] == 'vsd':
                obj = getattr(TB, dut)
                obj.api.new_session()
                obj.update_vsd_session()
            else:
                adut = getattr(TB, dut)
                t = threading.Thread(target=_open_ssh_session, args=(adut,))
                t.is_daemon = True
                t.start()
                threads.append(t)

    [thread.join() for thread in threads]


def initialize_topology():
    return Topology()
