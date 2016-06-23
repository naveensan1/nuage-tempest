from oslo_log import log as logging
from nuagetempest.lib import nuage_ext
from nuagetempest.lib import nuage_tempest_test_loader
from nuagetempest.lib import topology
import re
import traceback
from tempest import config

conf = config.CONF
LOG = logging.getLogger(__name__)

class NuageExtensionInit():

    def __init__(self):
        LOG.warning(("Look here i am in init setupmodule"))
        LOG.debug(dir(self))
        self.nuage_extension = nuage_ext.NuageExtension()
        self.TB = topology.initialize_topology() 
        LOG.warning(("Look here i am in init setupmodule"))
        LOG.debug(dir(self))

    #@classmethod
    #def setUpModule():
    #    self._open_ssh()

    def _generate_tag(self, tag, class_name):
        tb = traceback.extract_stack()
        for t in tb:
            if re.search('_generate_tag\(', str(t)):
                l = len(str.split(t[0], '/'))
                t_part1 = str.split(t[0], '/')[l-2]
                t_part2_1 = str.split(t[0], '/')[l-1]
                t_part2 = str.split(t_part2_1, '.')[0]
                t_part4 = str.split(t[2])[0][4:]
                return t_part1 + '.' + t_part2 + '.' + class_name + '.' + t_part4 + '.' + tag

    def _open_ssh(self, otherTB):
        LOG.warning("look here: infunction _open_ssh printint dir-otherTB")
        LOG.warning(dir(otherTB))
        for dut in dir(otherTB):
            LOG.warning("look here doing the ssh printing dut")
            LOG.warning(dut)
            LOG.warning(conf.nuagext.nuage_components)
            LOG.warning(dut.split('_')[0])
            if dut.split('_')[0] in conf.nuagext.nuage_components + ['osc']:
                if dut.split('_')[0] == 'vsd':
                    obj = getattr(otherTB, dut)
                    obj.api.new_session()
                    obj.update_vsd_session()
                else:
                    obj = getattr(otherTB, dut)
                    obj.ssh.open()

nuage_ext = NuageExtensionInit()
#nuage_ext.TB = topology.initialize_topology()
#nuage_ext._open_ssh()
LOG.debug(dir(nuage_ext))

def load_tests(loader, tests, pattern):
    return nuage_tempest_test_loader.nuage_load_tests(loader, pattern)

