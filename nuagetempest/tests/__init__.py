from oslo_log import log as logging
from nuagetempest.lib import nuage_ext
from nuagetempest.lib import nuage_tempest_test_loader
import re
import traceback
from tempest import config

conf = config.CONF
LOG = logging.getLogger(__name__)

class NuageExtensionInit():

    def __init__(self):
        self.nuage_extension = nuage_ext.NuageExtension()

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

nuage_ext = NuageExtensionInit()

def load_tests(loader, tests, pattern):
    return nuage_tempest_test_loader.nuage_load_tests(loader, pattern)
