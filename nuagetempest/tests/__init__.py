from oslo_log import log as logging
from nuagetempest.lib import nuage_ext
from nuagetempest.lib import topology
import re
import traceback
from tempest import config

CONF = config.CONF
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

for dut in dir(topology.testbed):
    if dut.split('_')[0] in CONF.nuagext.nuage_components + ['osc']:
        if dut.split('_')[0] == 'vsd':
            obj = getattr(topology.testbed, dut)
            obj.api.new_session()
            obj.update_vsd_session()
        else:
            obj = getattr(topology.testbed, dut)
            obj.ssh.open()

nuage_ext = NuageExtensionInit()

#def add_csproot_to_cms():
#    vsd = topology.testbed.vsd_1
#    global_ent_id = vsd.session.user.enterprise_id
#    global_ent = vsd.vspk.NUEnterprise(id=global_ent_id)
#    grp_filter = 'name IS "CMS Group"'
#    usr_filter = 'userName IS "csproot"'
#    vsd.add_user_to_group(global_ent, usr_filter=usr_filter, grp_filter=grp_filter)

#add_csproot_to_cms()
