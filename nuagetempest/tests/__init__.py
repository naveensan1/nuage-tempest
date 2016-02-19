from nuagetempest.lib import topology
from oslo_log import log as logging
from nuagetempest.lib import nuage_ext
import re
import traceback
from tempest import config
import libVSD

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
    
nuage_ext = NuageExtensionInit()

class Testbed(object):

    def __init__(self):
        path_to_esrcalls = CONF.nuagext.esr_calls_file
        testbed = CONF.nuagext.exec_server
        testbed_user = CONF.nuagext.exec_server_user
        if not (path_to_esrcalls or testbed or testbed_user):
            raise Exception('Testbed topo file or exec server is not provided')
        self.testbed = topology.Topology(path_to_esrcalls)

topo = Testbed()

for k,v in topo.testbed.duts.iteritems():
    for comp in CONF.nuagext.nuage_components:
        if k.startswith(comp):
            LOG.info('Opening SSH session to {}'.format(k))
            v.ssh.open()
    if k.startswith('vsd'):
        vsd_ip = CONF.nuage_vsd_group.nuage_vsd_server.split(':')[0]
        vsd_port = CONF.nuage_vsd_group.nuage_vsd_server.split(':')[1]
        api_client = libVSD.client.ApiClient(address=vsd_ip, port=vsd_port)
        api_client.new_session()
        helper = libVSD.helpers.VSDHelpers(api_client)
