from libduts import topology
from libduts import linux
from oslo_log import log as logging
from nuagetempest.lib import nuage_ext
import re
import traceback
from tempest import config
from jira import JIRA

CONF = config.CONF
BUGS_DICT = {}
LOG = logging.getLogger(__name__)

class NuageExtensionInit():
    
    def __init__(self):
        self.nuage_extension = nuage_ext.NuageExtension()
        self._read_bugs_file()
        self.jira = JIRA('http://mvjira.mv.usa.alcatel.com:8080', basic_auth=("regression", "2fdb64fd-421c-4969-8b81-0d6d332d573c"))

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
            
    def _skip_test_check_bug(self, fn):
        def wrapped(*args, **kwargs):
            m = re.search(r"function (\w+)", str(fn))
            open_bug = False
            if BUGS_DICT == {}:
                return fn(*args, **kwargs)
            if m.group(1) in BUGS_DICT.keys():
                for bug in BUGS_DICT.get(m.group(1)):
                    issue = self.jira.issue(bug)
                    if issue.fields.status.name == "Open":
                        open_bug = True
                        break
            if open_bug is True:
                LOG.info("This test has a open bug Skipping")
                return
            else:
                return fn(*args, **kwargs)
        return wrapped
    
    def _parse_bugs_line(self, line):
        line = line.split()
    
        try:
            tc = line[0]
            bugs = line[1:]
            return tc, bugs
        except:
            return None, None

    def _read_bugs_file(self):
        try:
            with open('/opt/stack/open-bugs.txt', 'r') as bugs_file:
                for line in bugs_file.readlines():
                    tc_name, bugs = self._parse_bugs_line(line)
                    BUGS_DICT[tc_name] = bugs
        except IOError:
            return
            
nuage_ext = NuageExtensionInit()

class Testbed(object):

    def __init__(self):
        path_to_esrcalls = CONF.nuagext.esr_calls_file
        testbed = CONF.nuagext.exec_server
        testbed_user = CONF.nuagext.exec_server_user
        if not (path_to_esrcalls or testbed or testbed_user):
            raise Exception('esrcalls file/exec_ser/exec_ser_uname not provided')
        self.T = topology.Topology(path_to_esrcalls)

layer = Testbed()

for k,v in layer.T.duts.iteritems():
    v.ssh.open()
