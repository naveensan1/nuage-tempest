from .sanity import \
    TestSSH, \
    TestVMsAreReachable, \
    TestVSDServicesAreUp, \
    TestLinks

# Customize the test classes here if necessay

__all__ = [
    'TestSSH', 'TestVMsAreReachable', 'TestVSDServicesAreUp', 'TestLinks'
]

import time
from vspk.vsdk.v3_2 import *
import nutopos
from nose2.compat import unittest

LICENSE = "MDEyOHb3tX7A10w7c/oClOJTyxOIVAssArZJpo/5LlSPifxPrlhepIO5B9OM60SuI1HVgRNeYxW3WYnHzy2eqzT+kp8XHlSjPUOcNhxJDfSCevul8hRF8EMUvSzaWGJ+G4m2LmQ1+tKzZ48MgKFkOYaeHTuuFDt2+AvcNGLEjFXilW06MDE2MjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAkOyl181q5j2UHPUCD5nzBE5Gz0g3N1n8KAs6aEcNO7ueXvPUeiuNQ//ui0vE9otuo4AnLJkLKuxoIJmVjIKzxXlMEqsAK5zwOJpECOTEMxjZkyWcAujQg/ajVRcUAW+91UPz2nkzs1WkPhKs5ZjJTrksoEvmMt5fhNFXgLY2jCcCAwEAATA1MTd7InByb3ZpZGVyIjoiTnVhZ2UgTmV0d29ya3MgLSBBbGNhdGVsLUx1Y2VudCBJbmMiLCJwcm9kdWN0VmVyc2lvbiI6IjMuMCIsImxpY2Vuc2VJZCI6MSwibWFqb3JSZWxlYXNlIjoxLCJtaW5vclJlbGVhc2UiOjAsInVzZXJOYW1lIjoiYWRtaW4iLCJlbWFpbCI6ImFkbWluQGFsdS5jb20iLCJjb21wYW55IjoiQWxjYXRlbCBMdWNlbnQiLCJwaG9uZSI6Ijk5OS05OTktOTk5OSIsInN0cmVldCI6IjgwNSBFIE1pZGRsZWZpZWxkIFJkIiwiY2l0eSI6Ik1vdW50YWluIFZpZXciLCJzdGF0ZSI6IkNBIiwiemlwIjoiOTQwNDMiLCJjb3VudHJ5IjoiVVNBIiwiY3VzdG9tZXJLZXkiOiJmZWZlZmVmZS1mZWZlLWZlZmUtZmVmZSIsImFsbG93ZWRWTXNDb3VudCI6LTEsImFsbG93ZWROSUNzQ291bnQiOi0xLCJhbGxvd2VkVlJTc0NvdW50IjotMSwiYWxsb3dlZFZSU0dzQ291bnQiOi0xLCJhbGxvd2VkQ1BFc0NvdW50IjotMSwiaXNDbHVzdGVyTGljZW5zZSI6ZmFsc2UsImV4cGlyYXRpb25EYXRlIjoiMDgvMDUvMjAxNiJ9"

class OpenstackSanity(unittest.TestCase):

    def setUp(self):

        nutopos.T.open_ssh_sessions()


        def setup_vsd():
            self.session = NUVSDSession(username=u'csproot', password=u'csproot', enterprise=u'csp', api_url=u'https://vsd-1:8443')
            self.session.start()
            license = NULicense()
            license.license = LICENSE
            self.session.user.create_child(license)

        def setup_tblinux():

            nutopos.T.testbed.cmd.send(cmd='ifconfig eth1 10.10.5.1/24 up')
            nutopos.T.testbed.cmd.send(cmd='route add -net 10.10.0.0/16 gw 10.10.5.254')
            nutopos.T.testbed.cmd.send(cmd='route add -net 10.100.100.0/24 gw 10.10.5.254')
            nutopos.T.testbed.cmd.send(cmd='route -n')
            #nutopos.T.testbed.cmd.send(cmd='ping 10.100.100.20 -c 5')
            nutopos.T.testbed.cmd.ping(destination='10.100.100.20', count='5')

        def setup_osc():

            cmd = 'python set_and_audit_cms.py --plugin-config-file /etc/neutron/plugin.ini --neutron-config-file /etc/neutron/neutron.conf'
            path = '/opt/upgrade-script/upgrade-scripts'
            nutopos.T.osc.cmd.send(cmd='cd ' + path + ';' + cmd)

            nutopos.T.osc.cmd.send(cmd='service neutron-server restart')
            time.sleep(5)
            nutopos.T.osc.cmd.send(cmd='service neutron-server status')

            nutopos.T.osc.cmd.send(cmd='source ~/admin_rc;neutron net-create tempestPublicNw --router:external')
            nutopos.T.osc.cmd.send(cmd='source ~/admin_rc;neutron subnet-create tempestPublicNw 10.10.100.0/24 --name tempestPublicSubnet')
            nutopos.T.osc.cmd.send(cmd='source ~/admin_rc;neutron net-list')
            nutopos.T.osc.cmd.send(cmd='source ~/admin_rc;neutron subnet-list')

        setup_vsd()
        setup_tblinux()
        setup_osc()

    def test_osc(self):
        #for dut in nutopos.T.duts_list:
        #    print dut
        nutopos.T.osc.cmd.send(cmd='service neutron-server status')

