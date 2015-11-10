import time
import vspk.vsdk.v3_2 as vspk
# from nose2.compat import unittest

LICENSE = "MDEyOHb3tX7A10w7c/oClOJTyxOIVAssArZJpo/5LlSPifxPrlhepIO5B9OM60SuI1HVgRNeYxW3WYnHzy2eqzT+kp8XHlSjPUOcNhxJDfSCevul8hRF8EMUvSzaWGJ+G4m2LmQ1+tKzZ48MgKFkOYaeHTuuFDt2+AvcNGLEjFXilW06MDE2MjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAkOyl181q5j2UHPUCD5nzBE5Gz0g3N1n8KAs6aEcNO7ueXvPUeiuNQ//ui0vE9otuo4AnLJkLKuxoIJmVjIKzxXlMEqsAK5zwOJpECOTEMxjZkyWcAujQg/ajVRcUAW+91UPz2nkzs1WkPhKs5ZjJTrksoEvmMt5fhNFXgLY2jCcCAwEAATA1MTd7InByb3ZpZGVyIjoiTnVhZ2UgTmV0d29ya3MgLSBBbGNhdGVsLUx1Y2VudCBJbmMiLCJwcm9kdWN0VmVyc2lvbiI6IjMuMCIsImxpY2Vuc2VJZCI6MSwibWFqb3JSZWxlYXNlIjoxLCJtaW5vclJlbGVhc2UiOjAsInVzZXJOYW1lIjoiYWRtaW4iLCJlbWFpbCI6ImFkbWluQGFsdS5jb20iLCJjb21wYW55IjoiQWxjYXRlbCBMdWNlbnQiLCJwaG9uZSI6Ijk5OS05OTktOTk5OSIsInN0cmVldCI6IjgwNSBFIE1pZGRsZWZpZWxkIFJkIiwiY2l0eSI6Ik1vdW50YWluIFZpZXciLCJzdGF0ZSI6IkNBIiwiemlwIjoiOTQwNDMiLCJjb3VudHJ5IjoiVVNBIiwiY3VzdG9tZXJLZXkiOiJmZWZlZmVmZS1mZWZlLWZlZmUtZmVmZSIsImFsbG93ZWRWTXNDb3VudCI6LTEsImFsbG93ZWROSUNzQ291bnQiOi0xLCJhbGxvd2VkVlJTc0NvdW50IjotMSwiYWxsb3dlZFZSU0dzQ291bnQiOi0xLCJhbGxvd2VkQ1BFc0NvdW50IjotMSwiaXNDbHVzdGVyTGljZW5zZSI6ZmFsc2UsImV4cGlyYXRpb25EYXRlIjoiMDgvMDUvMjAxNiJ9"


def setup_vsd():
    session = vspk.NUVSDSession(username='csproot', password='csproot',
                                enterprise=u'csp', api_url='https://vsd-1:8443')
    session.start()
    license = vspk.NULicense()
    license.license = LICENSE
    try:
        session.user.create_child(license)
    except:
        pass


def setup_tblinux(layer):
    testbed = layer.T.testbed
    testbed.ssh.su('root', 'tigris')
    testbed.cmd('ifconfig eth1 10.10.5.1/24 up', strict=False)
    testbed.cmd('route add -net 10.10.0.0/16 gw 10.10.5.254', strict=False)
    testbed.cmd('route add -net 10.100.100.0/24 gw 10.10.5.254', strict=False)
    testbed.cmd('route -n', strict=False)
    # testbed.cmd('ping 10.100.100.20 -c 5')
    # testbed.cmd.ping(destination='10.100.100.20', count='5')
    testbed.ssh.exit()


def setup_osc(layer):
    osc = layer.T.osc

    audit_cmd = ('python set_and_audit_cms.py '
                 '--plugin-config-file /etc/neutron/plugin.ini '
                 '--neutron-config-file /etc/neutron/neutron.conf')
    path = '/opt/upgrade-script/upgrade-scripts'
    cmd = 'cd {path} ; {audit_cmd}'.format(path=path, audit_cmd=audit_cmd)
    osc.cmd(cmd, strict=False)

    osc.cmd('service neutron-server restart')
    time.sleep(5)
    osc.cmd('service neutron-server status')

    cmds = [
        'source ~/admin_rc',
        'neutron net-create tempestPublicNw --router:external',
        'neutron subnet-create tempestPublicNw 10.10.100.0/24 --name tempestPublicSubnet',
        'neutron net-list',
        'neutron subnet-list'
    ]
    osc.cmd(' ; '.join(cmds))

def setup_tempestcfg():

    print "hello"

def initial_setup(layer):
    setup_vsd()
    setup_tblinux(layer)
    setup_osc(layer)

setup_tempestcfg()

# def test_osc(self):
#     #for dut in nutopos.T.duts_list:
#     #    print dut
#     nutopos.T.osc.cmd.send(cmd='service neutron-server status')
