from tempest import test
from nuagetempest import layer

class TestServerBasicOps(test.BaseTestCase):
    
    def __init__(self):
        pass

    class _server_basic_ops(test.BaseTestCase):

        def __init__(self):
            pass
    
        def verify_vm(self):
            verified = False
            for k, vsc in layer.vsces.iteritems():
                print vsc.cmd('show vswitch-controller vports type vm')