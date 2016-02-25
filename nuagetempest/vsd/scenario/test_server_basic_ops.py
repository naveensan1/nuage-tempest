from tempest import config
from nuagetempest.tests.scenario.test_server_basic_ops import TestServerBasicOps
from tempest import test
import re
import unittest
import sys

CONF = config.CONF

class TestServerBasicOps(TestServerBasicOps):
    
    def __init__(self):
        pass

    class _server_basic_ops(TestServerBasicOps):

        def __init__(self):
            self.def_net_partition = CONF.nuage.nuage_default_netpartition
        
        def verify_vm(self, cls):
            neutron_routers = self.network_client.list_routers()['routers'][0]
            pass
            
