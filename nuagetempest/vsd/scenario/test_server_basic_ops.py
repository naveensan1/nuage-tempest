from tempest import config
from nuagetempest.lib import vsd_client
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
            self.vsd_client = vsd_client.vsd_client() 
        
        def verify_vm(self):
            neutron_routers = self.network_client.list_routers()['routers'][0]
            enterprises = self.vsd_client.get_enterprises()
            for enterprise in enterprises:
                if enterprise.name == self.def_net_partition:
                    vsd_l3domains = self.vsd_client.get_l3domains(enterprise)
                    
            for l3domain in vsd_l3domains:
                if l3domain.description != None:
                    if re.search('BasicOps', l3domain.description):
                        self.assertTrue(l3domain.name == neutron_routers['id'])
                        self.assertTrue(l3domain.description == neutron_routers['name'])
            
