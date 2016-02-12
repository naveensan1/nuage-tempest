from tempest import config
from nuagetempest.lib import vsd_client
from nuagetempest.tests.api.test_routers import RoutersTest
from tempest import test
import re
import unittest
import sys

CONF = config.CONF

class RoutersTest(RoutersTest):
    
    def __init__(self):
        pass  

    class _create_router_interface(RoutersTest):

        def __init__(self):
            self.def_net_partition = CONF.nuage.nuage_default_netpartition
            self.vsd_client = vsd_client.vsd_client()

        def verify_r_i(self):
            neutron_routers = self.client.list_routers()['routers'][0]
            neutron_subnets = self.subnets_client.list_subnets()['subnets'][0]
            subnet_ids = neutron_subnets['id']
            enterprises = self.vsd_client.get_enterprises()
            for enterprise in enterprises:
                if enterprise.name == self.def_net_partition:
                    vsd_l3domains = self.vsd_client.get_l3domains(enterprise)
            verified = False
            for l3domain in vsd_l3domains:
                if l3domain.description != None:
                    if re.search('router-', l3domain.description):
                        self.assertTrue(l3domain.name == neutron_routers['id'])
                        self.assertTrue(l3domain.description == neutron_routers['name'])
                        subnets = self.vsd_client.get_subnets(l3domain)
                        for subnet in subnets:
                            if re.search('tempest-subnet-', subnet.description):
                                if subnet.name in subnet_ids:
                                    verified = True
            self.assertTrue(verified == True)
            print "verify_r_i"
