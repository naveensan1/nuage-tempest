from tempest import config
from nuagetempest.library import neutron_client
from nuagetempest.library import vsd_client
from tempest import test
import re
import unittest
import sys

CONF = config.CONF

class RoutersTest(test.BaseTestCase):
    
    def __init__(self):
        pass

    class _create_router_interface(test.BaseTestCase):
        
        def __init__(self):
           self.def_net_partition = CONF.nuage.nuage_default_netpartition
           self.neutron_client = neutron_client.neutron_client()
           self.vsd_client = vsd_client.vsd_client() 

        def verify_r_i(self):
            neutron_routers = self.neutron_client.get_neutron_routers()[0]
            neutron_subnets = self.neutron_client.get_neutron_subnets()
            subnet_ids = []
            for neutron_subnet in neutron_subnets:
                subnet_ids.append(neutron_subnet['id'])
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