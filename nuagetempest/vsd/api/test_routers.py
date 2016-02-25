from tempest import config
from nuagetempest.lib import topology
from nuagetempest.tests.api.test_routers import RoutersTest
from tempest import test
import re
import unittest
import sys

CONF = config.CONF
TB = topology.testbed

class RoutersTest(RoutersTest):
    
    def __init__(self):
        pass  

    class _create_router_interface(RoutersTest):

        def __init__(self):
            self.def_net_partition = CONF.nuage.nuage_default_netpartition

        def verify_r_i(self, cls):
            '''filter_str = 'name is "{}"'.format(self.def_net_partition)
            vsd_enterprise = TB.vsd_0.get_enterprise(filter=filter_str)
            filter_str = 'name is "{}"'.format(cls._openstack.routers['id'])
            vsd_l3d = TB.vsd_0.get_domain(enterprise=vsd_enterprise.id,
                                             filter=filter_str)
            if vsd_l3d:
                filter_str = 'name is "{}"'.format(self.openstack.subnet01['id'])
                subnet = TB.vsd_0.get_subnet_from_domain(domain=vsd_l3d,
                                                            filter=filter_str)
                if not subnet:
                    raise "Nuage Subnet not found"
            else:
                raise "Nuage Domain not found"
            print "verify_r_i"'''
            pass
