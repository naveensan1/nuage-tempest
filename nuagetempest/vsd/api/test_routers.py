from tempest import config
from nuagetempest.tests import helper
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

        def verify_r_i(self):
            filter_str = 'name is "{}"'.format(self.def_net_partition)
            vsd_enterprise = helper.get_enterprise(filter=filter_str)
            filter_str = 'name is "{}"'.format(self.os.router['id'])
            vsd_l3d = helper.get_domain(enterprise=vsd_enterprise.id,
                                             filter=filter_str)
            if vsd_l3d:
                filter_str = 'name is "{}"'.format(self.os.subnet01['id'])
                subnet = helper.get_subnet_from_domain(domain=vsd_l3d,
                                                            filter=filter_str)
                if not subnet:
                    raise "Nuage Subnet not found"
            else:
                raise "Nuage Domain not found"
            print "verify_r_i"
