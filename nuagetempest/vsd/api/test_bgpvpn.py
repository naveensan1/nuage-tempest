from tempest import config
from nuagetempest.lib import topology
from nuagetempest.lib import base
from tempest import test
import re
import unittest
import sys

CONF = config.CONF
TB = topology.testbed


class RouterAssociationTest():

    def __init__(self):
        pass
    
    class _router_association_create():
        def __init__(self):
            pass
        
        def verify_l3domain_rt_rd(self, obj):
            os_router = obj.os_data.get_resource('os-router-ra-1').os_data
            l3domain_ext_id = base.get_external_id(os_router['id'])
            vsd_l3dom = TB.vsd_1.get_domain(
                filter=base.get_filter_str('externalID', l3domain_ext_id))
            