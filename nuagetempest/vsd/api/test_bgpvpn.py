from tempest import config
from oslo_log import log as logging
from nuagetempest.lib import topology
from nuagetempest.lib import base
from tempest import test
import re
import unittest
import sys

CONF = config.CONF
TB = topology.testbed

LOG = logging.getLogger(__name__)

class RouterAssociationTest():

    def __init__(self):
        pass
    
    def _verify_rt_rd_on_neutron_vsd(self, obj, router_tag):
        LOG.info("Verifying rt and rd on neutron and Nuage VSD")
        neutron_router = obj.os_data.get_resource(router_tag).os_data
        vsd_l3d = obj.os_data.get_resource(router_tag).vsd_data
        obj.assertEqual(neutron_router['rt'], vsd_l3d._route_target)
        obj.assertEqual(neutron_router['rd'], vsd_l3d._route_distinguisher)

    class _router_association_create():
        def __init__(self):
            self.router_associate_test =  RouterAssociationTest()
            pass
        
        def verify_l3domain_rt_rd(self, obj):
            os_router = obj.os_data.get_resource('os-router-ra-1').os_data
            l3domain_ext_id = base.get_external_id(os_router['id'])
            vsd_l3dom = TB.vsd_1.get_domain(
                filter=base.get_filter_str('externalID', l3domain_ext_id))
            obj.os_data.update_resource('os-router-ra-1', vsd_data=vsd_l3dom)
            self.router_associate_test._verify_rt_rd_on_neutron_vsd(obj,
                    'os-router-ra-1')
            
    class _router_association_create_list():
        def __init__(self):
            self.router_associate_test =  RouterAssociationTest()
            pass
        
        def verify_l3domain_rt_rd(self, obj):
            os_router = obj.os_data.get_resource('os-router-ra-1').os_data
            l3domain_ext_id = base.get_external_id(os_router['id'])
            vsd_l3dom = TB.vsd_1.get_domain(
                filter=base.get_filter_str('externalID', l3domain_ext_id))
            obj.os_data.update_resource('os-router-ra-1', vsd_data=vsd_l3dom)
            self.router_associate_test._verify_rt_rd_on_neutron_vsd(obj,
                    'os-router-ra-1')           
            