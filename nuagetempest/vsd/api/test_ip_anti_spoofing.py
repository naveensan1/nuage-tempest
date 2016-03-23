from tempest import config
from nuagetempest.lib import topology
from tempest import test
import re
import unittest
import sys

CONF = config.CONF
TB = topology.testbed

class IpAntiSpoofingTest():
    
    def __init__(self):
        pass
    
    class _create_delete_sec_disabled_ntw_port_l2domain():
        def __init__(self):
            pass
        def verify_security_disabled_ntw_port_l2domain(self, obj):
            #from pygash import utils; utils.interpreter()
            #obtin the parent of port
            l2domain = obj.os_data.get_resource('l2domain-1').data
            l2domain_ext_id = l2domain['id'] + '@' + CONF.nuage.nuage_cms_id
            vsd_l2domain = TB.vsd_1.session.user.l2_domains.get_first(
                           filter='externalID == "{}"'.format(l2domain_ext_id))

            port = obj.os_data.get_resource('port-1').data 
            vsd_port = vsd_l2domain.vports.get_first()
           
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
            
            #check policygroup is PG_FOR_LESS_SECURITY_XXXX
            vsd_port_pg = vsd_port.policy_groups.get_first()
            vsd_l2dom_pg = vsd_l2domain.policy_groups.get_first()
            obj.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l2dom_pg.name)
    
    class _create_delete_sec_disabled_ntw_l2domain():
        def __init__(self):
            pass
        def verify_security_disabled_ntw_l2domain(self, obj):
            #obtin the parent of port
            l2domain = obj.os_data.get_resource('l2domain-1').data
            l2domain_ext_id = l2domain['id'] + '@' + CONF.nuage.nuage_cms_id
            vsd_l2domain = TB.vsd_1.session.user.l2_domains.get_first(
                           filter='externalID == "{}"'.format(l2domain_ext_id))

            port = obj.os_data.get_resource('port-1').data 
            vsd_port = vsd_l2domain.vports.get_first()
           
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
            
            #check policygroup is PG_FOR_LESS_SECURITY_XXXX
            vsd_port_pg = vsd_port.policy_groups.get_first()
            vsd_l2dom_pg = vsd_l2domain.policy_groups.get_first()
            obj.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l2dom_pg.name)
     
    class _create_delete_sec_disabled_port_l2domain():
        def __init__(self):
            pass
        def verify_security_disabled_port_l2domain(self, obj):
            #obtin the parent of port
            l2domain = obj.os_data.get_resource('l2domain-1').data
            l2domain_ext_id = l2domain['id'] + '@' + CONF.nuage.nuage_cms_id
            vsd_l2domain = TB.vsd_1.session.user.l2_domains.get_first(
                           filter='externalID == "{}"'.format(l2domain_ext_id))

            port = obj.os_data.get_resource('port-1').data 
            vsd_port = vsd_l2domain.vports.get_first()
           
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
            
            #check policygroup is PG_FOR_LESS_SECURITY_XXXX
            vsd_port_pg = vsd_port.policy_groups.get_first()
            vsd_l2dom_pg = vsd_l2domain.policy_groups.get_first()
            obj.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l2dom_pg.name)
  

    class _create_delete_sec_disabled_ntw_port_l3domain():
        def __init__(self):
            pass
        def verify_security_disabled_ntw_port_l3domain(self, obj):
            router = obj.os_data.get_resource('router-1').data
            router_ext_id = router['id']  + '@' + CONF.nuage.nuage_cms_id
            vsd_l3dom = TB.vsd_1.get_domain(
                        filter='externalID == "{}"'.format(router_ext_id))
            subnet = obj.os_data.get_resource('subnet-1').data
            subnet_ext_id = subnet['id']  + '@' + CONF.nuage.nuage_cms_id
            vsd_sub = TB.vsd_1.get_subnet(
                      filter='externalID == "{}"'.format(subnet_ext_id))
            
            port = obj.os_data.get_resource('port-1').data
            port_ext_id = port['id']  + '@' + CONF.nuage.nuage_cms_id
            vsd_port = TB.vsd_1.get_vport(subnet=vsd_sub,
                       filter='externalID == "{}"'.format(port_ext_id))
            
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
  
            #Check the policy group is PG_FOR_LESS_SECURITY_XXX
            vsd_l3dom_pg = vsd_l3dom.policy_groups.get_first()
            vsd_port_pg = vsd_port.policy_groups.get_first()
            obj.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l3dom_pg.name)
 
