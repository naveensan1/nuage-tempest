from tempest import config
from nuagetempest.lib import topology
from nuagetempest.lib import base
from tempest import test
import re
import unittest
import sys

CONF = config.CONF
TB = topology.testbed


class IpAntiSpoofingTest():

    def __init__(self):
        pass

    def _get_vsd_l2dom_port(self, l2dom, port):
        # Method to get the VSD object for l2domain and port
        l2domain_ext_id = base.get_external_id(l2dom['id'])
        vsd_l2domain = TB.vsd_1.get_l2domain(
            filter=base.get_filter_str('externalID', l2domain_ext_id))
        vsd_ports = vsd_l2domain.vports.get()
        while vsd_ports.__len__() > 0:
            vsd_port = vsd_ports.pop()
            if port['id'] == vsd_port.name:
                break
        #vsd_port = vsd_l2domain.vports.get_first()
        return (vsd_l2domain, vsd_port)

    def _get_vsd_router_subnet_port(self, router, subnet, port):
        # Method to get the VSD objects for router, subnet and port
        router_ext_id = base.get_external_id(router['id'])
        vsd_l3dom = TB.vsd_1.get_domain(
            filter=base.get_filter_str('externalID', router_ext_id))
        subnet_ext_id = base.get_external_id(subnet['id'])
        vsd_sub = TB.vsd_1.get_subnet(
            filter=base.get_filter_str('externalID', subnet_ext_id))
        port_ext_id = base.get_external_id(port['id'])
        vsd_port = TB.vsd_1.get_vport(subnet=vsd_sub,
            filter=base.get_filter_str('externalID', port_ext_id))
        return (vsd_l3dom, vsd_sub, vsd_port)

    def _verify_ingress_egress_rules(self, obj, vsd_pg,
                                     in_rule=None, eg_rule=None):
        # Method to verify the ingress and egress rules created for ports with
        # port-security-enabled set to False
        if in_rule is None:
            in_rule = TB.vsd_1.get_ingress_acl_entry(filter=None)
        if eg_rule is None:
            eg_rule = TB.vsd_1.get_egress_acl_entry(filter=None)
        obj.assertEqual(in_rule.network_type, 'ANY')
        obj.assertEqual(in_rule.location_type, 'POLICYGROUP')
        obj.assertEqual(in_rule.location_id, vsd_pg.id)

        obj.assertEqual(eg_rule.network_type, 'ANY')
        obj.assertEqual(eg_rule.location_type, 'POLICYGROUP')
        obj.assertEqual(eg_rule.location_id, vsd_pg.id)

    def _verify_vip_and_anti_spoofing_l2dom(self, port, vsd_port,
                                            vip_params, obj):
        # Case where only the anti-spoofing is enabled
        if obj.get_vip_action(vip_params) == obj.vip_action.spoofing:
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
        # Case where VIP gets created. Verify the ip and mac of VIP 
        if obj.get_vip_action(vip_params) == obj.vip_action.vip:
            obj.assertEqual(vsd_port.address_spoofing, 'INHERITED')
            vsd_vips = vsd_port.virtual_ips.get()
            for os_vip in port['allowed_address_pairs']:
                vsd_vip = vsd_vips.pop()
                obj.assertEqual(os_vip['ip_address'], vsd_vip.virtual_ip)
                obj.assertEqual(os_vip['mac_address'], vsd_vip.mac)

        # Case where no action occurs on VSD for given AAP
        if obj.get_vip_action(vip_params) == obj.vip_action.no_vip:
            obj.assertEqual(vsd_port.address_spoofing, 'INHERITED')
   
    class _create_delete_sec_disabled_ntw_port_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_security_disabled_port_l2domain(self, obj):
            # obtin the parent of port
            l2domain = obj.os_data.get_resource('l2dom1-1').os_data
            port = obj.os_data.get_resource('port1-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom1-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port1-1', vsd_data=vsd_port)
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
            # check policygroup is PG_FOR_LESS_SECURITY_XXXX
            vsd_port_pg = vsd_port.policy_groups.get_first()
            vsd_l2dom_pg = vsd_l2domain.policy_groups.get_first()
            obj.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l2dom_pg.name)
            # Check the two ingress and egress rules
            self.ip_anti_spoof._verify_ingress_egress_rules(obj, vsd_port_pg)

    class _create_delete_sec_disabled_ntw_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_security_disabled_port_l2domain(self, obj):
            # obtain the parent of port
            l2domain = obj.os_data.get_resource('l2dom2-1').os_data
            port = obj.os_data.get_resource('port2-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom2-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port2-1', vsd_data=vsd_port)
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
            # check policygroup is PG_FOR_LESS_SECURITY_XXXX
            vsd_port_pg = vsd_port.policy_groups.get_first()
            vsd_l2dom_pg = vsd_l2domain.policy_groups.get_first()
            obj.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l2dom_pg.name)
            # Check the two ingress and egress rules
            self.ip_anti_spoof._verify_ingress_egress_rules(obj, vsd_port_pg)

    class _create_delete_sec_disabled_port_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_security_disabled_port_l2domain(self, obj):
            # obtain the parent of port
            l2domain = obj.os_data.get_resource('l2dom3-1').os_data
            port = obj.os_data.get_resource('port3-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom3-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port3-1', vsd_data=vsd_port)
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
            # check policygroup is PG_FOR_LESS_SECURITY_XXXX
            vsd_port_pg = vsd_port.policy_groups.get_first()
            vsd_l2dom_pg = vsd_l2domain.policy_groups.get_first()
            obj.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l2dom_pg.name)
            # Check the two ingress and egress rules
            self.ip_anti_spoof._verify_ingress_egress_rules(obj, vsd_port_pg)

    class _create_delete_sec_disabled_ntw_port_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_security_disabled_port_l3domain(self, obj):
            router = obj.os_data.get_resource('router4-1').os_data
            subnet = obj.os_data.get_resource('subnet4-1').os_data
            port = obj.os_data.get_resource('port4-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router4-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet4-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port4-1', vsd_data=vsd_port)
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
            # Check the policy group is PG_FOR_LESS_SECURITY_XXX
            vsd_l3dom_pg = vsd_l3dom.policy_groups.get_first()
            vsd_port_pg = vsd_port.policy_groups.get_first()
            obj.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l3dom_pg.name)
            # Check the two ingress and egress rules
            self.ip_anti_spoof._verify_ingress_egress_rules(obj, vsd_port_pg)

    class _create_delete_sec_disabled_ntw_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_security_disabled_port_l3domain(self, obj):
            router = obj.os_data.get_resource('router5-1').os_data
            subnet = obj.os_data.get_resource('subnet5-1').os_data
            port = obj.os_data.get_resource('port5-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router5-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet5-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port5-1', vsd_data=vsd_port)
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
            # Check the policy group is PG_FOR_LESS_SECURITY_XXX
            vsd_l3dom_pg = vsd_l3dom.policy_groups.get_first()
            vsd_port_pg = vsd_port.policy_groups.get_first()
            obj.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l3dom_pg.name)
            # Check the two ingress and egress rules
            self.ip_anti_spoof._verify_ingress_egress_rules(obj, vsd_port_pg)

    class _create_delete_sec_disabled_port_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_security_disabled_port_l3domain(self, obj):
            router = obj.os_data.get_resource('router6-1').os_data
            subnet = obj.os_data.get_resource('subnet6-1').os_data
            port = obj.os_data.get_resource('port6-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router6-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet6-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port6-1', vsd_data=vsd_port)
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
            # Check the policy group is PG_FOR_LESS_SECURITY_XXX
            vsd_l3dom_pg = vsd_l3dom.policy_groups.get_first()
            vsd_port_pg = vsd_port.policy_groups.get_first()
            obj.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l3dom_pg.name)
            # Check the two ingress and egress rules
            self.ip_anti_spoof._verify_ingress_egress_rules(obj, vsd_port_pg)

    class _update_ntw_from_sec_disabled_to_enabled_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_security_disabled_port_l2domain(self, obj):
            # obtain the parent of port
            l2domain = obj.os_data.get_resource('l2dom7-1').os_data
            port = obj.os_data.get_resource('port7-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom7-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port7-1', vsd_data=vsd_port)
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
            # check policygroup is PG_FOR_LESS_SECURITY_XXXX
            vsd_port_pg = vsd_port.policy_groups.get_first()
            vsd_l2dom_pg = vsd_l2domain.policy_groups.get_first()
            obj.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l2dom_pg.name)
            # Check the two ingress and egress rules
            self.ip_anti_spoof._verify_ingress_egress_rules(obj, vsd_port_pg)

        def verify_security_enabled_port_l2domain(self, obj):
            l2domain = obj.os_data.get_resource('l2dom7-1').os_data
            port_1 = obj.os_data.get_resource('port7-1').os_data
            port_2 = obj.os_data.get_resource('port7-2').os_data
            vsd_port_1 = obj.os_data.get_resource('port7-1').vsd_data
            vsd_l2domain, vsd_port_2 = self.ip_anti_spoof._get_vsd_l2dom_port(
                                       l2domain, port_2)
            obj.os_data.update_resource('port7-2', vsd_data=vsd_port_2)
            obj.assertEqual(vsd_port_1.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port_2.address_spoofing, 'INHERITED')
            obj.assertEqual(vsd_port_1.name, port_1['id'])
            obj.assertEqual(vsd_port_2.name, port_2['id'])

            port_1_pg = vsd_port_1.policy_groups.get_first()
            port_2_pg = vsd_port_2.policy_groups.get_first()
            obj.assertEqual(port_1_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertNotEqual(port_2_pg.name[:21], 'PG_FOR_LESS_SECURITY_')

    class _update_ntw_from_sec_enabled_to_disabled_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_security_enabled_port_l2domain(self, obj):
            # obtain the parent of port
            l2domain = obj.os_data.get_resource('l2dom8-1').os_data
            port = obj.os_data.get_resource('port8-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom8-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port8-1', vsd_data=vsd_port)
            obj.assertEqual(vsd_port.address_spoofing, 'INHERITED')
            obj.assertEqual(vsd_port.name, port['id'])
            # check policygroup is PG_FOR_LESS_SECURITY_XXXX
            vsd_port_pg = vsd_port.policy_groups.get_first()
            vsd_l2dom_pg = vsd_l2domain.policy_groups.get_first()
            obj.assertNotEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l2dom_pg.name)

        def verify_security_disabled_port_l2domain(self, obj):
            l2domain = obj.os_data.get_resource('l2dom8-1').os_data
            port_1 = obj.os_data.get_resource('port8-1').os_data
            port_2 = obj.os_data.get_resource('port8-2').os_data
            vsd_port_1 = obj.os_data.get_resource('port8-1').vsd_data
            vsd_l2domain, vsd_port_2 = self.ip_anti_spoof._get_vsd_l2dom_port(
                                       l2domain, port_2)
            obj.os_data.update_resource('port8-2', vsd_data=vsd_port_2)
            obj.assertEqual(vsd_port_1.address_spoofing, 'INHERITED')
            obj.assertEqual(vsd_port_2.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port_1.name, port_1['id'])
            obj.assertEqual(vsd_port_2.name, port_2['id'])

            port_1_pg = vsd_port_1.policy_groups.get_first()
            port_2_pg = vsd_port_2.policy_groups.get_first()
            obj.assertNotEqual(port_1_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(port_2_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
    
    class _update_port_from_sec_disabled_to_enabled_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_security_disabled_port_l2domain(self, obj):
            # obtain the parent of port
            l2domain = obj.os_data.get_resource('l2dom9-1').os_data
            port = obj.os_data.get_resource('port9-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom9-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port9-1', vsd_data=vsd_port)
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
            # check policygroup is PG_FOR_LESS_SECURITY_XXXX
            vsd_port_pg = vsd_port.policy_groups.get_first()
            vsd_l2dom_pg = vsd_l2domain.policy_groups.get_first()
            obj.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l2dom_pg.name)
            # Check the two ingress and egress rules
            self.ip_anti_spoof._verify_ingress_egress_rules(obj, vsd_port_pg)

        def verify_security_enabled_port_l2domain(self, obj):
            l2domain = obj.os_data.get_resource('l2dom9-1').os_data
            port = obj.os_data.get_resource('port9-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                       l2domain, port)
            obj.os_data.update_resource('port9-1', vsd_data=vsd_port)
            obj.assertEqual(vsd_port.address_spoofing, 'DISABLED')
            obj.assertEqual(vsd_port.name, port['id'])

            port_pg = vsd_port.policy_groups.get_first()
            obj.assertEqual(port_pg, None)

    class _update_port_from_sec_enabled_to_disabled_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_security_enabled_port_l2domain(self, obj):
            # obtain the parent of port
            l2domain = obj.os_data.get_resource('l2dom10-1').os_data
            port = obj.os_data.get_resource('port10-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom10-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port10-1', vsd_data=vsd_port)
            obj.assertEqual(vsd_port.address_spoofing, 'INHERITED')
            obj.assertEqual(vsd_port.name, port['id'])
            # check policygroup is PG_FOR_LESS_SECURITY_XXXX
            vsd_port_pg = vsd_port.policy_groups.get_first()
            vsd_l2dom_pg = vsd_l2domain.policy_groups.get_first()
            obj.assertNotEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l2dom_pg.name)

        def verify_security_disabled_port_l2domain(self, obj):
            l2domain = obj.os_data.get_resource('l2dom10-1').os_data
            port = obj.os_data.get_resource('port10-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                       l2domain, port)
            obj.os_data.update_resource('port10-1', vsd_data=vsd_port)
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])

            port_pg = vsd_port.policy_groups.get_first()
            obj.assertEqual(port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
    
    class _update_ntw_from_sec_disabled_to_enabled_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_security_disabled_port_l3domain(self, obj):
            # obtain the parent of port
            router = obj.os_data.get_resource('router11-1').os_data
            subnet = obj.os_data.get_resource('subnet11-1').os_data
            port = obj.os_data.get_resource('port11-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router11-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet11-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port11-1', vsd_data=vsd_port)

            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
            # check policygroup is PG_FOR_LESS_SECURITY_XXXX
            vsd_port_pg = vsd_port.policy_groups.get_first()
            vsd_l3dom_pg = vsd_l3dom.policy_groups.get_first()
            obj.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l3dom_pg.name)
            # Check the two ingress and egress rules
            self.ip_anti_spoof._verify_ingress_egress_rules(obj, vsd_port_pg)

        def verify_security_enabled_port_l3domain(self, obj):
            router = obj.os_data.get_resource('router11-1').os_data
            subnet = obj.os_data.get_resource('subnet11-1').os_data
            port_1 = obj.os_data.get_resource('port11-1').os_data
            port_2 = obj.os_data.get_resource('port11-2').os_data
            vsd_port_1 = obj.os_data.get_resource('port11-1').vsd_data
            (vsd_l3dom, vsd_sub, vsd_port_2) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port_2)
            obj.os_data.update_resource('port11-2', vsd_data=vsd_port_2)
            obj.assertEqual(vsd_port_1.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port_2.address_spoofing, 'INHERITED')
            obj.assertEqual(vsd_port_1.name, port_1['id'])
            obj.assertEqual(vsd_port_2.name, port_2['id'])

            port_1_pg = vsd_port_1.policy_groups.get_first()
            port_2_pg = vsd_port_2.policy_groups.get_first()
            obj.assertEqual(port_1_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertNotEqual(port_2_pg.name[:21], 'PG_FOR_LESS_SECURITY_')

    class _update_ntw_from_sec_enabled_to_disabled_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_security_enabled_port_l3domain(self, obj):
            # obtain the parent of port
            router = obj.os_data.get_resource('router12-1').os_data
            subnet = obj.os_data.get_resource('subnet12-1').os_data
            port = obj.os_data.get_resource('port12-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router12-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet12-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port12-1', vsd_data=vsd_port)

            obj.assertEqual(vsd_port.address_spoofing, 'INHERITED')
            obj.assertEqual(vsd_port.name, port['id'])
            # check policygroup is PG_FOR_LESS_SECURITY_XXXX
            vsd_port_pg = vsd_port.policy_groups.get_first()
            vsd_l3dom_pg = vsd_l3dom.policy_groups.get_first()
            obj.assertNotEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l3dom_pg.name)

        def verify_security_disabled_port_l3domain(self, obj):
            router = obj.os_data.get_resource('router12-1').os_data
            subnet = obj.os_data.get_resource('subnet12-1').os_data
            port_1 = obj.os_data.get_resource('port12-1').os_data
            port_2 = obj.os_data.get_resource('port12-2').os_data
            vsd_port_1 = obj.os_data.get_resource('port12-1').vsd_data
            (vsd_l3dom, vsd_sub, vsd_port_2) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port_2)
            obj.os_data.update_resource('port12-2', vsd_data=vsd_port_2)

            obj.assertEqual(vsd_port_1.address_spoofing, 'INHERITED')
            obj.assertEqual(vsd_port_2.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port_1.name, port_1['id'])
            obj.assertEqual(vsd_port_2.name, port_2['id'])

            port_1_pg = vsd_port_1.policy_groups.get_first()
            port_2_pg = vsd_port_2.policy_groups.get_first()
            obj.assertNotEqual(port_1_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(port_2_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
    
    class _update_port_from_sec_disabled_to_enabled_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_security_disabled_port_l3domain(self, obj):
            # obtain the parent of port
            router = obj.os_data.get_resource('router13-1').os_data
            subnet = obj.os_data.get_resource('subnet13-1').os_data
            port = obj.os_data.get_resource('port13-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router13-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet13-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port13-1', vsd_data=vsd_port)

            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
            # check policygroup is PG_FOR_LESS_SECURITY_XXXX
            vsd_port_pg = vsd_port.policy_groups.get_first()
            vsd_l3dom_pg = vsd_l3dom.policy_groups.get_first()
            obj.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l3dom_pg.name)
            # Check the two ingress and egress rules
            self.ip_anti_spoof._verify_ingress_egress_rules(obj, vsd_port_pg)

        def verify_security_enabled_port_l3domain(self, obj):
            router = obj.os_data.get_resource('router13-1').os_data
            subnet = obj.os_data.get_resource('subnet13-1').os_data
            port = obj.os_data.get_resource('port13-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('port13-1', vsd_data=vsd_port) 
            obj.assertEqual(vsd_port.address_spoofing, 'DISABLED')
            obj.assertEqual(vsd_port.name, port['id'])

            port_pg = vsd_port.policy_groups.get_first()
            obj.assertEqual(port_pg, None)

    class _update_port_from_sec_enabled_to_disabled_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_security_enabled_port_l3domain(self, obj):
            # obtain the parent of port
            router = obj.os_data.get_resource('router14-1').os_data
            subnet = obj.os_data.get_resource('subnet14-1').os_data
            port = obj.os_data.get_resource('port14-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router14-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet14-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port14-1', vsd_data=vsd_port)

            obj.assertEqual(vsd_port.address_spoofing, 'INHERITED')
            obj.assertEqual(vsd_port.name, port['id'])
            # check policygroup is PG_FOR_LESS_SECURITY_XXXX
            vsd_port_pg = vsd_port.policy_groups.get_first()
            vsd_l3dom_pg = vsd_l3dom.policy_groups.get_first()
            obj.assertNotEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l3dom_pg.name)

        def verify_security_disabled_port_l3domain(self, obj):
            router = obj.os_data.get_resource('router14-1').os_data
            subnet = obj.os_data.get_resource('subnet14-1').os_data
            port = obj.os_data.get_resource('port14-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('port14-1', vsd_data=vsd_port)
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])

            port_pg = vsd_port.policy_groups.get_first()
            obj.assertEqual(port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')

    class _anti_spoofing_for_params_0_0_0_0_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            l2domain = obj.os_data.get_resource('l2dom21-1').os_data
            port = obj.os_data.get_resource('port21-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom21-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port21-1', vsd_data=vsd_port)
            vip_params = ('0', '0', '0', '0')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_0_0_0_1_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            l2domain = obj.os_data.get_resource('l2dom22-1').os_data
            port = obj.os_data.get_resource('port22-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom22-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port22-1', vsd_data=vsd_port)
            vip_params = ('0', '0', '0', '1')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_0_0_1_1_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            l2domain = obj.os_data.get_resource('l2dom23-1').os_data
            port = obj.os_data.get_resource('port23-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom23-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port23-1', vsd_data=vsd_port)
            vip_params = ('0', '0', '1', '1')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_0_1_0_0_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            l2domain = obj.os_data.get_resource('l2dom24-1').os_data
            port = obj.os_data.get_resource('port24-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom24-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port24-1', vsd_data=vsd_port)
            vip_params = ('0', '1', '0', '0')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_0_1_0_1_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            l2domain = obj.os_data.get_resource('l2dom25-1').os_data
            port = obj.os_data.get_resource('port25-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom25-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port25-1', vsd_data=vsd_port)
            vip_params = ('0', '1', '0', '1')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_0_1_1_1_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            l2domain = obj.os_data.get_resource('l2dom26-1').os_data
            port = obj.os_data.get_resource('port26-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom26-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port26-1', vsd_data=vsd_port)
            vip_params = ('0', '1', '1', '1')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_1_0_0_0_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            l2domain = obj.os_data.get_resource('l2dom27-1').os_data
            port = obj.os_data.get_resource('port27-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom27-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port27-1', vsd_data=vsd_port)
            vip_params = ('1', '0', '0', '0')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_1_0_0_1_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            l2domain = obj.os_data.get_resource('l2dom28-1').os_data
            port = obj.os_data.get_resource('port28-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom28-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port28-1', vsd_data=vsd_port)
            
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
            
    class _anti_spoofing_for_params_1_0_1_1_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            l2domain = obj.os_data.get_resource('l2dom29-1').os_data
            port = obj.os_data.get_resource('port29-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom29-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port29-1', vsd_data=vsd_port)
            vip_params = ('1', '0', '1', '1')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_1_1_0_0_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            l2domain = obj.os_data.get_resource('l2dom30-1').os_data
            port = obj.os_data.get_resource('port30-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom30-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port30-1', vsd_data=vsd_port)
            vip_params = ('1', '1', '0', '0')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_1_1_0_1_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            l2domain = obj.os_data.get_resource('l2dom31-1').os_data
            port = obj.os_data.get_resource('port31-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom31-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port31-1', vsd_data=vsd_port)
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])

    class _anti_spoofing_for_params_1_1_1_1_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            l2domain = obj.os_data.get_resource('l2dom32-1').os_data
            port = obj.os_data.get_resource('port32-1').os_data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
            obj.os_data.update_resource('l2dom32-1', vsd_data=vsd_l2domain)
            obj.os_data.update_resource('port32-1', vsd_data=vsd_port)
            vip_params = ('1', '1', '1', '1')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_0_0_0_0_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            router = obj.os_data.get_resource('router41-1').os_data
            subnet = obj.os_data.get_resource('subnet41-1').os_data
            port = obj.os_data.get_resource('port41-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router41-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet41-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port41-1', vsd_data=vsd_port)
            vip_params = ('0', '0', '0', '0')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_0_0_0_1_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            router = obj.os_data.get_resource('router42-1').os_data
            subnet = obj.os_data.get_resource('subnet42-1').os_data
            port = obj.os_data.get_resource('port42-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router42-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet42-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port42-1', vsd_data=vsd_port)
            vip_params = ('0', '0', '0', '1')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_0_0_1_1_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            router = obj.os_data.get_resource('router43-1').os_data
            subnet = obj.os_data.get_resource('subnet43-1').os_data
            port = obj.os_data.get_resource('port43-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router43-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet43-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port43-1', vsd_data=vsd_port)
            vip_params = ('0', '0', '1', '1')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_0_1_0_0_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            router = obj.os_data.get_resource('router44-1').os_data
            subnet = obj.os_data.get_resource('subnet44-1').os_data
            port = obj.os_data.get_resource('port44-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router44-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet44-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port44-1', vsd_data=vsd_port)
            vip_params = ('0', '1', '0', '0')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_0_1_0_1_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            router = obj.os_data.get_resource('router45-1').os_data
            subnet = obj.os_data.get_resource('subnet45-1').os_data
            port = obj.os_data.get_resource('port45-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router45-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet45-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port45-1', vsd_data=vsd_port) 
            vip_params = ('0', '1', '0', '1')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_0_1_1_1_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            router = obj.os_data.get_resource('router46-1').os_data
            subnet = obj.os_data.get_resource('subnet46-1').os_data
            port = obj.os_data.get_resource('port46-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router46-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet46-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port46-1', vsd_data=vsd_port)
            vip_params = ('0', '1', '1', '1')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_1_0_0_0_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            router = obj.os_data.get_resource('router47-1').os_data
            subnet = obj.os_data.get_resource('subnet47-1').os_data
            port = obj.os_data.get_resource('port47-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router47-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet47-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port47-1', vsd_data=vsd_port)
            vip_params = ('1', '0', '0', '0')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_1_0_0_1_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            router = obj.os_data.get_resource('router48-1').os_data
            subnet = obj.os_data.get_resource('subnet48-1').os_data
            port = obj.os_data.get_resource('port48-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router48-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet48-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port48-1', vsd_data=vsd_port)
            vip_params = ('1', '0', '0', '1')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)
 
    class _anti_spoofing_for_params_1_0_1_1_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            router = obj.os_data.get_resource('router49-1').os_data
            subnet = obj.os_data.get_resource('subnet49-1').os_data
            port = obj.os_data.get_resource('port49-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router49-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet49-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port49-1', vsd_data=vsd_port)
            vip_params = ('1', '0', '1', '1')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_1_1_0_0_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            router = obj.os_data.get_resource('router50-1').os_data
            subnet = obj.os_data.get_resource('subnet50-1').os_data
            port = obj.os_data.get_resource('port50-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router50-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet50-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port50-1', vsd_data=vsd_port)
            vip_params = ('1', '1', '0', '0')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_1_1_0_1_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            router = obj.os_data.get_resource('router51-1').os_data
            subnet = obj.os_data.get_resource('subnet51-1').os_data
            port = obj.os_data.get_resource('port51-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router51-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet51-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port51-1', vsd_data=vsd_port)
            vip_params = ('1', '1', '0', '1')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

    class _anti_spoofing_for_params_1_1_1_1_l3domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_vip_and_anti_spoofing(self, obj):
            router = obj.os_data.get_resource('router52-1').os_data
            subnet = obj.os_data.get_resource('subnet52-1').os_data
            port = obj.os_data.get_resource('port52-1').os_data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.os_data.update_resource('router52-1', vsd_data=vsd_l3dom)
            obj.os_data.update_resource('subnet52-1', vsd_data=vsd_sub)
            obj.os_data.update_resource('port52-1', vsd_data=vsd_port)
            vip_params = ('1', '1', '1', '1')
            self.ip_anti_spoof._verify_vip_and_anti_spoofing_l2dom(
                port, vsd_port, vip_params, obj)

