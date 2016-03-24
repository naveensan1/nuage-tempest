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
        vsd_l2domain = TB.vsd_1.session.user.l2_domains.get_first(
                       filter='externalID == "{}"'.format(l2domain_ext_id))
        vsd_port = vsd_l2domain.vports.get_first()
        return (vsd_l2domain, vsd_port)

    def _get_vsd_router_subnet_port(self, router, subnet, port):
        # Method to get the VSD objects for router, subnet and port
        router_ext_id = base.get_external_id(router['id'])
        vsd_l3dom = TB.vsd_1.get_domain(
                    filter='externalID == "{}"'.format(router_ext_id))
        subnet_ext_id = base.get_external_id(subnet['id'])
        vsd_sub = TB.vsd_1.get_subnet(
                  filter='externalID == "{}"'.format(subnet_ext_id))
        port_ext_id = base.get_external_id(port['id'])
        vsd_port = TB.vsd_1.get_vport(subnet=vsd_sub,
                   filter='externalID == "{}"'.format(port_ext_id))
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

    class _create_delete_sec_disabled_ntw_port_l2domain():
        def __init__(self):
            self.ip_anti_spoof = IpAntiSpoofingTest()
            pass

        def verify_security_disabled_ntw_port_l2domain(self, obj):
            # obtin the parent of port
            l2domain = obj.os_data.get_resource('l2domain-1').data
            port = obj.os_data.get_resource('port-1').data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
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

        def verify_security_disabled_ntw_l2domain(self, obj):
            # obtain the parent of port
            l2domain = obj.os_data.get_resource('l2domain-1').data
            port = obj.os_data.get_resource('port-1').data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
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
            l2domain = obj.os_data.get_resource('l2domain-1').data
            port = obj.os_data.get_resource('port-1').data
            vsd_l2domain, vsd_port = self.ip_anti_spoof._get_vsd_l2dom_port(
                                     l2domain, port)
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

        def verify_security_disabled_ntw_port_l3domain(self, obj):
            router = obj.os_data.get_resource('router-1').data
            subnet = obj.os_data.get_resource('subnet-1').data
            port = obj.os_data.get_resource('port-1').data
            (vsd_l3dom, vsd_sub, vsd_port) = self.ip_anti_spoof.\
                _get_vsd_router_subnet_port(router, subnet, port)
            obj.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            obj.assertEqual(vsd_port.name, port['id'])
            # Check the policy group is PG_FOR_LESS_SECURITY_XXX
            vsd_l3dom_pg = vsd_l3dom.policy_groups.get_first()
            vsd_port_pg = vsd_port.policy_groups.get_first()
            obj.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
            obj.assertEqual(vsd_port_pg.name, vsd_l3dom_pg.name)
            # Check the two ingress and egress rules
            self.ip_anti_spoof._verify_ingress_egress_rules(obj, vsd_port_pg)
