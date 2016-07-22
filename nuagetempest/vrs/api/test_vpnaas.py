from tempest import config
from oslo_log import log as logging
from nuagetempest.lib import base
from nuagetempest.lib import test_base
from tempest import test
import re
import unittest
import sys
from nuagetempest.tests import nuage_ext


CONF = config.CONF

LOG = logging.getLogger(__name__)

class VPNaaSCliTests():

    def __init__(self):
        pass

    def verify_dummy_router(self, obj, dummy_router_tag):
        pass

    def verify_dummy_subnet(self, obj, dummy_subnet_tag, cidr):
        pass

    class _create_delete_vpnservice():
        def __init__(self):
            self.vpnaas_cli_test = VPNaaSCliTests()
            pass

        def verify_vpn_dummy_router(self, obj):
            pass

    class _create_delete_ipsecsiteconnection():
        def __init__(self):
            self.vpnaas_cli_test = VPNaaSCliTests()
            pass

        def verify_ipsec_vminterface(self, obj):
            """ Verify the ipsecsiteconnection
            VM interface on the VRS1 - network node """
            # VPNservice 1
            tag_vpnservice1 = (
                obj.os_data_struct.get_resource('vpnservicetag1').user_data
            )
            vpnservice1 = (
                obj.os_data_struct.get_resource(\
                        tag_vpnservice1['name']).os_data
            )
            os_vpnservice_ip1 = vpnservice1['vpnservice']['external_v4_ip']

            # VPNservice 2
            tag_vpnservice2 = (
                obj.os_data_struct.get_resource('vpnservicetag2').user_data
            )
            vpnservice2 = (
                obj.os_data_struct.get_resource(\
                        tag_vpnservice2['name']).os_data
            )
            os_vpnservice_ip2 = vpnservice2['vpnservice']['external_v4_ip']

            # Checking on VRS
            vms = obj.TB.vrs_1.cmd.vmportshow()
            # VPN1 vminterface
            vpnvm1 = (
                (vm for vm in vms if vm['ip'] == os_vpnservice_ip1).next()
            )
            obj.assertEqual(vpnvm1['ip'], os_vpnservice_ip1)
            obj.assertEqual(vpnvm1['bridge'], 'alubr0')
            # VPN2 vminterface
            vpnvm2 = (
                (vm for vm in vms if vm['ip'] == os_vpnservice_ip2).next()
            )
            obj.assertEqual(vpnvm2['ip'], os_vpnservice_ip2)
            obj.assertEqual(vpnvm2['bridge'], 'alubr0')

        def verify_vpn_dummy_router(self, obj):
            pass

class VPNaaSTest():

    def __init__(self):
        pass

    def verify_dummy_router(self, obj, dummyrouter, dummyroutertag):
        pass

    def verify_dummy_subnet(self, obj, dummysubnet, dummysubnettag, cidr):
        pass

    class _ipsecsiteconnection_create_delete():
        def __init__(self):
            self.vpnaas_test = VPNaaSTest()
            pass

        def verify_ipsec_vminterface(self, obj):
            """ Verify the ipsecsiteconnection
            VM interface on the VRS1 - network node """
            vpnservice = (
                obj.os_data_struct.get_resource('vpnservice').os_data
            )
            os_vpnservice_ip = vpnservice['external_v4_ip']
            vms = obj.TB.vrs_1.cmd.vmportshow()
            vpnvm = (
                (vm for vm in vms if vm['ip'] == os_vpnservice_ip).next()
            )
            obj.assertEqual(vpnvm['ip'], os_vpnservice_ip)
            obj.assertEqual(vpnvm['bridge'], 'alubr0')

        def verify_vpn_dummy_router(self, obj):
            pass

    class _vpnservice_create_delete():
        def __init__(self):
            self.vpnaas_test = VPNaaSTest()
            pass

        def verify_vpn_dummy_router(self, obj):
            pass
