from tempest import config
from oslo_log import log as logging
from nuagetempest.lib import topology
from nuagetempest.lib import base
from nuagetempest.lib import test_base
from tempest import test
import re
import unittest
import sys

CONF = config.CONF
TB = topology.testbed

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
            tag_vpnservice = (
                obj.os_data_struct.get_resource('vpnservice').user_data
            )
            vpnservice = (
                obj.os_data_struct.get_resource(\
                        tag_vpnservice['name']).os_data
            )
            os_vpnservice_ip = vpnservice['external_v4_ip']
            vms = TB.vrs_1.cmd.vmportshow()
            vpnvm = (
                (vm for vm in vms if vm['ip'] == os_vpnservice_ip).next()
            )
            obj.assertEqual(vpnvm['ip'], os_vpnservice_ip)
            obj.assertEqual(vpnvm['bridge'], 'alubr0')

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
            vpnservice = (
                obj.os_data_struct.get_resource('vpnservice').os_data
            )
            os_vpnservice_ip = vpnservice['external_v4_ip']
            vms = TB.vrs_1.cmd.vmportshow()
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
