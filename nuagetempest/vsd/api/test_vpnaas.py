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
        LOG.info("Verifying the dummy router")
        dummy_router = (
            obj.os_data_struct.get_resource(dummy_router_tag).os_data
        )
        l3domain_ext_id = test_base.get_external_id(dummy_router['id'])
        vsd_l3dom = TB.vsd_1.get_domain(
            filter=test_base.get_filter_str('externalID', l3domain_ext_id)
        )
        obj.os_data_struct.update_resource(dummy_router_tag, \
            vsd_data=vsd_l3dom)

    def verify_dummy_subnet(self, obj, dummy_subnet_tag, cidr):
        dummy_subnet = (
            obj.os_data_struct.get_resource(dummy_subnet_tag).os_data
        )
        subnet_ext_id = test_base.get_external_id(dummy_subnet['id'])
        vsd_subnet = TB.vsd_1.get_subnet(
            filter=test_base.get_filter_str('externalID', subnet_ext_id)
        )
        obj.assertEqual(dummy_subnet['cidr'], vsd_subnet.address)
        obj.assertEqual(cidr, vsd_subnet.address)
        obj.os_data_struct.update_resource(dummy_subnet_tag, \
            vsd_data=vsd_subnet)

    class _create_delete_vpnservice():
        def __init__(self):
            self.vpnaas_cli_test = VPNaaSCliTests()
            pass

        def verify_vpn_dummy_router(self, obj):

            # Verifying dummy router
            tag_router = obj.os_data_struct.get_resource('routertag').user_data
            os_router = obj.os_data_struct.get_resource(tag_router['name']).os_data
            dummy_router_name = 'r_d_' + os_router['id']
            self.vpnaas_cli_test.verify_dummy_router(obj, dummy_router_name)

            # Verifying dummy subnet
            tag_public = obj.os_data_struct.get_resource('publicnettag').user_data
            os_public = obj.os_data_struct.get_resource(tag_public['name']).os_data
            public_cidr = os_public['cidr']

            tag_subnet = obj.os_data_struct.get_resource('subnettag').user_data
            os_subnet = obj.os_data_struct.get_resource(tag_subnet['name']).os_data
            dummy_subnet_name = 's_d_' + os_subnet['id']
            self.vpnaas_cli_test.verify_dummy_subnet(obj, \
                dummy_subnet_name, public_cidr)

    class _create_delete_ipsecsiteconnection():
        def __init__(self):
            self.vpnaas_cli_test = VPNaaSCliTests()
            pass

        def verify_ipsec_vminterface(self, obj):
            pass

        def verify_vpn_dummy_router(self, obj):
            pass

class VPNaaSTest():

    def __init__(self):
        pass

    def verify_dummy_router(self, obj, dummyrouter, dummyroutertag):
        LOG.info("Verifying the dummy router")
        l3domain_ext_id = test_base.get_external_id(dummyrouter['id'])
        vsd_l3dom = TB.vsd_1.get_domain(
            filter=test_base.get_filter_str('externalID', l3domain_ext_id)
        )
        obj.os_data_struct.update_resource(dummyroutertag, \
            vsd_data=vsd_l3dom)

    def verify_dummy_subnet(self, obj, dummysubnet, dummysubnettag, cidr):
        LOG.info("Verifying the dummy subnet")
        subnet_ext_id = test_base.get_external_id(dummysubnet['id'])
        vsd_subnet = TB.vsd_1.get_subnet(
            filter=test_base.get_filter_str('externalID', subnet_ext_id)
        )
        obj.os_data_struct.update_resource(dummysubnettag, \
            vsd_data=vsd_subnet)
        obj.assertEqual(dummysubnet['cidr'].split("/")[0], \
                vsd_subnet.address)
        obj.assertEqual(cidr, vsd_subnet.address)

    class _ipsecsiteconnection_create_delete():
        def __init__(self):
            self.vpnaas_test = VPNaaSTest()
            pass

        def verify_ipsec_vminterface(self, obj):
            vsd_subnet = (
                obj.os_data_struct.get_resource('dummysubnet').vsd_data
            )
            vpnservice_ip = (
                vsd_subnet.vm_interfaces.fetch()[0][0].ip_address
            )
            vpnservice = (
                obj.os_data_struct.get_resource('vpnservice').os_data
            )
            os_vpnservice_ip = vpnservice['external_v4_ip']
            obj.assertEqual(vpnservice_ip, os_vpnservice_ip)

        def verify_vpn_dummy_router(self, obj):
            # verify dummy router
            os_dummyrouter = (
                obj.os_data_struct.get_resource('dummyrouter').os_data
            )
            self.vpnaas_test.verify_dummy_router(\
                obj, os_dummyrouter, 'dummyrouter')
            os_dummysubnet = (
                obj.os_data_struct.get_resource('dummysubnet').os_data
            )
            pubsub_id = (
                obj.os_data_struct.get_resource('router1').\
                        os_data['external_gateway_info']\
                        ['external_fixed_ips'][0]['subnet_id']
            )
            pubsubextid = test_base.get_external_id(pubsub_id)
            vsd_pubsubnet = TB.vsd_1.get_subnet(
                    filter = \
                            test_base.get_filter_str('externalID', pubsubextid)
                    )
            self.vpnaas_test.verify_dummy_subnet(\
                obj, os_dummysubnet, 'dummysubnet', vsd_pubsubnet.address)

    class _vpnservice_create_delete():
        def __init__(self):
            self.vpnaas_test = VPNaaSTest()
            pass

        def verify_vpn_dummy_router(self, obj):
            # verify dummy router
            os_dummyrouter = (
                obj.os_data_struct.get_resource('dummyrouter').os_data
            )
            self.vpnaas_test.verify_dummy_router(\
                obj, os_dummyrouter, 'dummyrouter')
            os_dummysubnet = (
                obj.os_data_struct.get_resource('dummysubnet').os_data
            )
            pubsub_id = (
                obj.os_data_struct.get_resource('router1').\
                        os_data['external_gateway_info']\
                        ['external_fixed_ips'][0]['subnet_id']
            )
            pubsubextid = test_base.get_external_id(pubsub_id)
            vsd_pubsubnet = TB.vsd_1.get_subnet(
                    filter = \
                            test_base.get_filter_str('externalID', pubsubextid)
                    )
            self.vpnaas_test.verify_dummy_subnet(\
                obj, os_dummysubnet, 'dummysubnet', vsd_pubsubnet.address)
