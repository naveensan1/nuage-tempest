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
        """ Verifies Dummy Router on VSD """
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
        """ Verifies Dummy Subnet on VSD """
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
            """ Verifies Dummy Router/Subnet for vpnservice """
            # Verifying dummy router
            tag_router = obj.os_data_struct.get_resource('routertag').user_data
            os_router = obj.os_data_struct.get_resource(tag_router['name']).os_data
            dummy_router_name = 'r_d_' + os_router['id']
            self.vpnaas_cli_test.verify_dummy_router(obj, dummy_router_name)

            # Getting Public net info
            tag_public = obj.os_data_struct.get_resource('publicnettag').user_data
            os_public = obj.os_data_struct.get_resource(tag_public['name']).os_data
            public_cidr = os_public['cidr']

            # Verifying dummy subnet
            tag_subnet = obj.os_data_struct.get_resource('subnettag').user_data
            os_subnet = obj.os_data_struct.get_resource(tag_subnet['name']).os_data
            dummy_subnet_name = 's_d_' + os_subnet['id']
            self.vpnaas_cli_test.verify_dummy_subnet(obj, \
                dummy_subnet_name, public_cidr)

    class _create_duplicate_vpnservice():
        def __init__(self):
            self.vpnaas_cli_test = VPNaaSCliTests()
            pass

        def verify_vpn_dummy_router(self, obj):
            """ Verifies Dummy Router/Subnet for vpnservice """
            # Verifying dummy router
            tag_router = obj.os_data_struct.get_resource('routertag').user_data
            os_router = obj.os_data_struct.get_resource(tag_router['name']).os_data
            dummy_router_name = 'r_d_' + os_router['id']
            self.vpnaas_cli_test.verify_dummy_router(obj, dummy_router_name)

            # Getting Public net info
            tag_public = obj.os_data_struct.get_resource('publicnettag').user_data
            os_public = obj.os_data_struct.get_resource(tag_public['name']).os_data
            public_cidr = os_public['cidr']

            # Verifying dummy subnet
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
            """ Verifies VM interface for ipsecsiteconnection """
            # Verifying vm interface for vpn1
            tag_subnet1 = obj.os_data_struct.get_resource('dummysubnet1').user_data
            vsd_subnet1 = (
                obj.os_data_struct.get_resource(tag_subnet1['name']).vsd_data
            )
            vpnservice_ip1 = (
                vsd_subnet1.vm_interfaces.fetch()[0][0].ip_address
            )
            tag_vpnservice1 = obj.os_data_struct.get_resource('vpnservice1').user_data
            vpnservice1 = (
                obj.os_data_struct.get_resource(tag_vpnservice1['name']).os_data
            )
            os_vpnservice_ip1 = vpnservice1['external_v4_ip']
            obj.assertEqual(vpnservice_ip1, os_vpnservice_ip1)

            # Verifying vm interface for vpn2
            tag_subnet2 = obj.os_data_struct.get_resource('dummysubnet2').user_data
            vsd_subnet2 = (
                obj.os_data_struct.get_resource(tag_subnet2['name']).vsd_data
            )
            vpnservice_ip2 = (
                vsd_subnet2.vm_interfaces.fetch()[0][0].ip_address
            )
            tag_vpnservice2 = obj.os_data_struct.get_resource('vpnservice2').user_data
            vpnservice2 = (
                obj.os_data_struct.get_resource(tag_vpnservice2['name']).os_data
            )
            os_vpnservice_ip2 = vpnservice2['external_v4_ip']
            obj.assertEqual(vpnservice_ip2, os_vpnservice_ip2)

        def verify_vpn_dummy_router(self, obj):
            """ Verifies Dummy Routers/Subnets for vpnservices """
            # Verifying dummy router1
            tag_router1 = obj.os_data_struct.get_resource('routertag1').user_data
            os_router1 = obj.os_data_struct.get_resource(tag_router1['name']).os_data
            dummy_router_name1 = 'r_d_' + os_router1['id']
            self.vpnaas_cli_test.verify_dummy_router(obj, dummy_router_name1)

            # Verifying dummy router2
            tag_router2 = obj.os_data_struct.get_resource('routertag2').user_data
            os_router2 = obj.os_data_struct.get_resource(tag_router2['name']).os_data
            dummy_router_name2 = 'r_d_' + os_router2['id']
            self.vpnaas_cli_test.verify_dummy_router(obj, dummy_router_name2)

            # Getting public Cidr
            tag_public = obj.os_data_struct.get_resource('publicnettag').user_data
            os_public = obj.os_data_struct.get_resource(tag_public['name']).os_data
            public_cidr = os_public['cidr']

            # Verifying dummy subnet1
            tag_subnet1 = obj.os_data_struct.get_resource('subnettag1').user_data
            os_subnet1 = obj.os_data_struct.get_resource(tag_subnet1['name']).os_data
            dummy_subnet_name1 = 's_d_' + os_subnet1['id']
            self.vpnaas_cli_test.verify_dummy_subnet(obj, \
                dummy_subnet_name1, public_cidr)

            # Verifying dummy subnet2
            tag_subnet2 = obj.os_data_struct.get_resource('subnettag2').user_data
            os_subnet2 = obj.os_data_struct.get_resource(tag_subnet2['name']).os_data
            dummy_subnet_name2 = 's_d_' + os_subnet2['id']
            self.vpnaas_cli_test.verify_dummy_subnet(obj, \
                dummy_subnet_name2, public_cidr)

class VPNaaSTest():

    def __init__(self):
        pass

    def verify_dummy_router(self, obj, dummyrouter, dummyroutertag):
        """ Verifies Dummy Router on VSD """
        LOG.info("Verifying the dummy router")
        # Getting externalID for dummy router
        l3domain_ext_id = test_base.get_external_id(dummyrouter['id'])
        vsd_l3dom = TB.vsd_1.get_domain(
            filter=test_base.get_filter_str('externalID', l3domain_ext_id)
        )
        # Adding vsd info to os_data_struct
        obj.os_data_struct.update_resource(dummyroutertag, \
            vsd_data=vsd_l3dom)

    def verify_dummy_subnet(self, obj, dummysubnet, dummysubnettag, cidr):
        """ Verifies Dummy Subnet on VSD """
        LOG.info("Verifying the dummy subnet")
        # Getting externalID for dummy subnet
        subnet_ext_id = test_base.get_external_id(dummysubnet['id'])
        vsd_subnet = TB.vsd_1.get_subnet(
            filter=test_base.get_filter_str('externalID', subnet_ext_id)
        )
        # Adding vsd info to os_data_struct
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
            """ Verifies VM interface for ipsecsiteconnection """
            # Getting subnet for dummy subnet 
            vsd_subnet = (
                obj.os_data_struct.get_resource('dummysubnet').vsd_data
            )
            # Getting vm interface in dummy subnet
            vpnservice_ip = (
                vsd_subnet.vm_interfaces.fetch()[0][0].ip_address
            )
            vpnservice = (
                obj.os_data_struct.get_resource('vpnservice').os_data
            )
            # Comparing vpnservice ip with dummy vminterface ip
            os_vpnservice_ip = vpnservice['external_v4_ip']
            obj.assertEqual(vpnservice_ip, os_vpnservice_ip)

        def verify_vpn_dummy_router(self, obj):
            """ Verifies Dummy Router/Subnet for vpnservice """
            # verify dummy router
            os_dummyrouter = (
                obj.os_data_struct.get_resource('dummyrouter').os_data
            )
            self.vpnaas_test.verify_dummy_router(\
                obj, os_dummyrouter, 'dummyrouter')
            # verify dummy subnet
            os_dummysubnet = (
                obj.os_data_struct.get_resource('dummysubnet').os_data
            )
            pubsub_id = (
                obj.os_data_struct.get_resource('router1').\
                        os_data['external_gateway_info']\
                        ['external_fixed_ips'][0]['subnet_id']
            )
            pubsubextid = test_base.get_external_id(pubsub_id)
            # Comparing the dummy subnet cidr with public subnet cidr
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
            """ Verifies Dummy Router/Subnet for vpnservice """
            # verify dummy router
            os_dummyrouter = (
                obj.os_data_struct.get_resource('dummyrouter').os_data
            )
            self.vpnaas_test.verify_dummy_router(\
                obj, os_dummyrouter, 'dummyrouter')
            # verify dummy subnet
            os_dummysubnet = (
                obj.os_data_struct.get_resource('dummysubnet').os_data
            )
            pubsub_id = (
                obj.os_data_struct.get_resource('router1').\
                        os_data['external_gateway_info']\
                        ['external_fixed_ips'][0]['subnet_id']
            )
            pubsubextid = test_base.get_external_id(pubsub_id)
            # Comparing the dummy subnet cidr with public subnet cidr
            vsd_pubsubnet = TB.vsd_1.get_subnet(
                    filter = \
                            test_base.get_filter_str('externalID', pubsubextid)
                    )
            self.vpnaas_test.verify_dummy_subnet(\
                obj, os_dummysubnet, 'dummysubnet', vsd_pubsubnet.address)
