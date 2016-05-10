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

class VPNaaSCliTests():

    def __init__(self):
        pass

    def verify_dummy_router(self, obj, dummy_router_tag):
        dummy_router = (
            obj.os_data.get_resource(dummy_router_tag).os_data
        )
        l3domain_ext_id = base.get_external_id(dummy_router['id'])
        vsd_l3dom = TB.vsd_1.get_domain(
            filter=base.get_filter_str('externalID', l3domain_ext_id)
        )

    def verify_dummy_subnet(self, obj, dummy_subnet_tag):
        dummy_subnet = (
            obj.os_data.get_resource(dummy_subnet_tag).os_data
        )
        subnet_ext_id = base.get_external_id(dummy_subnet['id'])
        vsd_subnet = TB.vsd_1.get_subnet(
            filter=base.get_filter_str('externalID', subnet_ext_id)
        )

    class _create_delete_vpnservice():
        def __init__(self):
            pass

        def verify_vpn_dummy_router(self, obj):
            import pdb;pdb.set_trace()

            # Verifying dummy router
            tag_router = obj.os_data.get_resource('routertag').user_data
            os_router = obj.os_data.get_resource(os_router['name']).os_data
            dummy_router_name = 'r_d_' + router['id']
            self.verify_dummy_router(obj, dummy_router_name)

            # Verifying dummy subnet
            tag_subnet = obj.os_data.get_resource('subnettag').user_data
            os_subnet = obj.os_data.get_resource(os_subnet['name']).os_data
            dummy_subnet_name = 's_d' + subnet['id']
            self.verify_dummy_subnet(obj, dummy_subnet_name)

    class _create_delete_ipsecsiteconnection():
        def __init__(self):
            pass

        def verify_ipsec_vminterface(self, obj):
            pass

        def verify_vpn_dummy_router(self, obj):
            pass
