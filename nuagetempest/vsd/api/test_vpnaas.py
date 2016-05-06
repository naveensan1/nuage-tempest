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

    class _create_delete_vpnservice():
        def __init__(self):
            pass

        def verify_vpn_dummy_router(self, obj):

    class _create_delete_ipsecsiteconnection():
        def __init__(self):
            pass

        def verify_ipsec_vminterface(self, obj):

        def verify_vpn_dummy_router(self, obj):

