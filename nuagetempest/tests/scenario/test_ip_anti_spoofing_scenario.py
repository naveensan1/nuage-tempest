from nuagetempest.thirdparty.nuage import test_allowed_addr_pair_nuage
from tempest.common.utils import data_utils
from tempest.api.network import base
from tempest import test
from nuagetempest.tests import nuage_ext
from tempest import config
from nuagetempest.lib.openstackData import openstackData
from nuagetempest.tests.api import test_ip_anti_spoofing as antispoof
from tempest.scenario import manager
from tempest.api.compute import base as serv_base

import netaddr

class IpAntiSpoofingTestScenario(antispoof.IpAntiSpoofingTestBase,
                                 manager.NetworkScenarioTest,
                                 serv_base.BaseV2ComputeTest):

    @classmethod
    def resource_setup(cls):
        super(IpAntiSpoofingTestScenario, cls).resource_setup()   
        
    def test_vm_in_sec_disabled_port_l2domain(self):
        ''' L2domain testcase to spawn VM in port with
            port-security-enabled set to False at port level only'''
        network, l2domain, port = self._create_network_port_l2resources(
                                  ntw_security='True', port_security='False',
                                  l2domain_name='l2dom3-1',
                                  port_name='port3-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], False)
        ntw = {'uuid': network['id'], 'port': port['id']}
        vm = self.create_server(name='vm', networks=[ntw], 
                                wait_until='ACTIVE')
        self.os_data.insert_resource(vm['name'], 'port3-1', os_data=vm) 
        self.assertEqual(port['fixed_ips'][0]['ip_address'],
                         vm['addresses'][network['name']][0]['addr'])
        self.assertEqual(port['mac_address'],
            vm['addresses'][network['name']][0]['OS-EXT-IPS-MAC:mac_addr'])
        self.assertEqual(vm['status'], 'ACTIVE')         
        tag_name = 'verify_vm_in_sec_disabled_port_l2domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

