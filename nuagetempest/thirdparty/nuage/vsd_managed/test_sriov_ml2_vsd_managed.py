# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

## Author Sailaja Yanamandra ##
## These tests are for the first sriov ml2 with mitaka deliverable and run only on the e2e setup ## 
## Assumption - all the configuration for the setup is already done ##
from netaddr import *
import testtools
import time

from oslo_log import log as logging
from tempest import config
from tempest import test
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions 


#from nuagetempest.lib.openstackcli import openstack_cliclient
from nuagetempest.lib.utils import constants
from nuagetempest.lib.test import nuage_test
from nuagetempest.lib.test import tags
from nuagetempest.lib.nuage_tempest_test_loader import Release
from nuagetempest.thirdparty.nuage.vsd_managed import base_vsd_managed_networks
#from nuagetempest.thirdparty.nuage.vsd_managed import base_vsd_managed_port_attributes
from nuagetempest.thirdparty.nuage.vsd_managed import base_vsd_managed_sriov
#from nuagetempest.thirdparty.nuage.upgrade.external_id.external_id import ExternalId

from tempest.api.compute import base as serv_base
from tempest.scenario import manager as scenario_manager
from nuagetempest.services import nuage_client

CONF = config.CONF
LOG = logging.getLogger(__name__)


@nuage_test.class_header(tags=tags.VSD_MANAGED)
class ML2VSDManagedSRIOVTest(base_vsd_managed_sriov.BaseVSDManagedSRIOV,serv_base.BaseV2ComputeTest,scenario_manager.ScenarioTest):
    @classmethod
    def setUpClass(self):
        super(ML2VSDManagedSRIOVTest, self).setUpClass()
        self.network ,self.vsd_dummy_network,self.network_12 , self.vsd_network_12 , self.network_34 , self.vsd_subnet_34  = self.setup_sriov_networks()
    @classmethod
    def setup_clients(self):
        super(ML2VSDManagedSRIOVTest, self).setup_clients()
        self.nuage_vsd_client = nuage_client.NuageRestClient()
        #self.admin_client = self.os_adm.network_client



    @nuage_test.header()
    def test_l2dom_sriovport_onevlan(self):
        port_name = 'sxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-iov-07-33'
        port = self.sriov_port_create(self.network,port_name)

    def test_l3dom_sriovport_onevlan(self):
        port_name = 'sxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-iov-07-34'
        port = self.sriov_port_create(self.network,port_name)

    def test_l2l3dom_sriovport_indivlan(self):
        port_name = 'sxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-iov-02-33-34-35'
        port = self.sriov_port_create(self.network,port_name)

    def test_l2l3dom_sriovport_groupvlan(self):
        port_name = 'sxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-iov-02-33..35'
        port = self.sriov_port_create(self.network,port_name)

    def test__sriovport_nonexistent_vlan(self):
        port_name = 'sxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-iov-02-67'
        expected_exception = exceptions.ServerFault
        msg = "Got server fault"
        self.assertRaisesRegexp(exceptions.ServerFault , msg , self.sriov_port_create,self.network,port_name)

    def test__sriovport_overlapping_vlan(self):
        port_name = 'sxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-iov-02-34-33..35'
        expected_exception = exceptions.ServerFault
        msg = "Got server fault"
        self.assertRaisesRegexp(exceptions.ServerFault , msg , self.sriov_port_create,self.network,port_name)

    def test_l2l3dom_sriovvm_mixvlan(self):
        port_name = 'sxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-iov-02-20-33..35'
        port = self.sriov_port_create(self.network,port_name)
        vm = self._create_server_sriov_port(port,name="sriov-vm1")
        time.sleep(5)
        #find bridgeport created on the dummy network
        bridge_port = self.nuage_vsd_client.get_l2domain_vports(self.vsd_dummy_network[0]['ID'])
        #find the gateway port id of the vlan associated
        vlan_obj = self.nuage_vsd_client.get_bridge_port_gateway_vlan(bridge_port[0])
        gateway_port_id = vlan_obj[0]['parentID']
        # get all the vlans on the gateway port. should have all the vlans in the port name 
        vlans_in_port = self.nuage_vsd_client.get_gateway_vlan("ports" , gateway_port_id) 
        vlan_list = []
        for vlan_id in vlans_in_port:
            vlan_list.append(vlan_id['value'])
        orig_vlan_list = [0, 20,33,34,35]
        for id in orig_vlan_list:
            if id not in vlan_list:
                raise exceptions.NotFound("vlan " + str(id) + " not in found vlans" ) 
        pass


    def test_l2l3dom_sriovvm_delete(self):
        port_name = 'sxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-iov-02-20'
        port = self.sriov_port_create(self.network,port_name)
        #vm = self._create_server_sriov_port(port,name="sriov-vm2")
        vmkwargs = {'name': "sriov-vm2", 'flavorRef': '2',
                        'imageRef': CONF.compute.image_ref,
                        'networks': [{'port': port['id']}] }
        vm = self.servers_client.create_server(**vmkwargs)
        time.sleep(5)        
        #find bridgeport created on the dummy network
        bridge_port = self.nuage_vsd_client.get_l2domain_vports(self.vsd_dummy_network[0]['ID'])
        #find the gateway port id of the vlan associated
        vlan_obj = self.nuage_vsd_client.get_bridge_port_gateway_vlan(bridge_port[0])
        gateway_port_id = vlan_obj[0]['parentID']
        # get all the vlans on the gateway port. should have all the vlans in the port name
        vlans_in_port = self.nuage_vsd_client.get_gateway_vlan("ports" , gateway_port_id)
        vlan_list = []
        for vlan_id in vlans_in_port:
            vlan_list.append(vlan_id['value'])
        orig_vlan_list = [0, 22]
        for id in orig_vlan_list:
            if id not in vlan_list:
                raise exceptions.NotFound("vlan " + str(id) + " not in found vlans" )
        #delete vm 
        self.servers_client.delete_server(vm['server']['id'])
        time.sleep(2)
        #check vlans are deleted
        vlans_del_vm_port = self.nuage_vsd_client.get_gateway_vlan("ports" , gateway_port_id)
        vlan_list = []
        for vlan_id in vlans_del_vm_port:
            vlan_list.append(vlan_id['value'])
        orig_vlan_list = [0, 22]
        for id in orig_vlan_list:
            if id in vlan_list:
                raise exceptions.NotFound("vlan " + str(id) + " not in found vlans" )

        pass

    def test_vlan_unaware_l2vm(self):
        port_name = "vlanunaware-port1-vlan12"
        port = self.sriov_port_create(self.network_12,port_name)
        vm = self._create_server_sriov_port(port,name="vlanunaware-sriov-vm1")
        time.sleep(2)
        #find bridgeport created on the dummy network
        bridge_port = self.nuage_vsd_client.get_l2domain_vports(self.vsd_network_12[0]['ID'])
        #find the gateway port id of the vlan associated
        vlan_obj = self.nuage_vsd_client.get_bridge_port_gateway_vlan(bridge_port[0])
        gateway_port_id = vlan_obj[0]['parentID']
        # get all the vlans on the gateway port. should have all the vlans in the port name
        vlans_in_port = self.nuage_vsd_client.get_gateway_vlan("ports" , gateway_port_id)
        vlan_list = []
        for vlan_id in vlans_in_port:
            vlan_list.append(vlan_id['value'])
        orig_vlan_list = [12]
        for id in orig_vlan_list:
            if id not in vlan_list:
                raise exceptions.NotFound("vlan " + str(id) + " not in found vlans" )
        pass
   
    def test_vlan_unaware_l3vm(self):
	port_name = "vlanunaware-port1-vlan34"
        port = self.sriov_port_create(self.network_34,port_name)
        vm = self._create_server_sriov_port(port,name="vlanunaware-sriov-vm2")
        time.sleep(2)
        bridge_port = self.nuage_vsd_client.get_l3_subnet_vports(self.vsd_subnet_34[0]['ID'])
        vlan_obj = self.nuage_vsd_client.get_bridge_port_gateway_vlan(bridge_port[0])
        gateway_port_id = vlan_obj[0]['parentID']
        # get all the vlans on the gateway port. should have all the vlans in the port name
        vlans_in_port = self.nuage_vsd_client.get_gateway_vlan("ports" , gateway_port_id)
        vlan_list = []
        for vlan_id in vlans_in_port:
            vlan_list.append(vlan_id['value'])
        orig_vlan_list = [34]
        for id in orig_vlan_list:
            if id not in vlan_list:
                raise exceptions.NotFound("vlan " + str(id) + " not in found vlans" )
        pass

