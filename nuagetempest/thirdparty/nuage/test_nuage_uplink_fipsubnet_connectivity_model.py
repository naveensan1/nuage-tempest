# Copyright 2015 OpenStack super(FloatingIPTestAdminNuage, cls).resource_setup()
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

import netaddr
import uuid

from oslo_log import log as logging

from nuagetempest.lib.test import nuage_test
from tempest.api.network.admin import test_floating_ips_admin_actions
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest import config
from nuagetempest.lib import service_mgmt
from nuagetempest.lib.utils import constants as nuage_constants
from nuagetempest.services.nuage_client import NuageRestClient
from nuagetempest.services.nuage_network_client import NuageNetworkClientJSON
from tempest.api.network import base


from tempest import test

CONF = config.CONF
LOG = logging.getLogger(__name__)

class FloatingIPTestAdminNuage(base.BaseAdminNetworkTest):

    @classmethod
    def setup_clients(cls):
        super(FloatingIPTestAdminNuage, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()

        # Overriding cls.client with Nuage network client
        cls.client = NuageNetworkClientJSON(
            cls.os.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os.default_params)

        cls.service_manager = service_mgmt.ServiceManager()

        if not cls.service_manager.is_service_running(nuage_constants.NEUTRON_SERVICE):
            cls.service_manager.comment_configuration_attribute(
                CONF.nuage_sut.nuage_plugin_configuration,
                nuage_constants.NUAGE_UPLINK_GROUP,
                nuage_constants.NUAGE_UPLINK)
            cls.service_manager.start_service(nuage_constants.NEUTRON_SERVICE)
            cls.service_manager.wait_for_service_status(nuage_constants.NEUTRON_SERVICE)

    @classmethod
    def resource_setup(cls):
        super(FloatingIPTestAdminNuage, cls).resource_setup()
        # resources required for uplink subnet
        cls.gateway = None
        cls.gatewayport = None
        cls.gatewayvlan = None
        cls.uplinksubnet = None

    @classmethod
    def resource_cleanup(cls):
        if cls.uplinksubnet:
            cls.nuage_vsd_client.delete_uplink_subnet(
                cls.uplinksubnet[0]['ID']) 
        if cls.gatewayvlan:
            cls.nuage_vsd_client.delete_gateway_vlan(cls.gatewayvlan[0]['ID'])
        if cls.gatewayport:
            cls.nuage_vsd_client.delete_gateway_port(cls.gatewayport[0]['ID'])
        if cls.gateway:
            cls.nuage_vsd_client.delete_gateway(cls.gateway[0]['ID'])
        super(FloatingIPTestAdminNuage, cls).resource_cleanup()
             
    @classmethod
    def create_gateway_port_vlan(cls, gw_type='VRSG', vlan_no=200):
        gw_name = data_utils.rand_name('gw-')
        cls.gateway = cls.nuage_vsd_client.create_gateway(
            gw_name, str(uuid.uuid4()), gw_type, None)
        gw_port_name = data_utils.rand_name('gw-port-')
        cls.gatewayport = cls.nuage_vsd_client.create_gateway_port(
            gw_port_name, 'test', 'ACCESS', cls.gateway[0]['ID']) 
        cls.gatewayvlan = cls.nuage_vsd_client.create_gateway_vlan(
            cls.gatewayport[0]['ID'], 'test', vlan_no)
        

#    @classmethod
    def create_uplink_subnet(cls, parentID=""):
        uplink_subnet_dict = {}
        uplink_subnet_dict['name'] = "uplink-sub1"
        uplink_subnet_dict['address'] = "210.20.0.0"
        uplink_subnet_dict['netmask'] = "255.255.255.0"
        uplink_subnet_dict['gateway'] = '210.20.0.1'
        uplink_subnet_dict['uplinkVportName'] = 'vlan1'
        uplink_subnet_dict['uplinkInterfaceIP'] = '210.20.0.2'
        uplink_subnet_dict['uplinkInterfaceMAC'] = "00:11:22:33:44:55"
        uplink_subnet_dict['uplinkGWVlanAttachmentID'] = cls.gatewayvlan[0]['ID']
        uplink_subnet_dict['sharedResourceParentID'] = parentID
        cls.uplinksubnet = cls.nuage_vsd_client.create_uplink_subnet(
                               **uplink_subnet_dict)
        cls.addCleanup(cls.delete_uplink_subnet, str(cls.uplinksubnet[0]['ID']))

    def delete_uplink_subnet(self, subnet_id):
        self.uplinksubnet = None
        return self.nuage_vsd_client.delete_uplink_subnet(subnet_id)

    @classmethod
    def delete_gateway_port_vlan(cls):
        if cls.gatewayvlan:
            cls.nuage_vsd_client.delete_gateway_vlan(cls.gatewayvlan[0]['ID'])
            cls.gatewayvlan = None
        if cls.gatewayport:
            cls.nuage_vsd_client.delete_gateway_port(cls.gatewayport[0]['ID'])
            cls.gatewayport = None
        if cls.gateway:
            cls.nuage_vsd_client.delete_gateway(cls.gateway[0]['ID'])
            cls.gateway = None
  
    def create_fip_subnet(self, cidr, nuage_uplink=None):
        name = data_utils.rand_name('network-')
        kwargs = {'name': name,
                  'router:external': True}
        body = self.admin_networks_client.create_network(**kwargs)
        pubnet = body['network']
        self.addCleanup(self.admin_networks_client.delete_network, pubnet['id'])
        fipsub_name = data_utils.rand_name('fipsub-')
        kwargs = {'name': fipsub_name,
                  'network_id': pubnet['id'],
                  'ip_version': 4,
                  'cidr': cidr}
        if nuage_uplink:
            kwargs.update({'nuage_uplink': nuage_uplink})
        body = self.admin_subnets_client.create_subnet(**kwargs)
        self.assertEqual(fipsub_name, body['subnet']['name'])
        self.assertEqual(cidr, body['subnet']['cidr'])
        return  body['subnet']

    def delete_fip_subnet(self, fipsubID):
        try:
            self.admin_subnets_client.delete_subnet(fipsubID)
        except Exception as exc:
            LOG.exception(exc)

    def add_uplink_key_to_plugin_file(self, nuage_uplink):
       self.service_manager.stop_service(nuage_constants.NEUTRON_SERVICE)
       # Add the shared zone ID to the plugin.ini file
       self.service_manager.set_configuration_attribute(
           CONF.nuage_sut.nuage_plugin_configuration,
           nuage_constants.NUAGE_UPLINK_GROUP,
           nuage_constants.NUAGE_UPLINK, 
           nuage_uplink)
       self.service_manager.start_service(nuage_constants.NEUTRON_SERVICE)
       self.service_manager.wait_for_service_status(nuage_constants.NEUTRON_SERVICE)


    def delete_uplink_key_from_plugin_file(self):
       self.service_manager.stop_service(nuage_constants.NEUTRON_SERVICE)
       self.service_manager.comment_configuration_attribute(
           CONF.nuage_sut.nuage_plugin_configuration,
           nuage_constants.NUAGE_UPLINK_GROUP,
           nuage_constants.NUAGE_UPLINK)
       self.service_manager.start_service(nuage_constants.NEUTRON_SERVICE)
       self.service_manager.wait_for_service_status(nuage_constants.NEUTRON_SERVICE)

    @test.attr(type='smoke')
    def test_create_fipsubs_in_shared_domain(self):
        # Create first FIP subnet
        fipsub1 = self.create_fip_subnet('172.40.0.0/24')
        self.addCleanup(self.delete_fip_subnet, fipsub1['id'])

        # Get FIP parentID
        fip_extID =  self.nuage_vsd_client.get_vsd_external_id(fipsub1['id'])
        nuage_fipsubnet1 = self.nuage_vsd_client.get_sharedresource(
          filters='externalID', filter_value= fip_extID)
        self.assertEqual(fipsub1['id'], nuage_fipsubnet1[0]['name'])      

        # Create uplink subnet on VSD
        self.create_gateway_port_vlan()

        self.create_uplink_subnet(parentID=nuage_fipsubnet1[0]['parentID'])

        # Verify the uplink-subnet parentID with the FIPsubnet parentID
        self.assertEqual(nuage_fipsubnet1[0]['parentID'],
                         self.uplinksubnet[0]['sharedResourceParentID'])
        # Create FIP subnet with nuage_uplink option 
        fipsub2 = self.create_fip_subnet('198.40.0.0/24', nuage_fipsubnet1[0]['parentID'])
        self.addCleanup(self.delete_fip_subnet, fipsub2['id'])
        fip_extID =  self.nuage_vsd_client.get_vsd_external_id(fipsub2['id'])
        nuage_fipsubnet2 = self.nuage_vsd_client.get_sharedresource(
          filters='externalID', filter_value= fip_extID)
        self.assertEqual(fipsub2['id'], nuage_fipsubnet2[0]['name'])      
        self.assertEqual(nuage_fipsubnet1[0]['parentID'],
                         nuage_fipsubnet2[0]['parentID'])
        #self.delete_gateway_port_vlan()

    @test.attr(type='smoke')
    def test_show_fipsubs_in_shared_domain(self):
        fipsub = self.create_fip_subnet('172.40.0.0/24')
        self.addCleanup(self.delete_fip_subnet, fipsub['id'])
        # Check the nuage_uplink field in subnet-show
        body = self.admin_subnets_client.show_subnet(fipsub['id'])
        fipsub_show = body['subnet']
        # Get FIP parentID in VSD
        fip_extID =  self.nuage_vsd_client.get_vsd_external_id(fipsub['id'])
        nuage_fipsubnet = self.nuage_vsd_client.get_sharedresource(
          filters='externalID', filter_value= fip_extID)
        self.assertEqual(fipsub_show['id'], nuage_fipsubnet[0]['name'])
        self.assertEqual(fipsub_show['nuage_uplink'], nuage_fipsubnet[0]['parentID'])

    def test_fipsubs_in_shared_domain_negative(self):
        # Create fipsub with invalid UUID for nuage_uplink
        name = data_utils.rand_name('network-')
        kwargs = {'name': name,
                  'router:external': True}
        body = self.admin_networks_client.create_network(**kwargs)
        pubnet = body['network']
        self.addCleanup(self.admin_networks_client.delete_network, pubnet['id'])
        fipsub_name = data_utils.rand_name('fipsub-')
        kwargs = {'name': fipsub_name,
                  'network_id': pubnet['id'],
                  'ip_version': 4,
                  'cidr': '160.60.0.0/24',
                  'nuage_uplink' : '111111111'}
        self.assertRaises(exceptions.BadRequest,
                          self.admin_subnets_client.create_subnet,
                          **kwargs)        

        # Creation FIP subnet with same cidr and nuage_uplink should fail
        fipsub1 = self.create_fip_subnet('172.40.0.0/24')
        self.addCleanup(self.delete_fip_subnet, fipsub1['id'])
        fip_extID =  self.nuage_vsd_client.get_vsd_external_id(fipsub1['id'])
        nuage_fipsubnet1 = self.nuage_vsd_client.get_sharedresource(
          filters='externalID', filter_value= fip_extID)

        kwargs = {'name': fipsub_name,
                  'network_id': pubnet['id'],
                  'ip_version': 4,
                  'cidr': '172.40.0.0/24',
                  'nuage_uplink' : nuage_fipsubnet1[0]['parentID']}
        self.assertRaises(exceptions.ServerFault,
                          self.admin_subnets_client.create_subnet,
                          **kwargs)
       
        # Update of nuage_uplink is should not be allowed
        # Will Fail due to OPENSTACK-1083
        self.assertRaises(exceptions.BadRequest,
                         self.admin_subnets_client.update_subnet,
                         fipsub1['id'],
                         nuage_uplink='c6166803-c4cb-40a0-805a-e42bbf4c0790')
      
    def test_fipsub_with_nuageuplink_and_uplinksub_no_parentID(self):
       # Create gateway, port and vlan on VSD
       self.create_gateway_port_vlan()
       # Create uplink subnet without passing parentID
       self.create_uplink_subnet()

       #self.uplinksubnet
       fipsub1 = self.create_fip_subnet('172.40.0.0/24', 
           self.uplinksubnet[0]['parentID'])
       self.addCleanup(self.delete_fip_subnet, fipsub1['id'])
       fip_extID =  self.nuage_vsd_client.get_vsd_external_id(fipsub1['id'])
       nuage_fipsubnet1 = self.nuage_vsd_client.get_sharedresource(
           filters='externalID', filter_value= fip_extID)
       self.assertEqual(fipsub1['id'], nuage_fipsubnet1[0]['name'])
       self.assertEqual(self.uplinksubnet[0]['parentID'],
                        nuage_fipsubnet1[0]['parentID'])
      
    def test_fipsub_with_uplinkID_in_file_and_uplinksub_no_parentID(self):
       # Create gateway, port and vlan on VSD
       self.create_gateway_port_vlan()
       # Create uplink subnet without passing parentID
       self.create_uplink_subnet()
       # place parentID in plugin file
       # and restart the neutron
       self.add_uplink_key_to_plugin_file(self.uplinksubnet[0]['parentID'])
       fipsub1 = self.create_fip_subnet('172.40.0.0/24')
       self.addCleanup(self.delete_fip_subnet, fipsub1['id'])
       fip_extID =  self.nuage_vsd_client.get_vsd_external_id(fipsub1['id'])
       nuage_fipsubnet1 = self.nuage_vsd_client.get_sharedresource(
           filters='externalID', filter_value= fip_extID)
       self.assertEqual(fipsub1['id'], nuage_fipsubnet1[0]['name'])
       self.assertEqual(self.uplinksubnet[0]['parentID'],
                        nuage_fipsubnet1[0]['parentID'])
       self.delete_uplink_key_from_plugin_file()
     
    def test_fipsub_create_with_uplinkID_in_plugin_file(self):
       fipsub1 = self.create_fip_subnet('172.40.0.0/24')
       self.addCleanup(self.delete_fip_subnet, fipsub1['id'])
       fip_extID =  self.nuage_vsd_client.get_vsd_external_id(fipsub1['id'])
       nuage_fipsubnet1 = self.nuage_vsd_client.get_sharedresource(
                          filters='externalID', filter_value= fip_extID)
       fipsub2 = self.create_fip_subnet('182.40.0.0/24')
       self.addCleanup(self.delete_fip_subnet, fipsub2['id'])
       fip_extID =  self.nuage_vsd_client.get_vsd_external_id(fipsub2['id'])
       nuage_fipsubnet2 = self.nuage_vsd_client.get_sharedresource(
                          filters='externalID', filter_value= fip_extID)
       self.add_uplink_key_to_plugin_file(nuage_fipsubnet1[0]['parentID'])
       # create a second subnet
       fipsub3 = self.create_fip_subnet('192.40.0.0/24')
       self.addCleanup(self.delete_fip_subnet, fipsub3['id'])
       fip_extID =  self.nuage_vsd_client.get_vsd_external_id(fipsub3['id'])
       nuage_fipsubnet3 = self.nuage_vsd_client.get_sharedresource(
                          filters='externalID', filter_value= fip_extID)
       # check if the fipsubnet created without nuage-uplink 
       # option belongs to same shared zone
       self.assertEqual(nuage_fipsubnet1[0]['parentID'],
                        nuage_fipsubnet3[0]['parentID'])
       # Create a fipsubnet with nuage-uplink option
       # overriding the nuage_uplink key in ini file
       fipsub4 = self.create_fip_subnet('201.40.0.0/24',
           nuage_fipsubnet2[0]['parentID'])
       self.addCleanup(self.delete_fip_subnet, fipsub4['id'])
       fip_extID =  self.nuage_vsd_client.get_vsd_external_id(fipsub4['id'])
       nuage_fipsubnet4 = self.nuage_vsd_client.get_sharedresource(
                          filters='externalID', filter_value= fip_extID)
       self.assertEqual(nuage_fipsubnet2[0]['parentID'],
                        nuage_fipsubnet4[0]['parentID'])
       self.delete_uplink_key_from_plugin_file()

    def test_multi_fipsubs_with_uplinkID_in_file_and_uplinksub_no_parentID(self):
       # Create gateway, port and vlan on VSD
       self.create_gateway_port_vlan()
       # Create uplink subnet without passing parentID
       self.create_uplink_subnet()
       # place parentID in plugin file
       # and restart the neutron
       self.add_uplink_key_to_plugin_file(self.uplinksubnet[0]['parentID'])
       fipsub1 = self.create_fip_subnet('172.40.0.0/24')
       fip_extID =  self.nuage_vsd_client.get_vsd_external_id(fipsub1['id'])
       nuage_fipsubnet1 = self.nuage_vsd_client.get_sharedresource(
           filters='externalID', filter_value= fip_extID)
       self.assertEqual(fipsub1['id'], nuage_fipsubnet1[0]['name'])
       self.assertEqual(self.uplinksubnet[0]['parentID'],
                        nuage_fipsubnet1[0]['parentID'])
       fipsub2 = self.create_fip_subnet('182.40.0.0/24')
       fip_extID =  self.nuage_vsd_client.get_vsd_external_id(fipsub2['id'])
       nuage_fipsubnet2 = self.nuage_vsd_client.get_sharedresource(
           filters='externalID', filter_value= fip_extID)
       self.assertEqual(fipsub2['id'], nuage_fipsubnet2[0]['name'])
       self.assertEqual(self.uplinksubnet[0]['parentID'],
                        nuage_fipsubnet2[0]['parentID'])
       # delete all the fipsubnets and create a new one
       self.delete_fip_subnet(fipsub1['id'])
       self.delete_fip_subnet(fipsub2['id'])
       
       #create a third fipsubnet
       fipsub3 = self.create_fip_subnet('192.40.0.0/24')
       self.addCleanup(self.delete_fip_subnet, fipsub3['id'])
       fip_extID =  self.nuage_vsd_client.get_vsd_external_id(fipsub3['id'])
       nuage_fipsubnet3 = self.nuage_vsd_client.get_sharedresource(
           filters='externalID', filter_value= fip_extID)
       self.assertEqual(fipsub3['id'], nuage_fipsubnet3[0]['name'])
       self.assertEqual(self.uplinksubnet[0]['parentID'],
                        nuage_fipsubnet3[0]['parentID'])

       self.delete_uplink_key_from_plugin_file()

