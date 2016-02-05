# Copyright 2013 OpenStack Foundation
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

from neutronclient.v2_0 import client as neutronclient
from keystoneclient.auth.identity import v2
from keystoneclient import session
import keystoneclient.v2_0.client as ksclient
import os

class neutron_client():
    def __init__(self):
        self.osClient = neutron_client_setup()
    
    def get_neutron_routers(self):
        neutron_routers = self.osClient.adminneutron.list_routers()
        return neutron_routers['routers']
    
    def get_neutron_networks(self):
        neutron_networks = self.osClient.adminneutron.list_networks()
        return neutron_networks['networks']
    
    def get_neutron_subnets(self):
        neutron_subnets = self.osClient.adminneutron.list_subnets()
        return neutron_subnets['subnets']

class neutron_client_setup():
  def __init__(self):
    self.adminneutron = self. _client()
    self.keystone = self.get_keystone_client()

  def get_keystone_creds(self):
    d = {}
    d['username'] = 'admin'
    d['password'] = 'tigris'
    d['auth_url'] = 'http://localhost:5000/v2.0'
    d['tenant_name'] = 'admin'
    return d

  def get_neutron_creds(self,tenant_name):
    d = self.get_keystone_creds()
    d['tenant_name'] = tenant_name
    return d;

  def  _client(self):
    neutron_creds = self.get_neutron_creds('admin')
    return neutronclient.Client(**neutron_creds)

  def get_keystone_client(self):
    creds = self.get_keystone_creds()
    return ksclient.Client(**creds)
