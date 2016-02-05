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

from vspk.vsdk.v3_2 import *
from vspk.vsdk.v3_2.utils import set_log_level
from tempest import config
CONF = config.CONF

class vsd_client():
    def __init__(self):
        server = CONF.nuage_vsd_group.nuage_vsd_server
        self.session = NUVSDSession(username=u'csproot',
                        password=u'csproot',
                        enterprise=u'csp', 
                        api_url=u'https://%s' % server)
        self.session.start()
   
    def get_enterprises(self):
        enterprises = self.session.user.enterprises.fetch()
        return enterprises[0]

    def get_l3domains(self, enterprise):
        domains = enterprise.domains.fetch()
        return domains[0]
    
    def get_l2domains(self, enterprise):
        l2domains = enterprise.l2_domains.fetch()
        return l2domains[0]
    
    def get_subnets(self, l3domain):
        subnets = l3domain.subnets.fetch()
        return subnets[0]