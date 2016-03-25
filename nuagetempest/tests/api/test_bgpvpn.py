# Copyright 2015 Alcatel-Lucent USA Inc.
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

from oslo_log import log as logging

from tempest import config
from nuagetempest.services.bgpvpn.mixins import BGPVPNMixin
from nuagetempest.services.bgpvpn.mixins import L3Mixin
from nuagetempest.services.bgpvpn.mixins import NetworkMixin

from tempest.lib import exceptions as lib_exc

from testtools.matchers import Contains
from testtools.matchers import Equals
from testtools.matchers import Not

LOG = logging.getLogger(__name__)
CONF = config.CONF


class BgpvpnBase(BGPVPNMixin):

    @classmethod
    def resource_setup(cls):
        super(BgpvpnBase, cls).resource_setup()
        cls.tenant_id = cls.bgpvpn_client.tenant_id
        cls.admin_tenant_id = cls.bgpvpn_client_admin.tenant_id


class BgpvpnTest(BgpvpnBase):

    def test_bgpvpn_create(self):
        bgpvpns = self.bgpvpn_client.list_bgpvpns()
        pre_ids = [bgpvpn['id'] for bgpvpn in bgpvpns]
        with self.bgpvpn(tenant_id=self.tenant_id) as created_bgpvpn:
            bgpvpns = self.bgpvpn_client.list_bgpvpns()
            post_ids = [bgpvpn['id'] for bgpvpn in bgpvpns]
            self.assertThat(pre_ids, Not(Contains(created_bgpvpn['id'])))
            self.assertThat(post_ids, Contains(created_bgpvpn['id']))

    def test_bgpvpn_create_unsupported_type(self):
        self.assertRaisesRegexp(
            lib_exc.BadRequest, "driver does not support l2",
            self.bgpvpn_client_admin.create, type='l2')

    def test_bgpvpn_create_non_admin(self):
        self.assertRaises(lib_exc.Forbidden, self.bgpvpn_client.create)


class RouterAssociationTest(BgpvpnBase, L3Mixin):

    def test_router_association_create(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_distinguishers=['123:321'],
                         route_targets=['123:321']) as bgpvpn,\
                self.router() as router,\
                self.router_assocation(router['id'],
                                       bgpvpn['id']) as rtr_assoc:
            router = self.network_client.show_router(router['id'])['router']
            self.assertThat(router['rd'],
                            Equals(bgpvpn['route_distinguishers'][0]))
            self.assertThat(router['rt'], Equals(bgpvpn['route_targets'][0]))
            rtr_assoc_show = self.rtr_assoc_client.show_router_assocation(
                rtr_assoc['id'], bgpvpn['id'])
            self.assertThat(rtr_assoc_show['router_id'], Equals(router['id']))

    def test_router_association_missing_rd(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_targets=['123:321']) as bgpvpn,\
                self.router() as router:
            self.assertRaisesRegexp(
                lib_exc.BadRequest, "route_distinguisher is required",
                self.rtr_assoc_client.create_router_assocation,
                bgpvpn['id'], router_id=router['id'])

    def test_router_association_missing_rt(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_distinguishers=['123:321']) as bgpvpn, \
                self.router() as router:
            self.assertRaisesRegexp(
                lib_exc.BadRequest, "route_target is required",
                self.rtr_assoc_client.create_router_assocation,
                bgpvpn['id'], router_id=router['id'])

    def test_router_association_multiplerouters_singlebgpvpn(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_distinguishers=['123:321'],
                         route_targets=['123:321']) as bgpvpn, \
                self.router() as router, \
                self.router() as router2, \
                self.router_assocation(router['id'],
                                       bgpvpn['id']):
            self.assertRaisesRegexp(
                lib_exc.BadRequest,
                "Can not have more than 1 router association per bgpvpn",
                self.rtr_assoc_client.create_router_assocation,
                bgpvpn['id'], router_id=router2['id'])

    def test_router_association_singlerouter_multiplebgpvpn(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_distinguishers=['123:321'],
                         route_targets=['123:321']) as bgpvpn, \
                self.bgpvpn(tenant_id=self.tenant_id,
                            route_distinguishers=['234:432'],
                            route_targets=['234:432']) as bgpvpn2, \
                self.router() as router, \
                self.router_assocation(router['id'],
                                       bgpvpn['id']):
            self.assertRaisesRegexp(
                lib_exc.BadRequest,
                "Can not have more than 1 router association per router",
                self.rtr_assoc_client.create_router_assocation,
                bgpvpn2['id'], router_id=router['id'])


class NetworkAssociationTest(BgpvpnBase, NetworkMixin):

    def test_network_association_unsupported(self):
        with self.network() as net, \
                self.bgpvpn(tenant_id=self.tenant_id) as bgpvpn:
            self.assertRaisesRegexp(
                lib_exc.BadRequest, "not support network association",
                self.net_assoc_client.create_network_association,
                bgpvpn['id'], network_id=net['id'])
        self.assertRaisesRegexp(
            lib_exc.BadRequest, "not support network association",
            self.net_assoc_client.list_network_associations,
            'dummy')
        self.assertRaisesRegexp(
            lib_exc.BadRequest, "not support network association",
            self.net_assoc_client.delete_network_association,
            'dummy', 'dummy')
        self.assertRaisesRegexp(
            lib_exc.BadRequest, "not support network association",
            self.net_assoc_client.update_network_association,
            'dummy', 'dummy')
