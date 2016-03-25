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
"""
These mixins extend BaseTestCase, so your testclass should only extend the
mixins it needs. The reason for this design is that now every mixin a test
extends will have 'setup_clients' called automagically for you. A test class'
structure would look like:
    BaseTestCase
         |
     BaseMixin
    /    |    \
mixin1 mixin2  mixin3
    \    |    /
     TestClass
"""
import contextlib

from tempest.common.utils import data_utils
from tempest.test import BaseTestCase
from . import bgpvpn_client

class BaseMixin(BaseTestCase):
    """Base class for all Mixins.

    This class exists because calling get_client_manager() in every mixin would
    reinitialize all the clients over and over again. So don't use
    get_client_manager in the mixins, but cls.manager and cls.admin_manager
    instead.
    """
    @classmethod
    def setup_clients(cls):
        super(BaseMixin, cls).setup_clients()
        cls.manager = cls.get_client_manager()
        cls.admin_manager = cls.get_client_manager(credential_type='admin')
        cls.manager.bgpvpn_client = bgpvpn_client.BGPVPNClient(
                                        cls.manager.auth_provider)
        cls.admin_manager.bgpvpn_client = bgpvpn_client.BGPVPNClient(
                                        cls.manager.auth_provider)
        cls.manager.net_assoc_client = bgpvpn_client.BGPVPNNetworkAssociationClient(
                                            cls.manager.auth_provider)
        cls.admin_manager.net_assoc_client = bgpvpn_client.BGPVPNNetworkAssociationClient(
                                            cls.manager.auth_provider)
        cls.manager.rtr_assoc_client = bgpvpn_client.BGPVPNRouterAssociationClient(
                                            cls.manager.auth_provider)
        cls.admin_manager.rtr_assoc_client = bgpvpn_client.BGPVPNRouterAssociationClient(
                                            cls.manager.auth_provider)

class BGPVPNMixin(BaseMixin):

    @classmethod
    def setup_clients(cls):
        super(BGPVPNMixin, cls).setup_clients()
        cls.bgpvpn_client = cls.manager.bgpvpn_client
        cls.bgpvpn_client_admin = cls.admin_manager.bgpvpn_client
        cls.net_assoc_client = cls.manager.net_assoc_client
        cls.net_assoc_client_admin = cls.admin_manager.net_assoc_client
        cls.rtr_assoc_client = cls.manager.rtr_assoc_client
        cls.rtr_assoc_client_admin = cls.admin_manager.rtr_assoc_client

    @contextlib.contextmanager
    def bgpvpn(self, do_delete=True, as_admin=True, **kwargs):
        client = self.bgpvpn_client_admin if as_admin else self.bgpvpn_client
        bgpvpn = {'name': data_utils.rand_name('bgpvpn')}
        bgpvpn.update(kwargs)
        bgpvpn = client.create_bgpvpn(**bgpvpn)
        try:
            yield bgpvpn
        finally:
            if do_delete:
                client.delete_bgpvpn(bgpvpn['id'])

    @contextlib.contextmanager
    def router_assocation(self, router_id, bgpvpn_id, do_delete=True,
                          as_admin=False, **kwargs):
        client = (self.rtr_assoc_client_admin if as_admin
                  else self.rtr_assoc_client)
        rtr_assoc = {'router_id': router_id}
        rtr_assoc.update(kwargs)
        rtr_assoc = client.create_router_assocation(bgpvpn_id, **rtr_assoc)
        try:
            yield rtr_assoc
        finally:
            if do_delete:
                client.delete_router_assocation(rtr_assoc['id'], bgpvpn_id)

    @contextlib.contextmanager
    def network_assocation(self, network_id, bgpvpn_id, do_delete=True,
                           as_admin=False, **kwargs):
        client = (self.net_assoc_client_admin if as_admin
                  else self.net_assoc_client)
        net_assoc = {'network_id': network_id}
        net_assoc.update(kwargs)
        net_assoc = client.create_network_association(bgpvpn_id, **net_assoc)
        try:
            yield net_assoc
        finally:
            if do_delete:
                client.delete_network_association(net_assoc['id'], bgpvpn_id)


class NetworkMixin(BaseMixin):

    @classmethod
    def setup_clients(cls):
        super(NetworkMixin, cls).setup_clients()
        cls.network_client = cls.manager.network_client
        cls.network_client_admin = cls.admin_manager.network_client
        cls.networks_client = cls.manager.networks_client
        cls.networks_client_admin = cls.admin_manager.networks_client
        cls.subnets_client = cls.manager.subnets_client
        cls.subnets_client_admin = cls.admin_manager.subnets_client

    @contextlib.contextmanager
    def network(self, do_delete=True, as_admin=False, **kwargs):
        client = (self.networks_client_admin if as_admin
                  else self.networks_client)
        network = {'name': data_utils.rand_name('network')}
        network.update(kwargs)
        network = client.create_network(**network)['network']
        try:
            yield network
        finally:
            if do_delete:
                client.delete_network(network['id'])

    @contextlib.contextmanager
    def subnet(self, cidr, do_delete=True, as_admin=False, **kwargs):
        client = self.subnets_client_admin if as_admin else self.subnets_client
        subnet = {'name': data_utils.rand_name('subnet'),
                  'cidr': cidr}
        subnet.update(kwargs)
        subnet = client.create_subnet(**subnet)['subnet']
        try:
            yield subnet
        finally:
            if do_delete:
                client.delete_subnet(subnet['id'])

    @contextlib.contextmanager
    def port(self, network_id, do_delete=True, as_admin=False, **kwargs):
        client = self.network_client_admin if as_admin else self.network_client
        port = {'name': data_utils.rand_name('port'),
                'network_id': network_id}
        port.update(kwargs)
        port = client.create_port(**port)['port']
        try:
            yield port
        finally:
            if do_delete:
                client.delete_port(port['id'])


class L3Mixin(BaseMixin):

    @classmethod
    def setup_clients(cls):
        super(L3Mixin, cls).setup_clients()
        cls.routers_client = cls.manager.routers_client
        cls.routers_client_admin = cls.admin_manager.routers_client

    @contextlib.contextmanager
    def router(self, do_delete=True, as_admin=False, **kwargs):
        client = self.routers_client_admin if as_admin else self.routers_client
        router = {'name': data_utils.rand_name('router')}
        router.update(kwargs)
        router = client.create_router(**router)['router']
        try:
            yield router
        finally:
            if do_delete:
                client.delete_router(router['id'])
