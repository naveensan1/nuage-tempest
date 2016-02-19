# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from tempest import config
from tempest import test
from nuagetempest.lib.utils import constants
from nuagetempest.lib.test import nuage_test

import base_nuage_domain_tunnel_type

CONF = config.CONF


class NuageDomainTunnelType(base_nuage_domain_tunnel_type.NuageDomainTunnelTypeBase):
    @test.attr(type='smoke')
    @nuage_test.header()
    def test_create_show_router_with_default_tunnel_type(self):
        # Given the default domain tunnel type is GRE
        self.must_have_default_domain_tunnel_type(constants.DOMAIN_TUNNEL_TYPE_GRE)

        # When I create a router
        created_router = self._create_router()

        # Then the router has the default tunnel type
        self.assertEqual(created_router['tunnel_type'], constants.DOMAIN_TUNNEL_TYPE_GRE)

        # When I get the router
        show_router = self._show_router(created_router['id'])

        # Then the router has the default tunnel type
        self.assertEqual(show_router['tunnel_type'], constants.DOMAIN_TUNNEL_TYPE_GRE)

    @nuage_test.header()
    def test_create__update_router_with_tunnel_type_gre(self):
        domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_GRE

        # When I create a router with tunnel type
        created_router = self._do_create_router_with_domain_tunnel_type(domain_tunnel_type)

        # Then I have a router in OpenStack with the requested domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(created_router, domain_tunnel_type)

        domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_VXLAN
        updated_router = self._update_router(created_router['id'], tunnel_type=domain_tunnel_type)

        # Then I have a router in OpenStack with the requested domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(updated_router, domain_tunnel_type)

    @nuage_test.header()
    def test_create_router_with_tunnel_type_gre_lowercase(self):
        domain_tunnel_type = str.lower(constants.DOMAIN_TUNNEL_TYPE_GRE)

        # When I create a router with tunnel type
        created_router = self._do_create_router_with_domain_tunnel_type(domain_tunnel_type)

        # Then I have a router in OpenStack with the requested domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(created_router, domain_tunnel_type)

    @nuage_test.header()
    def test_create__update_router_with_tunnel_type_gre_to_default(self):
        # Given the default domain tunnel type is VXLAN
        data_center_default_domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_VXLAN
        self.must_have_default_domain_tunnel_type(data_center_default_domain_tunnel_type)

        # When I create a router with tunnel type
        domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_GRE
        created_router = self._do_create_router_with_domain_tunnel_type(domain_tunnel_type)

        # Then I have a router in OpenStack with the requested domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(created_router, domain_tunnel_type)

        # When I change to the data center default tunnel type
        domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_DEFAULT
        updated_router = self._update_router(created_router['id'], tunnel_type=domain_tunnel_type)

        # Then I have a router in OpenStack with the requested domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(updated_router, data_center_default_domain_tunnel_type)

    @nuage_test.header()
    def test_create__update_router_with_tunnel_type_vlan(self):
        domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_VXLAN

        # When I create a router with tunnel type
        created_router = self._do_create_router_with_domain_tunnel_type(domain_tunnel_type)

        # Then I have a router in OpenStack with the requested domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(created_router, domain_tunnel_type)

        domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_GRE
        updated_router = self._update_router(created_router['id'], tunnel_type=domain_tunnel_type)

        # Then I have a router in OpenStack with the requested domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(updated_router, domain_tunnel_type)

    @nuage_test.header()
    def test_create__update_router_with_tunnel_type_vxlan_to_default(self):
        # Given the default domain tunnel type is GRE
        data_center_default_domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_GRE
        self.must_have_default_domain_tunnel_type(data_center_default_domain_tunnel_type)

        # When I create a router with tunnel type
        domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_VXLAN
        created_router = self._do_create_router_with_domain_tunnel_type(domain_tunnel_type)

        # Then I have a router in OpenStack with the requested domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(created_router, domain_tunnel_type)

        # When I change to the data center default tunnel type
        domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_DEFAULT
        updated_router = self._update_router(created_router['id'], tunnel_type=domain_tunnel_type)

        # Then I have a router in OpenStack with the requested domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(updated_router, data_center_default_domain_tunnel_type)

    @nuage_test.header()
    def test_list_routers_does_not_show_domain_type(self):
        def get_attr(from_dict, key):
            return from_dict[key]

        # Given I have 2 routers
        router1 = self._create_router()
        router2 = self._create_router()

        # When I get the list of routers
        router_list = self._list_routers()

        # Then my routers are the list
        self.assertIn(router1['id'],
                      [my_router['id'] for my_router in router_list])
        self.assertIn(router2['id'],
                      [my_router['id'] for my_router in router_list])

        # But there is no tunnel_type attribute in the response
        found_routers = filter(lambda a_router: a_router['id'] == router1['id'], router_list)
        self.assertRaises(KeyError, get_attr, found_routers[0], 'tunnel_type')

    def test_change_default_tunnel_type_does_not_affect_existing_routers_created_with_default_domain_tunnel_type(self):
        # Given the default domain tunnel type is GRE
        data_center_default_domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_GRE
        self.must_have_default_domain_tunnel_type(data_center_default_domain_tunnel_type)

        # When I create a router with tunnel type
        domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_DEFAULT
        created_router = self._do_create_router_with_domain_tunnel_type(domain_tunnel_type)

        # Then I have a router in OpenStack with the requested domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(created_router, data_center_default_domain_tunnel_type)

        # When I change the data center default tunnel type
        data_center_default_domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_VXLAN
        self.must_have_default_domain_tunnel_type(data_center_default_domain_tunnel_type)

        # Then the router tunnel type has not changed
        show_router = self._show_router(created_router['id'])
        self.assertEqual(created_router['tunnel_type'], show_router['tunnel_type'])
