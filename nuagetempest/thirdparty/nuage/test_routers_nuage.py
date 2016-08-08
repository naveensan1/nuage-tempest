# Copyright 2013 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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
from random import randint
import uuid

import netaddr
from nuagetempest.lib.utils import constants as n_constants
from nuagetempest.services.nuage_client import NuageRestClient
from nuagetempest.services.nuage_network_client import NuageNetworkClientJSON
from tempest.api.network import test_routers
from tempest.common.utils import data_utils
from tempest.lib.common.utils import data_utils as lib_data_utils
from tempest import config
from tempest import test
from tempest.lib import exceptions


CONF = config.CONF

NUAGE_PAT_ENABLED = 'ENABLED'
NUAGE_PAT_DISABLED = 'DISABLED'


class RoutersTestNuage(test_routers.RoutersTest):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(RoutersTestNuage, cls).setup_clients()
        cls.client = NuageNetworkClientJSON(
            cls.os.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os.default_params)
        cls.nuage_vsd_client = NuageRestClient()
        # initialize admin client
        cls.admin_client = NuageNetworkClientJSON(
            cls.os_adm.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os.default_params)

    @classmethod
    def resource_setup(cls):
        super(RoutersTestNuage, cls).resource_setup()

    @test.attr(type='smoke')
    def test_create_show_list_update_delete_router(self):
        # Create a router
        name = data_utils.rand_name('router-')
        create_body = self.routers_client.create_router(
            name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=False)
        self.addCleanup(self._delete_router, create_body['router']['id'])
        self.assertEqual(create_body['router']['name'], name)
        # VSD validation
        rtr_id = create_body['router']['id']
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=rtr_id)
        self.assertEqual(nuage_domain[0][u'description'], name)
        self.assertEqual(
            create_body['router']['external_gateway_info']['network_id'],
            CONF.network.public_network_id)
        self.assertEqual(create_body['router']['admin_state_up'], False)
        # Show details of the created router
        show_body = self.routers_client.show_router(create_body['router']['id'])
        self.assertEqual(show_body['router']['name'], name)
        self.assertEqual(
            show_body['router']['external_gateway_info']['network_id'],
            CONF.network.public_network_id)
        self.assertEqual(show_body['router']['admin_state_up'], False)
        # List routers and verify if created router is there in response
        list_body = self.routers_client.list_routers()
        routers_list = list()
        for router in list_body['routers']:
            routers_list.append(router['id'])
        self.assertIn(create_body['router']['id'], routers_list)
        # Update the name of router and verify if it is updated
        updated_name = 'updated ' + name
        update_body = self.routers_client.update_router(create_body['router']['id'],
                                                        name=updated_name)
        self.assertEqual(update_body['router']['name'], updated_name)
        show_body = self.routers_client.show_router(
            create_body['router']['id'])
        self.assertEqual(show_body['router']['name'], updated_name)

    @test.attr(type='smoke')
    def test_add_remove_router_interface_with_subnet_id(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        # Validate that an L2Domain is created on VSD for the subnet creation
        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID',
            filter_value=subnet['id'])
        self.assertEqual(nuage_l2dom[0][u'name'], subnet['id'])

        router = self._create_router(data_utils.rand_name('router-'))
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=router['id'])
        # Add router interface with subnet id
        interface = self.routers_client.add_router_interface(
            router['id'], subnet_id=subnet['id'])
        self.addCleanup(self._remove_router_interface_with_subnet_id,
                        router['id'], subnet['id'])
        self.assertIn('subnet_id', interface.keys())
        self.assertIn('port_id', interface.keys())
        # Verify router id is equal to device id in port details
        show_port_body = self.ports_client.show_port(
            interface['port_id'])
        self.assertEqual(show_port_body['port']['device_id'],
                         router['id'])
        # Validate VSD L2 Domain created above is deleted and added as a
        # L3Domain subnet
        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID',
            filter_value=subnet['id'])
        self.assertEqual(nuage_l2dom, '', "L2 domain is not deleted")
        nuage_domain_subnet = self.nuage_vsd_client.get_domain_subnet(
            parent=n_constants.DOMAIN, parent_id=nuage_domain[0]['ID'])

        self.assertEqual(nuage_domain_subnet[0][u'name'], subnet['id'])

    @test.attr(type='smoke')
    def test_add_remove_router_interface_with_port_id(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        # Validate that an L2Domain is created on VSD for the subnet creation
        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID',
            filter_value=subnet['id'])
        self.assertEqual(nuage_l2dom[0][u'name'], subnet['id'])

        router = self._create_router(data_utils.rand_name('router-'))
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=router['id'])
        port_body = self.ports_client.create_port(
            network_id=network['id'])
        # add router interface to port created above
        interface = self.routers_client.add_router_interface(
            router['id'], port_id=port_body['port']['id'])
        self.addCleanup(self._remove_router_interface_with_port_id,
                        router['id'], port_id=port_body['port']['id'])
        self.assertIn('subnet_id', interface.keys())
        self.assertIn('port_id', interface.keys())
        # Verify router id is equal to device id in port details
        show_port_body = self.ports_client.show_port(
            interface['port_id'])
        self.assertEqual(show_port_body['port']['device_id'],
                         router['id'])
        # Validate L2 Domain created above is deleted and added as a L3Domain
        # subnet
        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID', filter_value=subnet['id'])
        self.assertEqual(
            nuage_l2dom, '', "L2 domain is not deleted in VSD")
        nuage_domain_subnet = self.nuage_vsd_client.get_domain_subnet(
            n_constants.DOMAIN, nuage_domain[0]['ID'])
        self.assertEqual(nuage_domain_subnet[0][u'name'], subnet['id'])

    @test.requires_ext(extension='extraroute', service='network')
    @test.attr(type='smoke')
    def test_update_extra_route(self):
        self.network = self.create_network()
        self.name = self.network['name']
        self.subnet = self.create_subnet(self.network)
        # Add router interface with subnet id
        self.router = self._create_router(
            data_utils.rand_name('router-'), True)
        # VSD validation
        # Verify Router is created in VSD
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=self.router['id'])
        self.assertEqual(
            nuage_domain[0][u'description'], self.router['name'])

        self.create_router_interface(self.router['id'], self.subnet['id'])
        self.addCleanup(
            self._delete_extra_routes,
            self.router['id'])
        # Update router extra route, second ip of the range is
        # used as next hop
        cidr = netaddr.IPNetwork(self.subnet['cidr'])
        next_hop = str(cidr[2])
        destination = str(self.subnet['cidr'])
        test_routes = [{'nexthop': next_hop, 'destination': destination}]
        extra_route = self.routers_client.update_extra_routes(
            router_id=self.router['id'],
            routes=test_routes)
        self.assertEqual(1, len(extra_route['router']['routes']))
        self.assertEqual(destination,
                         extra_route['router']['routes'][0]['destination'])
        self.assertEqual(next_hop,
                         extra_route['router']['routes'][0]['nexthop'])
        show_body = self.routers_client.show_router(self.router['id'])
        self.assertEqual(destination,
                         show_body['router']['routes'][0]['destination'])
        self.assertEqual(next_hop,
                         show_body['router']['routes'][0]['nexthop'])

        # VSD validation
        nuage_static_route = self.nuage_vsd_client.get_staticroute(
            parent=n_constants.DOMAIN, parent_id=nuage_domain[0]['ID'])
        self.assertEqual(
            nuage_static_route[0][u'nextHopIp'], next_hop, "wrong nexthop")

    @test.attr(type='smoke')
    def test_add_router_interface_different_netpart(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        # Validate that L2Domain is created on VSD
        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID', filter_value=subnet['id'])
        self.assertEqual(nuage_l2dom[0]['name'], subnet['id'])

        # Create net-partition
        netpart_name = data_utils.rand_name('netpart')
        netpart = {
            'net_partition': netpart_name
        }
        netpart_body = self.client.create_netpartition(netpart_name)
        self.addCleanup(self.client.delete_netpartition,
                        netpart_body['net_partition']['id'])

        # Create router in new net-partition
        rtr_body = self.routers_client.create_router(
            data_utils.rand_name('router'), admin_state_up=True, **netpart)
        self.addCleanup(self._delete_router, rtr_body['router']['id'])

        # Verify Router is created in correct net-partition
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=rtr_body['router']['id'],
            netpart_name=netpart_name)
        self.assertEqual(rtr_body['router']['name'], nuage_domain[0][
            'description'])
        self.assertEqual(netpart_body['net_partition']['id'],
                         nuage_domain[0]['parentID'])

        # Add router interface with subnet id
        # Since subnet and router are in different net-partitions,
        # VSD should throw an exception
        self.assertRaises(
            exceptions.BadRequest,
            self.routers_client.add_router_interface,
            rtr_body['router']['id'], subnet_id=subnet['id'])

    @test.attr(type='smoke')
    def test_router_create_with_template(self):
        # Create a router template in VSD
        template_name = data_utils.rand_name('rtr-template')
        nuage_template = self.nuage_vsd_client.create_l3domaintemplate(
            template_name)
        args = [n_constants.DOMAIN_TEMPLATE, nuage_template[0]['ID'],
                True]
        self.addCleanup(self.nuage_vsd_client.delete_resource, *args)

        # Create zones under the template
        nuage_isolated_zone = self.nuage_vsd_client.create_zonetemplate(
            nuage_template[0]['ID'], 'openstack-isolated')

        nuage_public_zone = self.nuage_vsd_client.create_zonetemplate(
            nuage_template[0]['ID'], 'openstack-shared')

        # Verify template and zones are created correctly
        self.assertEqual(template_name, nuage_template[0]['name'])
        self.assertEqual('openstack-isolated',
                         nuage_isolated_zone[0]['name'])
        self.assertEqual('openstack-shared',
                         nuage_public_zone[0]['name'])

        rtr_template = {
            'nuage_router_template': nuage_template[0]['ID']
        }
        # Create a router using new template
        rtr_body = self.routers_client.create_router(
            data_utils.rand_name('router'), admin_state_up=True,
            **rtr_template)
        self.addCleanup(self._delete_router, rtr_body['router']['id'])

        # Verify router is created with correct template
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=rtr_body['router']['id'])
        self.assertEqual(rtr_body['router']['name'], nuage_domain[0][
            'description'])
        self.assertEqual(nuage_template[0]['ID'],
                         nuage_domain[0]['templateID'])

    @test.attr(type='smoke')
    def test_router_create_with_incorrect_template(self):
        template_id = str(uuid.uuid1())
        rtr_template = {
            'nuage_router_template': template_id
        }
        # Create a router using new template and verify correct exception is
        # raised
        self.assertRaises(exceptions.ServerFault,
                          self.routers_client.create_router,
                          data_utils.rand_name('router'),
                          True,
                          **rtr_template)

    @test.attr(type='smoke')
    def test_router_create_with_template_no_zones(self):
        # Create a router template in VSD
        template_name = data_utils.rand_name('rtr-template')
        nuage_template = self.nuage_vsd_client.create_l3domaintemplate(
            template_name)
        args = [n_constants.DOMAIN_TEMPLATE, nuage_template[0]['ID'],
                True]
        self.addCleanup(self.nuage_vsd_client.delete_resource, *args)

        # Verify template and zones are created correctly
        self.assertEqual(template_name, nuage_template[0]['name'])

        rtr_template = {
            'nuage_router_template': nuage_template[0]['ID']
        }

        self.assertRaises(exceptions.ServerFault,
                          self.routers_client.create_router,
                          data_utils.rand_name('router'),
                          True,
                          **rtr_template)

    @test.attr(type='smoke')
    def test_router_create_with_netpart(self):
        netpart_name = data_utils.rand_name('netpart')
        netpart = {
            'net_partition': netpart_name
        }

        # Create net-partition
        netpart_body = self.client.create_netpartition(netpart_name)
        self.addCleanup(self.client.delete_netpartition,
                        netpart_body['net_partition']['id'])

        # Create router in that net-partition
        rtr_body = self.routers_client.create_router(
            data_utils.rand_name('router'), admin_state_up=True, **netpart)
        self.addCleanup(self._delete_router, rtr_body['router']['id'])

        # Verify Router is created in correct net-partition
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=rtr_body['router']['id'],
            netpart_name=netpart_name)
        self.assertEqual(rtr_body['router']['name'], nuage_domain[0][
            'description'])
        self.assertEqual(netpart_body['net_partition']['id'],
                         nuage_domain[0]['parentID'])

    @test.attr(type='smoke')
    def test_router_create_with_rt_rd(self):
        # Create a router with specific rt/rd values
        rtrd = {
            'rt': '64435:' + str(randint(0, 1000)),
            'rd': '64435:' + str(randint(0, 1000)),
        }
        create_body = self.routers_client.create_router(
            data_utils.rand_name('router'), admin_state_up=True, **rtrd)
        self.addCleanup(self._delete_router, create_body['router']['id'])

        # Verify router is created in VSD with correct rt/rd values
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['name'], nuage_domain[0][
            'description'])
        self.assertEqual(rtrd['rd'], nuage_domain[0]['routeDistinguisher'])
        self.assertEqual(rtrd['rt'], nuage_domain[0]['routeTarget'])

    @test.attr(type='smoke')
    def test_router_update_rt_rd(self):
        # Create a router
        create_body = self.routers_client.create_router(
            data_utils.rand_name('router'), external_gateway_info=None,
            admin_state_up=True)
        self.addCleanup(self._delete_router, create_body['router']['id'])

        # Verify router is created in VSD
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['name'],
                         nuage_domain[0]['description'])

        # Update rt/rd
        rt = '64435:' + str(randint(0, 1000))
        rd = '64435:' + str(randint(0, 1000))
        self.client.update_router_rdrt(create_body['router']['id'],
                                       rt=rt, rd=rd)

        # Get the domain from VSD and verify that rt/rd are updated
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(rd, nuage_domain[0]['routeDistinguisher'])
        self.assertEqual(rt, nuage_domain[0]['routeTarget'])

    @test.attr(type='smoke')
    def test_router_update_no_rt_rd(self):
        # Create a router
        create_body = self.routers_client.create_router(
            data_utils.rand_name('router'), external_gateway_info=None,
            admin_state_up=True)
        self.addCleanup(self._delete_router, create_body['router']['id'])

        # Verify router is created in VSD
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['name'],
                         nuage_domain[0]['description'])

        update_dict = dict()
        self.routers_client.update_router(create_body['router']['id'], **update_dict)

        # Get the domain from VSD and verify that rt/rd is not updated
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['rd'],
                         nuage_domain[0]['routeDistinguisher'])
        self.assertEqual(create_body['router']['rt'],
                         nuage_domain[0]['routeTarget'])

    @test.attr(type='smoke')
    def test_router_update_rt(self):
        # Create a router
        create_body = self.routers_client.create_router(
            data_utils.rand_name('router'), external_gateway_info=None,
            admin_state_up=True)
        self.addCleanup(self._delete_router, create_body['router']['id'])

        # Verify router is created in VSD
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['name'],
                         nuage_domain[0]['description'])

        # Update rt
        rt = '64435:' + str(randint(0, 1000))
        self.client.update_router_rdrt(create_body['router']['id'], rt=rt)

        # Get the domain from VSD and verify that rt is updated
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(rt, nuage_domain[0]['routeTarget'])

    @test.attr(type='smoke')
    def test_router_update_rd(self):
        # Create a router
        create_body = self.routers_client.create_router(
            data_utils.rand_name('router'), external_gateway_info=None,
            admin_state_up=True)
        self.addCleanup(self._delete_router, create_body['router']['id'])

        # Verify router is created in VSD
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['name'],
                         nuage_domain[0]['description'])

        # Update rd

        rd = '64435:' + str(randint(0, 1000))

        self.client.update_router_rdrt(create_body['router']['id'], rd=rd)

        # Get the domain from VSD and verify that rd is updated
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(rd, nuage_domain[0]['routeDistinguisher'])

    @test.attr(type='smoke')
    def test_add_router_interface_shared_network(self):
        # Create a shared network
        network = {
            'name': data_utils.rand_name('network'),
            'shared': True
        }
        net_body = self.admin_networks_client.create_network(**network)
        self.addCleanup(self.admin_networks_client.delete_network,
                        net_body['network']['id'])
        subnet = {
            'network_id': net_body['network']['id'],
            'cidr': '21.21.21.0/24',
            'name': data_utils.rand_name('subnet'),
            'ip_version': 4
        }
        subn_body = self.admin_subnets_client.create_subnet(**subnet)
        self.addCleanup(self.admin_subnets_client.delete_subnet,
                        subn_body['subnet']['id'])

        # Add router interface with subnet id
        router = {
            'name': data_utils.rand_name('router'),
            'admin_state_up': True
        }

        rtr_body = self.admin_routers_client.create_router(**router)
        self.addCleanup(self.admin_routers_client.delete_router,
                        rtr_body['router']['id'])

        # Verify Router is created in VSD
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=rtr_body['router']['id'])
        self.assertEqual(nuage_domain[0]['description'],
                         rtr_body['router']['name'])

        self.admin_routers_client.add_router_interface(
            rtr_body['router']['id'],
            subnet_id=subn_body['subnet']['id'])

        # Verify that the subnet is attached to public zone in VSD
        nuage_zones = self.nuage_vsd_client.get_zone(nuage_domain[0]['ID'])
        shared_zone_id = None
        for zone in nuage_zones:
            if '-pub-' in zone['name']:
                shared_zone_id = zone['ID']

        nuage_domain_subn = self.nuage_vsd_client.get_domain_subnet(
            n_constants.ZONE, shared_zone_id,
            filters='externalID', filter_value=subn_body['subnet']['id'])
        self.assertIsNotNone(nuage_domain_subn[0])

        # Delete the router interface
        self.admin_routers_client.remove_router_interface(
            rtr_body['router']['id'],
            subnet_id=subn_body['subnet']['id'])

        # Verify that the subnet is created with everybody permissions
        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID', filter_value=subn_body['subnet']['id'])
        nuage_perm = self.nuage_vsd_client.get_permissions(
            n_constants.L2_DOMAIN, nuage_l2dom[0]['ID'], filters='name',
            filter_value='Everybody')
        self.assertIsNotNone(nuage_perm[0])

    def _delete_extra_routes(self, router_id):
        self.routers_client.delete_extra_routes(router_id)

    @test.requires_ext(extension='ext-gw-mode', service='network')
    @test.attr(type='smoke')
    def test_create_router_with_default_snat_value(self):
        (super(RoutersTestNuage, self).
         test_create_router_with_default_snat_value())
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=self.routers[-1]['id'])
        self.assertEqual(nuage_domain[0]['PATEnabled'], NUAGE_PAT_DISABLED)

    @test.requires_ext(extension='ext-gw-mode', service='network')
    @test.attr(type='smoke')
    def test_create_router_with_snat_explicit(self):
        name = data_utils.rand_name('snat-router')
        # Create a router enabling snat attributes
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            external_gateway_info = {
                'network_id': CONF.network.public_network_id,
                'enable_snat': enable_snat}
            create_body = self.admin_routers_client.create_router(
                name, external_gateway_info=external_gateway_info)
            self.addCleanup(self.admin_routers_client.delete_router,
                            create_body['router']['id'])
            # Verify snat attributes after router creation
            self._verify_router_gateway(create_body['router']['id'],
                                        exp_ext_gw_info=external_gateway_info)
            nuage_domain = self.nuage_vsd_client.get_l3domain(
                filters='externalID',
                filter_value=create_body['router']['id'])
            self.assertEqual(
                nuage_domain[0]['PATEnabled'],
                NUAGE_PAT_ENABLED if enable_snat else NUAGE_PAT_DISABLED)

    @test.requires_ext(extension='ext-gw-mode', service='network')
    @test.attr(type='smoke')
    def test_update_router_set_gateway_with_snat_explicit(self):
        super(RoutersTestNuage,
              self).test_update_router_set_gateway_with_snat_explicit()
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=self.routers[-1]['id'])
        self.assertEqual(nuage_domain[0]['PATEnabled'], NUAGE_PAT_ENABLED)

    @test.requires_ext(extension='ext-gw-mode', service='network')
    @test.attr(type='smoke')
    def test_update_router_set_gateway_without_snat(self):
        super(RoutersTestNuage,
              self).test_update_router_set_gateway_without_snat()
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=self.routers[-1]['id'])
        self.assertEqual(nuage_domain[0]['PATEnabled'], NUAGE_PAT_DISABLED)

    @test.requires_ext(extension='ext-gw-mode', service='network')
    @test.attr(type='smoke')
    def test_update_router_reset_gateway_without_snat(self):
        router = self._create_router(
            data_utils.rand_name('router-'),
            external_network_id=CONF.network.public_network_id)
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=router['id'])
        self.assertEqual(nuage_domain[0]['PATEnabled'], NUAGE_PAT_DISABLED)
        self.admin_routers_client.update_router_with_snat_gw_info(
            router['id'],
            external_gateway_info={
                'network_id': CONF.network.public_network_id,
                'enable_snat': False})
        self._verify_router_gateway(
            router['id'],
            {'network_id': CONF.network.public_network_id,
             'enable_snat': False})
        self._verify_gateway_port(router['id'])
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=router['id'])
        self.assertEqual(nuage_domain[0]['PATEnabled'], NUAGE_PAT_DISABLED)

    # TODO: waelj: submit an upstream pull request on tempest.services.network.json.network_client to process
    # all attributes in kwargs (to support extended attribute updates)

    # overrule the parent class in order to allow update of tunnel_type
    def _patch_update_router(self, router_id, set_enable_snat, **kwargs):
        uri = '/routers/%s' % router_id
        body = self.admin_client.show_resource(uri)

        # patch for tunnel_type, and backhaul-attributes
        update_body = {'name': kwargs.get('name', body['router']['name']), 'admin_state_up': kwargs.get(
            'admin_state_up', body['router']['admin_state_up']),
                       'tunnel_type': kwargs.get('tunnel_type', body['router']['tunnel_type']),
                       'nuage_backhaul_vnid': kwargs.get('nuage_backhaul_vnid', body['router']['nuage_backhaul_vnid']),
                       'nuage_backhaul_rt': kwargs.get('nuage_backhaul_rt', body['router']['nuage_backhaul_rt']),
                       'nuage_backhaul_rd': kwargs.get('nuage_backhaul_rd', body['router']['nuage_backhaul_rd'])
        }
        # end of patch for tunnel_type

        cur_gw_info = body['router']['external_gateway_info']
        if cur_gw_info:
            # TODO(kevinbenton): setting the external gateway info is not
            # allowed for a regular tenant. If the ability to update is also
            # merged, a test case for this will need to be added similar to
            # the SNAT case.
            cur_gw_info.pop('external_fixed_ips', None)
            if not set_enable_snat:
                cur_gw_info.pop('enable_snat', None)
        update_body['external_gateway_info'] = kwargs.get(
            'external_gateway_info', body['router']['external_gateway_info'])
        if 'distributed' in kwargs:
            update_body['distributed'] = kwargs['distributed']
        update_body = dict(router=update_body)
        return self.admin_client.update_resource(uri, update_body)

    def patch_update_router(self, router_id, **kwargs):
        """Update a router leaving enable_snat to its default value."""
        # If external_gateway_info contains enable_snat the request will fail
        # with 404 unless executed with admin client, and therefore we instruct
        # _update_router to not set this attribute
        # NOTE(salv-orlando): The above applies as long as Neutron's default
        # policy is to restrict enable_snat usage to admins only.
        return self._patch_update_router(router_id, set_enable_snat=False, **kwargs)

    # end of overruled messages

    @test.attr(type='smoke')
    def test_router_create_update_show_delete_with_backhaul_vnid_rt_rd(self):
        name = data_utils.rand_name('router-')
        bkhaul_vnid = lib_data_utils.rand_int_id()
        bkhaul_rt = "1:1"
        bkhaul_rd = "2:2"
        create_body = self.admin_routers_client.create_router(
            name, nuage_backhaul_vnid=str(bkhaul_vnid),
            nuage_backhaul_rt=bkhaul_rt,
            nuage_backhaul_rd=bkhaul_rd,
            tunnel_type="VXLAN")
        self.addCleanup(self._delete_router, create_body['router']['id'], routers_client=self.admin_routers_client)
        self.assertEqual(create_body['router']['name'], name)
        self.assertEqual(create_body['router']['nuage_backhaul_vnid'],
                         bkhaul_vnid)
        self.assertEqual(create_body['router']['nuage_backhaul_rt'],
                         bkhaul_rt)
        self.assertEqual(create_body['router']['nuage_backhaul_rd'],
                         bkhaul_rd)
        # VSD validation
        rtr_id = create_body['router']['id']
        l3dom_ext_id = self.nuage_vsd_client.get_vsd_external_id(
            rtr_id)
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=l3dom_ext_id)
        self.assertEqual(nuage_domain[0][u'description'], name)
        self.assertEqual(nuage_domain[0][u'backHaulVNID'], bkhaul_vnid)
        self.assertEqual(nuage_domain[0][u'backHaulRouteTarget'], bkhaul_rt)
        self.assertEqual(nuage_domain[0][u'backHaulRouteDistinguisher'],
                         bkhaul_rd)
        # Show details of the created router
        show_body = self.admin_routers_client.show_router(create_body['router']['id'])
        self.assertEqual(show_body['router']['name'], name)
        self.assertEqual(show_body['router']['nuage_backhaul_vnid'],
                         bkhaul_vnid)
        self.assertEqual(show_body['router']['nuage_backhaul_rt'], bkhaul_rt)
        self.assertEqual(show_body['router']['nuage_backhaul_rd'], bkhaul_rd)

        # Update the backhaul rt:rd to new values
        updated_bkhaul_vnid = lib_data_utils.rand_int_id()
        updated_bkhaul_rt = "3:3"
        updated_bkhaul_rd = "4:4"
        update_body = self.patch_update_router(create_body['router']['id'],
                                               nuage_backhaul_vnid=str(updated_bkhaul_vnid),
                                               nuage_backhaul_rt=updated_bkhaul_rt,
                                               nuage_backhaul_rd=updated_bkhaul_rd)
        show_body = self.admin_routers_client.show_router(create_body['router']['id'])
        self.assertEqual(show_body['router']['nuage_backhaul_vnid'],
                         updated_bkhaul_vnid)
        self.assertEqual(show_body['router']['nuage_backhaul_rt'],
                         updated_bkhaul_rt)
        self.assertEqual(show_body['router']['nuage_backhaul_rd'],
                         updated_bkhaul_rd)
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=l3dom_ext_id)
        self.assertEqual(nuage_domain[0][u'backHaulVNID'],
                         updated_bkhaul_vnid)
        self.assertEqual(nuage_domain[0][u'backHaulRouteTarget'],
                         updated_bkhaul_rt)
        self.assertEqual(nuage_domain[0][u'backHaulRouteDistinguisher'],
                         updated_bkhaul_rd)


    def test_router_backhaul_vnid_rt_rd_negative(self):
        # Incorrect backhaul-vnid value
        self.assertRaises(exceptions.ServerFault,
                          self.routers_client.create_router,
                          data_utils.rand_name('router-'),
                          nuage_backhaul_vnid="0xb")
        self.assertRaises(exceptions.ServerFault,
                          self.routers_client.create_router,
                          data_utils.rand_name('router-'),
                          nuage_backhaul_rt="-1:1")
        self.assertRaises(exceptions.ServerFault,
                          self.routers_client.create_router,
                          data_utils.rand_name('router-'),
                          nuage_backhaul_rd="2:-3")

