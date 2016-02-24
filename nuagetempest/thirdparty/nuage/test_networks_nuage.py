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

import netaddr
from nuagetempest.lib.utils import constants as n_constants
from nuagetempest.services.nuage_client import NuageRestClient
from tempest.api.network import base
from tempest.api.network import test_networks
from tempest.common.utils import data_utils
from tempest import config
from tempest import test
from tempest_lib import exceptions


CONF = config.CONF


class NetworksTestJSONNuage(test_networks.NetworksTest):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(NetworksTestJSONNuage, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(NetworksTestJSONNuage, cls).resource_setup()

    def convert_dec_hex(self, ip_address):
        ip_address_hex = "0x" + \
            "".join([(hex(int(x))[2:].zfill(2))
                     for x in ip_address.split('.')])
        return ip_address_hex

    def _verify_vsd_dhcp_options(self, nuage_dhcpopt, subnet):
        # VSD validation
        if subnet.get('gateway_ip', None):
            #  Verify L2Domain dhcp options are set on VSD
            self.assertEqual(self.convert_dec_hex(
                subnet['gateway_ip'])[2:], nuage_dhcpopt[0]['value'])
            self.assertEqual(nuage_dhcpopt[0]['type'], "03")
        if subnet.get('dns_nameservers'):
            self.assertEqual(nuage_dhcpopt[1]['type'],
                             "06")
            dns1 = self.convert_dec_hex(subnet['dns_nameservers'][0])[2:]
            dns2 = self.convert_dec_hex(subnet['dns_nameservers'][1])[2:]
            dhcp_dns = [nuage_dhcpopt[1]['value'][
                0:8], nuage_dhcpopt[1]['value'][8:]]
            status = False
            if (dns1 in dhcp_dns and dns2 in dhcp_dns):
                status = True
            self.assertTrue(
                status, "subnet dns_nameservers do not match dhcp options")

            self.assertEqual(nuage_dhcpopt[2]['type'],
                             "79")
        if subnet.get('host_routes'):
            self.assertEqual(
                self.convert_dec_hex(
                    subnet['host_routes'][0]['nexthop'])[2:],
                nuage_dhcpopt[2]['value'][-8:])

    def _create_verify_delete_subnet(self, cidr=None, mask_bits=None,
                                     **kwargs):
        network = self.create_network()
        net_id = network['id']
        gateway = kwargs.pop('gateway', None)
        subnet = self.create_subnet(network, gateway, cidr, mask_bits,
                                    **kwargs)
        compare_args_full = dict(gateway_ip=gateway, cidr=cidr,
                                 mask_bits=mask_bits, **kwargs)
        compare_args = dict((k, v) for k, v in compare_args_full.iteritems()
                            if v is not None)

        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID', filter_value=subnet['id'])
        nuage_dhcpopt = self.nuage_vsd_client.get_dhcpoption(
            n_constants.L2_DOMAIN, nuage_l2dom[0]['ID'])

        if 'dns_nameservers' in set(subnet).intersection(compare_args):
            self.assertEqual(sorted(compare_args['dns_nameservers']),
                             sorted(subnet['dns_nameservers']))
            del subnet['dns_nameservers'], compare_args['dns_nameservers']
        # VSD validation
        self._verify_vsd_dhcp_options(nuage_dhcpopt, subnet)
        self._compare_resource_attrs(subnet, compare_args)
        self.networks_client.delete_network(net_id)
        self.networks.pop()
        self.subnets.pop()

    @test.attr(type='smoke')
    def test_create_update_delete_network_subnet(self):
        super(NetworksTestJSONNuage,
              self).test_create_update_delete_network_subnet()
        # VSD validation
        # Validate that an L2Domain is created on VSD for the subnet creation
        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID', filter_value=self.subnets[-1]['id'])

        self.assertEqual(nuage_l2dom[0]['name'], self.subnets[-1]['id'])

    @test.attr(type='smoke')
    def test_delete_network_with_subnet(self):
        # Creates a network
        name = data_utils.rand_name('network-')
        body = self.networks_client.create_network(name=name)
        network = body['network']
        net_id = network['id']
        self.addCleanup(self._try_delete_network, net_id)
        # Find a cidr that is not in use yet and create a subnet with it
        subnet = self.create_subnet(network)
        subnet_id = subnet['id']
        # VSD validation
        # Validate that an L2Domain is created on VSD for the subnet creation
        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID', filter_value=subnet['id'])

        self.assertEqual(nuage_l2dom[0]['name'], subnet['id'])

        # Delete network while the subnet still exists
        body = self.networks_client.delete_network(net_id)

        # Verify that the subnet got automatically deleted.
        self.assertRaises(exceptions.NotFound, self.subnets_client.show_subnet,
                          subnet_id)

        # VSD validation
        # Validate that an L2Domain is deleted on VSD for the subnet creation
        nuage_dell2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID',
            filter_value=subnet['id'])

        self.assertEqual(nuage_dell2dom, '')

        # Since create_subnet adds the subnet to the delete list, and it is
        # is actually deleted here - this will create and issue, hence remove
        # it from the list.
        self.subnets.pop()

    @test.attr(type='smoke')
    def test_create_delete_subnet_with_gw(self):
        self._create_verify_delete_subnet(
            **self.subnet_dict(['gateway']))

    @test.attr(type='smoke')
    def test_create_delete_subnet_with_gw_and_allocation_pools(self):
        self._create_verify_delete_subnet(**self.subnet_dict(
            ['gateway', 'allocation_pools']))

    @test.attr(type='smoke')
    def test_create_delete_subnet_with_host_routes_and_dns_nameservers(self):
        self._create_verify_delete_subnet(
            **self.subnet_dict(['host_routes', 'dns_nameservers']))

    @test.attr(type='smoke')
    def test_update_subnet_gw_dns_host_routes_dhcp(self):
        network = self.create_network()
        subnet = self.create_subnet(
            network, **self.subnet_dict(['gateway', 'host_routes',
                                         'dns_nameservers',
                                         'allocation_pools']))
        subnet_id = subnet['id']
        # VSD validation; validate l2dom in vsd is created with the correct
        # dhcp options
        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID', filter_value=subnet['id'])
        nuage_dhcpopt = self.nuage_vsd_client.get_dhcpoption(
            n_constants.L2_DOMAIN, nuage_l2dom[0]['ID'])
        self._verify_vsd_dhcp_options(nuage_dhcpopt, subnet)

        new_gateway = str(netaddr.IPAddress(
                          self._subnet_data[self._ip_version]['gateway']) + 1)
        # Verify subnet update
        new_host_routes = self._subnet_data[self._ip_version][
            'new_host_routes']

        new_dns_nameservers = self._subnet_data[self._ip_version][
            'new_dns_nameservers']
        kwargs = {'host_routes': new_host_routes,
                  'dns_nameservers': new_dns_nameservers,
                  'gateway_ip': new_gateway, 'enable_dhcp': True}

        new_name = "New_subnet"
        body = self.subnets_client.update_subnet(subnet_id, name=new_name,
                                                 **kwargs)
        updated_subnet = body['subnet']
        kwargs['name'] = new_name

        # VSD validation check params got updated in VSD
        update_dhcpopt = self.nuage_vsd_client.get_dhcpoption(
            n_constants.L2_DOMAIN, nuage_l2dom[0]['ID'])
        self._verify_vsd_dhcp_options(update_dhcpopt, updated_subnet)

        self.assertEqual(sorted(updated_subnet['dns_nameservers']),
                         sorted(kwargs['dns_nameservers']))
        del subnet['dns_nameservers'], kwargs['dns_nameservers']

    @test.attr(type='smoke')
    def test_create_delete_subnet_all_attributes(self):
        self._create_verify_delete_subnet(
            enable_dhcp=True,
            **self.subnet_dict(['gateway', 'host_routes', 'dns_nameservers']))


class NetworkNuageAdminTest(base.BaseAdminNetworkTest):
    @classmethod
    def setup_clients(cls):
        super(NetworkNuageAdminTest, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()

    def _create_network(self, external=True):
        post_body = {'name': data_utils.rand_name('network-')}
        if external:
            post_body['router:external'] = external
        body = self.admin_networks_client.create_network(**post_body)
        network = body['network']
        self.addCleanup(
            self.admin_networks_client.delete_network, network['id'])
        return network

    def test_create_delete_external_subnet_with_underlay(self):
        subname = 'underlay-subnet'
        ext_network = self._create_network()
        body = self.admin_subnets_client.create_subnet(
            network_id=ext_network['id'],
            cidr='135.20.0.0/24',
            ip_version=self._ip_version,
            name=subname, underlay=True)
        subnet = body['subnet']
        self.assertEqual(subnet['name'], subname)
        # TODO - Add VSD check here
        nuage_fippool = self.nuage_vsd_client.get_sharedresource(
            filters='externalID', filter_value=subnet['id'])
        self.assertEqual(nuage_fippool[0]['underlay'], True)
        self.admin_subnets_client.delete_subnet(subnet['id'])
        nuage_fippool = self.nuage_vsd_client.get_sharedresource(
            filters='externalID', filter_value=subnet['id'])
        self.assertEqual(nuage_fippool, '')

    def test_create_delete_external_subnet_without_underlay(self):
        subname = 'non-underlay-subnet'
        ext_network = self._create_network()
        body = self.admin_subnets_client.create_subnet(
            network_id=ext_network['id'],
            cidr='135.30.0.0/24',
            ip_version=self._ip_version,
            name=subname, underlay=False)
        subnet = body['subnet']
        self.assertEqual(subnet['name'], subname)
        # TODO - Add VSD check here
        # TODO - Add VSD check here
        nuage_fippool = self.nuage_vsd_client.get_sharedresource(
            filters='externalID', filter_value=subnet['id'])
        self.assertEqual(nuage_fippool[0]['underlay'], False)
        self.admin_subnets_client.delete_subnet(subnet['id'])
        nuage_fippool = self.nuage_vsd_client.get_sharedresource(
            filters='externalID', filter_value=subnet['id'])
        self.assertEqual(nuage_fippool, '')
