# Copyright 2016 Nokia
# All Rights Reserved.

from collections import namedtuple

from enum import Enum
from netaddr import IPNetwork
from tempest.common.utils import data_utils
from tempest.api.network import base
from tempest import test
from tempest import config
from nuagetempest.lib.test import nuage_test
from nuagetempest.tests import nuage_ext
from nuagetempest.lib import topology
from nuagetempest.lib.openstackData import openstackData
from nuagetempest.services.nuage_client import NuageRestClient


CONF = config.CONF


# Enum for the IP MAC anti spoofing or VIP creation actions
class Action(Enum):
    spoofing = 1
    vip = 2
    no_vip = 3


class IpAntiSpoofingTestBase(base.BaseNetworkTest):
    @classmethod
    def resource_setup(cls):
        super(IpAntiSpoofingTestBase, cls).resource_setup()
        cls.TB = topology.initialize_topology()
        topology.open_session(cls.TB)
        cls.def_net_partition = CONF.nuage.nuage_default_netpartition
        cls.os_data = openstackData()
        cls.os_data.insert_resource(cls.def_net_partition, parent='CMS',
                                    os_data={'name': cls.def_net_partition})

        cls.vip_action = Action
        cls.vip_param = namedtuple("VIP_Params",
                                   ["full_cidr", "diff_mac", "same_ip", "same_subn"])
        cls.vip_action_map = {}
        cls._populate_vip_action_map()
        cls.cur_vip_param = None

    @classmethod
    def resource_cleanup(cls):
        cls.os_data.delete_resource(cls.def_net_partition)

    @classmethod
    def setup_clients(cls):
        super(IpAntiSpoofingTestBase, cls).setup_clients()
        cls.nuageclient = NuageRestClient()

    @classmethod
    def _create_security_disabled_network(cls):
        kwargs = {'name': data_utils.rand_name('network-'),
                  'port_security_enabled': 'False'}
        body = cls.networks_client.create_network(**kwargs)
        return body['network']

    @classmethod
    def _create_subnet(cls, ntw, name=None, cidr=None):
        if cidr is None:
            cidr = '30.30.30.0/24'
        if name is None:
            name = data_utils.rand_name('subnet-')
        kwargs = {'name': name,
                  'network_id': ntw['id'],
                  'ip_version': 4,
                  'cidr': cidr}
        body = cls.subnets_client.create_subnet(**kwargs)
        return body['subnet']

    @classmethod
    def _create_security_disabled_port(cls, **kwargs):
        kwargs.update({'port_security_enabled': 'False'})
        body = cls.ports_client.create_port(**kwargs)
        return body['port']

    @classmethod
    def _populate_vip_action_map(cls):
        cls.vip_action_map.update({cls.vip_param('0', '0', '0', '0'): cls.vip_action.spoofing,
                                   cls.vip_param('0', '0', '0', '1'): cls.vip_action.spoofing,
                                   cls.vip_param('0', '0', '1', '1'): cls.vip_action.spoofing,
                                   cls.vip_param('0', '1', '0', '0'): cls.vip_action.spoofing,
                                   cls.vip_param('0', '1', '0', '1'): cls.vip_action.spoofing,
                                   cls.vip_param('0', '1', '1', '1'): cls.vip_action.spoofing,
                                   cls.vip_param('1', '0', '0', '0'): cls.vip_action.no_vip,
                                   cls.vip_param('1', '0', '0', '1'): cls.vip_action.vip,
                                   cls.vip_param('1', '0', '1', '1'): cls.vip_action.no_vip,
                                   cls.vip_param('1', '1', '0', '0'): cls.vip_action.spoofing,
                                   cls.vip_param('1', '1', '0', '1'): cls.vip_action.vip,
                                   cls.vip_param('1', '1', '1', '1'): cls.vip_action.spoofing})

    def _create_network_port_l2resources(self, ntw_security='True',
                                         port_security='True',
                                         port_name='port-1',
                                         l2domain_name='l2domain-1',
                                         netpart=None,
                                         allowed_address_pairs=None):
        # Method to create ntw, port and l2domain
        if netpart is None:
            netpart = self.def_net_partition
        if ntw_security == 'False':
            network = self._create_security_disabled_network()
        else:
            body = self.networks_client.create_network(
                name=data_utils.rand_name('network-'))
            network = body['network']
        self.addCleanup(self.networks_client.delete_network, network['id'])
        l2domain = self._create_subnet(network, name=l2domain_name)
        self.os_data.insert_resource(l2domain_name, netpart, os_data=l2domain)
        self.addCleanup(self.subnets_client.delete_subnet, l2domain['id'])
        # Populate the data dict required for port creation
        kwargs = {'name': port_name, 'network_id': network['id']}
        if allowed_address_pairs:
            kwargs.update({'allowed_address_pairs': allowed_address_pairs})
        if port_security == 'False':
            port = self._create_security_disabled_port(**kwargs)
        else:
            body = self.ports_client.create_port(**kwargs)
            port = body['port']
        self.os_data.insert_resource(port_name, l2domain_name, os_data=port)
        self.addCleanup(self.ports_client.delete_port, port['id'])
        self.addCleanup(self.os_data.delete_resource, l2domain_name)
        return network, l2domain, port

    def _create_network_port_l3resources(self, ntw_security='True',
                                         port_security='True',
                                         router_name='router-1',
                                         subnet_name='subnet-1',
                                         port_name='port-1',
                                         netpart=None,
                                         allowed_address_pairs=None):
        # Method to create ntw, router, subnet and port
        if netpart is None:
            netpart = self.def_net_partition
        if ntw_security == 'False':
            network = self._create_security_disabled_network()
        else:
            body = self.networks_client.create_network(
                name=data_utils.rand_name('network-'))
            network = body['network']
        self.addCleanup(self.networks_client.delete_network, network['id'])

        body = self.routers_client.create_router(name=router_name)
        router = body['router']
        self.os_data.insert_resource(router_name, netpart, os_data=router)
        self.addCleanup(self.routers_client.delete_router, router['id'])

        subnet = self._create_subnet(network, name=subnet_name)
        self.os_data.insert_resource(subnet_name, router_name, os_data=subnet)
        self.addCleanup(self.subnets_client.delete_subnet, subnet['id'])

        self.routers_client.add_router_interface(router['id'],
                                                 subnet_id=subnet['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        router['id'], subnet_id=subnet['id'])
        kwargs = {'name': port_name, 'network_id': network['id']}
        if allowed_address_pairs:
            kwargs.update({'allowed_address_pairs': allowed_address_pairs})
        if port_security == 'False':
            port = self._create_security_disabled_port(**kwargs)
        else:
            body = self.ports_client.create_port(**kwargs)
            port = body['port']
        self.os_data.insert_resource(port_name, subnet_name, os_data=port)
        self.addCleanup(self.ports_client.delete_port, port['id'])
        self.addCleanup(self.os_data.delete_resource, router_name)
        return network, router, subnet, port

    def _create_vsd_managed_l2resources(self, ntw_security='True',
                                        port_security='True',
                                        port_name='port-1',
                                        l2domain_name='l2domain-1',
                                        netpart=None,
                                        allowed_address_pairs=None):
        # Method to create VSD managed l3domain subnet. The ntw and port
        # are also created.
        if netpart is None:
            netpart = self.def_net_partition
        if ntw_security == 'False':
            network = self._create_security_disabled_network()
        else:
            body = self.networks_client.create_network(
                name=data_utils.rand_name('network-'))
            network = body['network']
        self.addCleanup(self.networks_client.delete_network, network['id'])
        # Create VSD Mananged l2domain subnet
        cidr = IPNetwork('40.40.40.0/24')
        cidr_ip = '40.40.40.0'
        cidr_mask = '255.255.255.0'
        gateway = '40.40.40.1'
        params = {
            'DHCPManaged': True,
            'address': cidr_ip,
            'netmask': cidr_mask,
            'gateway': gateway
        }
        l2dom_temp_name = data_utils.rand_name('l2dom-template-')
        vsd_l2dom_tmplt = self.nuageclient.create_l2domaintemplate(
            name=l2dom_temp_name, extra_params=params)
        self.addCleanup(self.nuageclient.delete_l2domaintemplate,
                        vsd_l2dom_tmplt[0]['ID'])
        vsd_l2dom = self.nuageclient.create_l2domain(name=l2domain_name,
                                                     templateId=vsd_l2dom_tmplt[0]['ID'])
        self.addCleanup(self.nuageclient.delete_l2domain, vsd_l2dom[0]['ID'])
        l2domain = self.create_subnet(
            network, cidr=cidr,
            mask_bits=24, gateway=None,
            nuagenet=vsd_l2dom[0]['ID'],
            net_partition=netpart)
        self.os_data.insert_resource(l2domain_name, netpart,
                                     os_data=l2domain, vsd_data=vsd_l2dom[0])
        self.addCleanup(self.subnets_client.delete_subnet, l2domain['id'])

        kwargs = {'name': port_name, 'network_id': network['id']}
        if allowed_address_pairs:
            kwargs.update({'allowed_address_pairs': allowed_address_pairs})
        if port_security == 'False':
            port = self._create_security_disabled_port(**kwargs)
        else:
            body = self.ports_client.create_port(**kwargs)
            port = body['port']
        self.os_data.insert_resource(port_name, l2domain_name, os_data=port)
        self.addCleanup(self.ports_client.delete_port, port['id'])
        self.addCleanup(self.os_data.delete_resource, l2domain_name)
        return network, l2domain, port

    def _create_vsd_managed_l3resources(self, ntw_security='True',
                                        port_security='True',
                                        router_name='router-1',
                                        subnet_name='subnet-1',
                                        port_name='port-1',
                                        netpart=None,
                                        allowed_address_pairs=None):
        # Method to create VSD managed l3domain subnet. The ntw and port
        # are also created.
        if netpart is None:
            netpart = self.def_net_partition
        if ntw_security == 'False':
            network = self._create_security_disabled_network()
        else:
            body = self.networks_client.create_network(
                name=data_utils.rand_name('network-'))
            network = body['network']
        self.addCleanup(self.networks_client.delete_network, network['id'])

        # Create VSD Mananged l3domain subnet
        router_temp_name = data_utils.rand_name('l3dom-template-')
        vsd_l3dom_tmplt = self.nuageclient.create_l3domaintemplate(
            router_temp_name)
        self.addCleanup(self.nuageclient.delete_l3domaintemplate,
                        vsd_l3dom_tmplt[0]['ID'])
        vsd_l3dom = self.nuageclient.create_domain(name=router_name,
                                                   templateId=vsd_l3dom_tmplt[0]['ID'])
        # create dummy place holder for VSD l3domain in os_data
        self.os_data.insert_resource(router_name, netpart, vsd_data=vsd_l3dom)
        self.addCleanup(self.nuageclient.delete_domain, vsd_l3dom[0]['ID'])
        zonename = data_utils.rand_name('l3dom-zone-')
        vsd_zone = self.nuageclient.create_zone(name=zonename,
                                                parent_id=vsd_l3dom[0]['ID'])
        cidr = IPNetwork('40.40.40.0/24')
        cidr_ip = '40.40.40.0'
        cidr_mask = '255.255.255.0'
        vsd_subnet = self.nuageclient.create_domain_subnet(
            parent_id=vsd_zone[0]['ID'],
            name=subnet_name,
            net_address=cidr_ip,
            netmask=cidr_mask,
            gateway='40.40.40.1')
        self.addCleanup(self.nuageclient.delete_domain_subnet,
                        vsd_subnet[0]['ID'])
        subnet = self.create_subnet(network,
                                    cidr=cidr,
                                    mask_bits=24,
                                    nuagenet=vsd_subnet[0]['ID'],
                                    net_partition=netpart)
        self.os_data.insert_resource(subnet_name, router_name,
                                     os_data=subnet, vsd_data=vsd_subnet[0])
        self.addCleanup(self.subnets_client.delete_subnet, subnet['id'])

        kwargs = {'name': port_name, 'network_id': network['id']}
        if allowed_address_pairs:
            kwargs.update({'allowed_address_pairs': allowed_address_pairs})
        if port_security == 'False':
            port = self._create_security_disabled_port(**kwargs)
        else:
            body = self.ports_client.create_port(**kwargs)
            port = body['port']
        self.os_data.insert_resource(port_name, subnet_name, os_data=port)
        self.addCleanup(self.ports_client.delete_port, port['id'])
        self.addCleanup(self.os_data.delete_resource, router_name)
        return network, subnet, port

    def get_vip_action(self, key):
        return self.vip_action_map.get(key)


class IpAntiSpoofingTest(IpAntiSpoofingTestBase):
    @nuage_test.header()
    def test_create_delete_sec_disabled_ntw_port_l2domain(self):
        # L2domain testcase to test network and port creation with
        # port-security-enabled set to False explicitly for both
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='False', port_security='False',
            l2domain_name='l2dom1-1',
            port_name='port1-1')
        self.assertEqual(network['port_security_enabled'], False)
        self.assertEqual(port['port_security_enabled'], False)
        tag_name = 'verify_security_disabled_port_l2domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_create_delete_sec_disabled_ntw_l2domain(self):
        # L2domain testcase to test network and port creation with
        # port-security-enabled set to False at network level only
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='False',
            l2domain_name='l2dom2-1',
            port_name='port2-1')
        self.assertEqual(network['port_security_enabled'], False)
        self.assertEqual(port['port_security_enabled'], False)
        tag_name = 'verify_security_disabled_port_l2domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_create_delete_sec_disabled_port_l2domain(self):
        # L2domain testcase to test network and port creation with
        # port-security-enabled set to False at port level only
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='False',
            l2domain_name='l2dom3-1',
            port_name='port3-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], False)
        tag_name = 'verify_security_disabled_port_l2domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_create_delete_sec_disabled_ntw_port_l3domain(self):
        # L3domain testcase to test the network and port creation with
        # port-security-enabled set to False explicitly for both
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='False',
            port_security='False',
            router_name='router4-1',
            subnet_name='subnet4-1',
            port_name='port4-1')
        self.assertEqual(network['port_security_enabled'], False)
        self.assertEqual(port['port_security_enabled'], False)
        tag_name = 'verify_security_disabled_port_l3domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_create_delete_sec_disabled_ntw_l3domain(self):
         # L3domain testcase to test the network and port creation with
         # port-security-enabled set to False explicitly for both
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='False',
            port_security='True',
            router_name='router5-1',
            subnet_name='subnet5-1',
            port_name='port5-1')
        self.assertEqual(network['port_security_enabled'], False)
        self.assertEqual(port['port_security_enabled'], False)
        tag_name = 'verify_security_disabled_port_l3domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_create_delete_sec_disabled_port_l3domain(self):
        # L3domain testcase to test the network and port creation with
        # port-security-enabled set to False explicitly for both
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='False',
            router_name='router6-1',
            subnet_name='subnet6-1',
            port_name='port6-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], False)
        tag_name = 'verify_security_disabled_port_l3domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_update_ntw_from_sec_disabled_to_enabled_l2domain(self):
        # L2domain testcase for updating the port-security-enabled flag
        # from False to True. Ports are created at both the states to check
        # if the network level security is correctly propogated.
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='False', port_security='True',
            l2domain_name='l2dom7-1',
            port_name='port7-1')
        self.assertEqual(network['port_security_enabled'], False)
        self.assertEqual(port['port_security_enabled'], False)
        tag_name = 'verify_security_disabled_port_l2domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)
        # Update the network and create a new port
        self.networks_client.update_network(network['id'],
                                            port_security_enabled='True')
        kwargs = {'name': 'port7-2', 'network_id': network['id']}
        body = self.ports_client.create_port(**kwargs)
        port_2 = body['port']
        self.addCleanup(self.ports_client.delete_port, port_2['id'])
        self.os_data.insert_resource(port_2['name'], 'l2dom7-1', os_data=port_2)
        tag_name = 'verify_security_enabled_port_l2domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_update_ntw_from_sec_enabled_to_disabled_l2domain(self):
        # L2domain testcase for updating the port-security-enabled flag
        # from True to False. Ports are created at both the states to check
        # if the network level security is correctly propogated.
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='True',
            l2domain_name='l2dom8-1',
            port_name='port8-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], True)
        tag_name = 'verify_security_enabled_port_l2domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)
        # Update the network and create a new port
        self.networks_client.update_network(network['id'],
                                            port_security_enabled='False')
        kwargs = {'name': 'port8-2', 'network_id': network['id']}
        body = self.ports_client.create_port(**kwargs)
        port_2 = body['port']
        self.addCleanup(self.ports_client.delete_port, port_2['id'])
        self.os_data.insert_resource(port_2['name'], 'l2dom8-1', os_data=port_2)
        tag_name = 'verify_security_disabled_port_l2domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_update_port_from_sec_disabled_to_enabled_l2domain(self):
        # L2domain testcase for updating the port-security-enabled flag
        # from False to True at port level. Network level flag set to
        # True by default
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='False',
            l2domain_name='l2dom9-1',
            port_name='port9-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], False)
        tag_name = 'verify_security_disabled_port_l2domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)
        # Update the port
        body = self.ports_client.update_port(port['id'],
                                             port_security_enabled='True')
        updated_port = body['port']
        self.os_data.update_resource(port['name'], os_data=updated_port)
        tag_name = 'verify_security_enabled_port_l2domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_update_port_from_sec_enabled_to_disabled_l2domain(self):
        # L2domain testcase for updating the port-security-enabled flag
        # from True to False at port level. Network level flag set to
        # True by default
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='True',
            l2domain_name='l2dom10-1',
            port_name='port10-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], True)
        tag_name = 'verify_security_enabled_port_l2domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)
        # Update the port
        self.ports_client.update_port(port['id'], security_groups=[])
        body = self.ports_client.update_port(port['id'],
                                             port_security_enabled='False')
        updated_port = body['port']
        self.os_data.update_resource(port['name'], os_data=updated_port)
        tag_name = 'verify_security_disabled_port_l2domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_update_ntw_from_sec_disabled_to_enabled_l3domain(self):
        # L3domain testcase for updating the port-security-enabled flag
        # from False to True. Ports are created at both the states to check
        # if the network level security is correctly propogated.
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='False',
            port_security='True',
            router_name='router11-1',
            subnet_name='subnet11-1',
            port_name='port11-1')
        self.assertEqual(network['port_security_enabled'], False)
        self.assertEqual(port['port_security_enabled'], False)
        tag_name = 'verify_security_disabled_port_l3domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)
        # Update the network and create a new port
        self.networks_client.update_network(network['id'],
                                            port_security_enabled='True')
        kwargs = {'name': 'port11-2', 'network_id': network['id']}
        body = self.ports_client.create_port(**kwargs)
        port_2 = body['port']
        self.addCleanup(self.ports_client.delete_port, port_2['id'])
        self.os_data.insert_resource(port_2['name'], 'subnet11-1', os_data=port_2)
        tag_name = 'verify_security_enabled_port_l3domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_update_ntw_from_sec_enabled_to_disabled_l3domain(self):
        # L3domain testcase for updating the port-security-enabled flag
        # from True to False. Ports are created at both the states to check
        # if the network level security is correctly propogated.
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router12-1',
            subnet_name='subnet12-1',
            port_name='port12-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], True)
        tag_name = 'verify_security_enabled_port_l3domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)
        # Update the network and create a new port
        self.networks_client.update_network(network['id'],
                                            port_security_enabled='False')
        kwargs = {'name': 'port12-2', 'network_id': network['id']}
        body = self.ports_client.create_port(**kwargs)
        port_2 = body['port']
        self.addCleanup(self.ports_client.delete_port, port_2['id'])
        self.os_data.insert_resource(port_2['name'], 'subnet12-1', os_data=port_2)
        tag_name = 'verify_security_disabled_port_l3domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_update_port_from_sec_disabled_to_enabled_l3domain(self):
        # L3domain testcase for updating the port-security-enabled flag
        # from False to True at port level. Network level flag set to
        # True by default
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='False',
            router_name='router13-1',
            subnet_name='subnet13-1',
            port_name='port13-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], False)
        tag_name = 'verify_security_disabled_port_l3domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)
        # Update the port
        body = self.ports_client.update_port(port['id'],
                                             port_security_enabled='True')
        updated_port = body['port']
        self.os_data.update_resource(port['name'], os_data=updated_port)
        tag_name = 'verify_security_enabled_port_l3domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_update_port_from_sec_enabled_to_disabled_l3domain(self):
        # L3domain testcase for updating the port-security-enabled flag
        # from True to False at port level. Network level flag set to
        # True by default
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router14-1',
            subnet_name='subnet14-1',
            port_name='port14-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], True)
        tag_name = 'verify_security_enabled_port_l3domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)
        # Update the port
        self.ports_client.update_port(port['id'], security_groups=[])
        body = self.ports_client.update_port(port['id'],
                                             port_security_enabled='False')
        updated_port = body['port']
        self.os_data.update_resource(port['name'], os_data=updated_port)
        tag_name = 'verify_security_disabled_port_l3domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_show_sec_disabled_ntw(self):
        pass

    @nuage_test.header()
    def test_show_sec_disabled_port(self):
        pass

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.0.0/24'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='True',
            l2domain_name='l2dom21-1',
            port_name='port21-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)
        pass

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, same subnet in
        # comparsion with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='True',
            l2domain_name='l2dom22-1',
            port_name='port22-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='True',
            l2domain_name='l2dom23-1',
            port_name='port23-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.0.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='True',
            l2domain_name='l2dom24-1',
            port_name='port24-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, same subnet in
        # comparsion with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='True',
            l2domain_name='l2dom25-1',
            port_name='port25-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='True',
            l2domain_name='l2dom26-1',
            port_name='port26-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.20.100'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='True',
            l2domain_name='l2dom27-1',
            port_name='port27-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, same ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '30.30.30.100'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='True',
            l2domain_name='l2dom28-1',
            port_name='port28-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='True',
            l2domain_name='l2dom29-1',
            port_name='port29-1')
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = port['mac_address']
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        body = self.ports_client.update_port(port['id'],
                                             allowed_address_pairs=allowed_address_pairs)
        port = body['port']
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.20.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='True',
            l2domain_name='l2dom30-1',
            port_name='port30-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different ip, different ip,  different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '30.30.30.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='True',
            l2domain_name='l2dom31-1',
            port_name='port31-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security='True', port_security='True',
            l2domain_name='l2dom32-1',
            port_name='port32-1')
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        body = self.ports_client.update_port(port['id'],
                                             allowed_address_pairs=allowed_address_pairs)
        port = body['port']
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.0.0/24'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router41-1',
            subnet_name='subnet41-1',
            port_name='port41-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)
        pass

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, same subnet in
        # comparsion with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router42-1',
            subnet_name='subnet42-1',
            port_name='port42-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router43-1',
            subnet_name='subnet43-1',
            port_name='port43-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.0.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router44-1',
            subnet_name='subnet44-1',
            port_name='port44-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, same subnet in
        # comparsion with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router45-1',
            subnet_name='subnet45-1',
            port_name='port45-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router46-1',
            subnet_name='subnet46-1',
            port_name='port46-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.20.100'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router47-1',
            subnet_name='subnet47-1',
            port_name='port47-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, same ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '30.30.30.100'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router48-1',
            subnet_name='subnet48-1',
            port_name='port48-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router49-1',
            subnet_name='subnet49-1',
            port_name='port49-1')
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = port['mac_address']
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        body = self.ports_client.update_port(port['id'],
                                             allowed_address_pairs=allowed_address_pairs)
        port = body['port']
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.20.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router50-1',
            subnet_name='subnet50-1',
            port_name='port50-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different ip, different ip,  different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '30.30.30.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router51-1',
            subnet_name='subnet51-1',
            port_name='port51-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router52-1',
            subnet_name='subnet52-1',
            port_name='port52-1')
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        body = self.ports_client.update_port(port['id'],
                                             allowed_address_pairs=allowed_address_pairs)
        port = body['port']
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_1_1_vsd_managed_l2domain(self):
        # IP Anti Spoofing tests for vsd managed port having vip parameters:
        # full cidr(/32 IP), different mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        network, subnet, port = self._create_vsd_managed_l2resources(ntw_security='True',
                                                                     port_security='True',
                                                                     l2domain_name='subnet64-1',
                                                                     port_name='port64-1')
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        body = self.ports_client.update_port(port['id'],
                                             allowed_address_pairs=allowed_address_pairs)
        port = body['port']
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_1_1_vsd_managed_l3domain(self):
        # IP Anti Spoofing tests for vsd managed port having vip parameters:
        # full cidr(/32 IP), different mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        network, subnet, port = self._create_vsd_managed_l3resources(ntw_security='True',
                                                                     port_security='True',
                                                                     router_name='router61-1',
                                                                     subnet_name='subnet61-1',
                                                                     port_name='port61-1')
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        body = self.ports_client.update_port(port['id'],
                                             allowed_address_pairs=allowed_address_pairs)
        port = body['port']
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_1_vsd_managed_l3domain(self):
        # IP Anti Spoofing tests for vsd managed subnet port with
        # vip parameters having full cidr(/32 IP), same mac, same ip,
        # different subnet in comparsion with the corresponding
        # port parameters
        ip_address = '40.40.40.100'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, subnet, port = self._create_vsd_managed_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router62-1',
            subnet_name='subnet62-1',
            port_name='port62-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_0_vsd_managed_l3domain(self):
        # IP Anti Spoofing tests for vsd managed subnet port with
        # vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.20.100'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, subnet, port = self._create_vsd_managed_l3resources(
            ntw_security='True',
            port_security='True',
            router_name='router63-1',
            subnet_name='subnet63-1',
            port_name='port63-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)


class IpAntiSpoofingCliTests(IpAntiSpoofingTestBase, test.BaseTestCase):
    @classmethod
    def resource_setup(cls):
        super(IpAntiSpoofingCliTests, cls).resource_setup()
        cls.def_net_partition = CONF.nuage.nuage_default_netpartition
        cls.os_data = openstackData()
        cls.os_data.insert_resource(cls.def_net_partition,
                                    parent='CMS')
        cls.os = cls.TB.osc_1.cli

    @classmethod
    def setup_clients(cls):
        super(IpAntiSpoofingCliTests, cls).setup_clients()

    @classmethod
    def resource_cleanup(cls):
        cls.os_data.delete_resource(cls.def_net_partition)

    def _create_ntw_with_sec_disabled(self, ntw_name):
        kwargs = {'port_security_enabled': 'false'}
        network = self.os.create_network(ntw_name, **kwargs)
        self.addCleanup(self.os.delete_network, network['id'])
        return network

    def _create_and_verify_ntw_port_with_sec_value(self, ntw_name, port_name,
                                                   ntw_security=None,
                                                   port_security=None):
        if ntw_security is None:
            network = self.os.create_network(ntw_name)
            ntw_security = 'True'
        else:
            kwargs = {'port_security_enabled': ntw_security}
            network = self.os.create_network(ntw_name, **kwargs)
        self.addCleanup(self.os.delete_network, network['id'])
        self.assertEqual(network['name'], ntw_name)
        self.assertEqual(network['port_security_enabled'], ntw_security)

        if port_security is None:
            port = self.os.create_port(network, port_name)
            port_security = ntw_security
        else:
            kwargs = {'port_security_enabled': port_security}
            port = self.os.create_port(network, port_name, **kwargs)
        self.addCleanup(self.os.delete_port, port['id'])
        self.assertEqual(port['port_security_enabled'], port_security)
        self.assertEqual(port['name'], port_name)
        return port

    def _create_l2resources(self, ntw_name, sub_name, port_name,
                            addr_pr=None, cidr='50.50.50.0/24', mac=None):
        network = self.os.create_network(ntw_name)
        self.addCleanup(self.os.delete_network, network['id'])
        cidr = IPNetwork(cidr)
        mask_bits = 24
        kwargs = {'name': sub_name,
                  'cidr': cidr,
                  'mask_bits': mask_bits}
        subnet = self.os.create_subnet(network, **kwargs)
        self.addCleanup(self.os.delete_subnet, subnet['id'])
        self.os_data.insert_resource(sub_name, self.def_net_partition,
                                     os_data=subnet)
        if mac:
            raise NotImplemented

        if addr_pr:
            kwargs = {'allowed_address_pairs': addr_pr,
                      'name': port_name}
            port = self.os.create_port(network, **kwargs)
        else:
            port = self.os.create_port(network)
        self.addCleanup(self.os.delete_port, port['id'])
        self.os_data.insert_resource(port_name, sub_name, os_data=port)
        self.addCleanup(self.os_data.delete_resource, sub_name)
        return subnet, port

    def _create_l3resources(self, ntw_name, router_name, sub_name, port_name,
                            addr_pr=None, cidr='50.50.50.0/24', mac=None):
        router = self.os.create_router(router_name)
        self.addCleanup(self.os.delete_router, router['id'])
        self.os_data.insert_resource(router_name, self.def_net_partition,
                                     os_data=router)
        network = self.os.create_network(ntw_name)
        self.addCleanup(self.os.delete_network, network['id'])
        cidr = IPNetwork(cidr)
        mask_bits = 24

        if mac:
            raise NotImplemented

        kwargs = {'name': sub_name,
                  'cidr': cidr,
                  'mask_bits': mask_bits}
        subnet = self.os.create_subnet(network, **kwargs)
        self.addCleanup(self.os.delete_subnet, subnet['id'])
        self.os_data.insert_resource(sub_name, router_name, os_data=subnet)
        self.os.create_router_interface(router['id'], subnet['id'])
        self.addCleanup(self.os.remove_router_interface,
                        router['id'], subnet['id'])
        if addr_pr:
            kwargs = {'allowed_address_pairs': addr_pr,
                      'name': port_name}
            port = self.os.create_port(network, **kwargs)
        else:
            port = self.os.create_port(network)
        self.addCleanup(self.os.delete_port, port['id'])
        self.os_data.insert_resource(port_name, sub_name, os_data=port)
        self.addCleanup(self.os_data.delete_resource, sub_name)
        return router, subnet, port

    @nuage_test.header()
    def test_create_show_update_delete_ntw_with_sec_disabled(self):
        ntw_name = data_utils.rand_name('network-')
        network = self._create_ntw_with_sec_disabled(ntw_name)
        self.assertEqual(network['port_security_enabled'], 'False')
        self.assertEqual(network['name'], ntw_name)
        # check the net-show to verify the port_security option
        ntw_show = self.os.show_network(network['id'])
        self.assertEqual(ntw_show['port_security_enabled'], 'False')
        self.assertEqual(ntw_show['name'], ntw_name)

        # update the network to enable port security
        kwargs = {'port_security_enabled': 'True'}
        self.os.update_network(network['id'], **kwargs)
        ntw_show = self.os.show_network(network['id'])
        self.assertEqual(ntw_show['port_security_enabled'], 'True')

    @nuage_test.header()
    def test_create_show_update_delete_port_with_sec_disabled(self):
        ntw_name = data_utils.rand_name('network-')
        port_name = data_utils.rand_name('port-')
        port = self._create_and_verify_ntw_port_with_sec_value(
            ntw_name, port_name,
            port_security='False')

        # Check the port-shows the right port-security value
        port_show = self.os.show_port(port['id'])
        self.assertEqual(port_show['port_security_enabled'], 'False')
        self.assertEqual(port_show['name'], port_name)

        # Update the port to enable port security
        kwargs = {'port_security_enabled': 'True'}
        self.os.update_port(port, **kwargs)
        port_show = self.os.show_port(port['id'])
        self.assertEqual(port_show['port_security_enabled'], 'True')

    @nuage_test.header()
    def test_create_port_in_sec_disabled_ntw(self):
        ntw_name = data_utils.rand_name('network-')
        port_name = data_utils.rand_name('port-')
        port = self._create_and_verify_ntw_port_with_sec_value(
            ntw_name, port_name,
            ntw_security='False')
        self.assertIsNotNone(port)

    @nuage_test.header()
    def test_create_sec_disabled_port_in_sec_disabled_ntw(self):
        ntw_name = data_utils.rand_name('network-')
        port_name = data_utils.rand_name('port-')
        port = self._create_and_verify_ntw_port_with_sec_value(
            ntw_name, port_name,
            ntw_security='False',
            port_security='False')
        self.assertIsNotNone(port)

    @nuage_test.header()
    def test_create_sec_enabled_port_in_sec_disabled_ntw(self):
        ntw_name = data_utils.rand_name('network-')
        port_name = data_utils.rand_name('port-')
        port = self._create_and_verify_ntw_port_with_sec_value(
            ntw_name, port_name,
            ntw_security='False',
            port_security='True')
        self.assertIsNotNone(port)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        allowed_addr_pair = 'type=dict list=true ip_address=30.30.30.0/24'
        ntw_name = 'network70-1'
        sub_name = 'subnet70-1'
        port_name = 'port70-1'
        self._create_l2resources(ntw_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, same subnet in
        # comparsion with the corresponding port parameters
        allowed_addr_pair = 'type=dict list=true ip_address=50.50.50.0/24'
        ntw_name = 'network71-1'
        sub_name = 'subnet71-1'
        port_name = 'port71-1'
        self._create_l2resources(ntw_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        #ip_address = '30.30.30.0/24'
        allowed_addr_pair = 'type=dict list=true ip_address=50.50.50.0/24'
        ntw_name = 'network72-1'
        sub_name = 'subnet72-1'
        port_name = 'port72-1'
        self._create_l2resources(ntw_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.0.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = 'type=dict list=true ip_address=' \
                            + ip_address + ',mac_address=' + mac_address
        ntw_name = 'network73-1'
        sub_name = 'subnet73-1'
        port_name = 'port73-1'
        self._create_l2resources(ntw_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, same subnet in
        # comparsion with the corresponding port parameters
        ip_address = '50.50.50.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = 'type=dict list=true ip_address=' \
                            + ip_address + ',mac_address=' + mac_address
        ntw_name = 'network74-1'
        sub_name = 'subnet74-1'
        port_name = 'port74-1'
        self._create_l2resources(ntw_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        ip_address = '50.50.50.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = 'type=dict list=true ip_address=' \
                            + ip_address + ',mac_address=' + mac_address
        ntw_name = 'network75-1'
        sub_name = 'subnet75-1'
        port_name = 'port75-1'
        self._create_l2resources(ntw_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.20.100'
        allowed_addr_pair = 'type=dict list=true ip_address=' + ip_address
        ntw_name = 'network76-1'
        sub_name = 'subnet76-1'
        port_name = 'port76-1'
        self._create_l2resources(ntw_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, same ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '50.50.50.100'
        allowed_addr_pair = 'type=dict list=true ip_address=' + ip_address
        ntw_name = 'network77-1'
        sub_name = 'subnet77-1'
        port_name = 'port77-1'
        self._create_l2resources(ntw_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        ntw_name = 'network78-1'
        sub_name = 'subnet78-1'
        port_name = 'port78-1'
        (subnet, port) = self._create_l2resources(ntw_name, sub_name, port_name)
        ip_address = port['fixed_ips'][0]['ip_address']

        mac_address = port['mac_address']
        allowed_addr_pair = 'type=dict list=true ip_address=' \
                            + ip_address + ',mac_address=' + mac_address
        kwargs = {'allowed_address_pairs': allowed_addr_pair}
        port = self.os.update_port(port, **kwargs)
        self.assertIsNone(port)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.20.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = 'type=dict list=true ip_address=' \
                            + ip_address + ',mac_address=' + mac_address
        ntw_name = 'network79-1'
        sub_name = 'subnet79-1'
        port_name = 'port79-1'
        self._create_l2resources(ntw_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different ip, different ip,  different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '50.50.50.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = 'type=dict list=true ip_address=' \
                            + ip_address + ',mac_address=' + mac_address
        ntw_name = 'network80-1'
        sub_name = 'subnet80-1'
        port_name = 'port80-1'
        self._create_l2resources(ntw_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        ntw_name = 'network81-1'
        sub_name = 'subnet81-1'
        port_name = 'port81-1'
        (subnet, port) = self._create_l2resources(ntw_name, sub_name, port_name)
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = 'type=dict list=true ip_address=' \
                            + ip_address + ',mac_address=' + mac_address
        kwargs = {'allowed_address_pairs': allowed_addr_pair}
        port = self.os.update_port(port, **kwargs)
        self.assertIsNone(port)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.0.0/24'
        allowed_addr_pair = 'type=dict list=true ip_address=' + ip_address
        ntw_name = 'network82-1'
        router_name = 'router82-1'
        sub_name = 'subnet82-1'
        port_name = 'port82-1'
        self._create_l3resources(ntw_name, router_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, same subnet in
        # comparsion with the corresponding port parameters
        ip_address = '50.50.50.0/24'
        allowed_addr_pair = 'type=dict list=true ip_address=' + ip_address
        ntw_name = 'network83-1'
        router_name = 'router83-1'
        sub_name = 'subnet83-1'
        port_name = 'port83-1'
        self._create_l3resources(ntw_name, router_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        ip_address = '50.50.50.0/24'
        allowed_addr_pair = 'type=dict list=true ip_address=' + ip_address
        ntw_name = 'network84-1'
        router_name = 'router84-1'
        sub_name = 'subnet84-1'
        port_name = 'port84-1'
        self._create_l3resources(ntw_name, router_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.0.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = 'type=dict list=true ip_address=' \
                            + ip_address + ',mac_address=' + mac_address
        ntw_name = 'network85-1'
        router_name = 'router85-1'
        sub_name = 'subnet85-1'
        port_name = 'port85-1'
        self._create_l3resources(ntw_name, router_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, same subnet in
        # comparsion with the corresponding port parameters
        ip_address = '50.50.50.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = 'type=dict list=true ip_address=' \
                            + ip_address + ',mac_address=' + mac_address
        ntw_name = 'network86-1'
        router_name = 'router86-1'
        sub_name = 'subnet86-1'
        port_name = 'port86-1'
        self._create_l3resources(ntw_name, router_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    def test_anti_spoofing_for_params_0_1_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        ip_address = '50.50.50.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = 'type=dict list=true ip_address=' \
                            + ip_address + ',mac_address=' + mac_address
        ntw_name = 'network87-1'
        router_name = 'router87-1'
        sub_name = 'subnet87-1'
        port_name = 'port87-1'
        self._create_l3resources(ntw_name, router_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.20.100'
        allowed_addr_pair = 'type=dict list=true ip_address=' + ip_address
        ntw_name = 'network88-1'
        router_name = 'router88-1'
        sub_name = 'subnet88-1'
        port_name = 'port88-1'
        self._create_l3resources(ntw_name, router_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    def test_anti_spoofing_for_params_1_0_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, same ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '50.50.50.100'
        allowed_addr_pair = 'type=dict list=true ip_address=' + ip_address
        ntw_name = 'network89-1'
        router_name = 'router89-1'
        sub_name = 'subnet89-1'
        port_name = 'port89-1'
        self._create_l3resources(ntw_name, router_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        ntw_name = 'network90-1'
        router_name = 'router90-1'
        sub_name = 'subnet90-1'
        port_name = 'port90-1'
        router, subnet, port = self._create_l3resources(ntw_name, router_name,
                                                        sub_name, port_name)
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = port['mac_address']
        allowed_addr_pair = 'type=dict list=true ip_address=' \
                            + ip_address + ',mac_address=' + mac_address
        kwargs = {'allowed_address_pairs': allowed_addr_pair}
        port = self.os.update_port(port, **kwargs)
        self.assertIsNone(port)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '20.20.20.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = 'type=dict list=true ip_address=' \
                            + ip_address + ',mac_address=' + mac_address
        ntw_name = 'network91-1'
        router_name = 'router91-1'
        sub_name = 'subnet91-1'
        port_name = 'port91-1'
        self._create_l3resources(ntw_name, router_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    def test_anti_spoofing_for_params_1_1_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different ip, different ip,  different subnet in
        # comparsion with the corresponding port parameters
        ip_address = '50.50.50.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = 'type=dict list=true ip_address=' \
                            + ip_address + ',mac_address=' + mac_address
        ntw_name = 'network92-1'
        router_name = 'router92-1'
        sub_name = 'subnet92-1'
        port_name = 'port92-1'
        self._create_l3resources(ntw_name, router_name, sub_name, port_name,
                                 addr_pr=allowed_addr_pair)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different mac, same ip, same subnet in
        # comparsion with the corresponding port parameters
        ntw_name = 'network93-1'
        router_name = 'router93-1'
        sub_name = 'subnet93-1'
        port_name = 'port93-1'
        router, subnet, port = self._create_l3resources(ntw_name, router_name,
                                                        sub_name, port_name)
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = 'type=dict list=true ip_address=' \
                            + ip_address + ',mac_address=' + mac_address
        kwargs = {'allowed_address_pairs': allowed_addr_pair}
        port = self.os.update_port(port, **kwargs)
        self.assertIsNone(port)
        tag_name = 'verify_vip_and_anti_spoofing'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)
