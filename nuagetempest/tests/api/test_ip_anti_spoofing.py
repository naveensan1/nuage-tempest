from nuagetempest.thirdparty.nuage import test_allowed_addr_pair_nuage
from tempest.common.utils import data_utils
from tempest.api.network import base
from tempest import test
from nuagetempest.tests import nuage_ext
from tempest import config
from nuagetempest.lib.openstackData import openstackData

import netaddr

CONF = config.CONF


class IpAntiSpoofingTest(base.BaseNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(IpAntiSpoofingTest, cls).resource_setup()
        cls.def_net_partition = CONF.nuage.nuage_default_netpartition
        cls.os_data = openstackData()
        cls.os_data.insert_resource({'name': cls.def_net_partition},
                                    parent='CMS')

    @classmethod
    def resource_cleanup(cls):
        cls.os_data.delete_resource(cls.def_net_partition)

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
    def _create_security_disabled_port(cls, ntw, name=None):
        if name is None:
            data_utils.rand_name('port-')
        kwargs = {'name': name, 'network_id': ntw['id'],
                  'port_security_enabled': 'False'}
        body = cls.ports_client.create_port(**kwargs)
        return body['port']

    def _create_network_port_l2resources(self, ntw_security='True',
                                         port_security='True',
                                         port_name='port-1',
                                         l2domain_name='l2domain-1',
                                         netpart=None):
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
        self.os_data.insert_resource(l2domain, netpart)
        self.addCleanup(self.subnets_client.delete_subnet, l2domain['id'])
        if port_security == 'False':
            port = self._create_security_disabled_port(network, name=port_name)
        else:
            body = self.ports_client.create_port(name=port_name,
                                                 network_id=network['id'])
            port = body['port']
        self.os_data.insert_resource(port, l2domain_name)
        self.addCleanup(self.ports_client.delete_port, port['id'])
        self.addCleanup(self.os_data.delete_resource, l2domain_name)
        return (network, l2domain, port)

    def _create_network_port_l3resources(self, ntw_security='True',
                                         port_security='True',
                                         port_name='port-1',
                                         subnet_name='subnet-1',
                                         l3dom_name='router-1',
                                         netpart=None):
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

        body = self.routers_client.create_router(name=l3dom_name)
        router = body['router']
        self.os_data.insert_resource(router, netpart)
        self.addCleanup(self.routers_client.delete_router, router['id'])

        subnet = self._create_subnet(network, name=subnet_name)
        self.os_data.insert_resource(subnet, l3dom_name)
        self.addCleanup(self.subnets_client.delete_subnet, subnet['id'])

        self.routers_client.add_router_interface(router['id'],
                                                 subnet_id=subnet['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        router['id'], subnet_id=subnet['id'])
        if port_security == 'False':
            port = self._create_security_disabled_port(network, name=port_name)
        else:
            body = self.ports_client.create_port(name=port_name,
                                                 network_id=network['id'])
            port = body['port']
        self.os_data.insert_resource(port, subnet_name)
        self.addCleanup(self.ports_client.delete_port, port['id'])
        self.addCleanup(self.os_data.delete_resource, l3dom_name)
        return (network, router, subnet, port)

    def test_create_delete_sec_disabled_ntw_port_l2domain(self):
        ''' L2domain testcase to test network and port creation with
            port-security-enabled set to False explicitly for both'''
        network, l2domain, port = self._create_network_port_l2resources(
                                  ntw_security='False', port_security='False')
        tag_name = 'verify_security_disabled_ntw_port_l2domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    def test_create_delete_sec_disabled_ntw_l2domain(self):
        ''' L2domain testcase to test network and port creation with
            port-security-enabled set to False at network level only'''
        network, l2domain, port = self._create_network_port_l2resources(
                                  ntw_security='False')
        tag_name = 'verify_security_disabled_ntw_l2domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    def test_create_delete_sec_disabled_port_l2domain(self):
        ''' L2domain testcase to test network and port creation with
            port-security-enabled set to False at port level only'''
        network, l2domain, port = self._create_network_port_l2resources(
                                  ntw_security='True', port_security='False')
        tag_name = 'verify_security_disabled_port_l2domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    def test_create_delete_sec_disabled_ntw_port_l3domain(self):
        ''' L3domain testcase to test the network and port creation with
            port-security-enabled set to False explicitly for both'''
        network, router, subnet, port = self._create_network_port_l3resources(
                                        ntw_security='False',
                                        port_security='False')
        tag_name = 'verify_security_disabled_ntw_port_l3domain'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)
