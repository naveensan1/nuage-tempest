from tempest.api.network import test_routers
from tempest.common.utils import data_utils
import netaddr
from tempest import test
from nuagetempest.tests import nuage_ext


class RoutersTest(test_routers.RoutersTest):

    @classmethod
    def resource_setup(cls):
        super(RoutersTest, cls).resource_setup()
        '''openstackArr = {
             'net-partitions': {},
             'routers': {},
	     'networks': {},
 	     'subnets': {},
        'router-interface': {} }
        cls.openstackArr = objview.objectview(openstackArr)'''

    @test.attr(type='smoke')
    def test_create_router_interface(cls):
        name = 'router1'
        network1 = cls.create_network(
            network_name=name)
        subnet1 = cls.create_subnet(network1, name=data_utils.rand_name('subnet-'))
        router = cls._create_router(data_utils.rand_name('router-'))
        interface1 = cls._add_router_interface_with_subnet_id(router['id'],
                                                                subnet1['id'])
        cls._verify_router_interface(router['id'], subnet1['id'],
                                      interface1['port_id'])
        nuage_ext.nuage_extension.nuage_components(nuage_ext._generate_tag('verify_r_i', cls.__class__.__name__), cls)
        
