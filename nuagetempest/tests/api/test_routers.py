from tempest.api.network import test_routers
from tempest.common.utils import data_utils
import netaddr
from tempest import test
from nuagetempest.tests import nuage_ext

class RoutersTest(test_routers.RoutersTest):

    @classmethod
    def resource_setup(cls):
        super(RoutersTest, cls).resource_setup()

    @test.attr(type='smoke')
    def test_create_router_interface(self):
        network01 = self.create_network(
            network_name=data_utils.rand_name('router-network01-'))
        subnet01 = self.create_subnet(network01, name=data_utils.rand_name('subnet-'))
        router = self._create_router(data_utils.rand_name('router-'))
        interface01 = self._add_router_interface_with_subnet_id(router['id'],
                                                                subnet01['id'])
        self._verify_router_interface(router['id'], subnet01['id'],
                                      interface01['port_id'])
        nuage_ext.nuage_extension.nuage_components(
                nuage_ext._generate_tag('verify_r_i', self.__class__.__name__))
        