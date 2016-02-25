from tempest.scenario import manager
from tempest import test
from nuagetempest.tests import nuage_ext
from tempest.scenario import test_server_basic_ops

class TestServerBasicOps(test_server_basic_ops.TestServerBasicOps):

    def setUp(self):
        super(TestServerBasicOps, self).setUp()
  
    @test.attr(type='smoke')
    @test.services('compute', 'network')
    def test_server_basic_ops(self):
        self.add_keypair()
        self.security_group = self._create_security_group()
        self.boot_instance()
        nuage_ext.nuage_extension.nuage_components(
                nuage_ext._generate_tag('verify_vm', self.__class__.__name__))
        self.servers_client.delete_server(self.instance['id'])