from tempest.api.network import base
from tempest_lib.common.utils.data_utils import rand_name
from tempest import exceptions
from oslo_log import log as logging
from tempest import config

CONF = config.CONF

LOG = logging.getLogger(__name__)

class NetPartitionTestJSON(base.BaseNetworkTest):
    _interface = 'json'

    @classmethod
    def setUpClass(cls):
        super(NetPartitionTestJSON, cls).setUpClass()
        cls.client = cls.get_client_manager().nuage_network_client
        cls.net_partitions = []

    @classmethod
    def tearDownClass(cls):
        super(NetPartitionTestJSON, cls).tearDownClass()
        has_exception = False

        for netpartition in cls.net_partitions:
            try:
                cls.client.delete_netpartition(netpartition['id'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        if has_exception:
            raise exceptions.TearDownException()

    @classmethod
    def create_netpartition(cls, np_name=None):
        """Wrapper utility that returns a test network."""
        np_name = np_name or rand_name('tempest-np-')

        body = cls.client.create_netpartition(np_name)
        netpartition = body['net_partition']
        cls.net_partitions.append(netpartition)
        return netpartition

    def test_create_list_verify_delete_netpartition(self):
        name = rand_name('tempest-np')
        body = self.client.create_netpartition(name)
        self.assertEqual('201', body.response['status'])
        netpart = body['net_partition']
        self.assertEqual(name, netpart['name'])
        body = self.client.list_netpartition()
        netpartition_idlist = list()
        netpartition_namelist = list()
        for netpartition in body['net_partitions']:
            netpartition_idlist.append(netpartition['id'])
            netpartition_namelist.append(netpartition['name'])
        self.assertIn(netpart['id'], netpartition_idlist)
        self.assertIn(netpart['name'], netpartition_namelist)
        body = self.client.delete_netpartition(netpart['id'])
        self.assertEqual('204', body.response['status'])

