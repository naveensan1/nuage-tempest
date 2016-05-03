from oslo_log import log as logging

from tempest import config
from nuagetempest.services.vpnaas.vpnaas_mixins import VPNMixin
from nuagetempest.lib import topology
from tempest import test
from tempest.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from nuagetempest.lib.test import nuage_test
from testtools.matchers import Contains
from testtools.matchers import Equals
from testtools.matchers import Not
from nuagetempest.lib.openstackData import openstackData
from nuagetempest.tests import nuage_ext
import uuid
import netaddr

LOG = logging.getLogger(__name__)
CONF = config.CONF
TB = topology.testbed


class VPNaaSBase(VPNMixin):

    @classmethod
    def resource_setup(cls):
        super(VPNaaSBase, cls).resource_setup()
        cls.def_net_partition = CONF.nuage.nuage_default_netpartition
        cls.os_data = openstackData()
        cls.os_data.insert_resource(cls.def_net_partition,
                                    parent='CMS')

    @classmethod
    def resource_cleanup(cls):
        cls.os_data.delete_resource(cls.def_net_partition)

class VPNaaSTest(VPNaaSBase):

    def test_ikepolicy_create_list(self):
        ikepolicies = self.ikepolicy_client.list_ikepolicy()
        pre_ids = [ikepolicy['id'] for ikepolicy in ikepolicies]
        with self.ikepolicy(tenant_id=self.tenant_id) as created_ikepolicy:
            ikepolicies = self.ikepolicy_client.list_ikepolicies()
            post_ids = [ikepolicy['id'] for ikepolicy in ikepolicies]
            self.assertThat(pre_ids, Not(Contains(created_ikepolicy['id'])))
            self.assertThat(post_ids, Contains(created_ikepolicy['id']))

    def test_ipsecpolicy_create_list(self):
        ipsecpolicy = self.ipsecpolicy_client.list_ipsecpolicy()
        pre_ids = [ipsecpolicy['id'] for ipsecpolicy in ipsecpolicies]
        with self.ipsecpolicy(tenant_id=self.tenant_id) as created_ipsecpolicy:
            ipsecpolicies = self.ipsecpolicy_client.list_ipsecpolicies()
            post_ids = [ipsecpolicy['id'] for ipsecpolicy in ipsecpolicies]
            self.assertThat(pre_ids, Not(Contains(created_ipsecpolicy['id'])))
            self.assertThat(post_ids, Contains(created_ipsecpolicy['id']))

class VPNaaSCliTests(test.BaseTestCase):

    @classmethod
    def setupClass(self):
        super(VPNaaSCliTests, self).setupClass()
        self.def_net_partition = CONF.nuage.nuage_default_netpartition
        self.os_handle = TB.osc_1.cli
        self.os_data = openstackData()
        self.os_data.insert_resource(self.def_net_partition,
                                    parent='CMS')

    def setup(self):
        super(VPNaaSCliTests, self).setup()

    def _verify_resource_list(self, resource, resource_dict, present):
        resource_list = [resources['id'] for resources in resource_dict]
        if present:
            if resource in resource_list:
                LOG.debug('Found %s', resource)
                return True
            else:
                LOG.debug('ERROR: Not Found %s', resource)
                return False
        else:
            if resource in resource_list:
                LOG.debug('ERROR: Found %s', resource)
                return False
            else:
                LOG.debug('Not Found %s', resource)
                return True

    def _create_verify_ikepolicy(self, name):
        name = data_utils.rand_name(name)
        # Creating a IKE Policy
        ikepolicy = TB.osc_1.cli.vpnaas_client.create_ikepolicy(name)
        # Showing the created IKE Policy
        ikepolicy_info = TB.osc_1.cli.vpnaas_client.show_ikepolicy(name)
        self.assertEqual(ikepolicy_info['name'], name)
        return ikepolicy['ikepolicy']['id']

    def _delete_verify_ikepolicy(self, id):
        # Deleting the IKE Policy
        TB.osc_1.cli.vpnaas_client.delete_ikepolicy(id)
        # Verifying delete in list IKE Policy
        ikepolicies = TB.osc_1.cli.vpnaas_client.list_ikepolicy()
        result = self._verify_resource_list(id, ikepolicies, False)
        self.assertEqual(result, True)

    def _create_verify_ipsecpolicy(self, name):
        name = data_utils.rand_name(name)
        # Creating a IPSecPolicy
        ipsecpolicy = TB.osc_1.cli.vpnaas_client.create_ipsecpolicy(name)
        # Showing the created IPSecPolicy
        ipsecpolicy_info = TB.osc_1.cli.vpnaas_client.show_ipsecpolicy(name)
        self.assertEqual(ipsecpolicy_info['name'], name)
        return ipsecpolicy['ipsecpolicy']['id']

    def _delete_verify_ipsecpolicy(self, id):
        # Deleting the IPSecPolicy
        TB.osc_1.cli.vpnaas_client.delete_ipsecpolicy(id)
        # Verifying delete in list IPSecPolicy
        ipsecpolicies = TB.osc_1.cli.vpnaas_client.list_ipsecpolicy()
        result = self._verify_resource_list(id, ipsecpolicies, False)
        self.assertEqual(result, True)

    def _create_verify_vpn_environment(self, name, cidr, public):
        netname = name + '-network-'
        netname = data_utils.rand_name(netname)
        network = TB.osc_1.cli.create_network(network_name=netname)
        mask_bit = int(cidr.split("/")[1])
        gateway_ip = cidr.split("/")[0][:cidr.rfind(".")] + ".1"
        cidr = netaddr.IPNetwork(cidr)
        subnet = (
            TB.osc_1.cli.create_subnet(
                network, gateway=gateway_ip,
                cidr=cidr, mask_bits=mask_bit
                )
        )
        routername = name + '-router-'
        routername = data_utils.rand_name(routername)
        router = TB.osc_1.cli.create_router(router_name=routername)
        TB.osc_1.cli.routers_client.add_router_interface_with_args(
            router['id'], subnet['id']
        )
        TB.osc_1.cli.routers_client.set_router_gateway_with_args(
            router['id'], public['network']['id']
        )
        return subnet, router

    def _delete_verify_vpn_environment(self, router,subnet):
        TB.osc_1.cli.routers_client.delete_router(
            router['id'])
        TB.osc_1.cli.networks_client.delete_network(
            subnet['network_id'])

    def _create_verify_vpnservice(self, name, router, subnet):
        name = name + '-vpnservice-'
        name = data_utils.rand_name(name)
        # Creating a VPNService
        vpnservice = (
            TB.osc_1.cli.vpnaas_client.create_vpnservice(
                router['id'], subnet['id'], name
            )
        )
        # Showing the created VPNService
        vpnservice_info = TB.osc_1.cli.vpnaas_client.show_vpnservice(vpnservice['vpnservice']['id'])
        self.assertEqual(vpnservice_info['name'], name)
        return vpnservice['vpnservice']

    def _delete_verify_vpnservice(self, id):
        # Deleting the VPNService
        TB.osc_1.cli.vpnaas_client.delete_vpnservice(id)
        # Verifying delete in list VPNService
        vpnservices = TB.osc_1.cli.vpnaas_client.list_vpnservice()
        result = self._verify_resource_list(id, vpnservices, False)
        self.assertEqual(result, True)

    def _create_verify_ipsecsiteconnection(self, vpnservice_id, ikepolicy_id,
                                  ipsecpolicy_id, peer_address, peer_id,
                                  peer_cidrs, psk, name):
        # Creating a IPSecSiteConnection
        ipsecsiteconnection = (
            TB.osc_1.cli.vpnaas_client.create_ipsecsiteconnection(
                vpnservice_id, ikepolicy_id, ipsecpolicy_id,
                peer_address, peer_id, peer_cidrs, psk, name
            )
        )
        # Showing the created IPSecSiteConnection
        ipsecsiteconnection_info = (
            TB.osc_1.cli.vpnaas_client.show_ipsecsiteconnection(
                ipsecsiteconnection['ipsecsiteconnection']['id']
            )
        )
        self.assertEqual(ipsecsiteconnection_info['name'], name)
        return ipsecsiteconnection['ipsecsiteconnection']

    def _delete_verify_ipsecsiteconnection(self, id):
        # Deleting the VPNService
        TB.osc_1.cli.vpnaas_client.delete_ipsecsiteconnection(id)
        # Verifying delete in list VPNService
        ipsecsiteconnections = TB.osc_1.cli.vpnaas_client.list_ipsecsiteconnection()
        result = self._verify_resource_list(id, ipsecsiteconnections, False)
        self.assertEqual(result, True)

    @test.attr(type='smoke')
    @nuage_test.header()
    def test_create_delete_ikepolicy(self):
        # Create Verify
        ikepolicy_id = self._create_verify_ikepolicy('ikepolicy')
        # Delete Verify
        self._delete_verify_ikepolicy(ikepolicy_id)

    def test_create_delete_ipsecpolicy(self):
        # Create Verify
        ipsecpolicy_id = self._create_verify_ipsecpolicy('ipsecpolicy')
        # Delete Verify
        self._delete_verify_ipsecpolicy(ipsecpolicy_id)

    def test_create_delete_vpnservice(self):
        name = 'vpn'
        pubnetname = name + '-publicnet-'
        pubnetname = data_utils.rand_name(pubnetname)
        pubnet = (
            TB.osc_1.cli.networks_client.create_network_with_args(
                pubnetname, '--router:external'
            )
        )
        pubcidr = '172.20.0.0/24'
        gateway = '172.20.0.1' 
        pub_mask = int(pubcidr.split('/')[1])
        pubcidr = netaddr.IPNetwork(pubcidr)
        pubsubnet = (
            TB.osc_1.cli.create_subnet(
                pubnet['network'], gateway=gateway,
                cidr=pubcidr, mask_bits=pub_mask
                )
        )
        subnet, router = (
            self._create_verify_vpn_environment(
                name, '10.20.0.0/24', pubnet
            )
        )
        # Create Verify VPNService
        vpnservice = self._create_verify_vpnservice(name, router, subnet)
        # Delete Verify VPNService
        self._delete_verify_vpnservice(vpnservice['id'])

    def test_create_delete_ipsecsiteconnection(self):
        name = 'vpn'
        pubnetid = CONF.network.public_network_id
        pubnet = TB.osc_1.cli.networks_client.show_network(pubnetid)
        # Creating Site1
        name1 = 'vpn1'
        cidr1 = '10.20.0.0/24'
        subnet1, router1 = (
            self._create_verify_vpn_environment(
                name1, cidr1, pubnet
            )
        )

        # VPN1
        vpnservice1 = self._create_verify_vpnservice(name1, router1, subnet1) 

        # Creating Site2
        name2 = 'vpn2'
        cidr2 = '10.30.0.0/24'
        subnet2, router2 = (
            self._create_verify_vpn_environment(
                name2, cidr2, pubnet
            )
        )

        # VPN2
        vpnservice2 = self._create_verify_vpnservice(name2, router2, subnet2)

        # Creating IKE Policy
        ikepolicy_id = self._create_verify_ikepolicy('ikepolicy')

        # Creating IPSecPolicy
        ipsecpolicy_id = self._create_verify_ipsecpolicy('ipsecpolicy')

        # Creating IPSecSiteConnection1
        vpn_ip1 = vpnservice1['external_v4_ip']
        name1 = 'site1'
        ipsecsiteconnection1 = (
            self._create_verify_ipsecsiteconnection(
                vpnservice1['id'], ikepolicy_id,
                ipsecpolicy_id, vpn_ip1, vpn_ip1,
                cidr1, 'secret', name1
            )
        )

        # Creating IPSecSiteConnection2
        vpn_ip2 = vpnservice2['external_v4_ip']
        name2 = 'site2'
        ipsecsiteconnection2 = (
            self._create_verify_ipsecsiteconnection(
                vpnservice2['id'], ikepolicy_id,
                ipsecpolicy_id, vpn_ip2, vpn_ip2,
                cidr2, 'secret', name2
            )
        )

        # Delete IPSecSiteconnections
        self._delete_verify_ipsecsiteconnection(ipsecsiteconnection1['id'])
        self._delete_verify_ipsecsiteconnection(ipsecsiteconnection2['id'])

        # Delete VPNService
        self._delete_verify_vpnservice(vpnservice1['id'])
        self._delete_verify_vpnservice(vpnservice2['id'])

        # Delete IKEpolicy and IPSecPolicy
        self._delete_verify_ipsecpolicy(ipsecpolicy_id)
        self._delete_verify_ikepolicy(ikepolicy_id)

        # Delete Routers and Subnets
        self._delete_verify_vpn_environment(router1, subnet1)
        self._delete_verify_vpn_environment(router2, subnet2)
