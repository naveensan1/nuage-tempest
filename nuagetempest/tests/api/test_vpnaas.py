from oslo_log import log as logging

from tempest import config
from nuagetempest.services.vpnaas.vpnaas_mixins import VPNMixin
from nuagetempest.lib import topology
from tempest import test
from tempest.common.utils import data_utils
from nuagetempest.lib.test import nuage_test
from testtools.matchers import Contains
from testtools.matchers import Not
from nuagetempest.lib.openstackData import openstackData
from nuagetempest.tests import nuage_ext
import netaddr

LOG = logging.getLogger(__name__)
CONF = config.CONF
TB = topology.testbed


class VPNaaSBase(VPNMixin):

    @classmethod
    def resource_setup(cls):
        super(VPNaaSBase, cls).resource_setup()
        cls.def_net_partition = CONF.nuage.nuage_default_netpartition
        cls.os_data_struct = openstackData()
        cls.os_data_struct.insert_resource(cls.def_net_partition,
                                    parent='CMS')

    @classmethod
    def resource_cleanup(cls):
        cls.os_data_struct.delete_resource(cls.def_net_partition)


class VPNaaSTest(VPNaaSBase):

    def test_ikepolicy_create_delete(self):
        ikepolicies = self.ikepolicy_client.list_ikepolicy()
        pre_ids = [ikepolicy['id'] for ikepolicy in ikepolicies]
        with self.ikepolicy('ikepolicy') as created_ikepolicy:
            ikepolicies = self.ikepolicy_client.list_ikepolicy()
            post_ids = [ikepolicy['id'] for ikepolicy in ikepolicies]
            self.assertThat(pre_ids, Not(Contains(created_ikepolicy['id'])))
            self.assertThat(post_ids, Contains(created_ikepolicy['id']))

    def test_ipsecpolicy_create_delete(self):
        ipsecpolicies = self.ipsecpolicy_client.list_ipsecpolicy()
        pre_ids = [ipsecpolicy['id'] for ipsecpolicy in ipsecpolicies]
        with self.ipsecpolicy('ipsecpolicy') as created_ipsecpolicy:
            ipsecpolicies = self.ipsecpolicy_client.list_ipsecpolicy()
            post_ids = [ipsecpolicy['id'] for ipsecpolicy in ipsecpolicies]
            self.assertThat(pre_ids, Not(Contains(created_ipsecpolicy['id'])))
            self.assertThat(post_ids, Contains(created_ipsecpolicy['id']))

    def test_vpnservice_create_delete(self):
        vpnservices = self.vpnservice_client.list_vpnservice()
        pre_ids = [vpnservice['id'] for vpnservice in vpnservices]
        routers = self.routers_client.list_routers()
        subnets = self.subnets_client.list_subnets()
        router_id = routers['routers'][0]['id']
        self.os_data_struct.insert_resource(
            'router1', os_data = routers['routers'][0],
            parent = self.def_net_partition
        )
        subnet_id = subnets['subnets'][0]['id']
        self.os_data_struct.insert_resource(
            'subnet1', os_data = subnets['subnets'][0],
            parent = 'router1'
        )
        kwargs = {'name': 'vpnservice'}
        with self.vpnservice(router_id, subnet_id,
                             **kwargs) as created_vpnservice:
            vpnservices = self.vpnservice_client.list_vpnservice()
            self.os_data_struct.insert_resource(
                'vpnservice', os_data = created_vpnservice,
                parent = 'router1'
            )
            post_ids = [vpnservice['id'] for vpnservice in vpnservices]
            self.assertThat(pre_ids, Not(Contains(created_vpnservice['id'])))
            self.assertThat(post_ids, Contains(created_vpnservice['id']))

    def test_ipsecsiteconnection_create_delete(self):
        ipsecsiteconnections = (
            self.ipsecsiteconnection_client.list_ipsecsiteconnection()
        )
        pre_ids = (
            [ipsecsiteconnection['id'] \
                 for ipsecsiteconnection in ipsecsiteconnections]
        )
        import pdb;pdb.set_trace()
        routers = self.routers_client.list_routers()
        subnets = self.subnets_client.list_subnets()
        router_id = routers['routers'][0]['id']
        subnet_id = subnets['subnets'][0]['id']
        kwargs = {'name': 'ipsecsiteconnection'}
        with self.vpnservice(router_id, subnet_id,
                **kwargs) as created_vpnservice,
                self.ikepolicy('ikepolicy') as created_ikepolicy,
                self.ipsecpolicy('ipsecpolicy') as created_ipsecpolicy:

            vpnservices = self.vpnservice_client.list_vpnservice()
            post_ids = [vpnservice['id'] for vpnservice in vpnservices]
            self.assertThat(pre_ids, Not(Contains(created_vpnservice['id'])))
            self.assertThat(post_ids, Contains(created_vpnservice['id']))
            with self.ipsecsiteconnection(created_vpnservice['id'],
                                       ) as created_ipsecsiteconnection:
                ipsecsiteconnections = (
                    self.ipsecsiteconnection_client.list_ipsecsiteconnection()
                )
                
            


class VPNaaSCliTests(test.BaseTestCase):

    @classmethod
    def resource_setup(self):
        super(VPNaaSCliTests, self).resource_setup()
        self.def_net_partition = CONF.nuage.nuage_default_netpartition
        self.os_handle = TB.osc_1.cli
        self.os_data_struct = openstackData()
        self.os_data_struct.insert_resource(self.def_net_partition,
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
        ikepolicy = self.os_handle.vpnaas_client.create_ikepolicy(name)
        # Showing the created IKE Policy
        ikepolicy_info = self.os_handle.vpnaas_client.show_ikepolicy(name)
        self.os_data_struct.insert_resource(ikepolicy['ikepolicy']['name'],
                                       user_data = { 'name' : name },
                                       os_data = ikepolicy,
                                       parent = 'CMS')
        self.assertEqual(ikepolicy_info['name'], name)
        return ikepolicy['ikepolicy']

    def _delete_verify_ikepolicy(self, id, name):
        # Deleting the IKE Policy
        self.os_handle.vpnaas_client.delete_ikepolicy(id)
        # Verifying delete in list IKE Policy
        ikepolicies = self.os_handle.vpnaas_client.list_ikepolicy()
        result = self._verify_resource_list(id, ikepolicies, False)
        self.os_data_struct.delete_resource(name)
        self.assertEqual(result, True)

    def _create_verify_ipsecpolicy(self, name):
        name = data_utils.rand_name(name)
        # Creating a IPSecPolicy
        ipsecpolicy = self.os_handle.vpnaas_client.create_ipsecpolicy(name)
        # Showing the created IPSecPolicy
        ipsecpolicy_info = self.os_handle.vpnaas_client.show_ipsecpolicy(name)
        self.os_data_struct.insert_resource(ipsecpolicy['ipsecpolicy']['name'],
                                       user_data = { 'name' : name },
                                       os_data = ipsecpolicy,
                                       parent = 'CMS')
        self.assertEqual(ipsecpolicy_info['name'], name)
        return ipsecpolicy['ipsecpolicy']

    def _delete_verify_ipsecpolicy(self, id, name):
        # Deleting the IPSecPolicy
        self.os_handle.vpnaas_client.delete_ipsecpolicy(id)
        # Verifying delete in list IPSecPolicy
        ipsecpolicies = self.os_handle.vpnaas_client.list_ipsecpolicy()
        result = self._verify_resource_list(id, ipsecpolicies, False)
        self.os_data_struct.delete_resource(name)
        self.assertEqual(result, True)

    def _create_verify_vpn_environment(self, name, cidr, public):
        netname = name + '-network-'
        netname = data_utils.rand_name(netname)
        network = self.os_handle.create_network(network_name=netname)
        mask_bit = int(cidr.split("/")[1])
        gateway_ip = cidr.split("/")[0][:cidr.rfind(".")] + ".1"
        cidr = netaddr.IPNetwork(cidr)
        subkwargs = { 'name' : netname }
        subnet = (
            self.os_handle.create_subnet(
                network, gateway=gateway_ip,
                cidr=cidr, mask_bits=mask_bit, **subkwargs
            )
        )
        routername = name + '-router-'
        routername = data_utils.rand_name(routername)
        router = self.os_handle.create_router(router_name=routername)
        self.os_handle.routers_client.add_router_interface_with_args(
            router['id'], subnet['id']
        )
        self.os_handle.routers_client.set_router_gateway_with_args(
            router['id'], public['network']['id']
        )
        self.os_data_struct.insert_resource(router['name'],
                                       user_data = { 'name' : routername },
                                       os_data = router,
                                       parent = 'CMS')
        self.os_data_struct.insert_resource(subnet['name'],
                                       user_data = { 'name' : netname,
                                                     'cidr' : cidr,
                                                     'gateway' : gateway_ip },
                                       os_data = subnet,
                                       parent = router['name'])
        return subnet, router

    def _delete_verify_vpn_environment(self, router, subnet):
        self.os_handle.routers_client.delete_router(
            router['id'])
        self.os_handle.networks_client.delete_network(
            subnet['network_id'])
        self.os_data_struct.delete_resource(subnet['name'])
        self.os_data_struct.delete_resource(router['name'])

    def _create_verify_vpnservice(self, name, router, subnet):
        name = name + '-vpnservice-'
        name = data_utils.rand_name(name)
        # Creating a VPNService
        vpnservice = (
            self.os_handle.vpnaas_client.create_vpnservice(
                router['id'], subnet['id'], name
            )
        )
        # Adding to os_data_struct
        self.os_data_struct.insert_resource(
            name, user_data = { 'name' : name,
                                'router' : router['id'],
                                'subnet' : subnet['id'] },
            os_data = vpnservice, parent = router['name'])

        # Showing the created VPNService
        vpnservice_info = self.os_handle.vpnaas_client.show_vpnservice(
            vpnservice['vpnservice']['id'])
        self.assertEqual(vpnservice_info['name'], name)

        # Verifying that the dummy router and subnet is created
        self._verify_vpnaas_dummy_router(router, subnet, vpnservice['vpnservice'])
        return vpnservice['vpnservice']

    def _verify_vpnaas_dummy_router(self, router, subnet, vpnservice):
        #Creating Dummy Router and subnet name
        dummy_router_name = 'r_d_' + router['id']
        dummy_subnet_name = 's_d_' + subnet['id']

        # Searching for dummy router in neutron
        dummy_router_info = (
            self.os_handle.routers_client.show_router(dummy_router_name)
        )
        dummy_router_info = dummy_router_info['router']
        import pdb;pdb.set_trace()
        self.assertEqual(dummy_router_info['name'], dummy_router_name)
        self.os_data_struct.insert_resource(
            dummy_router_name, os_data = dummy_router_info,
            parent = vpnservice['name']
        )

        # Searching for dummy subnet in neutron
        dummy_subnet_info = (
            self.os_handle.subnets_client.show_subnet(dummy_subnet_name)
        )
        dummy_subnet_info = dummy_subnet_info['subnet']
        self.assertEqual(dummy_subnet_info['name'], dummy_subnet_name)
        self.os_data_struct.insert_resource(
            dummy_subnet_name, os_data = dummy_subnet_info,
            parent = dummy_router_name
        )

    def _delete_verify_vpnservice(self, id, name):
        # Deleting the VPNService
        self.os_handle.vpnaas_client.delete_vpnservice(id)
        # Verifying delete in list VPNService
        vpnservices = self.os_handle.vpnaas_client.list_vpnservice()
        result = self._verify_resource_list(id, vpnservices, False)
        # Deleting from os_data_struct
        self.os_data_struct.delete_resource(name)
        self.assertEqual(result, True)

    def _create_verify_ipsecsiteconnection(self, vpnservice_id, ikepolicy_id,
                                           ipsecpolicy_id, peer_address,
                                           peer_id, peer_cidrs, psk,
                                           name, parent):
        name = name + '-ipsecsiteconnection-'
        name = data_utils.rand_name(name)
        # Creating a IPSecSiteConnection
        ipsecsiteconnection = (
            self.os_handle.vpnaas_client.create_ipsecsiteconnection(
                vpnservice_id, ikepolicy_id, ipsecpolicy_id,
                peer_address, peer_id, peer_cidrs, psk, name
            )
        )
        # Adding to os_data_struct
        self.os_data_struct.insert_resource(
            name, user_data = { 'name' : name,
                                'vpnservice_id' : vpnservice_id,
                                'ikepolicy_id' : ikepolicy_id,
                                'ipsecpolicy_id' : ipsecpolicy_id,
                                'peer_address' : peer_address,
                                'peer_id' : peer_id,
                                'peer_cidrs' : peer_cidrs,
                                'psk' : psk },
            os_data = ipsecsiteconnection, parent = parent)
 
        # Showing the created IPSecSiteConnection
        ipsecsiteconnection_info = (
            self.os_handle.vpnaas_client.show_ipsecsiteconnection(
                ipsecsiteconnection['ipsecsiteconnection']['id']
            )
        )
        self.assertEqual(ipsecsiteconnection_info['name'], name)
        return ipsecsiteconnection['ipsecsiteconnection']

    def _delete_verify_ipsecsiteconnection(self, id, name):
        # Deleting the VPNService
        self.os_handle.vpnaas_client.delete_ipsecsiteconnection(id)
        # Verifying delete in list VPNService
        ipsecsiteconnections = (
            self.os_handle.vpnaas_client.list_ipsecsiteconnection()
        )
        result = self._verify_resource_list(id, ipsecsiteconnections, False)
        self.os_data_struct.delete_resource(name)
        self.assertEqual(result, True)

    @test.attr(type='smoke')
    @nuage_test.header()
    def test_create_delete_ikepolicy(self):
        # Create Verify
        ikepolicy = self._create_verify_ikepolicy('ikepolicy')
        ikepolicy_id = ikepolicy['id']
        ikepolicy_name = ikepolicy['name']
        # Delete Verify
        self._delete_verify_ikepolicy(
            ikepolicy_id, ikepolicy_name
        )

    def test_create_delete_ipsecpolicy(self):
        # Create Verify
        ipsecpolicy = self._create_verify_ipsecpolicy('ipsecpolicy')
        ipsecpolicy_id = ipsecpolicy['id']
        ipsecpolicy_name = ipsecpolicy['name']
        # Delete Verify
        self._delete_verify_ipsecpolicy(
            ipsecpolicy_id, ipsecpolicy_name
        )

    def test_create_delete_vpnservice(self):
        name = 'vpn'
        pubnetid = CONF.network.public_network_id
        pubnet = self.os_handle.networks_client.show_network(pubnetid)
        # Creating Site for VPN Service
        subnet, router = (
            self._create_verify_vpn_environment(
                name, '10.20.0.0/24', pubnet
            )
        )
        # Storing vsd verification tagname
        self.os_data_struct.insert_resource(
            'routertag', user_data = {'name': router['name']}
        )
        self.os_data_struct.insert_resource(
            'subnettag', user_data = {'name': subnet['name']}
        )
        # Create Verify VPNService
        vpnservice = self._create_verify_vpnservice(
            name, router, subnet
        )

        tag_name = 'verify_vpn_dummy_router'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

        # Delete Verify VPNService
        self._delete_verify_vpnservice(
            vpnservice['id'], vpnservice['name'],
        )
        # Delete environment
        self._delete_verify_vpn_environment(
            router, subnet
        )

    def test_create_duplicate_vpnservice(self):
        name = 'vpn'
        pubnetid = CONF.network.public_network_id
        pubnet = self.os_handle.networks_client.show_network(pubnetid)
        # Creating Site for VPN Service
        subnet, router = (
            self._create_verify_vpn_environment(
                name, '10.20.0.0/24', pubnet
            )
        )
        # Create First Verify VPNService
        vpnservice = self._create_verify_vpnservice(
            name, router, subnet
        )

        # Create Duplicate VPNService
        vpnservice2 = (
            self.os_handle.vpnaas_client.create_vpnservice(
                router['id'], subnet['id'], name, False,
            )
        )
        
        # Delete Verify VPNService
        self._delete_verify_vpnservice(
            vpnservice['id'], vpnservice['name']
        )
        # Delete environment
        self._delete_verify_vpn_environment(
            router, subnet
        )

    def test_create_delete_ipsecsiteconnection(self):
        pubnetid = CONF.network.public_network_id
        pubnet = self.os_handle.networks_client.show_network(pubnetid)

        # Creating Site1
        name1 = 'vpn1'
        cidr1 = '10.20.0.0/24'
        subnet1, router1 = (
            self._create_verify_vpn_environment(
                name1, cidr1, pubnet
            )
        )

        # VPN1
        vpnservice1 = self._create_verify_vpnservice(
            name1, router1, subnet1
        )

        # Creating Site2
        name2 = 'vpn2'
        cidr2 = '10.30.0.0/24'
        subnet2, router2 = (
            self._create_verify_vpn_environment(
                name2, cidr2, pubnet
            )
        )

        # VPN2
        vpnservice2 = self._create_verify_vpnservice(
            name2, router2, subnet2
        )

        tag_name = 'verify_vpn_dummy_router'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

        # Creating IKE Policy
        ikepolicy = self._create_verify_ikepolicy('ikepolicy')
        ikepolicy_id = ikepolicy['id']
        ikepolicy_name = ikepolicy['name']

        # Creating IPSecPolicy
        ipsecpolicy = self._create_verify_ipsecpolicy('ipsecpolicy')

        ipsecpolicy_id = ipsecpolicy['id']
        ipsecpolicy_name = ipsecpolicy['name']

        # Creating IPSecSiteConnection1
        vpn_ip1 = vpnservice1['external_v4_ip']
        ipsecsiteconnection1 = (
            self._create_verify_ipsecsiteconnection(
                vpnservice1['id'], ikepolicy_id,
                ipsecpolicy_id, vpn_ip1, vpn_ip1,
                cidr1, 'secret', name1, vpnservice1['name']
            )
        )

        # Creating IPSecSiteConnection2
        vpn_ip2 = vpnservice2['external_v4_ip']
        ipsecsiteconnection2 = (
            self._create_verify_ipsecsiteconnection(
                vpnservice2['id'], ikepolicy_id,
                ipsecpolicy_id, vpn_ip2, vpn_ip2,
                cidr2, 'secret', name2, vpnservice2['name']
            )
        )

        tag_name = 'verify_ipsec_vminterface'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

        # Delete IPSecSiteconnections
        self._delete_verify_ipsecsiteconnection(
            ipsecsiteconnection1['id'], ipsecsiteconnection1['name']
        )
        self._delete_verify_ipsecsiteconnection(
            ipsecsiteconnection2['id'], ipsecsiteconnection2['name']
        )

        # Delete VPNService
        self._delete_verify_vpnservice(
            vpnservice1['id'], vpnservice1['name']
        )
        self._delete_verify_vpnservice(
            vpnservice2['id'], vpnservice2['name']
        )

        # Delete IKEpolicy and IPSecPolicy
        self._delete_verify_ipsecpolicy(
            ipsecpolicy_id, ipsecpolicy_name
        )
        self._delete_verify_ikepolicy(
            ikepolicy_id, ikepolicy_name
        )

        # Delete Routers and Subnets
        self._delete_verify_vpn_environment(
            router1, subnet1
        )
        self._delete_verify_vpn_environment(
            router2, subnet2
        )
