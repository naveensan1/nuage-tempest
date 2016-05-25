from oslo_log import log as logging

from tempest.scenario import manager
from tempest import config
from tempest.api.compute import base as serv_base
from nuagetempest.lib import topology
from nuagetempest.lib import base
from nuagetempest.lib import test_base
from nuagetempest.lib.openstackData import openstackData
from nuagetempest.tests.api import test_vpnaas
import netaddr

LOG = logging.getLogger(__name__)
CONF = config.CONF
TB = topology.testbed


class VPNaaSScenarioTest(test_vpnaas.VPNaaSBase,
                         serv_base.BaseV2ComputeTest):

    @classmethod
    def resource_setup(self):
        super(VPNaaSScenarioTest, self).resource_setup()
        self.os_handle = TB.osc_1.api
        self.vsd_handle = TB.vsd_1

    @classmethod
    def resource_cleanup(self):
        self.os_data_struct.delete_resource(self.def_net_partition)

    def _create_fip_resources(self):
        for i in range(2):
            # Creating the FIP
            fipnetname = 'FIP-net-'+str(i)
            fipkwargs = {'name':fipnetname, 'router:external':True}
            fipnetwork = (
                self.os_handle.admin_networks_client.create_network(**fipkwargs)
            )
            self.os_data_struct.insert_resource(\
                fipnetname, os_data=fipnetwork, \
                user_data=fipkwargs, parent='CMS')
            # Providing FIP Subnet Values
            fipaddr = '172.20.' + str(i) + '.0'
            fipgw = '172.20.' + str(i) + '.1'
            fipcidr = fipaddr + '/24'
            fipsubname = 'FIP-sub-'+str(i)
            fipsubkwargs = {'name':fipsubname, \
                'cidr': fipcidr, 'gateway_ip': fipgw, \
                'network_id': fipnetwork['network']['id'], \
                'ip_version': 4}
            self.addCleanup(\
                self.os_handle.admin_networks_client.delete_network, \
                fipnetwork['network']['id'])
            if i == 0:
                fipsubnet = (
                    self.os_handle.admin_subnets_client.create_subnet(\
                        **fipsubkwargs)
                )
                fip_ext_id = (
                    test_base.get_external_id(fipsubnet['subnet']['id'])
                )
                fip_vsd = self.vsd_handle.get_shared_network_resource(\
                    filter=test_base.get_filter_str('externalID',fip_ext_id))
                fip_vsd_parent_id = fip_vsd.parent_id
            else:
                fipsubkwargs['nuage_uplink'] = fip_vsd_parent_id
                fipsubnet = (
                    self.os_handle.admin_subnets_client.create_subnet(\
                        **fipsubkwargs)
                )
            self.addCleanup(self.os_handle.admin_subnets_client.delete_subnet, \
                fipsubnet['subnet']['id'])
            self.os_data_struct.insert_resource(\
                fipsubname, os_data=fipsubnet, \
                user_data=fipsubkwargs, parent=fipnetname)
            # Creating Networks/Subnets/Router Environment for Site
            # Router Create
            routername = 'router-'+str(i)
            router = (
                self.os_handle.routers_client.create_router(routername)
            )
            self.os_data_struct.insert_resource(\
                routername, os_data=router, \
                user_data={'name':routername}, parent=self.def_net_partition)
            self.addCleanup(self.os_handle.routers_client.delete_router, \
                router['router']['id'])
            # Network Create
            netname = 'network-'+str(i)
            netkwargs = {'name': netname}
            network = (
                self.os_handle.networks_client.create_network(**netkwargs)
            )
            self.os_data_struct.insert_resource(\
                    netname, os_data=network, \
                    user_data=netkwargs, parent=routername)
            self.addCleanup(self.os_handle.networks_client.delete_network, \
                network['network']['id'])
            # Subnet Create
            subname =  'subnet-'+str(i)
            subcidrpre = '26.' + str(i) + '.0'
            subaddr = subcidrpre + '.0'
            subgateway = subcidrpre + '.1'
            cidr = subaddr + '/24'
            subkwargs = {'name':subname, \
                         'cidr': cidr, 'gateway_ip': subgateway, \
                         'network_id': network['network']['id'], \
                         'ip_version': 4}
            subnet = (
                self.os_handle.subnets_client.create_subnet(**subkwargs)
            )
            self.addCleanup(self.os_handle.subnets_client.delete_subnet, \
                subnet['subnet']['id'])
            self.os_data_struct.insert_resource(\
                    subname, os_data=subnet, \
                    user_data=subkwargs, parent=netname)
            # Router interface add
            routerintkwargs = {'subnet_id':subnet['subnet']['id']}
            self.os_handle.routers_client.add_router_interface(\
                router['router']['id'], **routerintkwargs)
            self.addCleanup(\
                self.os_handle.routers_client.remove_router_interface, \
                router['router']['id'], **routerintkwargs)
            # Router gateway set
            routergwkwargs = (
                {'external_gateway_info':{'network_id':fipnetwork['network']['id']}}
            )
            self.os_handle.routers_client.update_router(\
                router['router']['id'], **routergwkwargs)
            routernogwkwargs = (
                {'external_gateway_info':''}
            )
            self.addCleanup(\
                self.os_handle.routers_client.update_router, \
                router['router']['id'], **routernogwkwargs)
            import pdb; pdb.set_trace()
            # VM Booting
            vmname = 'VM-'+str(i)
            vmkwargs = {'name':vmname, 'flavorRef': '1', \
                'imageRef':CONF.compute.image_ref, \
                'uuid': network['network']['id']}
            vm = self.os_handle.servers_client.create_server(**vmkwargs)
            self.os_data_struct.insert_resource(\
                    vmname, os_data=vm, \
                    user_data=vmkwargs, parent=subnetname)
            # create VPN-Service
            import pdb; pdb.set_trace()

            vpnname = 'VPN-'+str(i)
            vpnkwargs = {'name':vpnname}
            vpnservice = (
                self.os_handle.vpnservice_client.create_vpnservice(\
                router['router']['id'], subnet['subnet']['id'], **vpnkwargs)
            )
            vpnkwargs['router'] = router['router']['id']
            vpnkwargs['subnet'] = subnet['subnet']['id']
            self.addCleanup(self.os_handle.vpnservice_client.delete_vpnservice, \
                vpnservice['id'])
            self.os_data_struct.insert_resource(\
                vpnname, os_data=vpnservice, \
                user_data=vpnkwargs, parent=routername)

    def _createikepolicy_ipsecpolicy(self):
        # Creating IKEPolicy
        ikepolicyname = 'IKEPolicy'
        ikepolicy = (
            self.os_handle.ikepolicy_client.create_ikepolicy(ikepolicyname)
        )
        # Creating IPSecPolicy
        ipsecpolicyname = 'IPSecPolicy'
        ipsecpolicy = (
            self.os_handle.ipsecpolicy_client.create_ipsecpolicy(ipsecpolicyname)
        )
        return ikepolicy, ipsecpolicy

    def _create_ipsecsiteconnection(self, vpn1, vpn2, \
                     subnet2, ikepolicy, ipsecpolicy, name, vpntag):
        # Creating the IPSecSiteConnection
        ipnkwargs = { 'name': name }
        ipsecsiteconnection =\
        self.os_handle.ipsecsiteconnection_client.create_ipsecsiteconnection(\
            vpn1['id'], ikepolicy['id'], ipsecpolicy['id'], \
            vpn2['external_v4_ip'], vpn2['external_v4_ip'], \
            subnet2['cidr'], 'secret', **ipnkwargs
        )
        self.addCleanup(\
        self.os_handle.ipsecsiteconnection_client.delete_ipsecsiteconnection,\
        ipsecsiteconnection['id'])
        self.os_data_struct.insert_resource(name, \
            user_data={'vpn1': vpn1['id'], \
                       'vpn2': vpn2['id'], \
                       'remotecidr': subnet2['cidr'],
                       'secret': 'secret',
                       'name': 'name'}, \
            os_data=ipsecsiteconnection, parent=vpntag)
        return ipsecsiteconnection

    def test_vpnaas_end_to_end(self):
        """ Tests create/show/list/delete of two ipsecsiteconnection
        in two different vpnservices and test end to end connectivity """
        self._create_fip_resources()

        router1 = self.os_data_struct.get_resource('router-0').os_data
        router2 = self.os_data_struct.get_resource('router-1').os_data
        subnet1 = self.os_data_struct.get_resource('subnet-0').os_data
        subnet2 = self.os_data_struct.get_resource('subnet-1').os_data
        vpn1 = self.os_data_struct.get_resource('VPN-0').os_data
        vpn2 = self.os_data_struct.get_resource('VPN-1').os_data

        ikepolicy, ipsecpolicy = self._createikepolicy_ipsecpolicy()

        # Creating the IPSecSiteConnection
        ipsecsiteconnection1 = (
            self._create_ipsecsiteconnection(\
                vpn1, vpn2, subnet2, ikepolicy, ipsecpolicy, \
                'ipsecconn0', 'VPN-0')
        )

        ipsecsiteconnection2 = (
            self._create_ipsecsiteconnection(\
                vpn2, vpn1, subnet1, ikepolicy, ipsecpolicy, \
                'ipsecconn1', 'VPN-1')
        )
         
