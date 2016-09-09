# Copyright 2015 Alcatel-Lucent

from netaddr import *

from tempest import config
from tempest.lib.common.utils import data_utils

from nuagetempest.lib.utils import constants as constants
import base_nuage_extra_dhcp_options

from base_nuage_extra_dhcp_options import NUAGE_NETWORK_TYPE

CONF = config.CONF


class NuageExtraDHCPOptionsBaseL3(base_nuage_extra_dhcp_options.NuageExtraDHCPOptionsBase):
    @classmethod
    def resource_setup(cls):
        super(NuageExtraDHCPOptionsBaseL3, cls).resource_setup()

        cls.vsd_l3dom_template = []
        cls.vsd_l3domain = []
        cls.vsd_zone = []
        cls.vsd_subnet = []

        # Create a L3 OS managed network and find its corresponding VSD peer
        network_name = data_utils.rand_name('extra-dhcp-opt-L3-network')
        cls.osmgd_l3_network = cls.create_network(network_name=network_name)
        cidr = IPNetwork('99.99.99.0/24')
        cls.osmgd_l3_subnet = cls.create_subnet(cls.osmgd_l3_network, cidr=cidr, mask_bits=cidr.prefixlen)
        router_name = data_utils.rand_name('extra-dhcp-opt-router')
        cls.router = cls.create_router(router_name=router_name, admin_state_up=True)
        cls.create_router_interface(cls.router['id'], cls.osmgd_l3_subnet['id'])
        cls.os_l3_port = cls.create_port(cls.osmgd_l3_network)
        cls.nuage_domain = cls.nuage_vsd_client.get_resource(
            constants.DOMAIN,
            filters='externalID',
            filter_value=cls.nuage_vsd_client.get_vsd_external_id(cls.router['id']))
        cls.osmgd_l3_subnet = cls.nuage_vsd_client.get_domain_subnet(
            constants.DOMAIN, cls.nuage_domain[0]['ID'],
            filters='externalID', filter_value=cls.nuage_vsd_client.get_vsd_external_id(cls.osmgd_l3_subnet['id']))

        # Create a L3 VSD Managed and link to its OS network
        name = data_utils.rand_name('l3domain')
        cls.vsd_l3dom_tmplt = cls.create_vsd_l3dom_template(
            name=name)
        cls.vsd_l3dom = cls.create_vsd_l3domain(name=name,
                                                tid=cls.vsd_l3dom_tmplt[0]['ID'])
        zonename = data_utils.rand_name('l3dom-zone')
        cls.vsd_zone = cls.create_vsd_zone(name=zonename,
                                           domain_id=cls.vsd_l3dom[0]['ID'])
        subname = data_utils.rand_name('l3dom-sub')
        cidr = IPNetwork('10.10.100.0/24')
        cls.vsd_domain_subnet = cls.create_vsd_l3domain_subnet(
            name=subname,
            zone_id=cls.vsd_zone[0]['ID'],
            cidr=cidr,
            gateway='10.10.100.1')
        # create subnet on OS with nuagenet param set to subnet UUID
        net_name = data_utils.rand_name('vsdmgd-network')
        cls.vsdmgd_l3_network = cls.create_network(network_name=net_name)
        cls.vsdmgd_l3_subnet = cls.create_subnet(cls.vsdmgd_l3_network,
                                                 cidr=cidr, mask_bits=24, nuagenet=cls.vsd_domain_subnet[0]['ID'],
                                                 net_partition=CONF.nuage.nuage_default_netpartition)

    @classmethod
    def resource_cleanup(cls):
        # Delete VSD managed OpenStack resources BEFORE deletion of the VSD resources
        # Otherwise, VSD resource will not be able to remove all child resources
        # when these are CMS managed. (e.g. permissions, groups and users)
        cls._try_delete_resource(cls.networks_client.delete_network,
                                 cls.vsdmgd_l3_network['id'])

        for vsd_subnet in cls.vsd_subnet:
            cls.nuage_vsd_client.delete_domain_subnet(vsd_subnet[0]['ID'])

        for vsd_zone in cls.vsd_zone:
            cls.nuage_vsd_client.delete_zone(vsd_zone['ID'])

        for vsd_l3domain in cls.vsd_l3domain:
            cls.nuage_vsd_client.delete_domain(vsd_l3domain[0]['ID'])

        for vsd_l3dom_template in cls.vsd_l3dom_template:
            cls.nuage_vsd_client.delete_l3domaintemplate(vsd_l3dom_template[0]['ID'])
        super(NuageExtraDHCPOptionsBaseL3, cls).resource_cleanup()

    def _nuage_create_show_list_update_port_with_extra_dhcp_options(self,
                                                                    nuage_network_type,
                                                                    extra_dhcp_opts,
                                                                    new_extra_dhcp_opts):
        # do the test for requested nuage network type
        if  nuage_network_type == NUAGE_NETWORK_TYPE['OS_Managed_L3']:
            self._nuage_create_list_show_update_layer_x_port_with_extra_dhcp_options(
                self.osmgd_l3_network['id'], self.nuage_domain[0]['ID'],
                nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        elif nuage_network_type == NUAGE_NETWORK_TYPE['VSD_Managed_L3']:
            self._nuage_create_list_show_update_layer_x_port_with_extra_dhcp_options(
                self.vsdmgd_l3_network['id'], self.vsd_l3dom[0]['ID'],
                nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        else:
            self.assertTrue(False, 'Unknown NUAGE_NETWORK_TYPE detected')
        pass

    @classmethod
    def create_vsd_l3dom_template(cls, **kwargs):
        vsd_l3dom_tmplt = cls.nuage_vsd_client.create_l3domaintemplate(
            kwargs['name'] + '-template')
        cls.vsd_l3dom_template.append(vsd_l3dom_tmplt)
        return vsd_l3dom_tmplt

    @classmethod
    def create_vsd_l3domain(cls, **kwargs):
        vsd_l3dom = cls.nuage_vsd_client.create_domain(kwargs['name'],
                                                       kwargs['tid'])
        cls.vsd_l3domain.append(vsd_l3dom)
        return vsd_l3dom

    @classmethod
    def create_vsd_zone(cls, **kwargs):
        vsd_zone = cls.nuage_vsd_client.create_zone(kwargs['domain_id'],
                                                    kwargs['name'])
        cls.vsd_zone.append(vsd_zone)
        return vsd_zone

    @classmethod
    def create_vsd_l3domain_subnet(cls, **kwargs):
        vsd_subnet = cls.nuage_vsd_client.create_domain_subnet(kwargs['zone_id'],
                                                               kwargs['name'],
                                                               str(kwargs['cidr'].ip),
                                                               str(kwargs['cidr'].netmask),
                                                               kwargs['gateway'])
        cls.vsd_subnet.append(vsd_subnet)
        return vsd_subnet


class NuageExtraDHCPOptionsOSManagedL3Test(NuageExtraDHCPOptionsBaseL3):
    #
    # Openstack Managed Layer 3 networks
    #
    def __init__(self, *args, **kwargs):
        super(NuageExtraDHCPOptionsOSManagedL3Test, self).__init__(*args, **kwargs)
        self.nuage_network_type = NUAGE_NETWORK_TYPE['OS_Managed_L3']
        self.vsd_parent_type = constants.DOMAIN

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_001_netmask(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_001_netmask()

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_002_time_offset(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_002_time_offset()

    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_003_routers(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_003_routers()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_004_time_server(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_004_time_server()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_006_dns_server(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_006_dns_server()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_007_log_server(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_007_log_server()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_009_lpr_server(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_009_lpr_server()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_012_hostname(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_012_hostname()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_013_boot_file_size(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_013_boot_file_size()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_015_domain_name(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_015_domain_name()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_016_swap_server(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_016_swap_server()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_017_root_path(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_017_root_path()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_018_extension_path(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_018_extension_path()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_019_ip_forward_enable(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_019_ip_forward_enable()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_020_non_local_source_routing(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_020_non_local_source_routing()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_021_policy_filter(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_021_policy_filter()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_022_max_datagram_reassembly(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_022_max_datagram_reassembly()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_023_default_ttl(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_023_default_ttl()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_026_mtu(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_026_mtu()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_027_all_subnets_local(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_027_all_subnets_local()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_028_broadcast(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_028_broadcast()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_031_router_discovery(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_031_router_discovery()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_032_router_solicitation(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_032_router_solicitation()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_033_static_route(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_033_static_route()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_034_trailer_encapsulation(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_034_trailer_encapsulation()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_035_arp_timeout(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_035_arp_timeout()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_036_ethernet_encap(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_036_ethernet_encap()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_037_tcp_ttl(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_037_tcp_ttl()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_038_tcp_keepalive(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_038_tcp_keepalive()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_040_nis_domain(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_040_nis_domain()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_041_nis_server(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_041_nis_server()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_042_ntp_server(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_042_ntp_server()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_044_netbios_ns(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_044_netbios_ns()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_045_netbios_dd(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_045_netbios_dd()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_046_netbios_nodetype(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_046_netbios_nodetype()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_047_netbios_scope(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_047_netbios_scope()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_048_x_windows_fs(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_048_x_windows_fs()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_049_x_windows_dm(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_049_x_windows_dm()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_050_requested_address(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_050_requested_address()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_060_vendor_class(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_060_vendor_class()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_064_nisplus_domain(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_064_nisplus_domain()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_065_nisplus_server(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_065_nisplus_server()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_066_tftp_server(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_066_tftp_server()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_067_bootfile_name(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_067_bootfile_name()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_068_mobile_ip_home(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_068_mobile_ip_home()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_069_smtp_server(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_069_smtp_server()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_070_pop3_server(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_070_pop3_server()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_071_nntp_server(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_071_nntp_server()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_074_irc_server(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_074_irc_server()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_077_user_class(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_077_user_class()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_093_client_arch(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_093_client_arch()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_094_client_interface_id(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_094_client_interface_id()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_097_client_machine_id(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_097_client_machine_id()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_119_domain_search(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_119_domain_search()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_120_sip_server(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_120_sip_server()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_121_classless_static_route(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_121_classless_static_route()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_125_vendor_id_encap(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_125_vendor_id_encap()
    #
    # def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_255_server_ip_address(self):
    #     self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_255_server_ip_address()
    #
    # def test_nuage_openstack_managed_layer3_port_with_16_extra_dhcp_options(self):
    #     self._check_nuage_create_show_list_update_port_with_16_extra_dhcp_options()
    #

class NuageExtraDHCPOptionsVsdManagedL3Test(NuageExtraDHCPOptionsOSManagedL3Test):
    #
    # VSD Managed Layer 3 networks
    #
    def __init__(self, *args, **kwargs):
        super(NuageExtraDHCPOptionsVsdManagedL3Test, self).__init__(*args, **kwargs)
        self.nuage_network_type = NUAGE_NETWORK_TYPE['VSD_Managed_L3']
        self.vsd_parent_type = constants.DOMAIN
