# Copyright 2015 Alcatel-Lucent

from netaddr import *
from oslo_log import log as logging

from tempest import test
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.api.network import base

from nuagetempest.lib.utils import constants as constants
from nuagetempest.services import nuage_client

CONF = config.CONF

VERY_LONG_STRING = '\
kljflkajdfkadjflakfjaklfjadkfkjhfkjdhjklhfjhfnkljfhkjfh,kjhkvjhuhkjhfkjfhkldjfhkljfhaklfhadjklfhakrqrqerqwerqerqerqerq\
lfjhadkljfhfjhadklfjhadklfhafhaklfhfadkjfhadjkfhakljfhakljfhkadjfhkadjfhakdjfhadjkfhakdjfhkadjfhakldjfhakjfhkadjfhkadj\
fhadjklfhakljfhakldjfhakljfhakldjfhakjfhakldhfadjkhfkadjfhdjkfhdjkjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj\
jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj'

# 300 characters in the very big number
VERY_BIG_NUMBER = '\
12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890\
1234567890123456789012345678901234567890'

#
#  See http://tools.ietf.org/html/rfc2132
#
DHCP_OPTION_NUMBER_TO_NAME = {
    # 'pad': 0,  # In Decimal 0
    1: 'netmask',
    2: 'time-offset',
    3: 'router',
    4: 'time-server',
    6: 'dns-server',
    7: 'log-server',
    8: 'quotes-server',     # not in dnsmasq
    9: 'lpr-server',
    10: 'impress_server',   # not in dnsmasq
    11: 'rlp-server',       # not in dnsmasq
    12: 'hostname',
    13: 'boot-file-size',
    15: 'domain-name',
    16: 'swap-server',
    17: 'root-path',
    18: 'extension-path',
    19: 'ip-forward-enable',
    20: 'non-local-source-routing',
    21: 'policy-filter',
    22: 'max-datagram-reassembly',
    23: 'default-ttl',
    24: 'mtu_timeout',  #
    25: 'mtu_plateau',  #
    26: 'mtu',
    27: 'all-subnets-local',
    28: 'broadcast',
    29: 'mask-discovery',  # not in dnsmasq
    30: 'mask-supplier',  # not in dnsmasq
    31: 'router-discovery',
    32: 'router-solicitation',
    33: 'static-route',
    34: 'trailer-encapsulation',
    35: 'arp-timeout',
    36: 'ethernet-encap',
    37: 'tcp-ttl',
    38: 'tcp-keepalive',
    39: 'keep-alive-data',  # not in dnsmasq
    40: 'nis-domain',
    41: 'nis-server',
    42: 'ntp-server',
    43: 'vendor-specific',  # not in dnsmasq
    44: 'netbios-ns',
    45: 'netbios-dd',
    46: 'netbios-nodetype',
    47: 'netbios-scope',
    48: 'x-windows-fs',
    49: 'x-windows-dm',
    50: 'requested-address',
    51: 'address-time',  # not in dnsmasq
    52: 'overload',  # not in dnsmasq
    53: 'dhcp-msg-type',  # not in dnsmasq
    54: 'dhcp-server-id',  # not in dnsmasq
    55: 'parameter-list',  # not in dnsmasq
    56: 'dhcp-message',  # not in dnsmasq
    57: 'dhcp-max-msg-size',  # not in dnsmasq
    58: 'renewal-time',  # not in dnsmasq
    59: 'rebinding-time',  # not in dnsmasq
    60: 'vendor-class',
    61: 'client-id',  # not in dnsmasq
    62: 'netware/ip_domain',  # not in dnsmasq
    63: 'netware/ip_option',  # not in dnsmasq
    64: 'nis+-domain',
    65: 'nis+-server',
    66: 'tftp-server',
    67: 'bootfile-name',
    68: 'mobile-ip-home',
    69: 'smtp-server',
    70: 'pop3-server',
    71: 'nntp-server',
    72: 'www_server',  # not yet supported,
    73: 'finger_server',  # not yet supported,
    74: 'irc-server',
    75: 'streettalk-server',  # not yet supported,
    76: 'stda-server',  # not yet supported,
    77: 'user-class',
    78: 'directory_agent',  # In Decimal 78 - 0x4E not yet supported
    79: 'service_scope',  # In Decimal 79 - 0x4F not yet supported
    80: 'rapid_commit',  # In Decimal 80 - 0x50 not yet supported
    81: 'client_fqdn',  # In Decimal 81 - 0x51 not yet supported
    82: 'relay_agent_information',  # 0x52 not yet supported
    83: 'isns',  # 0x53 not yet supported
    93: 'client-arch',
    94: 'client-interface-id',
    97: 'client-machine-id',
    119: 'domain-search',
    120: 'sip-server',
    121: 'classless-static-route',
    125: 'vendor-id-encap',
    255: 'server-ip-address'
}


# Some options are treated as raw hex, (for easier comparison with the VSD dhcp options response)
TREAT_DHCP_OPTION_AS_RAW_HEX = [
    'client-machine-id',
    'classless-static-route',
    'client-interface-id',
    'vendor-id-encap',
    'server-ip-address'
]

# For easier vsd dhcp options comparison
TREAT_DHCP_OPTION_NETBIOS_NODETYPE = [
    'netbios-nodetype'
]

# Use these values for negative tests on ip addresses
BAD_IPV4_ADDRESSES = [
    '10.20.30.400',
    '-1.20.30.40',
    '255.0.0.351',
    'a.b.c.d',
    'we.want.you.now',
    'rubbish',
    VERY_LONG_STRING,
    '10.20.30.40;400.300.200.100'
]

# Bad values for those options treated as string
# numbers will be treated as strings, so no need to specify them here ...
BAD_STRING_TYPE_VALUES = [
    VERY_LONG_STRING,
    ''
]

# Upstream does only type checking, use these 'bad' integer values for all options that are int
BAD_INTEGER_TYPE_VALUES = [
    VERY_LONG_STRING,
    VERY_BIG_NUMBER,
    'some_small string'
]

# Distinghuih the 4 different cases
NUAGE_NETWORK_TYPE = {
    'OS_Managed_L2':  1,
    'OS_Managed_L3':  2,
    'VSD_Managed_L2': 3,
    'VSD_Managed_L3': 4
}


class NuageExtraDHCPOptionsBase(base.BaseAdminNetworkTest):

    LOG = logging.getLogger(__name__)

    @classmethod
    def skip_checks(cls):
        super(NuageExtraDHCPOptionsBase, cls).skip_checks()
        if not test.is_extension_enabled('extra_dhcp_opt', 'network'):
            msg = "Extra DHCP Options extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(NuageExtraDHCPOptionsBase, cls).setup_clients()
        cls.nuage_vsd_client = nuage_client.NuageRestClient()
        # os = cls.get_client_manager()
        #
        # # TODO: Hendrik: only use admin credentials where required!
        cls.client = cls.admin_client

    @classmethod
    def resource_setup(cls):
        super(NuageExtraDHCPOptionsBase, cls).resource_setup()

        cls.vsd_l2dom_template = []
        cls.vsd_l2domain = []
        cls.vsd_l3dom_template = []
        cls.vsd_l3domain = []
        cls.vsd_zone = []
        cls.vsd_subnet = []

        # Create a L2 OS managed network and find its corresponding VSD peer
        cls.osmgd_l2_network = cls.create_network()
        cls.osmgd_l2_subnet = cls.create_subnet(cls.osmgd_l2_network)
        # Find the "network:dhcp:nuage" port created by nuage
        cls.os_l2_port = cls.create_port(cls.osmgd_l2_network)
        cls.l2domain = cls.nuage_vsd_client.get_l2domain(
            'externalID',
            cls.nuage_vsd_client.get_vsd_external_id(cls.osmgd_l2_subnet['id'])
        )
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

        # Create a L2 VSD managed network and link to its OS network
        name = data_utils.rand_name('l2domain')
        vsd_l2_cidr = IPNetwork('100.100.100.0/24')
        cls.vsd_l2dom_tmpl = cls.create_vsd_dhcpmanaged_l2dom_template(name=name,
                                                                       cidr=vsd_l2_cidr,
                                                                       gateway='100.100.100.1')
        cls.vsd_l2dom = cls.create_vsd_l2domain(name=name,
                                                tid=cls.vsd_l2dom_tmpl[0]['ID'])
        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network')
        cls.vsdmgd_l2_network = cls.create_network(network_name=net_name)
        netpartition = CONF.nuage.nuage_default_netpartition
        cls.vsdmgd_l2_subnet = cls.create_subnet(cls.vsdmgd_l2_network,
                                                 gateway=None,
                                                 cidr=vsd_l2_cidr,
                                                 mask_bits=24,
                                                 nuagenet=cls.vsd_l2dom[0]['ID'],
                                                 net_partition=netpartition,
                                                 enable_dhcp=True)
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
        # cls._try_delete_resource(cls.client.delete_port,
        #                          cls.os_l2_port['id'])
        # cls._try_delete_resource(cls.client.delete_network,
        #                          cls.osmgd_l2_network['id'])
        # cls._try_delete_resource(cls.client.delete_port,
        #                          cls.os_l3_port['id'])
        # cls._try_delete_resource(cls.client.delete_router,
        #                          cls.router['id'])
        # cls._try_delete_resource(cls.client.delete_network,
        #                          cls.osmgd_l3_network['id'])

        # delete VSD managed OpenStack resources BEFORE deletion of the VSD resources
        # Otherwise, VSD resource will not be able to remove all child resources
        # when these are CMS managed. (e.g. permissions, groups and users)
        cls._try_delete_resource(cls.networks_client.delete_network,
                                 cls.vsdmgd_l2_network['id'])

        cls._try_delete_resource(cls.networks_client.delete_network,
                                 cls.vsdmgd_l3_network['id'])

        for vsd_l2domain in cls.vsd_l2domain:
            cls.nuage_vsd_client.delete_l2domain(vsd_l2domain[0]['ID'])

        for vsd_l2dom_template in cls.vsd_l2dom_template:
            cls.nuage_vsd_client.delete_l2domaintemplate(vsd_l2dom_template[0]['ID'])

        for vsd_subnet in cls.vsd_subnet:
            cls.nuage_vsd_client.delete_domain_subnet(vsd_subnet[0]['ID'])

        for vsd_zone in cls.vsd_zone:
            cls.nuage_vsd_client.delete_zone(vsd_zone['ID'])

        for vsd_l3domain in cls.vsd_l3domain:
            cls.nuage_vsd_client.delete_domain(vsd_l3domain[0]['ID'])

        for vsd_l3dom_template in cls.vsd_l3dom_template:
            cls.nuage_vsd_client.delete_l3domaintemplate(vsd_l3dom_template[0]['ID'])
        super(NuageExtraDHCPOptionsBase, cls).resource_cleanup()

    def _create_network(self, external=True):
        if external:
            post_body = {'name': data_utils.rand_name('ext-network'), 'router:external': external}
        else:
            post_body = {'name': data_utils.rand_name('network')}
        body = self.admin_networks_client.create_network(**post_body)
        network = body['network']
        self.addCleanup(self.admin_networks_client.delete_network, network['id'])
        return network

    def _create_port_with_extra_dhcp_options(self, network_id, extra_dhcp_opts, client=None):
        # allow tests to use admin client
        if not client:
            client = self.ports_client

        name = data_utils.rand_name('extra-dhcp-opt-port-name')
        create_body = client.create_port(
            name=name,
            network_id=network_id,
            extra_dhcp_opts=extra_dhcp_opts)
        self.addCleanup(client.delete_port, create_body['port']['id'])

    def _update_port_with_extra_dhcp_options(self, port_id, extra_dhcp_opts, client=None):
        # allow tests to use admin client
        if not client:
            client = self.ports_client
        name = data_utils.rand_name('updated-extra-dhcp-opt-port-name')
        update_body = client.update_port(
            port_id,
            name=name,
            extra_dhcp_opts=extra_dhcp_opts)
        # Confirm extra dhcp options were added to the port
        self._confirm_extra_dhcp_options(update_body['port'], extra_dhcp_opts)
        upd_show_body = client.show_port(port_id)
        self._confirm_extra_dhcp_options(upd_show_body['port'], extra_dhcp_opts)

    def _nuage_create_list_show_update_layer_x_port_with_extra_dhcp_options(self, network_id,
                                                                            vsd_network_id,
                                                                            nuage_network_type,
                                                                            extra_dhcp_opts,
                                                                            new_extra_dhcp_opts):
        # Create a port with given extra DHCP Options on an Openstack layer X managed network
        name = data_utils.rand_name('extra-dhcp-opt-port-name')
        create_body = self.ports_client.create_port(
            name=name,
            network_id=network_id,
            extra_dhcp_opts=extra_dhcp_opts)
        port_id = create_body['port']['id']
        self.addCleanup(self.ports_client.delete_port, port_id)
        # Does the response contain the extra dhcp otions we passed in the request
        self._confirm_extra_dhcp_options(create_body['port'], extra_dhcp_opts)
        # Confirm port created has Extra DHCP Options via show
        show_body = self.ports_client.show_port(port_id)
        self._confirm_extra_dhcp_options(show_body['port'], extra_dhcp_opts)
        # Confirm port created has Extra DHCP Options via lis ports
        list_body = self.ports_client.list_ports()
        ports = list_body['ports']
        port = [p for p in ports if p['id'] == port_id]
        self.assertTrue(port)
        self._confirm_extra_dhcp_options(port[0], extra_dhcp_opts)
        # Depending on the network type (L2 or L3) fetch the appropriate domain/subnet from the VSD
        if nuage_network_type in [NUAGE_NETWORK_TYPE['OS_Managed_L3'], NUAGE_NETWORK_TYPE['VSD_Managed_L3']]:
            parent = constants.DOMAIN
        else:
            parent = constants.L2_DOMAIN
        vports = self.nuage_vsd_client.get_vport(parent,
                                                 vsd_network_id,
                                                 'externalID',
                                                 self.nuage_vsd_client.get_vsd_external_id(port_id))
        vsd_dchp_options = self.nuage_vsd_client.get_dhcpoption(constants.VPORT, vports[0]['ID'])
        self._verify_vsd_extra_dhcp_options(vsd_dchp_options, extra_dhcp_opts)
        # update
        name = data_utils.rand_name('new-extra-dhcp-opt-port-name')
        update_body = self.ports_client.update_port(
            port_id,
            name=name,
            extra_dhcp_opts=new_extra_dhcp_opts)
        # Confirm extra dhcp options were added to the port
        # OPENSTACK-1059: update response contains old dhcp options
        self._confirm_extra_dhcp_options(update_body['port'], new_extra_dhcp_opts)
        upd_show_body = self.ports_client.show_port(port_id)
        self._confirm_extra_dhcp_options(upd_show_body['port'], new_extra_dhcp_opts)
        vsd_dchp_options = self.nuage_vsd_client.get_dhcpoption(constants.VPORT, vports[0]['ID'])
        self._verify_vsd_extra_dhcp_options(vsd_dchp_options, new_extra_dhcp_opts)
        pass

    def _nuage_create_show_list_update_port_with_extra_dhcp_options(self,
                                                                    nuage_network_type,
                                                                    extra_dhcp_opts,
                                                                    new_extra_dhcp_opts):
        # do the test for requested nuage network type
        if nuage_network_type == NUAGE_NETWORK_TYPE['OS_Managed_L2']:
            self._nuage_create_list_show_update_layer_x_port_with_extra_dhcp_options(
                self.osmgd_l2_network['id'], self.l2domain[0]['ID'],
                nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        elif nuage_network_type == NUAGE_NETWORK_TYPE['OS_Managed_L3']:
            self._nuage_create_list_show_update_layer_x_port_with_extra_dhcp_options(
                self.osmgd_l3_network['id'], self.nuage_domain[0]['ID'],
                nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        elif nuage_network_type == NUAGE_NETWORK_TYPE['VSD_Managed_L2']:
            self._nuage_create_list_show_update_layer_x_port_with_extra_dhcp_options(
                self.vsdmgd_l2_network['id'], self.vsd_l2dom[0]['ID'],
                nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        elif nuage_network_type == NUAGE_NETWORK_TYPE['VSD_Managed_L3']:
            self._nuage_create_list_show_update_layer_x_port_with_extra_dhcp_options(
                self.vsdmgd_l3_network['id'], self.vsd_l3dom[0]['ID'],
                nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        else:
            self.assertTrue(False, 'Unknown NUAGE_NETWORK_TYPE detected')
        pass

    def _confirm_extra_dhcp_options(self, port, extra_dhcp_opts):
        retrieved = port['extra_dhcp_opts']
        self.assertEqual(len(retrieved), len(extra_dhcp_opts))
        for retrieved_option in retrieved:
            for option in extra_dhcp_opts:
                if (retrieved_option['opt_value'] == option['opt_value'] and
                            retrieved_option['opt_name'] == option['opt_name']):
                    break
            else:
                self.fail('Extra DHCP option not found in port %s' %
                          str(retrieved_option))

    # function to be able to convert the value in to a VSD supported hex format
    def _convert_to_hex(self, value):
        hex_val = str(value[2:])
        if len(hex_val) % 2 != 0:
            length = len(hex_val) + 1
        else:
            length = len(hex_val)
        hex_val = hex_val.zfill(length)
        return hex_val

    def _convert_netbios_type(self, value):
        if value == '0x1':
            result = 'B-node'
        elif value == '0x2':
            result = 'P-node'
        elif value == '0x4':
            result = 'M-node'
        elif value == '0x8':
            result = 'H-node'
        else:
            result = 'error'
        return result

    def _convert_to_vsd_opt_values(self, opt_values, opt_name):
        # convert all elements in the openstack extra dhcp option value list into the format return by VSD
        # so we can use easy list comparison
        tmp_var = ""
        if opt_name in TREAT_DHCP_OPTION_AS_RAW_HEX:
            for opt_value in opt_values:
                # opt_values[opt_value.index(opt_value)] = self.my_convert_to_hex(opt_value)
                tmp_var += self._convert_to_hex(opt_value)
            opt_values = [tmp_var]
        if opt_name in TREAT_DHCP_OPTION_NETBIOS_NODETYPE:
            for opt_value in opt_values:
                # opt_values[opt_value.index(opt_value)] = self.my_convert_to_hex(opt_value)
                tmp_var += self._convert_netbios_type(opt_value)
            opt_values = [tmp_var]
        return opt_values

    def _verify_vsd_extra_dhcp_options(self, vsd_dchp_options, extra_dhcp_opts):
        # Verify the contents of the extra dhcp options returned by VSD (vsd_dhcp_options)
        # with the corresponding contents of the extra dhcp options passed to the plugin (extra_dhcp_opt)
        # The format is different, hence a more complex comparison loop
        for retrieved_option in vsd_dchp_options:
            for option in extra_dhcp_opts:
                # VSD returns option numbers, not names: convert
                vsd_opt_name = DHCP_OPTION_NUMBER_TO_NAME[retrieved_option['actualType']]
                vsd_opt_value = retrieved_option['actualValues']
                # Make a local list copy from option['opt_value'], using the separator ";"
                option_value_list = option['opt_value'].split(";")
                # Special trick for opt_name='router' and opt_value='0.0.0.0' which is converted into '00'
                # when sending to VSD,
                if vsd_opt_name == 'router' and option_value_list == ['0.0.0.0']:
                    if retrieved_option['value'] == '00':
                        vsd_opt_value = ['0.0.0.0']
                elif vsd_opt_name == 'server-ip-address':
                    # option 255 is treated bizarre in openstack. It should not contain any data, but for OS it does
                    # use that value in 'value' instead of 'actualValues'
                    vsd_opt_value = [retrieved_option['value']]
                elif vsd_opt_name == 'user-class':
                    # in case of 'user-class', the value as passed to OS is available in the 'value' field
                    # just prepend with '0x' to lign up completely with what was passed to the plugin
                    vsd_opt_value = ['0x' + str(retrieved_option['value'])]
                elif vsd_opt_name == 'classless-static-route':
                    # 'actualValues' contains a nice UI format (cidr + ip address).
                    # Use the encode value in the 'value' field
                    vsd_opt_value = [retrieved_option['value']]
                # Compare element by element, as the VSD stores it all in hex ...
                converted_os_opt_values = self._convert_to_vsd_opt_values(option_value_list, option['opt_name'])
                if converted_os_opt_values == vsd_opt_value and vsd_opt_name == option['opt_name']:
                    # Now check whether the length of this value > 0
                    if retrieved_option['length'] != '00':
                        break
                    else:
                        # don't fail yet, log to put all zero-length options in the log file
                        self.LOG.warning("VSD has extra DHCP option - %s of length zero !" % str(vsd_opt_name))
            else:
                self.fail('Extra DHCP option mismatch VSD  and Openstack')

    #
    # We need a kind of "library" with common nuage methods
    # For now: copied from test_vsd_manged_network.py, as this refactoring cannot be done in the scope of the
    # current release (3.2-R5)
    # ToDo: Solve properly
    #
    @classmethod
    def create_vsd_dhcpmanaged_l2dom_template(cls, **kwargs):
        params = {
            'DHCPManaged': True,
            'address': str(kwargs['cidr'].ip),
            'netmask': str(kwargs['cidr'].netmask),
            'gateway': kwargs['gateway']
        }
        vsd_l2dom_tmplt = cls.nuage_vsd_client.create_l2domaintemplate(
            kwargs['name'] + '-template', extra_params=params)
        cls.vsd_l2dom_template.append(vsd_l2dom_tmplt)
        return vsd_l2dom_tmplt

    @classmethod
    def create_vsd_l2domain(cls, **kwargs):
        vsd_l2dom = cls.nuage_vsd_client.create_l2domain(kwargs['name'],
                                                         templateId=kwargs['tid'])
        cls.vsd_l2domain.append(vsd_l2dom)
        return vsd_l2dom

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

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_001_netmask(self, nuage_network_type):
        # Create a port with Extra DHCP Options nbr 1 netmask
        extra_dhcp_opts = [
            {'opt_value': '255.255.255.0', 'opt_name': 'netmask'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '255.255.255.0', 'opt_name': 'netmask'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_002_time_offset(self, nuage_network_type):
        # Create a port with Extra DHCP Options two's complement 32-bit integer
        extra_dhcp_opts = [
            {'opt_value': '100', 'opt_name': 'time-offset'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '2137', 'opt_name': 'time-offset'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_003_routers(self, nuage_network_type):
        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '10.20.3.100', 'opt_name': 'router'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.3.200;10.20.3.201', 'opt_name': 'router'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        # Check value 0.0.0.0, which should disable the default route
        extra_dhcp_opts = [
            {'opt_value': '0.0.0.0', 'opt_name': 'router'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1.1.1.1;10.20.3.201', 'opt_name': 'router'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_004_time_server(self, nuage_network_type):

        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '10.20.4.100', 'opt_name': 'time-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.4.200;10.20.4.201', 'opt_name': 'time-server'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

        # def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_005_nameserver(self):
        #     pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_006_dns_server(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.6.100', 'opt_name': 'dns-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '100.20.6.200;10.20.6.201', 'opt_name': 'dns-server'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_007_log_server(self, nuage_network_type):
        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '10.20.7.100', 'opt_name': 'log-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.7.200;10.20.7.201', 'opt_name': 'log-server'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_009_lpr_server(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.9.100', 'opt_name': 'lpr-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.9.200;10.20.9.201', 'opt_name': 'lpr-server'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_012_hostname(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': 'edo.nuagenetworks.net', 'opt_name': 'hostname'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'updated.edo.nuagenetworks.net', 'opt_name': 'hostname'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_013_boot_file_size(self, nuage_network_type):
        # Create a port with Extra DHCP Options
        # file length is specified as an unsigned 16-bit integer
        extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'boot-file-size'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '2049', 'opt_name': 'boot-file-size'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        extra_dhcp_opts = [
            {'opt_value': '65535', 'opt_name': 'boot-file-size'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_015_domain_name(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': 'nuagenetworks.net', 'opt_name': 'domain-name'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'other.nuagenetworks.net', 'opt_name': 'domain-name'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_016_swap_server(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.16.100', 'opt_name': 'swap-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.16.200', 'opt_name': 'swap-server'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_017_root_path(self, nuage_network_type):

        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '/opt/nuage/root-path', 'opt_name': 'root-path'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '/opt/other-path/nuage/root-path', 'opt_name': 'root-path'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_018_extension_path(self, nuage_network_type):

        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '/opt/nuage/extension-path', 'opt_name': 'extension-path'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '/opt/other-path/nuage/extension-path', 'opt_name': 'extension-path'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_019_ip_forward_enable(self,
                                                                                                nuage_network_type):

        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '0', 'opt_name': 'ip-forward-enable'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'ip-forward-enable'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_020_non_local_source_routing(
            self,
            nuage_network_type):

        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '0', 'opt_name': 'non-local-source-routing'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'non-local-source-routing'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_021_policy_filter(self, nuage_network_type):

        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '10.20.21.100;255.255.255.0', 'opt_name': 'policy-filter'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.21.200;255.255.255.0;10.20.21.201;255.255.0.0', 'opt_name': 'policy-filter'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_022_max_datagram_reassembly(
            self,
            nuage_network_type):

        # Create a port with Extra DHCP Options 16 bit unsigned int min value = 576
        extra_dhcp_opts = [
            {'opt_value': '576', 'opt_name': 'max-datagram-reassembly'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '65535', 'opt_name': 'max-datagram-reassembly'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_023_default_ttl(self, nuage_network_type):

        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'default-ttl'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '255', 'opt_name': 'default-ttl'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_026_mtu(self, nuage_network_type):

        # Create a port with Extra DHCP Options. 16-bit unsigned integer.  The minimum legal value for the MTU is 68.
        extra_dhcp_opts = [
            {'opt_value': '68', 'opt_name': 'mtu'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '9000', 'opt_name': 'mtu'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        extra_dhcp_opts = [
            {'opt_value': '65535', 'opt_name': 'mtu'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_027_all_subnets_local(self,
                                                                                                nuage_network_type):

        extra_dhcp_opts = [
            {'opt_value': '0', 'opt_name': 'all-subnets-local'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'all-subnets-local'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_028_broadcast(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.28.255', 'opt_name': 'broadcast'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.28.28.255', 'opt_name': 'broadcast'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_031_router_discovery(self,
                                                                                               nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '0', 'opt_name': 'router-discovery'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'router-discovery'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_032_router_solicitation(self,
                                                                                                  nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.32.100', 'opt_name': 'router-solicitation'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.32.200', 'opt_name': 'router-solicitation'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_033_static_route(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.33.10;10.33.33.33', 'opt_name': 'static-route'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.33.33.0;10.33.33.33;10.33.34.0;10.33.34.10', 'opt_name': 'static-route'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_034_trailer_encapsulation(self,
                                                                                                    nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '0', 'opt_name': 'trailer-encapsulation'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'trailer-encapsulation'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_035_arp_timeout(self, nuage_network_type):
        # Create a port with Extra DHCP Options 32-bit unsigned integer
        extra_dhcp_opts = [
            {'opt_value': '1023', 'opt_name': 'arp-timeout'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '123', 'opt_name': 'arp-timeout'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        new_extra_dhcp_opts = [
            {'opt_value': str(constants.MAX_INT), 'opt_name': 'arp-timeout'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_036_ethernet_encap(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '0', 'opt_name': 'ethernet-encap'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'ethernet-encap'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_037_tcp_ttl(self, nuage_network_type):
        # Create a port with Extra DHCP Options 8 bit unsigned
        extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'tcp-ttl'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '255', 'opt_name': 'tcp-ttl'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_038_tcp_keepalive(self, nuage_network_type):
        # Create a port with Extra DHCP Options MAX_32BIT_UNSIGNED
        extra_dhcp_opts = [
            {'opt_value': '0', 'opt_name': 'tcp-keepalive'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1024', 'opt_name': 'tcp-keepalive'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        extra_dhcp_opts = [
            {'opt_value': str(constants.MAX_UNSIGNED_INT32), 'opt_name': 'tcp-keepalive'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_040_nis_domain(self, nuage_network_type):
        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': 'nis.nuagenetworks.net', 'opt_name': 'nis-domain'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'new-nis.nuagenetworks.net', 'opt_name': 'nis-domain'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_041_nis_server(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.41.100', 'opt_name': 'nis-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.41.200;10.20.41.201', 'opt_name': 'nis-server'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_042_ntp_server(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.42.100', 'opt_name': 'ntp-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.42.200;10.20.42.201', 'opt_name': 'ntp-server'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_044_netbios_ns(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.44.100', 'opt_name': 'netbios-ns'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.44.200;10.20.44.201', 'opt_name': 'netbios-ns'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_045_netbios_dd(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.45.100', 'opt_name': 'netbios-dd'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.45.200;10.20.45.201', 'opt_name': 'netbios-dd'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_046_netbios_nodetype(self,
                                                                                               nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '0x1', 'opt_name': 'netbios-nodetype'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0x2', 'opt_name': 'netbios-nodetype'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        extra_dhcp_opts = [
            {'opt_value': '0x4', 'opt_name': 'netbios-nodetype'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0x8', 'opt_name': 'netbios-nodetype'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_047_netbios_scope(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': 'nuage.netbios.scope.com', 'opt_name': 'netbios-scope'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'new.nuage.netbios.scope.com', 'opt_name': 'netbios-scope'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_048_x_windows_fs(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.47.100', 'opt_name': 'x-windows-fs'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.47.200;10.20.47.201', 'opt_name': 'x-windows-fs'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_049_x_windows_dm(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.48.100', 'opt_name': 'x-windows-dm'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.48.200;10.20.48.201', 'opt_name': 'x-windows-dm'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_050_requested_address(self,
                                                                                                nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.50.100', 'opt_name': 'requested-address'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.50.200', 'opt_name': 'requested-address'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_060_vendor_class(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '0401020304', 'opt_name': 'vendor-class'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '06010203040506', 'opt_name': 'vendor-class'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_064_nisplus_domain(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': 'nisplus.nuagenetworks.net', 'opt_name': 'nis+-domain'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'newer.nisplus.nuagenetworks.net', 'opt_name': 'nis+-domain'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_065_nisplus_server(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.65.100', 'opt_name': 'nis+-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.65.200;10.20.65.201', 'opt_name': 'nis+-server'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_066_tftp_server(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': 'tftp-server.nuagenetworks.net', 'opt_name': 'tftp-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'newer-tftp-server.nuagenetworks.net', 'opt_name': 'tftp-server'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_067_bootfile_name(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '/opt/nuage/bootfile-name', 'opt_name': 'bootfile-name'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '/opt/newer-nuage/newer-bootfile-name', 'opt_name': 'bootfile-name'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_068_mobile_ip_home(self, nuage_network_type):
        # Create a port with Extra DHCP Options: zero or more addresses
        extra_dhcp_opts = [
            {'opt_value': '10.20.68.100', 'opt_name': 'mobile-ip-home'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.68.20;200.20.68.201', 'opt_name': 'mobile-ip-home'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_069_smtp_server(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.69.100', 'opt_name': 'smtp-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.69.20;200.20.69.201', 'opt_name': 'smtp-server'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_070_pop3_server(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.70.10', 'opt_name': 'pop3-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.70.200;10.20.70.201', 'opt_name': 'pop3-server'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_071_nntp_server(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.71.100', 'opt_name': 'nntp-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.71.200;10.20.71.201', 'opt_name': 'nntp-server'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_074_irc_server(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '10.20.74.100', 'opt_name': 'irc-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.74.200;10.20.74.201', 'opt_name': 'irc-server'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_077_user_class(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '0x080001020304050607', 'opt_name': 'user-class'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0x1000010203040506070809aabbccddeeff', 'opt_name': 'user-class'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_093_client_arch(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '0;2;5', 'opt_name': 'client-arch'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '3;6;9', 'opt_name': 'client-arch'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_094_client_interface_id(self,
                                                                                                  nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '0x01020b', 'opt_name': 'client-interface-id'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0x01030f', 'opt_name': 'client-interface-id'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_097_client_machine_id(self,
                                                                                                nuage_network_type):
        # Create a port with Extra DHCP Options: first octet = zero (only valid value for this octet for now)
        extra_dhcp_opts = [
            {'opt_value': '0x000f0e0d0c0b0a09080706050403020100', 'opt_name': 'client-machine-id'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0x00ffeeddccbbaa99887766554433221100', 'opt_name': 'client-machine-id'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_119_domain_search(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': 'sales.domain.com;eng.domain.org', 'opt_name': 'domain-search'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'eng.domain.com;marketing.domain.com', 'opt_name': 'domain-search'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_120_sip_server(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': 'sip.domain.com', 'opt_name': 'sip-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'sip-updated.domain.com;sip2.domain.com', 'opt_name': 'sip-server'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_121_classless_static_route(
            self,
            nuage_network_type):
        # Create a port with Extra DHCP Options: see http://tools.ietf.org/html/rfc3442
        # Subnet number   Subnet mask      Destination descriptor
        # 10.17.0.0       255.255.0.0      16.10.17         -> r = 10.11.12.13 0x0a0b0c0d
        # 10.229.0.128    255.255.255.128  25.10.229.0.128  -> r = 10.11.12.14 0x0a0b0c0e
        # 10.198.122.47   255.255.255.255  32.10.198.122.47
        extra_dhcp_opts = [
            {'opt_value': '0x100a110a0b0c0d', 'opt_name': 'classless-static-route'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0X190ae500800a0b0c0e;0x100a110a0b0c0d', 'opt_name': 'classless-static-route'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_125_vendor_id_encap(self, nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '0x0a1679000a167901', 'opt_name': 'vendor-id-encap'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0x0a167a000a167a01;0x0a167b000a167b01', 'opt_name': 'vendor-id-encap'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_extra_dhcp_options_255_server_ip_address(self,
                                                                                                nuage_network_type):
        extra_dhcp_opts = [
            {'opt_value': '0x100a110a0b0c0d', 'opt_name': 'server-ip-address'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0X190ae500800a0b0c0e;0x100a110a0b0c0d', 'opt_name': 'server-ip-address'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts,
                                                                         new_extra_dhcp_opts)
        pass

    def _check_nuage_create_show_list_update_port_with_16_extra_dhcp_options(self, nuage_network_type):
        # Check whether the maximum of 16 dhcp option in one go is ok
        extra_dhcp_opts_16 = [
            {'opt_value': '255.255.255.0', 'opt_name': 'netmask'},
            {'opt_value': '200', 'opt_name': 'time-offset'},
            {'opt_value': '11.33.66.3', 'opt_name': 'router'},
            {'opt_value': '11.33.66.4', 'opt_name': 'time-server'},
            {'opt_value': '11.33.66.6', 'opt_name': 'dns-server'},
            {'opt_value': '11.33.66.7', 'opt_name': 'log-server'},
            {'opt_value': '11.33.66.9', 'opt_name': 'lpr-server'},
            {'opt_value': 'more-than16-hostname', 'opt_name': 'hostname'},
            {'opt_value': '8192', 'opt_name': 'boot-file-size'},
            {'opt_value': 'more-than16.domain.com', 'opt_name': 'domain-name'},
            {'opt_value': '11.33.66.16', 'opt_name': 'swap-server'},
            {'opt_value': '/opt/more-than16/root-path', 'opt_name': 'root-path'},
            {'opt_value': '/opt/more-than16/extension-path', 'opt_name': 'extension-path'},
            {'opt_value': '1', 'opt_name': 'ip-forward-enable'},
            {'opt_value': '1', 'opt_name': 'non-local-source-routing'},
            {'opt_value': '1576', 'opt_name': 'max-datagram-reassembly'}
        ]
        self._nuage_create_show_list_update_port_with_extra_dhcp_options(nuage_network_type,
                                                                         extra_dhcp_opts_16,
                                                                         extra_dhcp_opts_16)


class NuageExtraDHCPOptionsJSON(NuageExtraDHCPOptionsBase):
    """
    Tests the following operations with the Extra DHCP Options Neutron API
    extension:

        port create
        port list
        port show
        port update

    v2.0 of the Neutron API is assumed. It is also assumed that the Extra
    DHCP Options extension (extra_dhcp_opt)is enabled in the [network-feature-enabled]
    section of etc/tempest.conf
    """
    #
    # Openstack Manged Layer 2 networks
    #
    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_001_netmask(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_001_netmask(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_002_time_offset(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_002_time_offset(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_003_routers(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_003_routers(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_004_time_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_004_time_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_006_dns_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_006_dns_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_007_log_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_007_log_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_009_lpr_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_009_lpr_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_012_hostname(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_012_hostname(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_013_boot_file_size(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_013_boot_file_size(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_015_domain_name(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_015_domain_name(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_016_swap_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_016_swap_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_017_root_path(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_017_root_path(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_018_extension_path(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_018_extension_path(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_019_ip_forward_enable(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_019_ip_forward_enable(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_020_non_local_source_routing(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_020_non_local_source_routing(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_021_policy_filter(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_021_policy_filter(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_022_max_datagram_reassembly(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_022_max_datagram_reassembly(

            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_023_default_ttl(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_023_default_ttl(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_026_mtu(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_026_mtu(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_027_all_subnets_local(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_027_all_subnets_local(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_028_broadcast(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_028_broadcast(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_031_router_discovery(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_031_router_discovery(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_032_router_solicitation(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_032_router_solicitation(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_033_static_route(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_033_static_route(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_034_trailer_encapsulation(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_034_trailer_encapsulation(

            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_035_arp_timeout(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_035_arp_timeout(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_036_ethernet_encap(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_036_ethernet_encap(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_037_tcp_ttl(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_037_tcp_ttl(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_038_tcp_keepalive(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_038_tcp_keepalive(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_040_nis_domain(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_040_nis_domain(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_041_nis_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_041_nis_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_042_ntp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_042_ntp_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_044_netbios_ns(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_044_netbios_ns(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_045_netbios_dd(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_045_netbios_dd(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_046_netbios_nodetype(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_046_netbios_nodetype(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_047_netbios_scope(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_047_netbios_scope(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_048_x_windows_fs(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_048_x_windows_fs(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_049_x_windows_dm(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_049_x_windows_dm(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_050_requested_address(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_050_requested_address(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_060_vendor_class(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_060_vendor_class(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_064_nisplus_domain(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_064_nisplus_domain(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_065_nisplus_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_065_nisplus_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_066_tftp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_066_tftp_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_067_bootfile_name(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_067_bootfile_name(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_068_mobile_ip_home(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_068_mobile_ip_home(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_069_smtp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_069_smtp_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_070_pop3_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_070_pop3_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_071_nntp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_071_nntp_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_074_irc_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_074_irc_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_077_user_class(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_077_user_class(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_093_client_arch(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_093_client_arch(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_094_client_interface_id(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_094_client_interface_id(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_097_client_machine_id(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_097_client_machine_id(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_119_domain_search(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_119_domain_search(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_120_sip_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_120_sip_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_121_classless_static_route(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_121_classless_static_route(

            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_125_vendor_id_encap(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_125_vendor_id_encap(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_extra_dhcp_options_255_server_ip_address(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_255_server_ip_address(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])

    def test_nuage_openstack_managed_layer2_port_with_16_extra_dhcp_options(self):
        self._check_nuage_create_show_list_update_port_with_16_extra_dhcp_options(
            NUAGE_NETWORK_TYPE['OS_Managed_L2'])
    #
    # Openstack Manged Layer 3 networks
    #

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_001_netmask(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_001_netmask(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_002_time_offset(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_002_time_offset(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_003_routers(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_003_routers(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_004_time_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_004_time_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_006_dns_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_006_dns_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_007_log_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_007_log_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_009_lpr_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_009_lpr_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_012_hostname(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_012_hostname(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_013_boot_file_size(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_013_boot_file_size(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_015_domain_name(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_015_domain_name(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_016_swap_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_016_swap_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_017_root_path(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_017_root_path(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_018_extension_path(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_018_extension_path(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_019_ip_forward_enable(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_019_ip_forward_enable(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_020_non_local_source_routing(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_020_non_local_source_routing(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_021_policy_filter(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_021_policy_filter(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_022_max_datagram_reassembly(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_022_max_datagram_reassembly(

            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_023_default_ttl(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_023_default_ttl(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_026_mtu(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_026_mtu(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_027_all_subnets_local(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_027_all_subnets_local(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_028_broadcast(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_028_broadcast(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_031_router_discovery(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_031_router_discovery(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_032_router_solicitation(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_032_router_solicitation(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_033_static_route(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_033_static_route(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_034_trailer_encapsulation(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_034_trailer_encapsulation(

            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_035_arp_timeout(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_035_arp_timeout(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_036_ethernet_encap(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_036_ethernet_encap(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_037_tcp_ttl(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_037_tcp_ttl(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_038_tcp_keepalive(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_038_tcp_keepalive(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_040_nis_domain(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_040_nis_domain(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_041_nis_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_041_nis_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_042_ntp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_042_ntp_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_044_netbios_ns(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_044_netbios_ns(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_045_netbios_dd(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_045_netbios_dd(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_046_netbios_nodetype(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_046_netbios_nodetype(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_047_netbios_scope(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_047_netbios_scope(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_048_x_windows_fs(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_048_x_windows_fs(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_049_x_windows_dm(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_049_x_windows_dm(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_050_requested_address(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_050_requested_address(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_060_vendor_class(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_060_vendor_class(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_064_nisplus_domain(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_064_nisplus_domain(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_065_nisplus_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_065_nisplus_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_066_tftp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_066_tftp_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_067_bootfile_name(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_067_bootfile_name(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_068_mobile_ip_home(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_068_mobile_ip_home(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_069_smtp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_069_smtp_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_070_pop3_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_070_pop3_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_071_nntp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_071_nntp_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_074_irc_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_074_irc_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_077_user_class(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_077_user_class(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_093_client_arch(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_093_client_arch(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_094_client_interface_id(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_094_client_interface_id(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_097_client_machine_id(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_097_client_machine_id(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_119_domain_search(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_119_domain_search(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_120_sip_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_120_sip_server(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_121_classless_static_route(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_121_classless_static_route(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_125_vendor_id_encap(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_125_vendor_id_encap(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_port_with_extra_dhcp_options_255_server_ip_address(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_255_server_ip_address(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    def test_nuage_openstack_managed_layer3_create_port_with_16_extra_dhcp_options(self):
        self._check_nuage_create_show_list_update_port_with_16_extra_dhcp_options(
            NUAGE_NETWORK_TYPE['OS_Managed_L3'])

    #
    # VSD  Manged Layer 2 networks
    #
    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_001_netmask(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_001_netmask(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_002_time_offset(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_002_time_offset(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_003_routers(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_003_routers(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_004_time_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_004_time_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_006_dns_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_006_dns_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_007_log_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_007_log_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_009_lpr_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_009_lpr_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_012_hostname(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_012_hostname(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_013_boot_file_size(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_013_boot_file_size(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_015_domain_name(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_015_domain_name(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_016_swap_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_016_swap_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_017_root_path(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_017_root_path(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_018_extension_path(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_018_extension_path(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_019_ip_forward_enable(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_019_ip_forward_enable(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_020_non_local_source_routing(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_020_non_local_source_routing(

            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_021_policy_filter(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_021_policy_filter(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_022_max_datagram_reassembly(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_022_max_datagram_reassembly(

            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_023_default_ttl(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_023_default_ttl(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_026_mtu(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_026_mtu(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_027_all_subnets_local(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_027_all_subnets_local(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_028_broadcast(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_028_broadcast(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_031_router_discovery(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_031_router_discovery(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_032_router_solicitation(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_032_router_solicitation(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_033_static_route(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_033_static_route(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_034_trailer_encapsulation(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_034_trailer_encapsulation(

            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_035_arp_timeout(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_035_arp_timeout(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_036_ethernet_encap(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_036_ethernet_encap(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_037_tcp_ttl(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_037_tcp_ttl(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_038_tcp_keepalive(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_038_tcp_keepalive(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_040_nis_domain(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_040_nis_domain(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_041_nis_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_041_nis_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_042_ntp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_042_ntp_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_044_netbios_ns(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_044_netbios_ns(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_045_netbios_dd(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_045_netbios_dd(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_046_netbios_nodetype(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_046_netbios_nodetype(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_047_netbios_scope(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_047_netbios_scope(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_048_x_windows_fs(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_048_x_windows_fs(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_049_x_windows_dm(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_049_x_windows_dm(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_050_requested_address(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_050_requested_address(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_060_vendor_class(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_060_vendor_class(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_064_nisplus_domain(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_064_nisplus_domain(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_065_nisplus_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_065_nisplus_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_066_tftp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_066_tftp_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_067_bootfile_name(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_067_bootfile_name(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_068_mobile_ip_home(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_068_mobile_ip_home(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_069_smtp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_069_smtp_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_070_pop3_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_070_pop3_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_071_nntp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_071_nntp_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_074_irc_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_074_irc_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_077_user_class(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_077_user_class(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_093_client_arch(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_093_client_arch(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_094_client_interface_id(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_094_client_interface_id(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_097_client_machine_id(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_097_client_machine_id(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_119_domain_search(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_119_domain_search(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_120_sip_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_120_sip_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_121_classless_static_route(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_121_classless_static_route(

            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_125_vendor_id_encap(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_125_vendor_id_encap(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_port_with_extra_dhcp_options_255_server_ip_address(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_255_server_ip_address(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    def test_nuage_vsd_managed_layer2_create_port_with_16_extra_dhcp_options(self):
        self._check_nuage_create_show_list_update_port_with_16_extra_dhcp_options(
            NUAGE_NETWORK_TYPE['VSD_Managed_L2'])

    #
    # VSD  Manged Layer 3 networks
    #
    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_001_netmask(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_001_netmask(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_002_time_offset(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_002_time_offset(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_003_routers(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_003_routers(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_004_time_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_004_time_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_006_dns_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_006_dns_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_007_log_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_007_log_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_009_lpr_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_009_lpr_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_012_hostname(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_012_hostname(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_013_boot_file_size(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_013_boot_file_size(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_015_domain_name(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_015_domain_name(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_016_swap_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_016_swap_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_017_root_path(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_017_root_path(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_018_extension_path(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_018_extension_path(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_019_ip_forward_enable(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_019_ip_forward_enable(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_020_non_local_source_routing(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_020_non_local_source_routing(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_021_policy_filter(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_021_policy_filter(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_022_max_datagram_reassembly(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_022_max_datagram_reassembly(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_023_default_ttl(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_023_default_ttl(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_026_mtu(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_026_mtu(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_027_all_subnets_local(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_027_all_subnets_local(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_028_broadcast(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_028_broadcast(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_031_router_discovery(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_031_router_discovery(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_032_router_solicitation(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_032_router_solicitation(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_033_static_route(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_033_static_route(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_034_trailer_encapsulation(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_034_trailer_encapsulation(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_035_arp_timeout(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_035_arp_timeout(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_036_ethernet_encap(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_036_ethernet_encap(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_037_tcp_ttl(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_037_tcp_ttl(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_038_tcp_keepalive(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_038_tcp_keepalive(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_040_nis_domain(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_040_nis_domain(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_041_nis_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_041_nis_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_042_ntp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_042_ntp_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_044_netbios_ns(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_044_netbios_ns(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_045_netbios_dd(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_045_netbios_dd(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_046_netbios_nodetype(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_046_netbios_nodetype(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_047_netbios_scope(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_047_netbios_scope(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_048_x_windows_fs(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_048_x_windows_fs(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_049_x_windows_dm(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_049_x_windows_dm(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_050_requested_address(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_050_requested_address(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_060_vendor_class(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_060_vendor_class(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_064_nisplus_domain(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_064_nisplus_domain(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_065_nisplus_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_065_nisplus_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_066_tftp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_066_tftp_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_067_bootfile_name(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_067_bootfile_name(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_068_mobile_ip_home(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_068_mobile_ip_home(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_069_smtp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_069_smtp_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_070_pop3_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_070_pop3_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_071_nntp_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_071_nntp_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_074_irc_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_074_irc_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_077_user_class(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_077_user_class(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_093_client_arch(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_093_client_arch(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_094_client_interface_id(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_094_client_interface_id(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_097_client_machine_id(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_097_client_machine_id(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_119_domain_search(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_119_domain_search(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_120_sip_server(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_120_sip_server(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_121_classless_static_route(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_121_classless_static_route(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_125_vendor_id_encap(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_125_vendor_id_encap(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_port_with_extra_dhcp_options_255_server_ip_address(self):
        self._check_nuage_create_show_list_update_port_with_extra_dhcp_options_255_server_ip_address(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])

    def test_nuage_vsd_managed_layer3_create_port_with_16_extra_dhcp_options(self):
        self._check_nuage_create_show_list_update_port_with_16_extra_dhcp_options(
            NUAGE_NETWORK_TYPE['VSD_Managed_L3'])


class NuageExtraDHCPOptionsNegativeTest(NuageExtraDHCPOptionsBase):
    """
    Negative tests on
        port create
        port list
        port show
        port update

    v2.0 of the Neutron API is assumed. It is also assumed that the Extra
    DHCP Options extension (extra_dhcp_opt)is enabled in the [network-feature-enabled]
    section of etc/tempest.conf
    """

    @classmethod
    def skip_checks(cls):
        super(NuageExtraDHCPOptionsNegativeTest, cls).skip_checks()
        if not test.is_extension_enabled('extra_dhcp_opt', 'network'):
            msg = "Extra DHCP Options extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(NuageExtraDHCPOptionsNegativeTest, cls).resource_setup()

        # L2 OS managed network
        cls.osmgd_l2_network = cls.create_network()
        cls.osmgd_l2_subnet = cls.create_subnet(cls.osmgd_l2_network)
        cls.os_l2_port = cls.create_port(cls.osmgd_l2_network)
        cls.l2domain = cls.nuage_vsd_client.get_l2domain(
            'externalID',
            cls.nuage_vsd_client.get_vsd_external_id(cls.osmgd_l2_subnet['id'])
        )

    def _assert_nuage_create_port_with_extra_dhcp_options(self, network_id, extra_dhcp_opts):
        # Create a port with valid opt-name but invalid opt-value(s)
        self.assertRaises(exceptions.BadRequest,
                          self._create_port_with_extra_dhcp_options,
                          network_id,
                          extra_dhcp_opts)

    def _assert_nuage_update_port_with_extra_dhcp_options(self, port, extra_dhcp_opts):
        # Update an existing port with valid opt-name but invalid opt-value(s)
        self.assertRaises(exceptions.BadRequest,
                          self._update_port_with_extra_dhcp_options,
                          port,
                          extra_dhcp_opts)

    def _assert_create_update_port_with_bad_extra_dhcp_options_neg(self, network_id, bad_values, opt_name):
        for opt_value in bad_values:
            extra_dhcp_opts = [
                {'opt_value': opt_value, 'opt_name': opt_name}
            ]
            self.assertRaises(exceptions.BadRequest,
                              self._create_port_with_extra_dhcp_options,
                              network_id,
                              extra_dhcp_opts)
            self.assertRaises(exceptions.BadRequest,
                              self._update_port_with_extra_dhcp_options,
                              self.os_l2_port['id'],
                              extra_dhcp_opts)

    def test_nuage_create_port_with_extra_dhcp_options_001_netmask_neg(self):
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES, 'netmask')

    def test_nuage_create_port_with_extra_dhcp_options_002_time_offset_neg(self):
        # Create a port with Extra DHCP Options two's complement 32-bit integer
        network_id = self.osmgd_l2_network['id']
        bad_values = ['rubbish',
                      str(constants.MAX_UNSIGNED_INT32_PLUS_ONE),
                      VERY_LONG_STRING]
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, bad_values, 'netmask')

    def test_nuage_create_port_with_extra_dhcp_options_003_router_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES, 'router')

    def test_nuage_create_port_with_extra_dhcp_options_004_time_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        bad_values = ['rubbish',
                      str(constants.MAX_UNSIGNED_INT32_PLUS_ONE),
                      VERY_LONG_STRING]
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, bad_values, 'time-server')

    def test_nuage_create_port_with_extra_dhcp_options_006_dns_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES,
                                                                        'dns-server')

    def test_nuage_create_port_with_extra_dhcp_options_007_log_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES,
                                                                        'log-server')

    def test_nuage_create_port_with_extra_dhcp_options_009_lpr_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES,
                                                                        'lpr-server')

    def test_nuage_create_port_with_extra_dhcp_options_012_hostname_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        bad_values = [
            VERY_LONG_STRING]
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, bad_values,
                                                                        'hostname')

    def test_nuage_create_port_with_extra_dhcp_options_013_boot_file_size_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'boot-file-size')

    def test_nuage_create_port_with_extra_dhcp_options_015_domain_name_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_STRING_TYPE_VALUES,
                                                                        'domain-name')

    def test_nuage_create_port_with_extra_dhcp_options_016_swap_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES,
                                                                        'swap-server')

    def test_nuage_create_port_with_extra_dhcp_options_017_root_path_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_STRING_TYPE_VALUES,
                                                                        'root-path')

    def test_nuage_create_port_with_extra_dhcp_options_018_extension_path_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_STRING_TYPE_VALUES,
                                                                        'extension-path')

    def test_nuage_create_port_with_extra_dhcp_options_019_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'ip-forward-enable')

    def test_nuage_create_port_with_extra_dhcp_options_020_non_local_source_routing_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'non-local-source-routing')

    def test_nuage_create_port_with_extra_dhcp_options_021_policy_filter_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        bad_values = ['10.20.21.200;255.255.256.0',
                      '10.20.21.300;255.255.255.0',
                      '10.20.21.401;255.255.0.',
                      str(constants.MAX_UNSIGNED_INT32_PLUS_ONE),
                      VERY_LONG_STRING]
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, bad_values, 'policy-filter')

    def test_nuage_create_port_with_extra_dhcp_options_022_max_datagram_reassembly_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'max-datagram-reassembly')

    def test_nuage_create_port_with_extra_dhcp_options_023_default_ttl_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'default-ttl')

    def test_nuage_create_port_with_extra_dhcp_options_026_mtu_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES, 'mtu')

    def test_nuage_create_port_with_extra_dhcp_options_027_all_subnets_local_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES, 'TBD')

    def test_nuage_create_port_with_extra_dhcp_options_028_broadcast_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES, 'broadcast')

    def test_nuage_create_port_with_extra_dhcp_options_031_router_discovery_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'router-discovery')

    def test_nuage_create_port_with_extra_dhcp_options_032_router_solicitation_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES,
                                                                        'router-solicitation')
    #            {'opt_value': '10.33.33.0;10.33.33.33;10.33.34.0;10.33.34.10', 'opt_name': 'static-route'}

    def test_nuage_create_port_with_extra_dhcp_options_033_static_route_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        # The minimum length of this option is 8, and the length MUST be a multiple of 8.
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES, 'static-route')

    def test_nuage_create_port_with_extra_dhcp_options_034_trailer_encapsulation_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'trailer-encapsulation')

    def test_nuage_create_port_with_extra_dhcp_options_035_arp_timeout_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        # 32-bit unsigned integer
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'arp-timeout')

    def test_nuage_create_port_with_extra_dhcp_options_036_ethernet_encap_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'ethernet-encap')

    def test_nuage_create_port_with_extra_dhcp_options_037_tcp_ttl_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        # 8-bit unsigned integer.  The minimum value is 1.
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'tcp-ttl')

    def test_nuage_create_port_with_extra_dhcp_options_038_tcp_keepalive_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        # 32-bit unsigned integer
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'tcp-keepalive')

    def test_nuage_create_port_with_extra_dhcp_options_040_nis_domain_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_STRING_TYPE_VALUES,
                                                                        'nis-domain')

    def test_nuage_create_port_with_extra_dhcp_options_041_nis_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES,
                                                                        'nis-server')

    def test_nuage_create_port_with_extra_dhcp_options_042_ntp_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES, 'ntp-server')

    def test_nuage_create_port_with_extra_dhcp_options_044_netbios_ns_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES, 'netbios-ns')

    def test_nuage_create_port_with_extra_dhcp_options_045_netbios_dd_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES, 'netbios-dd')

    def test_nuage_create_port_with_extra_dhcp_options_046_netbios_nodetype_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        # Valid values: 0x1, 0x2, 0x4, 0x8
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'netbios-nodetype')

    def test_nuage_create_port_with_extra_dhcp_options_047_netbios_scope_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_STRING_TYPE_VALUES,
                                                                        'netbios-scope')

    def test_nuage_create_port_with_extra_dhcp_options_048_x_windows_fs_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES,
                                                                        'x-windows-fs')

    def test_nuage_create_port_with_extra_dhcp_options_049_x_windows_dm_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES,
                                                                        'x-windows-dm')

    def test_nuage_create_port_with_extra_dhcp_options_050_requested_address_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES,
                                                                        'requested-address')

    def test_nuage_create_port_with_extra_dhcp_options_060_vendor_class_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_STRING_TYPE_VALUES,
                                                                        'vendor-class')

    def test_nuage_create_port_with_extra_dhcp_options_064_nisplus_domain_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_STRING_TYPE_VALUES,
                                                                        'nis+-domain')

    def test_nuage_create_port_with_extra_dhcp_options_065_nisplus_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES,
                                                                        'nis+-server')

    def test_nuage_create_port_with_extra_dhcp_options_066_tftp_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_STRING_TYPE_VALUES,
                                                                        'tftp_server')

    def test_nuage_create_port_with_extra_dhcp_options_067_bootfile_name_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_STRING_TYPE_VALUES,
                                                                        'bootfile-name')

    def test_nuage_create_port_with_extra_dhcp_options_068_mobile_ip_home_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES,
                                                                        'mobile-ip-home')

    def test_nuage_create_port_with_extra_dhcp_options_069_smtp_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES,
                                                                        'smtp-server')

    def test_nuage_create_port_with_extra_dhcp_options_070_pop3_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES,
                                                                        'pop3-server')

    def test_nuage_create_port_with_extra_dhcp_options_071_nntp_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES,
                                                                        'nntp-server')

    def test_nuage_create_port_with_extra_dhcp_options_074_irc_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_IPV4_ADDRESSES,
                                                                        'irc-server')

    def test_nuage_create_port_with_extra_dhcp_options_077_user_class_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'user-class')

    def test_nuage_create_port_with_extra_dhcp_options_093_client_arch_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'client-arch')

    def test_nuage_create_port_with_extra_dhcp_options_094_client_interface_id_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'client-interface-id')

    def test_nuage_create_port_with_extra_dhcp_options_097_client_machine_id_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'client-machine-id')

    def test_nuage_create_port_with_extra_dhcp_options_119_domain_search_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_STRING_TYPE_VALUES,
                                                                        'domain-search')

    def test_nuage_create_port_with_extra_dhcp_options_120_sip_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_STRING_TYPE_VALUES,
                                                                        'sip-server')

    def test_nuage_create_port_with_extra_dhcp_options_121_classless_static_route_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'classless-static-route')

    def test_nuage_create_port_with_extra_dhcp_options_125_vendor_id_encap_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'vendor-id-encap')

    def test_nuage_create_port_with_extra_dhcp_options_255_server_ip_address_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, BAD_INTEGER_TYPE_VALUES,
                                                                        'server-ip-address')

    def test_nuage_create_port_with_extra_dhcp_options_wrong_option(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        bad_values = ['1', '2']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, bad_values,
                                                                        'non-existing-option')

    def test_nuage_create_port_with_extra_dhcp_options_large_option_name(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        network_id = self.osmgd_l2_network['id']
        some_values = ['1', '2']
        self._assert_create_update_port_with_bad_extra_dhcp_options_neg(network_id, some_values, VERY_LONG_STRING)

    def test_nuage_create_port_with_extra_dhcp_options_external_network_neg(self):
        # Try to create a port with  extra dhcp options on an external network
        # Should fail, as DHCP is handled externally
        ext_network = self._create_network()
        # subnet is needed for trying port creation
        ext_subnet = self.create_subnet(ext_network, client=self.admin_subnets_client)
        # check whether this subnet is not empty: avoid pep8 local variable not used
        self.assertNotEmpty(ext_subnet)
        extra_dhcp_opts = [
            {'opt_value': '12.22.32.42', 'opt_name': 'router'}
        ]
        self.assertRaises(exceptions.BadRequest,
                          self._create_port_with_extra_dhcp_options,
                          ext_network['id'],
                          extra_dhcp_opts,
                          client=self.admin_ports_client)
        pass

    def test_nuage_update_port_with_extra_dhcp_options_external_network_neg(self):
        # Try to create a port with  extra dhcp options on an external network
        # Should fail, as DHCP is handled externally
        ext_network = self._create_network()
        # subnet is needed for trying port creation
        ext_subnet = self.create_subnet(ext_network, client=self.admin_subnets_client)
        # check whether this subnet is not empty: avoid pep8 local variable not used
        self.assertNotEmpty(ext_subnet)
        # create a port
        name = data_utils.rand_name('extra-dhcp-opt-port-name')
        create_body = self.admin_ports_client.create_port(
            name=name,
            network_id=ext_network['id']
        )
        self.addCleanup(self.admin_ports_client.delete_port, create_body['port']['id'])
        # Now try to update
        extra_dhcp_opts = [
            {'opt_value': '12.22.32.42', 'opt_name': 'router'}
        ]
        self.assertRaises(exceptions.BadRequest,
                          self._update_port_with_extra_dhcp_options,
                          create_body['port']['id'],
                          extra_dhcp_opts,
                          client=self.admin_ports_client)

    def test_nuage_create_port_with_extra_dhcp_options_nuage_l2_to_l3_migration_port_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad extra DHCP option values
        # Cr
        extra_dhcp_opts = [
            {'opt_value': '10.20.30.40', 'opt_name': 'router'}
        ]
        # Find the device_owner = 'network:dhcp:nuage' port created by Nuage when the subnet was created
        list_body = self.ports_client.list_ports()
        all_ports = list_body['ports']
        nuage_ports = [p for p in all_ports if p['device_owner'] == 'network:dhcp:nuage']
        # Now fetch the one from our subnet
        our_nuage_port = [p for p in nuage_ports if p['fixed_ips'][0]['subnet_id'] == self.osmgd_l2_subnet['id']]
        self.assertTrue(our_nuage_port)
        self.assertRaises(exceptions.BadRequest,
                          self._update_port_with_extra_dhcp_options,
                          our_nuage_port[0]['id'],
                          extra_dhcp_opts)

    def test_nuage_create_port_with_extra_dhcp_options_ipv6_neg(self):
        network_id = self.osmgd_l2_network['id']
        extra_dhcp_opts = [
            {'opt_value': '255.255.255.0', 'opt_name': 'netmask', 'ip_version': '6'}
        ]
        self.assertRaises(exceptions.BadRequest,
                          self._create_port_with_extra_dhcp_options,
                          network_id,
                          extra_dhcp_opts)

    def test_nuage_create_port_with_extra_dhcp_options_multiple_times_neg(self):
        # When specifying the the same option multiple times, it should fail
        network_id = self.osmgd_l2_network['id']
        extra_dhcp_opts = [
            {'opt_value': '19.20.30.40', 'opt_name': 'router'},
            {'opt_value': '19.20.30.41', 'opt_name': 'router'},
            {'opt_value': '19.20.30.42', 'opt_name': 'router'},
            {'opt_value': '19.20.30.43', 'opt_name': 'router'},
            {'opt_value': '19.20.30.44', 'opt_name': 'router'}
        ]
        self.assertRaises(exceptions.BadRequest,
                          self._create_port_with_extra_dhcp_options,
                          network_id,
                          extra_dhcp_opts)

    def test_nuage_update_port_with_extra_dhcp_options_multiple_times_neg(self):
        # When specifying the the same option multiple times, it should fail
        extra_dhcp_opts = [
            {'opt_value': '19.20.30.40', 'opt_name': 'router'},
            {'opt_value': '19.20.30.41', 'opt_name': 'router'},
            {'opt_value': '19.20.30.42', 'opt_name': 'router'},
            {'opt_value': '19.20.30.43', 'opt_name': 'router'},
            {'opt_value': '19.20.30.44', 'opt_name': 'router'}
        ]
        self.assertRaises(exceptions.BadRequest,
                          self._update_port_with_extra_dhcp_options,
                          self.os_l2_port['id'],
                          extra_dhcp_opts)

    def test_nuage_create_port_with_extra_dhcp_options_more_than_16_neg(self):
        # When specifying the the same option multiple times, it should fail
        more_than_16_extra_dhcp_opts = [
            {'opt_value': '255.255.255.0', 'opt_name': 'netmask'},
            {'opt_value': '200', 'opt_name': 'time-offset'},
            {'opt_value': '11.33.66.3', 'opt_name': 'router'},
            {'opt_value': '11.33.66.4', 'opt_name': 'time-server'},
            {'opt_value': '11.33.66.6', 'opt_name': 'dns-server'},
            {'opt_value': '11.33.66.7', 'opt_name': 'log-server'},
            {'opt_value': '11.33.66.9', 'opt_name': 'lpr-server'},
            {'opt_value': 'more.than.16-hostname', 'opt_name': 'hostname'},
            {'opt_value': '8192', 'opt_name': 'boot-file-size'},
            {'opt_value': 'more.than.16.domain.com', 'opt_name': 'domain-name'},
            {'opt_value': '11.33.66.16', 'opt_name': 'swap-server'},
            {'opt_value': '/opt/more-than16/root-path', 'opt_name': 'root-path'},
            {'opt_value': '/opt/more-than16/extension-path', 'opt_name': 'extension-path'},
            {'opt_value': '1', 'opt_name': 'ip-forward-enable'},
            {'opt_value': '1', 'opt_name': 'non-local-source-routing'},
            {'opt_value': '1576', 'opt_name': 'max-datagram-reassembly'},
            {'opt_value': '150', 'opt_name': 'default-ttl'},
            {'opt_value': '2104', 'opt_name': 'mtu'}
        ]
        self.assertRaises(exceptions.BadRequest,
                          self._create_port_with_extra_dhcp_options,
                          self.osmgd_l2_network['id'],
                          more_than_16_extra_dhcp_opts)

    def test_nuage_show_port_non_existing_neg(self):
        # Try to show the extra dhcp options of a non-existing port
        bad_port_id = 'blablablabla'
        self.assertRaises(exceptions.NotFound,
                          self.ports_client.show_port,
                          bad_port_id)




