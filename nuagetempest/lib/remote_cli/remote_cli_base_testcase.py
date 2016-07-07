# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

import json
import re
import netaddr
from enum import Enum

from tempest import config
from tempest import exceptions

from oslo_log import log as logging
from tempest.lib.common.utils import data_utils

import ssh_cli
import output_parser as cli_output_parser

CONF = config.CONF

LOG = logging.getLogger(__name__)


class Role(Enum):
    admin = 1
    tenant = 2
    nonadmin = 3


class RemoteCliBaseTestCase(ssh_cli.ClientTestBase):
    credentials = ['primary', 'admin']

    """
    Base class for the Neutron tests that use the remote CLI clients

    Finally, it is assumed that the following option is defined in the
    [service_available] section of etc/tempest.conf

        neutron as True

    TODD: update
    """

    force_tenant_isolation = False

    # Default to ipv4.
    _ip_version = 4

    @classmethod
    def skip_checks(cls):
        if not CONF.service_available.neutron:
            raise cls.skipException("Neutron support is required")

    @classmethod
    def setup_clients(cls):
        super(RemoteCliBaseTestCase, cls).setup_clients()
        cls.users_client = cls.os_adm.users_client
        cls.tenants_client = cls.os_adm.tenants_client

    @classmethod
    def resource_setup(cls):
        # Create no network resources for these test.
        cls.set_network_resources()
        super(RemoteCliBaseTestCase, cls).resource_setup()

        cls.client_manager
        cls.network_cfg = CONF.network

        # cls.cli = ssh_cli.CLIClient(
        #     username=CONF.auth.admin_username,
        #     tenant_name=CONF.auth.admin_tenant_name,
        #     password=CONF.auth.admin_password,
        #     uri=CONF.identity.uri)
        cls.cli = ssh_cli.CLIClient(
            username=CONF.auth.admin_username,
            tenant_name=CONF.auth.admin_tenant_name,
            password=CONF.auth.admin_password,
            uri=CONF.identity.uri)
        cls.parser = cli_output_parser

        cls.networks = []
        cls.subnets = []
        cls.ports = []
        cls.routers = []
        cls.floating_ips = []
        cls.security_groups = []
        cls.security_group_rules = []

        cls.vms = []

        # cls.pools = []
        # cls.vips = []
        # cls.members = []
        # cls.health_monitors = []
        # cls.vpnservices = []
        # cls.ikepolicies = []
        # cls.metering_labels = []
        # cls.metering_label_rules = []
        # cls.fw_rules = []
        # cls.fw_policies = []
        # cls.ipsecpolicies = []

        cls.ethertype = "IPv" + str(cls._ip_version)
        # tricky stuff to work with 2 OS controllers on Nuage testbed
        # the IP adress of osc-2 is always osc-1 + 1
        # work with these 2 uri's

        cls.uri_1 = cls.os.identity_client.base_url
        ip_osc_1 = netaddr.IPAddress(re.findall(r'[0-9]+(?:\.[0-9]+){3}', cls.uri_1)[0])
#        ip_osc_1 = netaddr.IPAddress(re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(CONF.identity.uri))[0])
        ip_osc_2 = ip_osc_1 + 1
        cls.uri_2 = re.sub(str(ip_osc_1), str(ip_osc_2), cls.uri_1)

        # make the uri point to the one of osc-1
        cls.uri = cls.uri_1
        cls.admin_cli = ssh_cli.CLIClient(
            username=CONF.auth.admin_username,
            tenant_name=CONF.auth.admin_tenant_name,
            password=CONF.auth.admin_password,
            uri=cls.uri)
        cls.nonadmin_cli = ssh_cli.CLIClient(
            # Todo Hendrik: make sure a non-admin user is created in the admin project
            # username=CONF.identity.nonadmin_username,
            username="nonadmin",
            tenant_name=CONF.auth.admin_tenant_name,
            password=CONF.auth.admin_password,
            uri=cls.uri)

        cls.tenant = cls.tenants_client.create_tenant(
            data_utils.rand_name())['tenant']
        cls.user = cls.users_client.create_user(data_utils.rand_name(),
                                                "tigris",
                                                cls.tenant['id'],
                                                "")['user']
        cls.tenant_cli = ssh_cli.CLIClient(
            username=cls.user['name'],
            tenant_name=cls.tenant['name'],
            password="tigris",
            uri=cls.uri)
        cls.me = Role.tenant
        # Check if demo/demo is present, if not create
        pass

    def _get_clients(self):
        if self.me == Role.admin:
            self.cli = self.admin_cli
        elif self.me == Role.tenant:
            self.cli = self.tenant_cli
        else:
            self.cli = self.nonadmin_cli
        return self.cli

    def _use_osc(self, controller):
        if controller == 1:
            self.cli.uri = self.uri_1
        else:
            self.cli.uri = self.uri_2
        self._get_clients()

    def _as_admin(self):
        self.me = Role.admin
        self._get_clients()

    def _as_tenant(self):
        self.me = Role.tenant
        self._get_clients()

    @classmethod
    def resource_cleanup(cls):
        if CONF.service_available.neutron:
            # # Clean up ipsec policies
            # for ipsecpolicy in cls.ipsecpolicies:
            #     cls.client.delete_ipsecpolicy(ipsecpolicy['id'])
            # # Clean up firewall policies
            # for fw_policy in cls.fw_policies:
            #     cls.client.delete_firewall_policy(fw_policy['id'])
            # # Clean up firewall rules
            # for fw_rule in cls.fw_rules:
            #     cls.client.delete_firewall_rule(fw_rule['id'])
            # # Clean up ike policies
            # for ikepolicy in cls.ikepolicies:
            #     cls.client.delete_ikepolicy(ikepolicy['id'])
            # # Clean up vpn services
            # for vpnservice in cls.vpnservices:
            #     cls.client.delete_vpnservice(vpnservice['id'])

            # # # Clean up floating IPs
            # for floating_ip in cls.floating_ips:
            #     cls._delete_floating_ip(floating_ip['id'])

            # # Clean up health monitors
            # for health_monitor in cls.health_monitors:
            #     cls.client.delete_health_monitor(health_monitor['id'])
            # # Clean up members
            # for member in cls.members:
            #     cls.client.delete_member(member['id'])
            # # Clean up vips
            # for vip in cls.vips:
            #     cls.client.delete_vip(vip['id'])
            # # Clean up pools
            # for pool in cls.pools:
            #     cls.client.delete_pool(pool['id'])
            # # Clean up metering label rules
            # for metering_label_rule in cls.metering_label_rules:
            #     cls.admin_client.delete_metering_label_rule(
            #         metering_label_rule['id'])
            # # Clean up metering labels
            # for metering_label in cls.metering_labels:
            #     cls.admin_client.delete_metering_label(metering_label['id'])

            # TODO: security groups
            # TODO: security group rules

            # Clean up ports
            for port in cls.ports:
                cls._delete_port(port['id'])
            cls.ports = []

            # Clean up routers
            for router in cls.routers:
                cls.delete_router(router)
            cls.routers = []

            # Clean up subnets
            for subnet in cls.subnets:
                cls._delete_subnet(subnet['id'])
            cls.subnets = []

            # Clean up networks
            for network in cls.networks:
                cls._delete_network(network['id'])
            cls.networks = []

            # Todo: Hendrik check with Janwhy the next line was here.
            # resources get delted twice, causing testcas failure
            # super(RemoteCliBaseTestCase, cls).resource_cleanup()
        cls.users_client.delete_user(cls.user['id'])
        cls.tenants_client.delete_tenant(cls.tenant['id'])
        super(RemoteCliBaseTestCase, cls).resource_cleanup()

    def create_network_with_args(self, *args):
        """Wrapper utility that returns a test network."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('net-create', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'), 'Created a new network:')
        network = self.parser.details(response)
        self.networks.append(network)
        return network

    def create_network(self, network_name=None):
        """Wrapper utility that returns a test network."""
        network_name = network_name or data_utils.rand_name('test-network')
        return self.create_network_with_args(network_name)

    def delete_network(self, network_id):
        response = self.cli.delete_network(network_id)
        self.assertFirstLineStartsWith(response.split('\n'), 'Deleted network:')
        self.assertNotIn(network_id, response)
        # TODO: parse response for network id

    def show_network(self, network_id):
        response = self.cli.neutron('net-show', params=network_id)
        network = self.parser.details(response)
        self.assertEqual(network['id'], network_id)
        return network

    def list_networks(self):
        response = self.cli.neutron('net-list')
        return response

    def show_subnet(self, subnet_id):
        response = self.cli.neutron('subnet-show', params=subnet_id)
        subnet = self.parser.details(response)
        self.assertEqual(subnet['id'], subnet_id)
        return subnet

    def list_subnets(self):
        response = self.cli.neutron('subnet-list')
        return response

    def create_subnet_with_args(self, *args):
        """Wrapper utility that returns a test subnet."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('subnet-create', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'), 'Created a new subnet:')
        subnet = self.parser.details(response)
        self.subnets.append(subnet)
        return subnet

    def update_subnet_with_args(self, *args):
        """Wrapper utility that updates returns a test subnet."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('subnet-update', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'), 'Updated subnet:')

    def create_router_with_args(self, *args):
        """Wrapper utility that returns a test router."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('router-create', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'), 'Created a new router:')
        router = self.parser.details(response)
        self.routers.append(router)
        return router

    def create_router(self, router_name=None):
        """Wrapper utility that returns a test router."""
        router_name = router_name or data_utils.rand_name('test-router')
        return self.create_router_with_args(router_name)

    def update_router_with_args(self, *args):
        """Wrapper utility that returns a test router."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('router-update', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'), 'Updated router:')
        # router = self.parser.details(response)
        # return router

    def show_router(self, router_id):
        response = self.cli.neutron('router-show', params=router_id)
        router = self.parser.details(response)

        self.assertEqual(router['id'], router_id)
        return router

    def list_routers(self):
        response = self.cli.neutron('router-list')
        return response

    def set_router_gateway_with_args(self, *args):
        """Wrapper utility that sets the router gateway."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('router-gateway-set', params=the_params)
        self.assertFirstLineStartsWith(response.split('\n'), 'Set gateway for router')

    def add_router_interface_with_args(self, *args):
        """Wrapper utility that sets the router gateway."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('router-interface-add', params=the_params)
        self.assertFirstLineStartsWith(response.split('\n'), 'Added interface')

    def create_port_with_args(self, *args):
        """Wrapper utility that returns a test port."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('port-create', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'), 'Created a new port:')
        port = self.parser.details(response)
        self.ports.append(port)
        return port

    def create_port(self, network, port_name=None):
        """Wrapper utility that returns a test port."""
        port_name = port_name or data_utils.rand_name('cli-test-port-')
        response = self.create_port_with_args("--name ", port_name, network['id'])
        return response

    def update_port_with_args(self, port_id, *args):
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg
        response = self.cli.neutron('port-update ', params=the_params + ' ' + port_id)
        self.assertFirstLineStartsWith(response.split('\n'), 'Updated port:')

    def show_port(self, port_id):
        response = self.cli.neutron('port-show', params=port_id)
        port = self.parser.details(response)
        self.assertEqual(port['id'], port_id)
        return port

    def create_floating_ip_with_args(self, *args):
        """Wrapper utility that returns a test floating_ip."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('floatingip-create', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'), 'Created a new floatingip:')
        floating_ip = self.parser.details(response)
        self.floating_ips.append(floating_ip)
        return floating_ip

    def update_floating_ip_with_args(self, *args):
        """Wrapper utility that returns a test floating_ip."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('floatingip-update', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'), 'Updated floatingip:')

    def create_floating_ip(self, floating_ip_name=None):
        """Wrapper utility that returns a test floating_ip."""
        floating_ip_name = floating_ip_name or data_utils.rand_name('test-floating_ip')
        return self.create_floating_ip_with_args(floating_ip_name)

    def show_floating_ip(self, floating_ip_id):
        response = self.cli.neutron('floatingip-show', params=floating_ip_id)
        floating_ip = self.parser.details(response)
        return floating_ip

    def list_nuage_floating_ip_all(self):
        response = self.cli.neutron('nuage-floatingip-list')
        nuage_floating_ip_list = self.parser.details(response)
        return nuage_floating_ip_list

    def list_nuage_floating_ip_for_subnet(self, subnet_id):
        response = self.cli.neutron('nuage-floatingip-show --subnet ', params=subnet_id)
        nuage_floating_ip_list = self.parser.details(response)
        return nuage_floating_ip_list

    def list_nuage_floating_ip_for_port(self, port_id):
        response = self.cli.neutron('nuage-floatingip-show --subnet ', params=port_id)
        nuage_floating_ip_list = self.parser.details(response)
        return nuage_floating_ip_list

    def show_nuage_floating_ip(self, floating_ip_id):
        response = self.cli.neutron('floatingip-show', params=floating_ip_id)
        floating_ip = self.parser.details(response)
        return floating_ip

    def _kwargs_to_cli(self, **kwargs):
        params_str = ''
        if kwargs is not None:
            for key, value in kwargs.iteritems():

                print "%s == %s" % (key, value)
                params_str += " --%s %s" % (key, value)

            params_str = params_str.replace("_", "-")
        return params_str

    def associate_floating_ip(self, floating_ip_id, port_id, **kwargs):
        the_params = self._kwargs_to_cli(**kwargs)

        return self.cli.neutron('floatingip-associate', params=floating_ip_id+' ' + port_id + the_params)

    def disassociate_floating_ip(self, floating_ip_id):
        return self.cli.neutron('floatingip-disassociate', params=floating_ip_id)

    def create_security_group_with_args(self, *args):
        """Wrapper utility that returns a test security group."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('security-group-create', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'), 'Created a new security_group:')
        security_group = self.parser.details(response)
        self.security_groups.append(security_group)
        return security_group

    def create_security_group_rule_with_args(self, *args):
        """Wrapper utility that returns a test security group rule."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('security-group-rule-create', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'), 'Created a new security_group_rule:')
        security_group_rule = self.parser.details(response)
        self.security_group_rules.append(security_group_rule)
        return security_group_rule

    def create_vm_with_args(self, *args):
        """Wrapper utility that returns a test VM."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.nova('boot', params=the_params)

        # self.assertFirstLineStartsWith(response.split('\n'), 'Created a new VM:')
        vm = self.parser.details(response)
        self.vms.append(vm)
        return vm

    @classmethod
    def delete_router(cls, router):

        cls._clear_router_gateway(router['id'])

        interfaces = cls._list_router_ports(router['id'])

        for i in interfaces:
            fixed_ips = i['fixed_ips']
            fixed_ips_dict = json.loads(fixed_ips)
            subnet_id = fixed_ips_dict['subnet_id']
            cls._remove_router_interface_with_subnet_id(router['id'], subnet_id)

        cls._delete_router(router['id'])

    def assertTableStruct(self, items, field_names):
        """Verify that all items has keys listed in field_names."""
        for item in items:
            for field in field_names:
                self.assertIn(field, item)

    def assertFirstLineStartsWith(self, lines, beginning):
        self.assertTrue(lines[0].startswith(beginning),
                        msg=('Beginning of first line has invalid content: %s'
                             % lines[:3]))

    @classmethod
    def _delete_network(cls, network_id):
        cls.cli.neutron('net-delete', params=network_id)

    @classmethod
    def _delete_subnet(cls, subnet_id):
        cls.cli.neutron('subnet-delete', params=subnet_id)

    @classmethod
    def _delete_port(cls, port_id):
        cls.cli.neutron('port-delete', params=port_id)

    @classmethod
    def _delete_router(cls, router_id):
        cls.cli.neutron('router-delete', params=router_id)

    @classmethod
    def _delete_floating_ip(cls, floating_ip_id):
        cls.cli.neutron('floatingip-delete', params=floating_ip_id)

    @classmethod
    def _clear_router_gateway(cls, router_id):
        cls.cli.neutron('router-gateway-clear', params=router_id)

    @classmethod
    def _list_router_ports(cls, router_id):
        response = cls.cli.neutron('router-port-list', params=router_id)
        ports = cls.parser.listing(response)
        return ports

    @classmethod
    def _remove_router_interface_with_subnet_id(cls, router_id, subnet_id):
        response = cls.cli.neutron('router-interface-delete', params=router_id + ' ' + subnet_id)
        return response

    @classmethod
    def _remove_router_interface_with_subnet_id(cls, router_id, subnet_id):
        response = cls.cli.neutron('router-interface-delete', params=router_id + ' ' + subnet_id)
        return response

    # @classmethod
    def _cli_create_redirect_target_with_args(self, *args):
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('nuage-redirect-target-create', params=the_params)
        self.assertFirstLineStartsWith(response.split('\n'), 'Created a new nuage_redirect_target:')
        redirect_target = self.parser.details(response)
        # self.nuage_redirect_targets.append(redirect_target)
        return redirect_target

    def _cli_create_nuage_redirect_target_in_l2_subnet(self, l2subnet, name=None):
        if name is None:
            name = data_utils.rand_name('cli-os-l2-rt')
        # parameters for nuage redirection target
        response = self.cli.neutron(
            'nuage-redirect-target-create --insertion-mode VIRTUAL_WIRE  --redundancy-enabled false --subnet',
            params=l2subnet['name'] + ' ' + name)
        self.assertFirstLineStartsWith(response.split('\n'), 'Created a new nuage_redirect_target:')
        redirect_target = self.parser.details(response)
        # self.nuage_redirect_targets.append(redirect_target)
        return redirect_target

    def _cli_create_nuage_redirect_target_in_l3_subnet(self, l3subnet, name=None):
        if name is None:
            name = data_utils.rand_name('cli-os-l3-rt')
        response = self.cli.neutron(
            'nuage-redirect-target-create --insertion-mode L3  --redundancy-enabled false --subnet',
            params=l3subnet['name'] + ' ' + name)
        self.assertFirstLineStartsWith(response.split('\n'), 'Created a new nuage_redirect_target:')
        redirect_target = self.parser.details(response)
        # self.nuage_redirect_targets.append(redirect_target)
        return redirect_target

    def delete_redirect_target(self, redirect_target_id):
        self.cli.neutron('nuage-redirect-target-delete', params=redirect_target_id)

    def list_nuage_redirect_target_for_l2_subnet(self, l2subnet):
        response = self.cli.neutron('nuage-redirect-target-list --subnet ', params=l2subnet['id'])
        rt_list = self.parser.listing(response)
        return rt_list

    def list_nuage_redirect_target_for_port(self, port):
        response = self.cli.neutron('nuage-redirect-target-list --for-port ', params=port['id'])
        rt_list = self.parser.listing(response)
        return rt_list

    def show_nuage_redirect_target(self, redirect_target_id):
        response = self.cli.neutron('nuage-redirect-target-show', params=redirect_target_id)
        rt_show = self.parser.details(response)
        return rt_show

    def cli_create_nuage_redirect_target_rule_with_args(self, *args):
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg
        response = self.cli.neutron('nuage-redirect-target-rule-create ', params=the_params)
        rt_rule = self.parser.details(response)
        return rt_rule

    def list_nuage_policy_group_for_subnet(self, subnet_id):
        response = self.cli.neutron('nuage-policy-group-list --for-subnet ', params=subnet_id)
        rt_list = self.parser.listing(response)
        return rt_list

    def show_nuage_policy_group(self, policy_group_id):
        response = self.cli.neutron("nuage-policy-group-show", params=policy_group_id)
        show_pg = self.parser.details(response)
        return show_pg

    def list_nuage_floatingip_by_subnet(self, subnet_id):
        response = self.cli.neutron('nuage-floatingip-list --for-subnet ', params=subnet_id)
        fp_list = self.parser.listing(response)
        return fp_list

    def list_nuage_floatingip_by_port(self, port_id):
        response = self.cli.neutron('nuage-floatingip-list --for-port ', params=port_id)
        fp_list = self.parser.listing(response)
        return fp_list

    def show_nuage_floatingip(self, fp_id):
        response = self.cli.neutron('nuage-floatingip-show ', params=fp_id)
        show_fp = self.parser.details(response)
        return show_fp


class RemoteCliAdminBaseTestCase(RemoteCliBaseTestCase):

    def __init__(self, *args, **kwargs):
        super(RemoteCliAdminBaseTestCase, self, *args, **kwargs)

    def _get_clients(self):
        self.cli = ssh_cli.CLIClient(
            username=CONF.auth.admin_username,
            tenant_name=CONF.auth.admin_tenant_name,
            password=CONF.auth.admin_password,
            uri=CONF.identity.uri)

        return self.cli
