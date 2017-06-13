# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

import copy
import functools
import inspect
import logging
import testtools
from netaddr import IPAddress, IPNetwork

## from oslo_log import log as logging
from oslo_utils import excutils

from tempest import config
from tempest import test

from tempest import exceptions
from tempest.lib import exceptions as lib_exc
from tempest.lib.common import rest_client
from tempest.common.utils import data_utils
from tempest.common import waiters

from nuagetempest.lib.test import tags as test_tags
from nuagetempest.lib.test.tenant_server import TenantServer
from nuagetempest.lib.test import vsd_helper
from nuagetempest.services import nuage_client

CONF = config.CONF

LOG = logging.getLogger(__name__)


# noinspection PyUnusedLocal
def nuage_skip_because(*args, **kwargs):
    """A decorator useful to skip tests hitting known bugs

    @param bug: bug number causing the test to skip
    @param condition: optional condition to be True for the skip to have place
    @param interface: skip the test if it is the same as self._interface
    """
    def decorator(f):
        # noinspection PyUnusedLocal
        @functools.wraps(f)
        def wrapper(self, *func_args, **func_kwargs):
            msg = "UNDEFINED"
            if "message" in func_kwargs:
                message = func_kwargs["message"]

                msg = "Skipped because: %s" % message
                if message.startswith("OPENSTACK_"):
                    uri = "http://mvjira.mv.usa.alcatel.com/browse/" + message
                    msg += "\n"
                    msg += uri

            raise testtools.TestCase.skipException(msg)
        return wrapper
    return decorator


def header(tags=None, since=None, until=None):
    """A decorator to log info on the test, add tags and release filtering.

    :param tags: A set of tags to tag the test with. header(tags=['smoke'])
    behaves the same as test.attr(type='smoke'). It exists for convenience.
    :param since: Optional. Mark a test with a 'since' release version to
    indicate this test should only run on setups with release >= since
    :param until: Optional. Mark a test with a 'until' release version to
    indicate this test should only run on setups with release < until
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(self, *func_args, **func_kwargs):

            logging.info("TESTCASE STARTED: %s" % f.func_code.co_name)

            # Dump the message + the name of this function to the log.
            logging.info("in %s:%i" % (
                f.func_code.co_filename,
                f.func_code.co_firstlineno
            ))

            result = f(self, *func_args, **func_kwargs)
            logging.info("TESTCASE COMPLETED: %s" % f.func_code.co_name)
            return result

        _add_tags_to_method(tags, wrapper)
        if since:
            wrapper._since = since
        if until:
            wrapper._until = until
        return wrapper
    return decorator


def _add_tags_to_method(tags, wrapper):
    if tags:
        if isinstance(tags, str):
            tags = {tags}
        else:
            tags = tags
        try:
            existing = copy.deepcopy(wrapper.__testtools_attrs)
            # deepcopy the original one, otherwise it will affect other
            # classes which extend this class.
            if test_tags.ML2 in tags and test_tags.MONOLITHIC in existing:
                existing.remove(test_tags.MONOLITHIC)
            if test_tags.MONOLITHIC in tags and test_tags.ML2 in existing:
                existing.remove(test_tags.ML2)
            existing.update(tags)
            wrapper.__testtools_attrs = existing
        except AttributeError:
            wrapper.__testtools_attrs = set(tags)


def class_header(tags=None, since=None, until=None):
    """Applies the header decorator to all test_ methods of this class.

    :param tags: Optional. A set of tags to tag the test with.
    header(tags=['smoke']) behaves the same as test.attr(type='smoke'). It
    exists for convenience.
    :param since: Optional. Mark a test with a 'since' release version to
    indicate this test should only run on setups with release >= since
    :param until: Optional. Mark a test with a 'until' release version to
    indicate this test should only run on setups with release < until
    """
    method_wrapper = header(tags=tags, since=since, until=until)

    def decorator(cls):
        for name, method in inspect.getmembers(cls, inspect.ismethod):
            if name.startswith('test_'):
                setattr(cls, name, method_wrapper(method))
        return cls
    return decorator


class NuageBaseTest(test.BaseTestCase):
    """
    Base class for all testcases.
    This class will have all the common function and will intiate object of other
    class in setup_client rather then inheritance.
    """
    # Default to ipv4.
    _ip_version = 4

    credentials = ['primary', 'admin']

    default_netpartition_name = CONF.nuage.nuage_default_netpartition
    default_enterprise = None   # the default enterprise

    @classmethod
    def setup_credentials(cls):
        super(NuageBaseTest, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        super(NuageBaseTest, cls).setup_clients()
        cls.manager = cls.get_client_manager()
        cls.admin_manager = cls.get_client_manager(credential_type='admin')

        # TODO: fetch version from tempest.conf
        version = "v5_0"
        address = CONF.nuage.nuage_vsd_server
        cls.vsd = vsd_helper.VsdHelper(address, version=version)

    @classmethod
    def resource_cleanup(cls):
        super(NuageBaseTest, cls).resource_cleanup()

    def setUp(self):
        super(NuageBaseTest, self).setUp()
        self.keypairs = {}
        self.servers = []

        # cls.cidr4 = IPNetwork(CONF.network.tenant_network_cidr)
        # cls.mask_bits = CONF.network.tenant_network_mask_bits
        self.cidr4 = IPNetwork('1.2.3.0/24')
        self.mask_bits = self.cidr4._prefixlen
        self.gateway4 = str(IPAddress(self.cidr4) + 1)

        self.cidr6 = IPNetwork(CONF.network.tenant_network_v6_cidr)
        self.gateway6 = str(IPAddress(self.cidr6) + 1)

    def create_network(self, network_name=None, client=None, cleanup=True, **kwargs):
        """Wrapper utility that returns a test network."""
        network_name = network_name or data_utils.rand_name('test-network')

        if not client:
            client = self.manager

        body = client.networks_client.create_network(name=network_name, **kwargs)
        network = body['network']
        if cleanup:
            self.addCleanup(client.networks_client.delete_network, network['id'])
        return network

    def create_subnet(self, network, subnet_name=None, gateway='', cidr=None, mask_bits=None,
                      ip_version=None, client=None, cleanup=True, **kwargs):
        """Wrapper utility that returns a test subnet."""
        # allow tests to use admin client
        if not client:
            client = self.manager

        subnet_name = subnet_name or data_utils.rand_name('test-subnet-')

        # The cidr and mask_bits depend on the ip version.
        ip_version = ip_version if ip_version is not None else self._ip_version
        gateway_not_set = gateway == ''
        if ip_version == 4:
            cidr = cidr or IPNetwork(CONF.network.tenant_network_cidr)
            if mask_bits is None:
                mask_bits = CONF.network.tenant_network_mask_bits
        elif ip_version == 6:
            cidr = (cidr or
                    IPNetwork(CONF.network.tenant_network_v6_cidr))
            if mask_bits is None:
                mask_bits = CONF.network.tenant_network_v6_mask_bits

        # Find a cidr that is not in use yet and create a subnet with it
        for subnet_cidr in cidr.subnet(mask_bits):
            if gateway_not_set:
                gateway_ip = str(IPAddress(subnet_cidr) + 1)
            else:
                gateway_ip = gateway
            try:
                body = client.subnets_client.create_subnet(
                    name=subnet_name,
                    network_id=network['id'],
                    cidr=str(subnet_cidr),
                    ip_version=ip_version,
                    gateway_ip=gateway_ip,
                    **kwargs)
                break
            except lib_exc.BadRequest as e:
                is_overlapping_cidr = 'overlaps with another subnet' in str(e)
                if not is_overlapping_cidr:
                    raise
        else:
            message = 'Available CIDR for subnet creation could not be found'
            raise exceptions.BuildErrorException(message)
        subnet = body['subnet']

        if cleanup:
            self.addCleanup(client.subnets_client.delete_subnet, subnet['id'])

        return subnet

    def create_l2_vsd_managed_subnet(self, network, vsd_l2domain, ip_version=4, dhcp_managed=True):
        if not isinstance(vsd_l2domain, self.vsd.vspk.NUL2Domain):
            self.fail("Must have an VSD L2 domain")

        if ip_version == 4:
            cidr = IPNetwork(vsd_l2domain.address + "/" + vsd_l2domain.netmask),
            gateway = vsd_l2domain.gateway,
        elif ip_version == 6:
            gateway = vsd_l2domain.ipv6_gateway,
            cidr = IPNetwork(vsd_l2domain.ipv6_address),
        else:
            self.fail("IP version {} is not supported".format(ip_version))

        subnet = self.create_subnet(
            network,
            enable_dhcp=dhcp_managed,
            ip_version=ip_version,
            cidr=cidr[0],
            gateway=gateway[0],
            nuagenet=vsd_l2domain.id,
            net_partition=vsd_l2domain.parent_object.name)

        return subnet

    def create_l3_vsd_managed_subnet(self, network, vsd_subnet, dhcp_managed=True, ip_version=4):
        if not isinstance(vsd_subnet, self.vsd.vspk.NUSubnet):
            self.fail("Must have an VSD L3 subnet")

        if ip_version == 4:
            cidr = IPNetwork(vsd_subnet.address + "/" + vsd_subnet.netmask),
            gateway = vsd_subnet.gateway,
        elif ip_version == 6:
            gateway = vsd_subnet.ipv6_gateway,
            cidr = IPNetwork(vsd_subnet.ipv6_address),
        else:
            self.fail("IP version {} is not supported".format(ip_version))

        # subnet -> zone -> domain -> enterprise
        net_partition = vsd_subnet.parent_object.parent_object.parent_object.name

        subnet = self.create_subnet(
            network,
            enable_dhcp=dhcp_managed,
            ip_version=ip_version,
            cidr=cidr[0],
            gateway=gateway[0],
            nuagenet=vsd_subnet.id,
            net_partition=net_partition)

        return subnet

    def create_port(self, network, client=None, cleanup=True, **kwargs):
        """Wrapper utility that returns a test port."""
        if not client:
            client = self.manager
        body = client.ports_client.create_port(network_id=network['id'],
                                               **kwargs)
        port = body['port']
        if cleanup:
            self.addCleanup(client.ports_client.delete_port, port['id'])
        return port

    def update_port(self, port, client=None, **kwargs):
        """Wrapper utility that updates a test port."""
        if not client:
            client = self.manager
        body = client.ports_client.update_port(port['id'],
                                               **kwargs)
        return body['port']

    def create_router(self, router_name=None, admin_state_up=False,
                      external_network_id=None, enable_snat=None,
                      client=None, cleanup=True, **kwargs):
        ext_gw_info = {}
        if not client:
            client = self.manager
        if external_network_id:
            ext_gw_info['network_id'] = external_network_id
        if enable_snat is not None:
            ext_gw_info['enable_snat'] = enable_snat
        body = client.routers_client.create_router(
            router_name, external_gateway_info=ext_gw_info,
            admin_state_up=admin_state_up, **kwargs)
        router = body['router']
        if cleanup:
            self.addCleanup(client.routers_client.delete_router, router['id'])
        return router

    def create_floatingip(self, external_network_id,
                          client=None, cleanup=True):
        """Wrapper utility that returns a test floating IP."""
        if not client:
            client = self.manager
        body = client.floating_ips_client.create_floatingip(
            floating_network_id=external_network_id)
        fip = body['floatingip']
        if cleanup:
            self.addCleanup(client.floating_ips_client.delete_floatingip, fip['id'])
        return fip

    def create_router_interface(self, router_id, subnet_id, client=None):
        """Wrapper utility that returns a router interface."""
        if not client:
            client = self.manager
        interface = client.routers_client.add_router_interface(
            router_id, subnet_id=subnet_id)
        return interface

    def osc_list_networks(self, client=None, *args, **kwargs):
        """List networks using admin creds else provide client """
        if not client:
            client = self.admin_manager
        networks_list = client.networks_client.list_networks(
            *args, **kwargs)
        return networks_list['networks']

    def osc_list_subnets(self, client=None, *args, **kwargs):
        """List subnets using admin creds else provide client"""
        if not client:
            client = self.admin_manager
        subnets_list = client.subnets_client.list_subnets(
            *args, **kwargs)
        return subnets_list['subnets']

    def osc_list_routers(self, client=None, *args, **kwargs):
        """List routers using admin creds else provide client"""
        if not client:
            client = self.admin_manager
        routers_list = client.routers_client.list_routers(
            *args, **kwargs)
        return routers_list['routers']

    def osc_list_ports(self, client=None, *args, **kwargs):
        """List ports using admin creds else provide client"""
        if not client:
            client = self.admin_manager
        ports_list = client.ports_client.list_ports(
            *args, **kwargs)
        return ports_list['ports']

    def osc_list_server(self, server_id, client=None):
        """List server using admin creds else provide client"""
        if not client:
            client = self.admin_manager
        server_list = client.servers_client.show_server(server_id)
        return server_list['server']

    # noinspection PyBroadException
    def osc_create_test_server(self, client=None, tenant_networks=None, ports=None, wait_until=None,
                               volume_backed=False, name=None, flavor=None,
                               image_id=None, cleanup=True, **kwargs):
        """Common wrapper utility returning a test server.

        :param client: Client manager which provides OpenStack Tempest clients.
        :param tenant_network: Tenant network to be used for creating a server.
        :param wait_until: Server status to wait for the server to reach after
        its creation.
        :param volume_backed: Whether the instance is volume backed or not.
        :returns: a tuple
        """
        if not client:
            client = self.manager

        name = name
        flavor = flavor
        image_id = image_id

        if name is None:
            name = data_utils.rand_name(__name__ + "-instance")
        if flavor is None:
            flavor = CONF.compute.flavor_ref
        if image_id is None:
            image_id = CONF.compute.image_ref

        params = copy.copy(kwargs) or {}
        if tenant_networks:
            params.update({"networks": []})
            for network in tenant_networks:
                if 'id' in network.keys():
                    params['networks'].append({'uuid': network['id']})
        if ports:
            params.update({"networks": []})
            for port in ports:
                if 'id' in port.keys():
                    params['networks'].append({'port': port['id']})

        # kwargs = fixed_network.set_networks_kwarg(
        #     tenant_network, kwargs) or {}

        kwargs = copy.copy(params) or {}

        if wait_until is None:
            wait_until = 'ACTIVE'

        if volume_backed:
            volume_name = data_utils.rand_name('volume')
            volumes_client = client.volumes_v2_client
            if CONF.volume_feature_enabled.api_v1:
                volumes_client = client.volumes_client
            volume = volumes_client.create_volume(
                display_name=volume_name,
                imageRef=image_id)
            volumes_client.wait_for_volume_status(volume['volume']['id'],
                                                  'available')

            bd_map_v2 = [{
                         'uuid': volume['volume']['id'],
                         'source_type': 'volume',
                         'destination_type': 'volume',
                         'boot_index': 0,
                         'delete_on_termination': True}]
            kwargs['block_device_mapping_v2'] = bd_map_v2

            # Since this is boot from volume an image does not need
            # to be specified.
            image_id = ''

        body = client.servers_client.create_server(name=name, imageRef=image_id,
                                                   flavorRef=flavor,
                                                   **kwargs)

        # get the servers
        vm = rest_client.ResponseBody(body.response, body['server'])
        self.LOG.info("Id of vm %s", vm['id'])

        if wait_until:
            try:
                waiters.wait_for_server_status(client.servers_client, vm['id'], wait_until)

            except Exception:
                with excutils.save_and_reraise_exception():
                    if ('preserve_server_on_error' not in kwargs or
                            kwargs['preserve_server_on_error'] is False):
                        try:
                            client.servers_client.delete_server(vm['id'])
                        except Exception:
                            LOG.exception('Deleting server %s failed' % vm['id'])

        def cleanup_server():
            client.servers_client.delete_server(vm['id'])
            waiters.wait_for_server_termination(client.servers_client,
                                                vm['id'])

        if cleanup:
            self.addCleanup(cleanup_server)

        return vm

    def create_tenant_server(self, client=None, tenant_networks=None, ports=None, wait_until=None,
                             volume_backed=False, name=None, flavor=None,
                             image_id=None, cleanup=True, **kwargs):

        name = name or data_utils.rand_name('test-server')

        server = TenantServer(client, self.admin_manager.servers_client)
        server.openstack_data = self.osc_create_test_server(client=client,
                                                            tenant_networks=tenant_networks,
                                                            ports=ports,
                                                            volume_backed=volume_backed,
                                                            name=name,
                                                            flavor=flavor,
                                                            image_id=image_id,
                                                            wait_until=wait_until,
                                                            cleanup=cleanup,
                                                            **kwargs)
        server.init_console()
        self.addCleanup(server.close_console)
        return server

    def assert_ping(self, server1, server2, network, should_pass=True):
        # get IP address for <server2> in <network>
        ipv4_address = server2.get_server_ip_in_network(network['name'])

        ping_result = server1.ping(ipv4_address, should_pass=should_pass)

        if should_pass:
            if ping_result:
                self.LOG.debug("Traffic is recieved as expected")
            else:
                self.LOG.warning("Failed to ping")

        if not ping_result:
            self.LOG.error("Ping from server {} to server {} on IP addres {} failed".format(
                server1.openstack_data['id'],
                server2.openstack_data['id'],
                ipv4_address))

            # TODO: do more diagnostics here

            # finally fail
            self.fail("Ping failure")

    def assert_ping6(self, server1, server2, network, should_pass=True):
        # get IP address for <server2> in <network>
        ipv6_address = server2.get_server_ip_in_network(network['name'], ip_type=6)

        ping_result = server1.ping6(ipv6_address, should_pass=should_pass)

        if should_pass:
            if ping_result:
                self.LOG.debug("Traffic is recieved as expected")
            else:
                self.LOG.warning("Failed to ping")

        if not ping_result:
            self.LOG.error("Ping from server {} to server {} on IP addres {} failed".format(
                server1.openstack_data['id'],
                server2.openstack_data['id'],
                ipv6_address))

            # TODO: do more diagnostics here

            # finally fail
            self.fail("Ping6 failure")

    def start_webserver(self, vm_handle, port_number):
        # pkill not present on cirros
        output = vm_handle._send(cmd='killall nc', timeout=50)
        self.LOG.info("output of pkill comand is %s", output)
        output = vm_handle._send(cmd='netstat -an | grep ' + port_number, timeout=50)
        self.LOG.info("output of netstat comand is %s", output)
        output = vm_handle._send(cmd='echo -e \"got connected working fine 200 OKnn $(ifconfig)\" | nc -lp '
                                     + port_number + ' &', timeout=50)
        self.LOG.info("output of start webserver is %s", output)
        complete_output = str(output).strip('[]')
        if "Address already in use" in complete_output:
            self.LOG.info("some process is running on this port " + complete_output)
            self.fail("Fail to start webserver on port " + port_number)
        else:
            self.LOG.info("Webserver is successfully started on portnumber " + port_number)

    def stop_webserver(self, vm_handle):
        output = vm_handle._send(cmd='killall nc', timeout=50)
        self.LOG.info("output of pkill comand is %s", output)

    def verify_tcp_curl(self, vm_handle, completeurl, tcppass=True, verify_ip_address=None):
        output = vm_handle._send(cmd='curl -m 2 ' + completeurl, timeout=50)
        self.LOG.info("output of curl command is %s", output)
        complete_output = str(output).strip('[]')
        if tcppass:
            expectedresult = "got connected working fine"
        else:
            expectedresult = "couldn't connect to host"
        if expectedresult in complete_output:
            self.LOG.info("traffic is recieved as expected: " + expectedresult)
            if tcppass and verify_ip_address:
                if verify_ip_address in complete_output:
                    self.LOG.info("found the expected ipaddress " + verify_ip_address)
                else:
                    self.LOG.info("ip address not coming as expected " + verify_ip_address)
                    self.fail("ip address is not found in the curl " + complete_output)
        else:
            self.fail("traffic is not recieved as expected " + complete_output)
