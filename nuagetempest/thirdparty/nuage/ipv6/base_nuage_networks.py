# Copyright 2017 - Nokia
# All Rights Reserved.
from testtools.matchers import Equals
from testtools.matchers import ContainsDict

from netaddr import IPNetwork, IPAddress, IPRange

from tempest import config
from tempest import test
from tempest.common.utils import data_utils
from tempest import exceptions
from tempest.lib import exceptions as lib_exc
from nuagetempest.services.nuage_client import NuageRestClient

CONF = config.CONF


class BaseNuageNetworksTestCase(test.BaseTestCase):
    # Default to ipv4.
    _ip_version = 4

    @classmethod
    def setup_clients(cls):
        super(BaseNuageNetworksTestCase, cls).setup_clients()
        client_manager = cls.get_client_manager()

        cls.networks_client = client_manager.networks_client
        cls.subnets_client = client_manager.subnets_client
        cls.ports_client = client_manager.ports_client

    @classmethod
    def resource_setup(cls):
        # ML2-driver does not support net-partitions.
        # We have to create a default netpartition directly in the VSD
        if CONF.nuage_sut.nuage_plugin_mode == 'ml2':
            # create default netpartition if it is not there
            netpartition_name = cls.nuage_vsd_client.def_netpart_name
            net_partition = cls.nuage_vsd_client.get_net_partition(netpartition_name)
            if not net_partition:
                cls.net_partition = cls.nuage_vsd_client.create_net_partition(netpartition_name,
                                                                              fip_quota=100,
                                                                              extra_params=None)
        super(BaseNuageNetworksTestCase, cls).resource_setup()

    @classmethod
    def resource_cleanup(cls):
        super(BaseNuageNetworksTestCase, cls).resource_cleanup()


############################################################
# VSD resources
############################################################
class VsdTestCaseMixin(BaseNuageNetworksTestCase):

    @classmethod
    def setup_clients(cls):
        super(VsdTestCaseMixin, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()

    def create_vsd_l2domain_template(self, name=None, ip_type=None, dhcp_managed=None,
                                     cidr4=None,
                                     cidr6=None,
                                     **kwargs):
        params = {
        }

        if ip_type == "IPV4":
            params.update({'IPType': "IPV4"})
        elif ip_type == "DUALSTACK":
            params.update({'IPType': "DUALSTACK"})

        if cidr4:
            params.update({'address': str(cidr4.ip)})
            if "netmask" in kwargs:
                netmask = kwargs['netmask']
            else:
                netmask = str(cidr4.netmask)
            params.update({'netmask': netmask})

            if "gateway" in kwargs:
                gateway_ip = kwargs['gateway']
            else:
                gateway_ip = str(IPAddress(cidr4) + 1)
            params.update({'gateway': gateway_ip})

        if cidr6:
            params.update({'IPv6Address': str(cidr6)})

            if "gateway6" in kwargs:
                gateway6_ip = kwargs['gateway6']
            else:
                gateway6_ip = str(IPAddress(cidr6) + 1)
            params.update({'IPv6Gateway': gateway6_ip})

        if dhcp_managed:
            params.update({'DHCPManaged': dhcp_managed})

        if name is None:
            name = data_utils.rand_name('l2domain-template')

        # add all other kwargs as attributes (key,value) pairs
        for key, value in kwargs.iteritems():
            params.update({key: value})

        body = self.nuage_vsd_client.create_l2domaintemplate(name, extra_params=params)
        vsd_l2dom_template = body[0]

        self.addCleanup(self.nuage_vsd_client.delete_l2domaintemplate, vsd_l2dom_template['ID'])
        return vsd_l2dom_template

    def _verify_vsd_l2domain_template(self, l2domain_template,
                                      ip_type="IPV4", dhcp_managed=False,
                                      cidr4=None, cidr6=None, **kwargs):
        if ip_type == "IPV4":
            self.assertThat(l2domain_template, ContainsDict({'IPType': Equals("IPV4")}))
            self.assertIsNone(l2domain_template['IPv6Address'])
            self.assertIsNone(l2domain_template['IPv6Gateway'])
        elif ip_type == "DUALSTACK":
            self.assertThat(l2domain_template, ContainsDict({'IPType': Equals("DUALSTACK")}))
        else:
            raise NotImplementedError

        if cidr4:
            self.assertThat(l2domain_template, ContainsDict({'address': Equals(str(cidr4.ip))}))
            if "netmask" not in kwargs:
                netmask = str(cidr4.netmask)
                self.assertThat(l2domain_template, ContainsDict({'netmask': Equals(netmask)}))

            if "gateway" not in kwargs:
                gateway_ip = str(IPAddress(cidr4) + 1)
                self.assertThat(l2domain_template, ContainsDict({'gateway': Equals(gateway_ip)}))
        else:
            self.assertIsNone(l2domain_template['address'])
            self.assertIsNone(l2domain_template['gateway'])
            self.assertIsNone(l2domain_template['netmask'])

        if cidr6:
            self.assertThat(l2domain_template, ContainsDict({'IPv6Address': Equals(str(cidr6))}))
            if "IPv6Gateway" not in kwargs:
                gateway_ip = str(IPAddress(cidr6) + 1)
                self.assertThat(l2domain_template, ContainsDict({'IPv6Gateway': Equals(gateway_ip)}))

        if dhcp_managed:
            self.assertThat(l2domain_template, ContainsDict({'DHCPManaged': Equals(True)}))
        else:
            self.assertThat(l2domain_template, ContainsDict({'DHCPManaged': Equals(False)}))

        # verify all other kwargs as attributes (key,value) pairs
        for key, value in kwargs.iteritems():
            self.assertThat(l2domain_template, ContainsDict({key: Equals(value)}))

        self.assertIsNone(l2domain_template['externalID'])

    def _verify_vsd_l2domain_with_template(self, l2domain, l2domain_template):

        self.assertThat(l2domain, ContainsDict({'templateID': Equals(l2domain_template['ID'])}))
        self.assertIsNone(l2domain_template['externalID'])

        # matching values
        matching_attributes = ('IPType', 'address', 'gateway', 'netmask', 'IPv6Address', 'IPv6Gateway')
        for matching_attribute in matching_attributes:
            self.assertThat(l2domain, ContainsDict({matching_attribute: Equals(l2domain_template[matching_attribute])}))

    def create_vsd_l2domain(self, template_id, name=None, **kwargs):
        if name is None:
            name = data_utils.rand_name('l2domain-')

        extra_params = kwargs.get('extra_params')
        vsd_l2domains = self.nuage_vsd_client.create_l2domain(
            name,
            templateId=template_id,
            extra_params=extra_params)
        vsd_l2domain = vsd_l2domains[0]
        self.addCleanup(self.nuage_vsd_client.delete_l2domain, vsd_l2domain['ID'])
        return vsd_l2domain

    def create_vsd_l3dom_template(self, **kwargs):
        vsd_l3dom_templates = self.nuage_vsd_client.create_l3domaintemplate(
            kwargs['name'] + '-template')
        vsd_l3dom_template = vsd_l3dom_templates[0]
        self.addCleanup(self.nuage_vsd_client.delete_l3domaintemplate, vsd_l3dom_template['ID'])
        return vsd_l3dom_template

    def create_vsd_l3domain(self, **kwargs):
        extra_params = kwargs.get('extra_params')
        vsd_l3domains = self.nuage_vsd_client.create_domain(kwargs['name'],
                                                            kwargs['tid'],
                                                            extra_params=extra_params)
        vsd_l3domain = vsd_l3domains[0]
        self.addCleanup(self.nuage_vsd_client.delete_domain, vsd_l3domain['ID'])
        return vsd_l3domain

    def create_vsd_zone(self, **kwargs):
        extra_params = kwargs.get('extra_params')
        vsd_zones = self.nuage_vsd_client.create_zone(kwargs['domain_id'],
                                                      kwargs['name'],
                                                      extra_params=extra_params)
        vsd_zone = vsd_zones[0]
        self.addCleanup(self.nuage_vsd_client.delete_zone, vsd_zone['ID'])
        return vsd_zone

    def create_vsd_l3domain_dualstack_subnet(self, zone_id, subnet_name,
                                             cidr, gateway,
                                             cidr6, gateway6):
        extra_params = {'IPType': "DUALSTACK",
                        'IPv6Address': str(cidr6),
                        'IPv6Gateway': gateway6}

        vsd_subnets = self.nuage_vsd_client.create_domain_subnet(
            parent_id=zone_id,
            name=subnet_name,
            net_address=str(cidr.ip),
            netmask=str(cidr.netmask),
            gateway=gateway,
            extra_params=extra_params)

        vsd_subnet = vsd_subnets[0]
        self.addCleanup(self.nuage_vsd_client.delete_domain_subnet, vsd_subnet['ID'])
        return vsd_subnet


############################################################
# Neutron resources
############################################################
class NetworkTestCaseMixin(BaseNuageNetworksTestCase):

    def create_network(self, network_name=None, **kwargs):
        """Wrapper utility that returns a test network."""
        network_name = network_name or data_utils.rand_name('test-network')

        body = self.networks_client.create_network(name=network_name, **kwargs)
        network = body['network']
        self.addCleanup(self.networks_client.delete_network, network['id'])
        return network

    def create_subnet(self, network, gateway='', cidr=None, mask_bits=None,
                      ip_version=None, client=None, **kwargs):
        """Wrapper utility that returns a test subnet."""
        # allow tests to use admin client
        if not client:
            client = self.subnets_client

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
                body = client.create_subnet(
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

        self.addCleanup(client.delete_subnet, subnet['id'])

        return subnet

    def create_port(self, network, **kwargs):
        """Wrapper utility that returns a test port."""
        body = self.ports_client.create_port(network_id=network['id'],
                                             **kwargs)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        return port

    @classmethod
    def update_port(cls, port, **kwargs):
        """Wrapper utility that updates a test port."""
        body = cls.ports_client.update_port(port['id'],
                                            **kwargs)
        return body['port']

    def _verify_port(self, port, subnet4=None, subnet6=None, **kwargs):
        has_ipv4_ip = False
        has_ipv6_ip = False

        for fixed_ip in port['fixed_ips']:
            ip_address = fixed_ip['ip_address']
            if subnet4 and fixed_ip['subnet_id'] == subnet4['id']:
                start_ip_address = subnet4['allocation_pools'][0]['start']
                end_ip_address = subnet4['allocation_pools'][0]['end']
                ip_range = IPRange(start_ip_address, end_ip_address)
                self.assertIn(ip_address, ip_range)
                has_ipv4_ip = True

            if subnet6 and fixed_ip['subnet_id'] == subnet6['id']:
                start_ip_address = subnet6['allocation_pools'][0]['start']
                end_ip_address = subnet6['allocation_pools'][0]['end']
                ip_range = IPRange(start_ip_address, end_ip_address)
                self.assertIn(ip_address, ip_range)
                has_ipv6_ip = True

        if subnet4:
            self.assertTrue(has_ipv4_ip, "Must have an IPv4 ip in subnet: %s" % subnet4['id'])

        if subnet6:
            self.assertTrue(has_ipv6_ip, "Must have an IPv6 ip in subnet: %s" % subnet6['id'])

        self.assertIsNotNone(port['mac_address'])

        # verify all other kwargs as attributes (key,value) pairs
        for key, value in kwargs.iteritems():
            self.assertThat(port, ContainsDict({key: Equals(value)}))