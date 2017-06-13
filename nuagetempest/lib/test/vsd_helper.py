from tempest.common.utils import data_utils
from tempest import config
from oslo_log import log as logging
import importlib
from netaddr import IPAddress

CONF = config.CONF

LOG = logging.getLogger(__name__)


def fetch_by_name(fetcher, name):
    return fetcher.fetch(filter='name is "{}"'.format(name))[2]


def get_by_name(fetcher, name):
    return fetcher.get(filter='name is "{}"'.format(name))[0]


class VsdHelper(object):
    """
    Base class for VSD interactions.
    This class will have all the common function to communicate with vsd using vspk
    """
    CONST_ETHER_TYPE_IPV4 = "0x0800"
    CONST_ETHER_TYPE_IPV6 = "0x86DD"

    cms_id = CONF.nuage.nuage_cms_id
    default_netpartition_name = CONF.nuage.nuage_default_netpartition

    def __init__(self, base_url, user='csproot', password='csproot',
                 enterprise='csp', version=None):
        self.user = user
        self.password = password
        self.enterprise = enterprise
        self.url = 'https://{}'.format(base_url)

        vspk_module = "vspk." + str(version)
        self.vspk = importlib.import_module(vspk_module)

        self.session = None
        self.default_enterprise = None

    def new_session(self):
        """
        Start a new API session via vspk an return the corresponding 'vspk.NUVSDSession` object.
        Note that this object is also exposed as `self.session`
        """
        self.session = self.vspk.NUVSDSession(
            username=self.user,
            password=self.password,
            enterprise=self.enterprise,
            api_url=self.url)

        self.session.start()

        self.default_enterprise = get_by_name(self.session.user.enterprises, self.default_netpartition_name)
        # TODO: if not available, than create a default enterprise
        if not self.default_enterprise:
            assert "Should have a default enterprise for OpenStack Nuage plugin"

        return self.session

    def __call__(self):
        if not self.session:
            return self.new_session()
        return self.session

    def get_default_enterprise(self):
        if not self.default_enterprise:
            self()
        return self.default_enterprise

    def get_external_id_filter(self, object_id):
        ext_id = object_id + "@" + self.cms_id
        return 'externalID is "{}"'.format(ext_id)

    def create_l2domain_template(self, name=None, enterprise=None,
                                 dhcp_managed=True,
                                 ip_type="IPV4",
                                 cidr4=None,
                                 gateway4=None,
                                 cidr6=None,
                                 gateway6=None,
                                 **kwargs):
        if not enterprise:
            enterprise = self.get_default_enterprise()

        template_name = name or data_utils.rand_name('test-l2template')

        params = {}

        if dhcp_managed:
            params['dhcp_managed'] = dhcp_managed

        if ip_type == "IPV4":
            params.update({'ip_type': "IPV4"})
        elif ip_type == "DUALSTACK":
            params.update({'ip_type': "DUALSTACK"})

        if cidr4:
            params.update({'address': str(cidr4.ip)})
            if "netmask" in kwargs:
                netmask = kwargs['netmask']
            else:
                netmask = str(cidr4.netmask)
            params.update({'netmask': netmask})

            if gateway4:
                params.update({'gateway': gateway4})

        if ip_type == self.vspk.NUSubnet.CONST_IP_TYPE_DUALSTACK:
            params.update({'ipv6_address': str(cidr6)})

            if gateway6:
                params.update({'ipv6_gateway': gateway6})

        # add all other kwargs as attributes (key,value) pairs
        for key, value in kwargs.iteritems():
            params.update({key: value})

        template = self.vspk.NUL2DomainTemplate(
            name=template_name,
            **params)

        return enterprise.create_child(template)[0]

    def create_l2domain(self, name=None, enterprise=None, template=None):
        if not enterprise:
            enterprise = self.get_default_enterprise()

        if not template:
            assert "must provide a valid template"

        name = name or data_utils.rand_name('test-l2domain')

        l2domain = self.vspk.NUL2Domain(
            name=name,
            template=template)

        return enterprise.instantiate_child(l2domain, template)[0]

    def get_l2domain(self, enterprise=None, vspk_filter=None):
        """ get_l2domain
            @params: enterprise object or enterprise id
                     filter following vspk filter structure
            @return  l2 domain object
            @Example:
            self.vsd.get_l2domain(enterprise=enterprise,
                                vspk_filter='name == "{}"'.format(name))
            self.vsd.get_l2domain(enterprise=enterprise_id,
                               vspk_filter='name == "{}"'.format(name))
            self.vsd.get_l2domain(vspk_filter='externalID == "{}"'.format(ext_id))
        """
        l2_domain = None
        if enterprise:
            if not isinstance(enterprise, self.vspk.NUEnterprise):
                enterprise = self.vspk.NUEnterprise(id=enterprise)
            l2_domain = enterprise.l2_domains.get_first(filter=vspk_filter)
        elif filter:
            l2_domain = self.session.user.l2_domains.get_first(filter=vspk_filter)
        if not l2_domain:
            LOG.error('could not fetch the l2 domain matching the filter "{}"'
                      .format(vspk_filter))
        return l2_domain

    ###
    # l3 domain
    ###

    def create_l3domain_template(self, name=None, enterprise=None):
        if not enterprise:
            enterprise = self.get_default_enterprise()

        template_name = name or data_utils.rand_name('test-l3template')

        template = self.vspk.NUDomainTemplate(
            name=template_name)

        mytemplate = enterprise.create_child(template)
        return mytemplate[0]

    def create_l3domain(self, enterprise=None, name=None, template_id=None):
        if not enterprise:
            enterprise = self.get_default_enterprise()

        if not template_id:
            assert "Must provide a valid template ID"

        name = name or data_utils.rand_name('test-l3domain')

        l3domain_data = self.vspk.NUDomain(
            name=name,
            template_id=template_id)

        l3domain_tuple = enterprise.create_child(l3domain_data)

        return l3domain_tuple[0]

    def create_zone(self, name=None, domain=None):
        zone_name = name or data_utils.rand_name('test-zone')

        zone_data = self.vspk.NUZone(
            name=zone_name),

        zone_tuple = domain.create_child(zone_data[0])
        return zone_tuple[0]

    def create_subnet(self, name=None, zone=None,
                      ip_type="IPV4",
                      cidr4=None,
                      gateway4=None,
                      cidr6=None,
                      gateway6=None,
                      **kwargs):

        if not zone:
            assert "Must provide a valid zone"

        subnet_name = name or data_utils.rand_name('test-subnet')

        params = {}

        if cidr4:
            params.update({'address': str(cidr4.ip)})
            if "netmask" in kwargs:
                netmask = kwargs['netmask']
            else:
                netmask = str(cidr4.netmask)
            params.update({'netmask': netmask})

            if gateway4:
                params.update({'gateway': gateway4})

        if ip_type == self.vspk.NUSubnet.CONST_IP_TYPE_DUALSTACK:
            params.update({'ipv6_address': str(cidr6)})

            if gateway6:
                params.update({'ipv6_gateway': gateway6})

        subnet_data = self.vspk.NUSubnet(
            name=subnet_name,
            ip_type=ip_type,
            **params)

        subnet_tuple = zone.create_child(subnet_data)
        return subnet_tuple[0]

    ###
    # policy groups
    ###

    def create_policy_group(self, domain, name=None):
        pg = self.vspk.NUPolicyGroup(name=name, type='SOFTWARE')
        domain.create_child(pg)
        return domain.policy_groups.get_first(
            filter='name is "{}"'.format(name))

    def create_ingress_acl_template(self, domain, name='default-acl-template'):
        acl_params = {
            'name': name,
            'active': True,
            'default_allow_ip': True,
            'default_allow_non_ip': False,
            'allow_address_spoof': True,
        }

        ingress_tpl = self.vspk.NUIngressACLTemplate(**acl_params)
        domain.create_child(ingress_tpl)

        return domain.ingress_acl_templates.get_first(
            filter='name is "{}"'.format(name))

    def create_egress_acl_template(self, domain, name='default-acl-template'):
        acl_params = {
            'name': name,
            'active': True,
            'default_allow_ip': True,
            'default_allow_non_ip': False,
            'allow_address_spoof': True,
        }

        egress_tpl = self.vspk.NUEgressACLTemplate(**acl_params)
        domain.create_child(egress_tpl)

        return domain.egress_acl_templates.get_first(
            filter='name is "{}"'.format(name))

    def add_egress_acl_template_rule(self, template, name='default-acl-rule',
                                     protocol='ANY',
                                     location_type='ANY',
                                     network_type='ANY',
                                     stateful=False,
                                     egress="FORWARD"):
        entry = self.vspk.NUIngressACLEntryTemplate(name=name,
                                                    protocol=protocol,
                                                    location_type=location_type,
                                                    network_type=network_type,
                                                    stateful=stateful,
                                                    action=egress)
        return template.create_child(entry)[0]

    def define_any_to_any_acl(self, domain,
                              ingress='FORWARD', egress='FORWARD',
                              allow_ipv4=True,
                              allow_ipv6=False,
                              stateful=False, spoof=False):
        def create_acl_templates(the_domain, allow_spoofing):
            acl_params = {
                'name': 'default-acl-template',
                'active': True,
                'default_allow_ip': False,
                'default_allow_non_ip': False,
                'allow_address_spoof': allow_spoofing,
                'default_install_acl_implicit_rules': False
            }
            ingress_template = self.vspk.NUIngressACLTemplate(**acl_params)
            the_domain.create_child(ingress_template)
            egress_template = self.vspk.NUEgressACLTemplate(**acl_params)
            the_domain.create_child(egress_template)
            return ingress_template, egress_template

        # always delete first
        for acl in domain.ingress_acl_templates.get():
            acl.delete()
        for acl in domain.egress_acl_templates.get():
            acl.delete()
        # and then create new
        res = []
        ingress_tpl, egress_tpl = create_acl_templates(domain, spoof)

        if allow_ipv4:
            entry = self.vspk.NUIngressACLEntryTemplate(
                protocol='ANY',
                location_type='ANY',
                network_type='ANY',
                stateful=stateful,
                action=ingress)
            obj = ingress_tpl.create_child(entry)[0]
            res.append(obj.stats_id)
            entry = self.vspk.NUEgressACLEntryTemplate(
                protocol='ANY',
                location_type='ANY',
                network_type='ANY',
                stateful=stateful,
                action=egress)
            obj = egress_tpl.create_child(entry)[0]
            res.append(obj.stats_id)

        if allow_ipv6:
            entry = self.vspk.NUIngressACLEntryTemplate(
                ether_type=self.CONST_ETHER_TYPE_IPV6,
                protocol='ANY',
                location_type='ANY',
                network_type='ANY',
                stateful=stateful,
                action=ingress)
            obj = ingress_tpl.create_child(entry)[0]
            res.append(obj.stats_id)
            entry = self.vspk.NUEgressACLEntryTemplate(
                ether_type=self.CONST_ETHER_TYPE_IPV6,
                protocol='ANY',
                location_type='ANY',
                network_type='ANY',
                stateful=stateful,
                action=egress)
            obj = egress_tpl.create_child(entry)[0]
            res.append(obj.stats_id)

        return res
