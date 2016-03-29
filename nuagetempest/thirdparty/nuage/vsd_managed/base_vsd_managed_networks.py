# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from netaddr import *

from tempest.api.network import base
from tempest.lib.common.utils import data_utils
from tempest import config
from tempest.scenario import manager
from nuagetempest.services.nuage_network_client import NuageNetworkClientJSON
from nuagetempest.lib.utils import constants

from nuagetempest.services import nuage_client

CONF = config.CONF

# default values for shared L2/L3 networks
VSD_L2_SHARED_MGD_CIDR = IPNetwork('20.20.20.0/24')
VSD_L2_SHARED_MGD_GW = '20.20.20.1'

VSD_L3_SHARED_MGD_CIDR = IPNetwork('30.30.30.0/24')
VSD_L3_SHARED_MGD_GW = '30.30.30.1'


class BaseVSDMangedNetworkTest(base.BaseAdminNetworkTest,
                               manager.NetworkScenarioTest):

    @classmethod
    def setup_clients(cls):
        super(BaseVSDMangedNetworkTest, cls).setup_clients()
        cls.nuage_vsd_client = nuage_client.NuageRestClient()
        cls.admin_client = cls.os_adm.network_client

        cls.nuage_network_client = NuageNetworkClientJSON(
            cls.os.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os.default_params)

    @classmethod
    def resource_setup(cls):
        super(BaseVSDMangedNetworkTest, cls).resource_setup()
        cls.vsd_l2dom_template = []
        cls.vsd_l2domain = []
        cls.vsd_l3dom_template = []
        cls.vsd_l3domain = []
        cls.vsd_zone = []
        cls.vsd_subnet = []
        cls.vsd_shared_domain = []
        cls.keypairs = {}
        cls.security_group = []
        cls.vsd_policy_group = []

    @classmethod
    def resource_cleanup(cls):
        # cleanup the OpenStack managed objects first
        super(BaseVSDMangedNetworkTest, cls).resource_cleanup()

        for vsd_policy_group in cls.vsd_policy_group:
            cls.nuage_vsd_client.delete_policygroup(vsd_policy_group[0]['id'])

        for vsd_l2domain in cls.vsd_l2domain:
            cls.nuage_vsd_client.delete_l2domain(vsd_l2domain[0]['ID'])

        for vsd_l2dom_template in cls.vsd_l2dom_template:
            cls.nuage_vsd_client.delete_l2domaintemplate(vsd_l2dom_template[0]['ID'])

        for vsd_subnet in cls.vsd_subnet:
            cls.nuage_vsd_client.delete_domain_subnet(vsd_subnet[0]['ID'])

        for vsd_zone in cls.vsd_zone:
            cls.nuage_vsd_client.delete_zone(vsd_zone[0]['ID'])

        for vsd_l3domain in cls.vsd_l3domain:
            cls.nuage_vsd_client.delete_domain(vsd_l3domain[0]['ID'])

        for vsd_l3dom_template in cls.vsd_l3dom_template:
            cls.nuage_vsd_client.delete_l3domaintemplate(vsd_l3dom_template[0]['ID'])

        for vsd_shared_domain in cls.vsd_shared_domain:
            cls.nuage_vsd_client.delete_vsd_shared_resource(vsd_shared_domain[0]['ID'])

    @classmethod
    def create_vsd_dhcpmanaged_l2dom_template(cls, **kwargs):
        params = {
            'DHCPManaged': True,
            'address': str(kwargs['cidr'].ip),
            'netmask': str(kwargs['cidr'].netmask),
            'gateway': kwargs['gateway']
        }
        # todo: create open ingress/egress policy and apply to this template
        vsd_l2dom_tmplt = cls.nuage_vsd_client.create_l2domaintemplate(
            kwargs['name'] + '-template', extra_params=params)
        cls.vsd_l2dom_template.append(vsd_l2dom_tmplt)
        return vsd_l2dom_tmplt

    @classmethod
    def create_vsd_dhcpunmanaged_l2dom_template(cls, **kwargs):
        if "name" not in kwargs:
            name = data_utils.rand_name('l2domain-noIPAM-template')
        else:
            name = kwargs['name']
        # todo: create open ingress/egress policy and apply to this template
        vsd_l2dom_tmplt = cls.nuage_vsd_client.create_l2domaintemplate(name=name)
        cls.vsd_l2dom_template.append(vsd_l2dom_tmplt)
        return vsd_l2dom_tmplt

    @classmethod
    def create_vsd_l2domain(cls, **kwargs):
        if "name" not in kwargs:
            name = data_utils.rand_name('l2domain')
        else:
            name = kwargs['name']
        vsd_l2dom = cls.nuage_vsd_client.create_l2domain(name=name,
                                                    templateId=kwargs['tid'])
        cls.vsd_l2domain.append(vsd_l2dom)
        return vsd_l2dom

    @classmethod
    def create_vsd_l3dom_template(cls, **kwargs):
        if "name" not in kwargs:
            name = data_utils.rand_name('l3domain-template')
        else:
            name = kwargs['name']
        vsd_l3dom_tmplt = cls.nuage_vsd_client.create_l3domaintemplate(name=name)
        cls.vsd_l3dom_template.append(vsd_l3dom_tmplt)
        return vsd_l3dom_tmplt

    @classmethod
    def create_vsd_l3domain(cls, **kwargs):
        if "name" not in kwargs:
            name = data_utils.rand_name('l3domain')
        else:
            name = kwargs['name']
        vsd_l3dom = cls.nuage_vsd_client.create_domain(name,
                                                  kwargs['tid'])
        cls.vsd_l3domain.append(vsd_l3dom)
        return vsd_l3dom

    @classmethod
    def create_vsd_zone(cls, **kwargs):
        if "name" not in kwargs:
            name = data_utils.rand_name('vsd-zone')
        else:
            name = kwargs['name']
        if "extra_params" in kwargs:
            extra_params = kwargs.get('extra_params')
        else:
            extra_params = {}
        vsd_zone = cls.nuage_vsd_client.create_zone(kwargs['domain_id'],
                                                   name=name,
                                               extra_params=extra_params)
        cls.vsd_zone.append(vsd_zone)
        return vsd_zone

    @classmethod
    def create_vsd_l3domain_subnet(cls, **kwargs):
        vsd_subnet = cls.nuage_vsd_client.create_domain_subnet(
            kwargs['zone_id'],
            kwargs['name'],
            str(kwargs['cidr'].ip),
            str(kwargs['cidr'].netmask),
            kwargs['gateway'])
        cls.vsd_subnet.append(vsd_subnet)
        return vsd_subnet

    @classmethod
    def create_vsd_l3domain_managed_subnet(cls, **kwargs):
        if "name" not in kwargs:
            name = data_utils.rand_name('l3-managed-subnet')
        else:
            name = kwargs['name']
        if not "cidr" in kwargs:
            address = VSD_L3_SHARED_MGD_CIDR.ip
            netmask = VSD_L3_SHARED_MGD_CIDR.netmask
        else:
            address = kwargs['cidr'].ip
            netmask = kwargs['cidr'].netmask
        if not 'gateway' in kwargs:
            gateway = VSD_L3_SHARED_MGD_GW
        else:
            gateway = kwargs['gateway']
        if not 'extra_params' in kwargs:
            extra_params = None
        else:
            extra_params = kwargs['extra_params']
        vsd_subnet = cls.nuage_vsd_client.create_domain_subnet(kwargs['zone_id'],
                                                          name,
                                                          str(address),
                                                          str(netmask),
                                                          gateway,
                                                          extra_params)
        cls.vsd_subnet.append(vsd_subnet)
        return vsd_subnet

    @classmethod
    def create_vsd_l3domain_unmanaged_subnet(cls, **kwargs):
        if "name" not in kwargs:
            name = data_utils.rand_name('vsd-zone')
        else:
            name = kwargs['name']

        vsd_subnet = cls.nuage_vsd_client.create_domain_unmanaged_subnet(kwargs['zone_id'],
                                                                    name,
                                                                    kwargs['extra_params'])
        cls.vsd_subnet.append(vsd_subnet)
        return vsd_subnet

    @classmethod
    def create_vsd_shared_l2domain_unmanaged(cls, **kwargs):
        if "name" not in kwargs:
            name = data_utils.rand_name('vsd-l2domain-shared-unmgd')
        else:
            name = kwargs['name']
        vsd_l2_shared_domain = cls.nuage_vsd_client.create_vsd_shared_resource(name=name,
                                                                          type='L2DOMAIN')
        cls.vsd_shared_domain.append(vsd_l2_shared_domain)
        return vsd_l2_shared_domain

    @classmethod
    def create_vsd_shared_l2domain_managed(cls, **kwargs):
        if "name" in kwargs:
            name = kwargs['name']
        else:
            name = data_utils.rand_name('vsd-l2domain-shared-Mgd')
        #
        if 'cidr' in kwargs:
            cidr = kwargs['cidr']
        else:
            cidr = VSD_L2_SHARED_MGD_CIDR
        #
        if "gateway" in kwargs:
            gateway = kwargs['gateway']
        else:
            gateway = VSD_L2_SHARED_MGD_GW
        extra_params = {
            'DHCPManaged': True,
            'address': str(cidr.ip),
            'netmask': str(cidr.netmask),
            'gateway': gateway
        }
        vsd_l2_shared_domain = cls.nuage_vsd_client.create_vsd_shared_resource(name=name,
                                                                          type='L2DOMAIN',
                                                                          extra_params=extra_params)
        cls.vsd_shared_domain.append(vsd_l2_shared_domain)
        return vsd_l2_shared_domain

    @classmethod
    def create_vsd_shared_l3domain_managed(cls, **kwargs):
        if "name" in kwargs:
            name = kwargs['name']
        else:
            name = data_utils.rand_name('vsd-l3domain-mgd')
        #
        if 'cidr' in kwargs:
            cidr = kwargs['cidr']
        else:
            cidr = VSD_L3_SHARED_MGD_CIDR
        #
        if "gateway" in kwargs:
            gateway = kwargs['gateway']
        else:
            gateway = VSD_L3_SHARED_MGD_GW
        extra_params = {
            'DHCPManaged': True,
            'address': str(cidr.ip),
            'netmask': str(cidr.netmask),
            'gateway': gateway
        }
        vsd_l3_shared_domain = cls.nuage_vsd_client.create_vsd_shared_resource(name=name,
                                                                          type='PUBLIC',
                                                                          extra_params=extra_params)
        cls.vsd_shared_domain.append(vsd_l3_shared_domain)
        return vsd_l3_shared_domain

    @classmethod
    def link_l2domain_to_shared_domain(cls, domain_id, shared_domain_id):
        update_params = {
            'associatedSharedNetworkResourceID': shared_domain_id
        }
        cls.nuage_vsd_client.update_l2domain(domain_id, update_params=update_params)

    def create_vsd_l2_policy_group(cls, vsd_l2_subnet_id, name=None, type=None, extra_params=None):
        if name is None:
            name = data_utils.rand_name('vsd-policy-group')
        policy_group = cls.nuage_vsd_client.create_policygroup(constants.L2_DOMAIN,
                                                          vsd_l2_subnet_id,
                                                          name=name,
                                                          type=type,
                                                          extra_params=extra_params)
        cls.vsd_policy_group.append(policy_group)
        return policy_group
        pass

