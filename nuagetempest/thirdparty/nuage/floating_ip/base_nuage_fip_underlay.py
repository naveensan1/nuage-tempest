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

import re
from netaddr import IPNetwork

from testtools.matchers import Equals
from testtools.matchers import ContainsDict

from tempest.api.network import base
from tempest.lib.common.utils import data_utils
from oslo_log import log as logging

from tempest import config
from tempest.lib import exceptions
from tempest import test
from nuagetempest.lib.utils import constants as nuage_constants

from nuagetempest.services import nuage_client
from nuagetempest.lib import service_mgmt

CONF = config.CONF


class NuageFipUnderlayBase(base.BaseAdminNetworkTest,):
    LOG = logging.getLogger(__name__)
    # user order of tests as in this file to avoid unnecessary neutron restart
    #   unittest.TestLoader.sortTestMethodsUsing(None)

    @classmethod
    def setup_clients(cls):
        super(NuageFipUnderlayBase, cls).setup_clients()
        cls.nuage_vsd_client = nuage_client.NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(NuageFipUnderlayBase, cls).resource_setup()
        if not test.is_extension_enabled('router', 'network'):
            msg = "router extension not enabled."
            raise cls.skipException(msg)

        if not CONF.service_available.neutron:
            msg = "Skipping allexternalID Neutron cli tests because it is not available"
            raise cls.skipException(msg)

        cls.ext_net_id = CONF.network.public_network_id
        cls.service_manager = service_mgmt.ServiceManager()

        nuage_fip_underlay_ini = cls.read_nuage_fip_underlay_value_ini()
        if nuage_fip_underlay_ini == '':
            nuage_fip_underlay_ini = None
        cls.nuage_fip_underlay_ini = nuage_fip_underlay_ini

        if not cls.service_manager.is_service_running(nuage_constants.NEUTRON_SERVICE):
            cls.service_manager.start_service(nuage_constants.NEUTRON_SERVICE)

    @classmethod
    def needs_ini_nuage_fip_underlay(cls, underlay_value):
        # underlay_value is supposed to be True/False/None, but can be different (add exception case)
        cls.service_manager.must_have_configuration_attribute(
            CONF.nuage_sut.nuage_plugin_configuration,
            nuage_constants.NUAGE_FIP_UNDERLAY_GROUP, nuage_constants.NUAGE_FIP_UNDERLAY, underlay_value)
        cls.nuage_fip_underlay_ini = underlay_value

    @classmethod
    def read_nuage_fip_underlay_value_ini(cls):
        fip_underlay_from_ini = cls.service_manager.get_configuration_attribute(
            CONF.nuage_sut.nuage_plugin_configuration,
            nuage_constants.NUAGE_FIP_UNDERLAY_GROUP, nuage_constants.NUAGE_FIP_UNDERLAY)
        return fip_underlay_from_ini

    # Taken from test_external_network_extensions.py,trying to avoid issues with the cli client
    def _create_network(self, external=True):
        post_body = {'name': data_utils.rand_name('network-')}
        if external:
            post_body['router:external'] = external
        body = self.admin_networks_client.create_network(**post_body)
        network = body['network']
        self.addCleanup(self.admin_networks_client.delete_network, network['id'])
        return network

    def _verify_create_delete_external_subnet_without_underlay(self):
        # default_underlay = None is same as False, change to False because that will be in the response
        default_underlay = self.nuage_fip_underlay_ini
        if default_underlay is None:
            default_underlay = False
        ext_network = self._create_network(external=True)
        subnet_name = 'non-underlay-subnet'
        body = self.admin_subnets_client.create_subnet(
            network_id=ext_network['id'],
            cidr='135.30.0.0/24',
            ip_version=self._ip_version,
            name=subnet_name)
        subnet = body['subnet']
        self.assertEqual(str(subnet['underlay']), str(default_underlay))
        nuage_fippool = self.nuage_vsd_client.get_sharedresource(
            filters='externalID', filter_value=self.nuage_vsd_client.get_vsd_external_id(subnet['id']))
        self.assertEqual(str(nuage_fippool[0]['underlay']), str(default_underlay))
        self.admin_subnets_client.delete_subnet(subnet['id'])
        nuage_fippool = self.nuage_vsd_client.get_sharedresource(
            filters='externalID', filter_value=self.nuage_vsd_client.get_vsd_external_id(subnet['id']))
        self.assertEqual(nuage_fippool, '')

    def _verify_create_external_fip_subnet_with_underlay(self):
        """
        Create an external fip subnet with underlay=False/True

        Response must include the correct underlay value
        """
        ext_network = self._create_network(external=True)
        underlay_states = [False, True]
        for underlay in underlay_states:
            subnet_name = data_utils.rand_name('create-external-fip-subnet-with-underlay')
            create_body = self.admin_subnets_client.create_subnet(network_id=ext_network['id'],
                                                                  cidr='135.99.77.0/24',
                                                                  ip_version=self._ip_version,
                                                                  name=subnet_name, underlay=underlay)
            subnet = create_body['subnet']
            self.assertEqual(create_body['subnet']['underlay'], underlay,
                             "FIP NOK: create response does not include underlay while it must: OPENSTACK-659")
            # Check value on VSD
            nuage_fippool = self.nuage_vsd_client.get_sharedresource(
                filters='externalID',
                filter_value=self.nuage_vsd_client.get_vsd_external_id(subnet['id']))
            self.assertEqual(nuage_fippool[0]['underlay'], underlay)
            # delete and check externalIDagain on VSD
            self.admin_subnets_client.delete_subnet(subnet['id'])
            nuage_fippool = self.nuage_vsd_client.get_sharedresource(
                filters='externalID',
                filter_value=self.nuage_vsd_client.get_vsd_external_id(subnet['id']))
            self.assertEqual(nuage_fippool, '')

    def _verify_show_external_subnet_without_underlay(self):
        """
        Show an external fip subnet created without underlay

        Response may not include underlay, irregardless of the nuage_fip_underlay setting
        """
        ext_network = self._create_network(external=True)
        subnet_name = data_utils.rand_name('show-external-fip-subnet-without-underlay')
        create_body = self.admin_subnets_client.create_subnet(network_id=ext_network['id'],
                                                              cidr='135.99.77.0/24',
                                                              ip_version=self._ip_version,
                                                              name=subnet_name)
        subnet = create_body['subnet']
        show_body = self.admin_subnets_client.show_subnet(subnet['id'])
        self.assertEqual(show_body['subnet']['name'], subnet_name)
        self.assertNotIn(show_body['subnet'], "underlay",
                         "FIP NOK: show response includes underlay section while it may not")
        self.admin_subnets_client.delete_subnet(subnet['id'])

    def _verify_show_external_subnet_with_underlay(self):
        """
        Show an external fip subnet with underlay=False/True

        Response must include the correct underlay value
        """
        ext_network = self._create_network(external=True)
        underlay_states = [False, True]
        for underlay in underlay_states:
            subnet_name = data_utils.rand_name('external-fip-subnet-show-underlay')
            create_body = self.admin_subnets_client.create_subnet(network_id=ext_network['id'],
                                                                  cidr='135.99.77.0/24',
                                                                  ip_version=self._ip_version,
                                                                  name=subnet_name, underlay=underlay)
            subnet = create_body['subnet']
            show_body = self.admin_subnets_client.show_subnet(subnet['id'])
            self.assertEqual(show_body['subnet']['name'], subnet_name)
            self.assertEqual(show_body['subnet']['underlay'], underlay,
                             "FIP NOK: show response does not include underlay section while it must: OPENSTACK-672")
            self.admin_subnets_client.delete_subnet(subnet['id'])
            pass

    def _verify_update_external_subnet_with_underlay_neg(self):
        ext_network = self._create_network(external=True)
        underlay_states = [False, True]
        cidr = IPNetwork('99.99.0.0/24')
        for underlay in underlay_states:
            subnet_name = data_utils.rand_name('underlay-subnet-update-not-allowed')
            create_body = self.admin_subnets_client.create_subnet(network_id=ext_network['id'],
                                                                  cidr=str(cidr.cidr),
                                                                  ip_version=self._ip_version,
                                                                  name=subnet_name, underlay=underlay)
            subnet = create_body['subnet']
            self.assertEqual(subnet['name'], subnet_name)
            # Response should include underlay status
            self.assertEqual(subnet['underlay'], underlay)
            subnet_id = subnet['id']
            new_name = subnet_name + '-updated-1'
            # Checking OPENSTACK-721: update name
            update_body = self.admin_subnets_client.update_subnet(subnet_id, name=new_name)
            self.assertEqual(update_body['subnet']['name'], new_name)
            new_underlay = False if underlay else True
            kvargs = {
                'name': new_name,
                'underlay': new_underlay
            }
            self.assertRaises(exceptions.BadRequest,
                              self.admin_subnets_client.update_subnet,
                              subnet_id,
                              **kvargs)
            self.admin_subnets_client.delete_subnet(subnet_id)
            cidr = cidr.next(1)
        pass

    def _verify_list_external_subnets_underlay(self):
        """
        List external subnets with and without underlay

        The created fip subnets must be in the list and a show of them reveals the same underlay value used during
        creation
        """
        cidr = IPNetwork('99.98.97.0/24')
        my_subnet_list = ['subnet-underlay_false',
                          'subnet_underlay_true',
                          'subnet_underlay']
        for this_subnet in my_subnet_list:
            this_ext_network = self._create_network(external=True)
            if re.search('true', this_subnet):
                underlay = True
            elif re.search('false', this_subnet):
                underlay = False
            else:
                # Use this for checking default behavior when nuage_fip_underlay is present in .ini file
                underlay = None
            subnet_name = data_utils.rand_name('list-external-fip-' + this_subnet)
            if underlay is None:
                create_body = self.admin_subnets_client.create_subnet(network_id=this_ext_network['id'],
                                                                      cidr=str(cidr.cidr),
                                                                      ip_version=self._ip_version,
                                                                      name=subnet_name)
            else:
                create_body = self.admin_subnets_client.create_subnet(network_id=this_ext_network['id'],
                                                                      cidr=str(cidr.cidr),
                                                                      ip_version=self._ip_version,
                                                                      name=subnet_name, underlay=underlay)
            # Verify the subnet exists in the list of all subnets
            list_body = self.admin_subnets_client.list_subnets()
            subnet_found = False
            for subnet in list_body['subnets']:
                if create_body['subnet']['id'] == subnet['id']:
                    # our created subnet is in the list: check the underlay field of the show output, as it is not
                    # in the list output for performance reasons (requires an extra api call per subnet...)
                    subnet_found = True
                    show_body = self.admin_subnets_client.show_subnet(subnet['id'])
                    underlay_listed = show_body['subnet']['underlay']

                    if underlay is not None:
                        # Verify underlay with the value used at creation time
                        # assign underlay_compare to underlay, the value used at creation
                        underlay_compare = create_body['subnet']['underlay']
                    else:
                        # No underlay given: should match the value in the .ini file
                        # Note that 'None' has same effect as false: check on False
                        underlay_compare = self.nuage_fip_underlay_ini
                        if underlay_compare is None:
                            underlay_compare = False
                    self.assertEqual(str(underlay_listed), str(underlay_compare),
                                     "FIP NOK: listed underlay values do not match")
            self.assertEqual(subnet_found, True, "FIP NOK: created fip subnet is not in the subnet list")
            cidr = cidr.next(1)

    def _verify_create_external_subnet_with_underlay_scale(self, tunnel_type, maximum):
        """
        Create/Delete "maximum" external fip subnets for the given tunnel_type (GRE/VXLAN)

        All external fip subnets should get created, have the right attributes on VSD and get deleted afterwards
        GRE: 32
        VXLAN: 400
        """
        # Todo: list the already existing external subnets, and then go to the max.
        # If there are already a few existing external networks,  we'll hit the ceiling before reaching max (QED)
        cidr = IPNetwork('99.99.0.0/24')
        for count in range(maximum - 2):
            ext_network = self._create_network(external=True)
            subnet_name = data_utils.rand_name(
                'external-fipsubnet-with-underlay-scale-' + str(maximum) + '-nbr' + str(count))
            # increase cidr_net to next /24 subnet
            cidr = cidr.next(1)
            body = self.admin_subnets_client.create_subnet(network_id=ext_network['id'],
                                                           cidr=str(cidr.cidr),
                                                           ip_version=self._ip_version,
                                                           name=subnet_name, underlay=True)
            subnet = body['subnet']
            # Response should include the same underlay status
            self.assertEqual(subnet['underlay'], True)
            # check underlay in VSD
            nuage_fippool = self.nuage_vsd_client.get_sharedresource(
                filters='externalID',
                filter_value=self.nuage_vsd_client.get_vsd_external_id(subnet['id']))
            self.assertEqual(nuage_fippool[0]['underlay'], True)
            # self.admin_client.delete_subnet(subnet['id'])
            # nuage_fippool = self.nuage_vsd_client.get_sharedresource(filters='externalID',
            #                                                      filter_value=subnet['id'])
            # self.assertEqual(nuage_fippool, '')
            # increase cidr to next /24 subnet
            cidr = cidr.next(1)

        # We reached the maximum of 32, check whether 33 fails
        ext_network = self._create_network(external=True)
        subnet_name = data_utils.rand_name('external-subnet-scale100-with-underlay-beyond32')
        kvargs = {
            'network_id': ext_network['id'],
            'cidr': str(cidr.cidr),
            'ip_version': self._ip_version,
            'name': subnet_name,
            'underlay': True
        }
        self.assertRaises(exceptions.ServerFault,
                          self.admin_subnets_client.create_subnet,
                          **kvargs)

    #
    # CLI methods
    #
    def _cli_create_delete_external_subnet_without_underlay(self):
        # underlay_default = None is same as False, change to False because that will be in the response
        if self.nuage_fip_underlay_ini is None:
            underlay_default = False
        else:
            underlay_default = self.nuage_fip_underlay_ini
        ext_network_name = data_utils.rand_name("ext-fip-network")
        ext_network = self.create_network_with_args(ext_network_name, " --router:external")
        ext_subnet_name = data_utils.rand_name('ext-non-underlay-subnet')
        subnet = self.create_subnet_with_args(ext_network['name'], "135.134.133.0/24", "--name ", ext_subnet_name)
        compare_str = str(underlay_default)
        self.assertIn(compare_str.lower(), str(subnet['underlay']).lower())
        nuage_fippool = self.nuage_vsd_client.get_sharedresource(
            filters='externalID', filter_value=self.nuage_vsd_client.get_vsd_external_id(subnet['id']))
        self.assertEqual(str(nuage_fippool[0]['underlay']), str(underlay_default))
        self.admin_subnets_client.delete_subnet(subnet['id'])
        nuage_fippool = self.nuage_vsd_client.get_sharedresource(
            filters='externalID', filter_value=self.nuage_vsd_client.get_vsd_external_id(subnet['id']))
        self.assertEqual(nuage_fippool, '')
        # Remove it from the cleanup list, as we deleted it ourselves already to check change in VSD
        self.subnets.remove(subnet)
        pass

    def _cli_create_external_fip_subnet_with_underlay(self):
        """
        Create an external fip subnet with underlay=False/True

        Response must include the correct underlay value
        """
        # self.needs_ini_nuage_fip_underlay(default_underlay)
        underlay_states = [False, True]
        for underlay in underlay_states:
            rand_name_str = data_utils.rand_name()
            ext_network_name = "ext-fip-network-" + rand_name_str
            ext_network = self.create_network_with_args(ext_network_name, " --router:external")
            ext_subnet_name = "ext-fip-underlay-subnet-" + rand_name_str
            # create 1 param without spaces, as create_subnet_with_args is adding spaces between arguments
            # and we require underlay=<value> without space
            underlay_str = "--underlay=" + str(underlay)
            subnet = self.create_subnet_with_args(ext_network['name'],
                                                  "136.135.134.0/24",
                                                  "--name ", ext_subnet_name,
                                                  underlay_str)
            # Compare the returned value with the given value, lowercased to avoid issues with upper/lowercase
            self.assertIn(str(underlay).lower(), str(subnet['underlay']).lower())
            # Check value on VSD
            nuage_fippool = self.nuage_vsd_client.get_sharedresource(
                filters='externalID',
                filter_value=self.nuage_vsd_client.get_vsd_external_id(subnet['id']))
            self.assertEqual(nuage_fippool[0]['underlay'], underlay)
            # delete and check again on VSD
            self.admin_subnets_client.delete_subnet(subnet['id'])
            nuage_fippool = self.nuage_vsd_client.get_sharedresource(
                filters='externalID',
                filter_value=self.nuage_vsd_client.get_vsd_external_id(subnet['id']))
            self.assertEqual(nuage_fippool, '')
            # Remove it from the cleanup list, as we deleted it ourselves already to check change in VSD
            self.subnets.remove(subnet)
        pass

    def _cli_show_external_subnet_without_underlay(self):
        """
        Show an external fip subnet created without underlay

        Response includes underlay values according default setting in the .ini file
        Note that no setting (None) is the same as False
        """
        default_underlay = self.nuage_fip_underlay_ini
        # self.needs_ini_nuage_fip_underlay(default_underlay)
        rand_name_str = data_utils.rand_name()
        ext_network_name = "ext-fip-network-" + rand_name_str
        ext_network = self.create_network_with_args(ext_network_name, " --router:external")
        ext_subnet_name = "ext-fip-underlay-subnet-" + rand_name_str
        subnet = self.create_subnet_with_args(ext_network['name'],
                                              "137.136.135.0/24",
                                              "--name ", ext_subnet_name)
        show_subnet = self.show_subnet(subnet['id'])
        # underlay value should match the default one
        check_str = str(default_underlay) if default_underlay is not None else "False"
        self.assertIn(check_str.lower(), str(show_subnet['underlay']).lower())
        pass

    def _cli_show_external_subnet_with_underlay(self):
        """
        Show an external fip subnet created with underlay

        Response includes underlay values according default setting in the .ini file
        """
        # self.needs_ini_nuage_fip_underlay(default_underlay)
        # avoid overlapping cidr's: use different ones ;-)
        # cleanup is at class level ftb, so use a different cidr according the value of default_underlay
        default_underlay = self.nuage_fip_underlay_ini
        if default_underlay is None:
            cidr_addition = 0
        elif default_underlay is False:
            cidr_addition = 20
        else:
            cidr_addition = 500
        cidr_net = IPNetwork('100.99.100.0/24').next(cidr_addition)
        underlay_states = [False, True]
        for underlay in underlay_states:
            rand_name_str = data_utils.rand_name()
            ext_network_name = "ext-fip-network-" + rand_name_str
            ext_network = self.create_network_with_args(ext_network_name, " --router:external")
            ext_subnet_name = "ext-fip-underlay-subnet-" + rand_name_str
            underlay_str = "--underlay=" + str(underlay)
            subnet = self.create_subnet_with_args(ext_network['name'],
                                                  cidr_net.__str__(),
                                                  "--name ", ext_subnet_name,
                                                  underlay_str)
            show_subnet = self.show_subnet(subnet['id'])
            # underlay value should match the default one
            self.assertIn(str(underlay).lower(), str(show_subnet['underlay']).lower())
            cidr_net = cidr_net.next(1)
        pass

    def _cli_update_external_subnet_with_underlay_neg(self):
        underlay_states = [False, True]
        for underlay in underlay_states:
            rand_name_str = data_utils.rand_name()
            ext_network_name = "ext-fip-network-" + rand_name_str
            ext_network = self.create_network_with_args(ext_network_name, " --router:external")
            ext_subnet_name = "ext-fip-underlay-subnet-update_not-allowed" + rand_name_str
            underlay_str = "--underlay=" + str(underlay)
            subnet = self.create_subnet_with_args(ext_network['name'],
                                                  "99.99.99.0/24",
                                                  "--name ", ext_subnet_name,
                                                  underlay_str)
            self.assertThat(subnet, ContainsDict({'underlay': Equals(str(underlay))}))

            # Check OPENSTACK-721: update name of subnet failing
            new_name = ext_subnet_name + "name_upd"
            self.update_subnet_with_args(subnet['id'], "--name ", new_name)
            show_subnet = self.show_subnet(subnet['id'])
            updated_name = show_subnet['name']

            self.assertEqual(updated_name, new_name)
            # Check VSD-18778 - state should not have changed
            self.assertThat(show_subnet, ContainsDict({'underlay': Equals(str(underlay))}))

            new_underlay_str = "--underlay=" + str(False if underlay is True else True)
            exp_message = "Cannot update read-only attribute underlay"
            self.assertRaisesRegexp(exceptions.SSHExecCommandFailed,
                                    exp_message,
                                    self.update_subnet_with_args, subnet['id'], new_underlay_str)

        pass

    def _cli_list_external_subnets_underlay(self):
        """
        List external subnets with and without underlay

        The created fip subnets must be in the list and a show of them reveals the same underlay value used during
        creation
        """
        # self.needs_ini_nuage_fip_underlay(default_underlay)
        # avoid overlapping cidr's: use different ones ;-)
        # cleanup is at class level ftb, so use a different cidr according the value of default_underlay
        default_underlay = self.nuage_fip_underlay_ini
        if default_underlay is None:
            cidr_addition = 0
        elif default_underlay is False:
            cidr_addition = 20
        else:
            cidr_addition = 50
        my_subnet_list = ['list-subnet-underlay-false-',
                          'list-subnet_underlay-true-',
                          'list-subnet_underlay-']
        cidr_net = IPNetwork('90.99.100.0/24').next(cidr_addition)
        for this_subnet in my_subnet_list:
            rand_name_str = data_utils.rand_name()
            ext_network_name = "ext-fip-network-" + rand_name_str
            ext_network = self.create_network_with_args(ext_network_name, " --router:external")
            ext_subnet_name = this_subnet + rand_name_str
            if re.search('true', this_subnet):
                underlay = True
            elif re.search('false', this_subnet):
                underlay = False
            else:
                # Use this for checking default behavior when nuage_fip_underlay is present in .ini file
                underlay = None
            cidr = str(cidr_net.cidr)
            if underlay is None:
                created_subnet = self.create_subnet_with_args(ext_network['name'],
                                                              cidr,
                                                              "--name ", ext_subnet_name)
            else:
                underlay_str = "--underlay=" + str(underlay)
                created_subnet = self.create_subnet_with_args(ext_network['name'],
                                                              cidr,
                                                              "--name ", ext_subnet_name,
                                                              underlay_str)
            subnet_list = self.parser.listing(self.list_subnets())
            # Verify the subnet exists in the list of all subnets
            subnet_found = False
            for subnet in subnet_list:
                created_id = created_subnet['id']
                listed_id = subnet['id']
                if created_id == listed_id:
                    # our created subnet is in the list: check the underlay field of the show output, as it is not
                    # in the list output for performance reasons (requires an extra api call per subnet...)
                    subnet_found = True
                    show_subnet = self.show_subnet(listed_id)
                    underlay_listed = show_subnet['underlay']
                    if underlay is not None:
                        # Verify underlay with the value used at creation time
                        underlay_compare = created_subnet['underlay']
                    else:
                        # No underlay given: should match the value in the .ini file
                        # Note that 'None' has same effect as false: check on False
                        underlay_compare = default_underlay
                        if default_underlay is None:
                            underlay_compare = False
                    self.assertEqual(underlay_listed, str(underlay_compare),
                                     "FIP NOK: listed underlay values do not match")
            cidr_net = cidr_net.next(1)
            self.assertEqual(subnet_found, True, "FIP NOK: created fip subnet is not in the subnet list")

