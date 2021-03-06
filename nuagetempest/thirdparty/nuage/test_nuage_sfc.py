import netaddr
import time

from oslo_log import log as logging
from tempest.api.network import base as base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest import test
from tempest.lib import exceptions as lib_exec

from nuagetempest.lib import base as nuagetempestbase 
from nuagetempest.lib.test import nuage_test
from nuagetempest.lib.utils import constants as n_constants
from nuagetempest.services.nuage_client import NuageRestClient
from nuagetempest.services.nuage_network_client import NuageNetworkClientJSON
from nuagetempest.services.networkingsfc import networkingsfc_client
from nuagetempest.services.networkingsfc.networkingsfc_client import NetworkingSFCClient as nsfc
from nuagetempest.lib.test.nuage_test import NuageBaseTest
from testtools.matchers import Contains

CONF = config.CONF

class nuage_sfc(NuageBaseTest):
    _interface = 'json'
    LOG = logging.getLogger(__name__)

    @classmethod
    def setup_clients(cls):
        super(nuage_sfc, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()
        cls.client = NuageNetworkClientJSON(
            cls.os.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os.default_params)
        cls.nsfc_client = nsfc(
            cls.os.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os.default_params)

    def setUp(self):
        self.addCleanup(self.resource_cleanup)
        super(nuage_sfc, self).setUp()

    @classmethod
    def resource_setup(self):
        super(nuage_sfc, self).resource_setup()
    @classmethod
    def _create_security_disabled_network(self, network_name):
        kwargs = {'name': network_name,
                  'port_security_enabled': 'False'}
        body = self.networks_client.create_network(**kwargs)
        return body['network']

    def _get_vsd_domain_id(self, router):
        router_ext_id = (
            self.nuage_vsd_client.get_vsd_external_id(
                router['id'])
        )
        domain = (
            self.nuage_vsd_client.get_l3domain(
                filters='externalID', filter_value=router_ext_id)
        )
        return domain[0]['ID']

    def _get_vsd_l2domain_id(self, subnet, netpart_name=None):
        subnet_ext_id = (
            self.nuage_vsd_client.get_vsd_external_id(
                subnet['id'])
        )

        vsd_subnet = self.nuage_vsd_client.get_l2domain(
            filters='externalID', filter_value=subnet_ext_id, netpart_name=netpart_name)
        return vsd_subnet[0]['ID']

    def _verify_flow_classifier_l2(
            self, network, subnet, FC1, ingressport, egressport, netpart_name=None):
        vsd_l2domain_id = self._get_vsd_l2domain_id(subnet, netpart_name)
        redirect_targets = self.nuage_vsd_client.get_redirection_target(
            'l2domains', vsd_l2domain_id)
        #rt_src_ext_id = 'fc_%s@%s' % (ingressport['id'], CMS_ID)
        pre_rt_src = 'fc_%s' % ingressport['id']
        rt_src_ext_id = self.nuage_vsd_client.get_vsd_external_id(pre_rt_src)
        rt_src = self.nuage_vsd_client.get_redirection_target(
            'l2domains', vsd_l2domain_id, filters='externalID', filter_value=rt_src_ext_id)
        #rt_dest_ext_id = 'fc_%s@%s' % (egressport['id'], CMS_ID)
        pre_rt_dest_ext_id = 'fc_%s' % egressport['id']
        rt_dest_ext_id = self.nuage_vsd_client.get_vsd_external_id( pre_rt_dest_ext_id)

        rt_dest = self.nuage_vsd_client.get_redirection_target(
            'l2domains', vsd_l2domain_id, filters='externalID', filter_value=rt_dest_ext_id)
        self.assertNotEquals(
            rt_src, '', "expected that source port rt is created but it is not")
        self.assertNotEquals(
            rt_dest,
            '',
            "expected that destination port rt is created but it is not")
        src_pg = self.nuage_vsd_client.get_policygroup(
            'l2domains', vsd_l2domain_id, filters='externalID', filter_value=rt_src_ext_id)
        dest_pg = self.nuage_vsd_client.get_policygroup(
            'l2domains',
            vsd_l2domain_id,
            filters='externalID',
            filter_value=rt_dest_ext_id)
        return rt_src, rt_dest, src_pg, dest_pg

    def _verify_flow_classifier(
            self, network, subnet, FC1, ingressport, egressport, router=None, vsd_domain_id=None):
        if router != 'None':
            vsd_domain_id = self._get_vsd_domain_id(router)
        redirect_targets = self.nuage_vsd_client.get_redirection_target(
            'domains', vsd_domain_id)
        #rt_src_ext_id = 'fc_%s@%s' % (ingressport['id'], CMS_ID)
        pre_rt_src = 'fc_%s' % ingressport['id']
        rt_src_ext_id = self.nuage_vsd_client.get_vsd_external_id(pre_rt_src)

        rt_src = self.nuage_vsd_client.get_redirection_target(
            'domains', vsd_domain_id, filters='externalID', filter_value=rt_src_ext_id)
        #rt_dest_ext_id = 'fc_%s@%s' % (egressport['id'], CMS_ID)
        pre_rt_dest_ext_id = 'fc_%s' % egressport['id']
        rt_dest_ext_id = self.nuage_vsd_client.get_vsd_external_id( pre_rt_dest_ext_id)

        rt_dest = self.nuage_vsd_client.get_redirection_target(
            'domains', vsd_domain_id, filters='externalID', filter_value=rt_dest_ext_id)
        self.assertNotEquals(
            rt_src, '', "expected that source port rt is created but it is not")
        self.assertNotEquals(
            rt_dest,
            '',
            "expected that destination port rt is created but it is not")
        src_pg = self.nuage_vsd_client.get_policygroup(
            n_constants.DOMAIN,
            vsd_domain_id,
            filters='externalID',
            filter_value=rt_src_ext_id)
        dest_pg = self.nuage_vsd_client.get_policygroup(
            n_constants.DOMAIN,
            vsd_domain_id,
            filters='externalID',
            filter_value=rt_dest_ext_id)
        return rt_src, rt_dest, src_pg, dest_pg

    def _get_l3_port_pair_group_redirect_target_pg(
            self, port_pair_group, router=None, vsd_domain_id=None, bidirectional_port=None):
        if router != 'None':
            vsd_domainid = self._get_vsd_domain_id(router)
        else:
            vsd_domainid = vsd_domain_id
        if bidirectional_port == 'true':
            pre_rt_ingress_egress_ext_id = 'ingress_egress_%s' % (
                port_pair_group['port_pair_group']['id'])
            rt_ingress_egress_ext_id = self.nuage_vsd_client.get_vsd_external_id(pre_rt_ingress_egress_ext_id)
            rt_ingress_egress = self.nuage_vsd_client.get_redirection_target(
                'domains', vsd_domainid, filters='externalID', filter_value=rt_ingress_egress_ext_id)
            port_pair_group_ingress_pg = self.nuage_vsd_client.get_policygroup(
                n_constants.DOMAIN,
                vsd_domainid,
                filters='externalID',
                filter_value=rt_ingress_egress_ext_id)
            return rt_ingress_egress, port_pair_group_ingress_pg
        else:
            pre_rt_ingress_ext_id = 'ingress_%s' % (
                port_pair_group['port_pair_group']['id'])
            rt_ingress_ext_id = self.nuage_vsd_client.get_vsd_external_id(pre_rt_ingress_ext_id)
            rt_ingress = self.nuage_vsd_client.get_redirection_target(
                'domains', vsd_domainid, filters='externalID', filter_value=rt_ingress_ext_id)
            #rt_egress_ext_id = 'egress_%s@%s' % (
            #    port_pair_group['port_pair_group']['id'], CMS_ID)
            pre_rt_egress_ext_id = 'egress_%s' % port_pair_group['port_pair_group']['id']
            rt_egress_ext_id = self.nuage_vsd_client.get_vsd_external_id(pre_rt_egress_ext_id)

            rt_egress = self.nuage_vsd_client.get_redirection_target(
                'domains', vsd_domainid, filters='externalID', filter_value=rt_egress_ext_id)
            port_pair_group_ingress_pg = self.nuage_vsd_client.get_policygroup(
                n_constants.DOMAIN, vsd_domainid, filters='externalID', filter_value=rt_ingress_ext_id)
            port_pair_group_egress_pg = self.nuage_vsd_client.get_policygroup(
                n_constants.DOMAIN, vsd_domainid, filters='externalID', filter_value=rt_egress_ext_id)
            return rt_ingress, rt_egress, port_pair_group_ingress_pg, port_pair_group_egress_pg

    def _get_l2_port_pair_group_redirect_target_pg(
            self, port_pair_group, subnet, bidirectional_port=None, netpart_name=None):
        vsd_l2domain_id = self._get_vsd_l2domain_id(subnet, netpart_name)
        if bidirectional_port == 'true':
            #rt_ingress_egress_ext_id = 'ingress_egress_%s@%s' % (
            #    port_pair_group['port_pair_group']['id'], CMS_ID)
            pre_rt_ingress_egress_ext_id = 'ingress_egress_%s' % port_pair_group['port_pair_group']['id']
            rt_ingress_egress_ext_id = self.nuage_vsd_client.get_vsd_external_id(pre_rt_ingress_egress_ext_id)
            rt_ingress_egress = self.nuage_vsd_client.get_redirection_target(
                'l2domains', vsd_l2domain_id, filters='externalID', filter_value=rt_ingress_egress_ext_id)
            port_pair_group_ingress_pg = self.nuage_vsd_client.get_policygroup(
                'l2domains',
                vsd_l2domain_id,
                filters='externalID',
                filter_value=rt_ingress_egress_ext_id)
            return rt_ingress_egress, port_pair_group_ingress_pg
        else:
            #rt_ingress_ext_id = 'ingress_%s@%s' % (
            #    port_pair_group['port_pair_group']['id'], CMS_ID)
            pre_rt_ingress_ext_id = 'ingress_%s' % port_pair_group['port_pair_group']['id']
            rt_ingress_ext_id = self.nuage_vsd_client.get_vsd_external_id(pre_rt_ingress_ext_id)
            rt_ingress = self.nuage_vsd_client.get_redirection_target(
                'l2domains', vsd_l2domain_id, filters='externalID', filter_value=rt_ingress_ext_id)
            #rt_egress_ext_id = 'egress_%s@%s' % (
            #    port_pair_group['port_pair_group']['id'], CMS_ID)
            pre_rt_egress_ext_id = 'egress_%s' % port_pair_group['port_pair_group']['id']
            rt_egress_ext_id = self.nuage_vsd_client.get_vsd_external_id(pre_rt_egress_ext_id)
            rt_egress = self.nuage_vsd_client.get_redirection_target(
                'l2domains', vsd_l2domain_id, filters='externalID', filter_value=rt_egress_ext_id)
            port_pair_group_ingress_pg = self.nuage_vsd_client.get_policygroup(
                'l2domains', vsd_l2domain_id, filters='externalID', filter_value=rt_ingress_ext_id)
            port_pair_group_egress_pg = self.nuage_vsd_client.get_policygroup(
                'l2domains', vsd_l2domain_id, filters='externalID', filter_value=rt_egress_ext_id)
            return rt_ingress, rt_egress, port_pair_group_ingress_pg, port_pair_group_egress_pg

    def _get_adv_fwd_rules_port_chain_l2(
            self, PC, subnet, netpart_name=None):
        vsd_l2domain_id = self._get_vsd_l2domain_id(subnet, netpart_name)
        #pc_ext_id = '%s@%s' % (PC['port_chain']['id'], CMS_ID)
        pc_ext_id = self.nuage_vsd_client.get_vsd_external_id( PC['port_chain']['id'])
        adv_fwd_template = self.nuage_vsd_client.get_advfwd_template(
            'l2domains', vsd_l2domain_id, 'externalID', pc_ext_id)
        rules = self.nuage_vsd_client.get_advfwd_entrytemplate(
            'ingressadvfwdtemplates', adv_fwd_template[0]['ID'])
        return rules

    def _get_adv_fwd_rules_port_chain(
            self, PC, router=None, vsd_domain_id=None):
        if router != 'None':
            vsd_domainid = self._get_vsd_domain_id(router)
        else:
            vsd_domainid = vsd_domain_id

        #pc_ext_id = '%s@%s' % (PC['port_chain']['id'], CMS_ID)
        pc_ext_id = self.nuage_vsd_client.get_vsd_external_id( PC['port_chain']['id'])
        adv_fwd_template = self.nuage_vsd_client.get_advfwd_template(
            'domains', vsd_domainid, 'externalID', pc_ext_id)
        rules = self.nuage_vsd_client.get_advfwd_entrytemplate(
            'ingressadvfwdtemplates', adv_fwd_template[0]['ID'])
        return rules
    def _configure_sfc_vm(self,vm,vlan):
        cmd = 'ip link add link eth0 name eth0.%s type vlan id %s ' % (vlan,vlan)
        vm.console().send(cmd=cmd, timeout=5)
        cmd = 'ifconfig eth1 up'
        vm.console().send(cmd=cmd, timeout=5)
        cmd = 'udhcpc -i eth1'
        vm.console().send(cmd=cmd, timeout=5)
        cmd = "ifconfig eth0 | grep 'inet addr' | cut -d ':' -f 2 | cut -d ' ' -f 1"
        output = vm.console().send(cmd=cmd, timeout=5)
        ip = output[0]
        cmd = 'ifconfig eth0.%s %s up' % (vlan,ip)
        vm.console().send(cmd=cmd, timeout=5)
        cmd = 'ip link add link eth1 name eth1.%s type vlan id %s ' % (vlan,vlan)
        vm.console().send(cmd=cmd, timeout=5)
        cmd = "ifconfig eth1 | grep 'inet addr' | cut -d ':' -f 2 | cut -d ' ' -f 1"
        output = vm.console().send(cmd=cmd, timeout=5)
        ip = output[0]
        cmd = 'ifconfig eth1.%s %s up' % (vlan,ip)
        vm.console().send(cmd=cmd, timeout=5)
        cmd = 'brctl addbr br0'
        vm.console().send(cmd=cmd, timeout=5)
        cmd = 'brctl addif br0 eth0.%s' % vlan
        vm.console().send(cmd=cmd, timeout=5)
        cmd = 'brctl addif br0 eth1.%s' % vlan
        vm.console().send(cmd=cmd, timeout=5)
        cmd = 'ip link set br0 up'
        vm.console().send(cmd=cmd, timeout=5)
        cmd = 'ifconfig eth0.%s up' % vlan
        vm.console().send(cmd=cmd, timeout=5)
        cmd = 'ifconfig eth1.%s up' % vlan
        vm.console().send(cmd=cmd, timeout=5)

    def _create_l3_port_chain(self, network, subnet, router):
        pp_list = []
        ppg_list = []
        src_port = self.create_port(network=network, name='src_port')
        dest_port = self.create_port(network=network, name='dest_port')
        image_id = self.osc_get_image_id(image_name='alpine')
        FC1 = self._create_flow_classifier(
            'FC1', src_port['id'], dest_port['id'], '10', 'icmp')
        p1 = self.create_port(
            network=network,
            name='p1',
            port_security_enabled=False)
        p2 = self.create_port(
            network=network,
            name='p2',
            port_security_enabled=False)
        p3 = self.create_port(
            network=network,
            name='p3',
            port_security_enabled=False)
        p4 = self.create_port(
            network=network,
            name='p4',
            port_security_enabled=False)

        sfcvm1 = self.create_tenant_server(
            ports=[p1, p2], wait_until='ACTIVE', name='sfc-vm1',image_id=image_id)
        sfcvm2 = self.create_tenant_server(
            ports=[p3, p4], wait_until='ACTIVE', name='sfc-vm2',image_id=image_id)

        time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1, p2)
        ppg1 = self._create_port_pair_group('ppg1', pp1)
        pp_list.append(pp1)
        ppg_list.append(ppg1)
        pp2 = self._create_port_pair('pp2', p3, p4)
        ppg2 = self._create_port_pair_group('ppg2', pp2)
        pp_list.append(pp2)
        ppg_list.append(ppg2)

        PC1 = self. _create_port_chain('PC1', [ppg1, ppg2], [FC1])
        self._verify_adv_fwd_rules_l3(network,subnet,router,src_port,dest_port,ppg_list,FC1,PC1,'10')
        return PC1, FC1, ppg_list, pp_list, src_port, dest_port


    def _verify_adv_fwd_rules_l3(self,network,subnet,router,src_port,dest_port,ppg_list,FC,PC,vlan):
        #assumption ppg_list is the order used in the creation of port chain
        rt_src, rt_dest, src_pg, dest_pg = self._verify_flow_classifier(
            network, subnet, FC, src_port, dest_port, router=router)

        if len(ppg_list) == 1:
           ppg1 = ppg_list[0]
           ppg1_rt_ingress, ppg1_rt_egress, ppg1_ingress_pg, ppg1_egress_pg = self._get_l3_port_pair_group_redirect_target_pg(
             ppg1, router=router)
           rules = self._get_adv_fwd_rules_port_chain(PC, router=router)
           for rule in rules:
             if (rule['locationID'] == src_pg[0]['ID']):
                rule_src_insfcvm1 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    ppg1_rt_ingress[0]['ID'],
                    "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                vlanRange = '%s-%s' % (vlan,vlan)
                self.assertEquals(
                    rule['vlanRange'],
                    vlanRange,
                    "sfc to sfc-vm1 vlan range is wrong")
                self.assertEquals(rule['redirectRewriteType'], 'VLAN')
             if (rule['locationID'] == ppg1_egress_pg[0]['ID']):
                rule_sfcvm1_dest = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    rt_dest[0]['ID'],
                    "sfcvm1 to dest adv fwd rule redirect target is wrong")
           self.assertIsNotNone(rule_src_insfcvm1)
           self.assertIsNotNone(rule_sfcvm1_dest)

        if len(ppg_list) == 2:
            ppg1 = ppg_list[0]
            ppg2 = ppg_list[1]
            ppg1_rt_ingress, ppg1_rt_egress, ppg1_ingress_pg, ppg1_egress_pg = self._get_l3_port_pair_group_redirect_target_pg(
                ppg1, router=router)
            ppg2_rt_ingress, ppg2_rt_egress, ppg2_ingress_pg, ppg2_egress_pg = self._get_l3_port_pair_group_redirect_target_pg(
                ppg2, router=router)
            rules = self._get_adv_fwd_rules_port_chain(PC, router=router)
            for rule in rules:
              if (rule['locationID'] == src_pg[0]['ID']):
                rule_src_insfcvm1 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    ppg1_rt_ingress[0]['ID'],
                    "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                vlanRange = '%s-%s' % (vlan,vlan)
                self.assertEquals(
                    rule['vlanRange'],
                    vlanRange,
                    "sfc to sfc-vm1 vlan range is wrong")
                self.assertEquals(rule['redirectRewriteType'], 'VLAN')
                self.assertEquals(
                    rule['redirectRewriteValue'], str(
                        PC['port_chain']['chain_parameters']['correlation_id']))
              if (rule['locationID'] == ppg1_egress_pg[0]['ID']):
                rule_sfcvm1_sfcvm2 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    ppg2_rt_ingress[0]['ID'],
                    "sfcvm1 to sfcvm2 adv fwd rule redirect target is wrong")
              if (rule['locationID'] == ppg2_egress_pg[0]['ID']):
                rule_sfcvm2_dest = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    rt_dest[0]['ID'],
                    "sfcvm1 to dest adv fwd rule redirect target is wrong")
            self.assertIsNotNone(rule_src_insfcvm1)
            self.assertIsNotNone(rule_sfcvm1_sfcvm2)
            self.assertIsNotNone(rule_sfcvm2_dest)

        if len(ppg_list) == 3:
           ppg1 = ppg_list[0]
           ppg2 = ppg_list[1]
           ppg3 = ppg_list[2]
           ppg1_rt_ingress, ppg1_rt_egress, ppg1_ingress_pg, ppg1_egress_pg = self._get_l3_port_pair_group_redirect_target_pg(
               ppg1, router=router)
           ppg2_rt_ingress, ppg2_rt_egress, ppg2_ingress_pg, ppg2_egress_pg = self._get_l3_port_pair_group_redirect_target_pg(
               ppg2, router=router)
           ppg3_rt_ingress, ppg3_rt_egress, ppg3_ingress_pg, ppg3_egress_pg = self._get_l3_port_pair_group_redirect_target_pg(
               ppg3, router=router)
           rules = self._get_adv_fwd_rules_port_chain(PC, router=router)
           for rule in rules:
             if (rule['locationID'] == src_pg[0]['ID']):
                rule_src_insfcvm1 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    ppg1_rt_ingress[0]['ID'],
                    "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                vlanRange = '%s-%s' %(vlan,vlan)
                self.assertEquals(
                    rule['vlanRange'],
                    vlanRange,
                    "sfc to sfc-vm1 vlan range is wrong")
                self.assertEquals(rule['redirectRewriteType'], 'VLAN')
             if (rule['locationID'] == ppg1_egress_pg[0]['ID']):
                rule_sfcvm1_sfcvm2 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    ppg2_rt_ingress[0]['ID'],
                    "sfcvm1 to sfcvm2 adv fwd rule redirect target is wrong")
             if (rule['locationID'] == ppg2_egress_pg[0]['ID']):
                rule_sfcvm2_sfcvm3 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    ppg3_rt_ingress[0]['ID'],
                    "sfcvm2 to sfcvm3 adv fwd rule redirect target is wrong")
             if (rule['locationID'] == ppg3_egress_pg[0]['ID']):
                rule_sfcvm3_dest = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    rt_dest[0]['ID'],
                    "sfcvm1 to dest adv fwd rule redirect target is wrong")

           self.assertIsNotNone(rule_src_insfcvm1)
           self.assertIsNotNone(rule_sfcvm1_sfcvm2)
           self.assertIsNotNone(rule_sfcvm2_sfcvm3)
           self.assertIsNotNone(rule_sfcvm3_dest)


    def _create_port_pair(self, name, ingress, egress):
        port_pair1 = self.nsfc_client.create_port_pair(
            name, ingress['id'], egress['id'])
        self.addCleanup(
            self.nsfc_client.delete_port_pair,
            port_pair1['port_pair']['id'])
        return port_pair1

    def _create_port_pair_group(self, name, port_pair):
        ppg1 = self.nsfc_client.create_port_pair_group(name, port_pair)
        self.addCleanup(
            self.nsfc_client.delete_port_pair_group,
            ppg1['port_pair_group']['id'])
        return ppg1

    def _create_flow_classifier(self, name, logical_src_port, logical_dest_port, vlan, protocol=None,
                                ethertype='IPv4', source_port_range_max=None, source_port_range_min=None, destination_port_range_min=None, destination_port_range_max=None):
        params = {'name': name, 'logical_source_port': logical_src_port, 'logical_destination_port': logical_dest_port,
                  'ethertype': ethertype, 'vlan_range_min': vlan, 'vlan_range_max': vlan}
        if protocol is not None:
            params['protocol'] = protocol
        if source_port_range_max is not None:
            params['source_port_range_max'] = source_port_range_max
        if source_port_range_min is not None:
            params['source_port_range_min'] = source_port_range_min
        if destination_port_range_min is not None:
            params['destination_port_range_min'] = destination_port_range_min
        if destination_port_range_max is not None:
            params['destination_port_range_max'] = destination_port_range_max

        FC1 = self.nsfc_client.create_flow_classifier(**params)
        self.addCleanup(
            self.nsfc_client.delete_flow_classifier,
            FC1['flow_classifier']['id'])
        return FC1

    def _create_port_chain(self, name, ppg_list, fc_list, chain_params=None):
        fc_id_list = []
        ppg_id_list = []
        for fc in fc_list:
            fc_id_list.append(fc['flow_classifier']['id'])
        for ppg in ppg_list:
            ppg_id_list.append(ppg['port_pair_group']['id'])

        params = {
            'name': name,
            'port_pair_groups': ppg_id_list,
            'flow_classifiers': fc_id_list}
        if chain_params:
            params['chain_parameters'] = chain_params
        PC1 = self.nsfc_client.create_port_chain(**params)
        self.addCleanup(
            self.nsfc_client.delete_port_chain,
            PC1['port_chain']['id'])
        return PC1

    def test_create_del_l2_l3_portpair_group(self):
        l3network = self.create_network()
        l3subnet = self.create_subnet(l3network)
        router = self.create_router(data_utils.rand_name('router-'))
        self.create_router_interface(router['id'], l3subnet['id'])
        l2network = self.create_network()
        l2subnet = self.create_subnet(l2network)

        network_list = [l3network, l2network]
        for network in network_list:
            port1 = self.create_port(
                network=network,
                name='port1',
                port_security_enabled=False)
            port2 = self.create_port(
                network=network,
                name='port2',
                port_security_enabled=False)
            image_id = self.osc_get_image_id(image_name='alpine')
            vm = self.create_tenant_server(
                ports=[
                    port1,
                    port2],
                wait_until='ACTIVE',
                name='vm',image_id=image_id)
            port_pair1 = self._create_port_pair('pp1', port1, port2)
            ppg1 = self._create_port_pair_group('ppg1', port_pair1)

    def test_create_delete_port_pair_group_single_port(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(data_utils.rand_name('router-'))
        self.create_router_interface(router['id'], subnet['id'])
        port1 = self.create_port(
            network=network,
            name='port1',
            port_security_enabled=False)
        image_id = self.osc_get_image_id(image_name='alpine')
        vm = self.create_tenant_server(
            ports=[port1], wait_until='ACTIVE', name='vm',image_id=image_id)
        port_pair1 = self._create_port_pair('pp1', port1, port1)
        ppg1 = self._create_port_pair_group('ppg1', port_pair1)
        pass

    def test_update_portpair_group(self):
        l3network = self.create_network()
        l3subnet = self.create_subnet(l3network)
        router = self.create_router(data_utils.rand_name('router-'))
        self.create_router_interface(router['id'], l3subnet['id'])
        l2network = self.create_network()
        l2subnet = self.create_subnet(l2network)
        image_id = self.osc_get_image_id(image_name='alpine')
        network_list = [l3network, l2network]
        for network in network_list:
            port1 = self.create_port(
                network=network,
                name='port1',
                port_security_enabled=False)
            port2 = self.create_port(
                network=network,
                name='port2',
                port_security_enabled=False)
            port3 = self.create_port(
                network=network,
                name='port3',
                port_security_enabled=False)
            port4 = self.create_port(
                network=network,
                name='port4',
                port_security_enabled=False)
            vm1 = self.create_tenant_server(
                ports=[port1, port2], wait_until='ACTIVE', name='vm1',image_id=image_id)
            vm2 = self.create_tenant_server(
                ports=[port3, port4], wait_until='ACTIVE', name='vm2',image_id=image_id)
            time.sleep(5)
            port_pair1 = self._create_port_pair('pp1', port1, port2)
            port_pair2 = self._create_port_pair('pp2', port3, port4)
            ppg1 = self._create_port_pair_group('ppg1', port_pair1)

            # update
            ppg1 = self.nsfc_client.update_port_pair_group(
                ppg1['port_pair_group']['id'], port_pair2)

    def test_create_delete_flow_classifier(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(data_utils.rand_name('router-'))
        self.create_router_interface(router['id'], subnet['id'])
        port1 = self.create_port(
            network=network,
            name='port1',
            port_security_enabled=False)
        port2 = self.create_port(
            network=network,
            name='port2',
            port_security_enabled=False)
        FC1 = self._create_flow_classifier('FC1', port1['id'], port2['id'], '10', 'tcp',
                                           source_port_range_max='23', source_port_range_min='23',
                                           destination_port_range_min='100', destination_port_range_max='100')
        rt_src, rt_dest, src_pg, dest_pg = self._verify_flow_classifier(
            network, subnet, FC1, port1, port2, router=router)

    def test_create_multiFC_same_src_dest(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(data_utils.rand_name('router-'))
        self.create_router_interface(router['id'], subnet['id'])

        port1 = self.create_port(
            network=network,
            name='port1',
            port_security_enabled=False)
        port2 = self.create_port(
            network=network,
            name='port2',
            port_security_enabled=False)
        FC1 = self.nsfc_client.create_flow_classifier(name="FC1",
                                                      ethertype='IPv4', logical_destination_port=port2['id'],
                                                      logical_source_port=port1['id'], protocol='tcp',
                                                      source_port_range_max='23', source_port_range_min='23',
                                                      destination_port_range_min='100',
                                                      destination_port_range_max='100', vlan_range_min=10, vlan_range_max=10)

        FC2 = self.nsfc_client.create_flow_classifier(name="FC1",
                                                      ethertype='IPv4', logical_destination_port=port2['id'],
                                                      logical_source_port=port1['id'], protocol='icmp',
                                                      vlan_range_max='100', vlan_range_min='100')

        FC3 = self.nsfc_client.create_flow_classifier(name="FC1",
                                                      ethertype='IPv4', logical_destination_port=port2['id'],
                                                      logical_source_port=port1['id'], protocol='udp',
                                                      vlan_range_max='105', vlan_range_min='105')

        rt_src, rt_dest, src_pg, dest_pg = self._verify_flow_classifier(
            network, subnet, FC1, port1, port2, router=router)
        self.nsfc_client.delete_flow_classifier(FC1['flow_classifier']['id'])
        rt_src, rt_dest, src_pg, dest_pg = self._verify_flow_classifier(
            network, subnet, FC2, port1, port2, router=router)
        self.nsfc_client.delete_flow_classifier(FC2['flow_classifier']['id'])
        rt_src, rt_dest, src_pg, dest_pg = self._verify_flow_classifier(
            network, subnet, FC3, port1, port2, router=router)
        self.nsfc_client.delete_flow_classifier(FC3['flow_classifier']['id'])

    def test_create_delete_port_chain_symmetric(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(data_utils.rand_name('router-'))
        image_id = self.osc_get_image_id(image_name='alpine')
        self.create_router_interface(router['id'], subnet['id'])
        src_port = self.create_port(network=network, name='src_port')
        dest_port = self.create_port(network=network, name='dest_port')
        FC1 = self._create_flow_classifier('FC1', src_port['id'], dest_port['id'], '10', 'tcp',
                                           source_port_range_max='23', source_port_range_min='23',
                                           destination_port_range_min='100', destination_port_range_max='100')
        p1 = self.create_port(
            network=network,
            name='p1',
            port_security_enabled=False)
        p2 = self.create_port(
            network=network,
            name='p2',
            port_security_enabled=False)
        p3 = self.create_port(
            network=network,
            name='p3',
            port_security_enabled=False)
        p4 = self.create_port(
            network=network,
            name='p4',
            port_security_enabled=False)

        sfcvm1 = self.create_tenant_server(
            ports=[p1, p2], wait_until='ACTIVE', name='sfc-vm1',image_id=image_id)
        sfcvm2 = self.create_tenant_server(
            ports=[p3, p4], wait_until='ACTIVE', name='sfc-vm2',image_id=image_id)

        time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1, p2)
        ppg1 = self._create_port_pair_group('ppg1', pp1)

        pp2 = self._create_port_pair('pp2', p3, p4)
        ppg2 = self._create_port_pair_group('ppg2', pp2)
        PC1 = self. _create_port_chain(
            'PC1', [
                ppg1, ppg2], [FC1], chain_params={
                'symmetric': 'true'})

        # verify
        rt_src, rt_dest, src_pg, dest_pg = self._verify_flow_classifier(
            network, subnet, FC1, src_port, dest_port, router=router)
        ppg1_rt_ingress, ppg1_rt_egress, ppg1_ingress_pg, ppg1_egress_pg = self._get_l3_port_pair_group_redirect_target_pg(
            ppg1, router=router)
        ppg2_rt_ingress, ppg2_rt_egress, ppg2_ingress_pg, ppg2_egress_pg = self._get_l3_port_pair_group_redirect_target_pg(
            ppg2, router=router)
        rules = self._get_adv_fwd_rules_port_chain(PC1, router=router)
        for rule in rules:
            if (rule['locationID'] == src_pg[0]['ID']):
                rule_src_insfcvm1 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    ppg1_rt_ingress[0]['ID'],
                    "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                self.assertEquals(
                    rule['vlanRange'],
                    '10-10',
                    "sfc to sfc-vm1 vlan range is wrong")
                self.assertEquals(rule['redirectRewriteType'], 'VLAN')
            if (rule['locationID'] == ppg1_egress_pg[0]['ID']):
                rule_sfcvm1_sfcvm2 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    ppg2_rt_ingress[0]['ID'],
                    "sfcvm1 to sfcvm2 adv fwd rule redirect target is wrong")
            if (rule['locationID'] == ppg2_egress_pg[0]['ID']):
                rule_sfcvm2_dest = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    rt_dest[0]['ID'],
                    "sfcvm1 to dest adv fwd rule redirect target is wrong")
            if (rule['locationID'] == dest_pg[0]['ID']):
                rev_rule_dest_egsfcvm2 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    ppg2_rt_egress[0]['ID'],
                    "dest to sfc-vm2 rev adv fwd rule redirect vport is wrong")
                self.assertEquals(
                    rule['vlanRange'],
                    '10-10',
                    "sfc dest to sfc-vm2 vlan range is wrong")
            if (rule['locationID'] == ppg2_ingress_pg[0]['ID']):
                rev_rule_sfcvm2_sfcvm1 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    ppg1_rt_egress[0]['ID'],
                    "sfcvm2 ingress to sfcvm1 egress rev adv fwd rule redirect target is wrong")
            if (rule['locationID'] == ppg1_ingress_pg[0]['ID']):
                rev_rule_sfcvm1_src = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    rt_src[0]['ID'],
                    "sfcvm1 to src rev  adv fwd rule redirect target is wrong")
        self.assertIsNotNone(rule_src_insfcvm1)
        self.assertIsNotNone(rule_sfcvm1_sfcvm2)
        self.assertIsNotNone(rule_sfcvm2_dest)
        self.assertIsNotNone(rev_rule_dest_egsfcvm2)
        self.assertIsNotNone(rev_rule_sfcvm2_sfcvm1)
        self.assertIsNotNone(rev_rule_sfcvm1_src)

    def test_create_delete_port_chain_one_ppg_l2(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        src_port = self.create_port(network=network, name='src_port')
        dest_port = self.create_port(network=network, name='dest_port')

        FC1 = self._create_flow_classifier('FC1', src_port['id'], dest_port['id'], '10', 'tcp',
                                           source_port_range_max='23', source_port_range_min='23',
                                           destination_port_range_min='100', destination_port_range_max='100')
        p1 = self.create_port(
            network=network,
            name='p1',
            port_security_enabled=False)
        p2 = self.create_port(
            network=network,
            name='p2',
            port_security_enabled=False)
        image_id = self.osc_get_image_id(image_name='alpine')
        sfcvm1 = self.create_tenant_server(
            ports=[p1, p2], wait_until='ACTIVE', name='sfc-vm1',image_id=image_id)
        time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1, p2)
        ppg1 = self._create_port_pair_group('ppg1', pp1)
        PC1 = self. _create_port_chain('PC1', [ppg1], [FC1])
        # verify
        self.assertNotEquals(
            PC1, '', 'port chain is empty')
        rt_src, rt_dest, src_pg, dest_pg = self._verify_flow_classifier_l2(
            network, subnet, FC1, src_port, dest_port)

        ppg1_rt_ingress, ppg1_rt_egress, ppg1_ingress_pg, ppg1_egress_pg = self._get_l2_port_pair_group_redirect_target_pg(
            ppg1, subnet)
        rules = self._get_adv_fwd_rules_port_chain_l2(PC1, subnet)
        for rule in rules:
            if (rule['locationID'] == src_pg[0]['ID']):
                rule_src_insfcvm1 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    ppg1_rt_ingress[0]['ID'],
                    "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                self.assertEquals(
                    rule['vlanRange'],
                    '10-10',
                    "sfc to sfc-vm1 vlan range is wrong")
                self.assertEquals(rule['redirectRewriteType'], 'VLAN')
            if (rule['locationID'] == ppg1_egress_pg[0]['ID']):
                rule_sfcvm1_dest = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    rt_dest[0]['ID'],
                    "sfcvm1 to dest adv fwd rule redirect target is wrong")
        self.assertIsNotNone(rule_src_insfcvm1)
        self.assertIsNotNone(rule_sfcvm1_dest)

    def test_create_delete_port_chain_one_ppg(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(data_utils.rand_name('router-'))
        self.create_router_interface(router['id'], subnet['id'])
        image_id = self.osc_get_image_id(image_name='alpine')
        src_port = self.create_port(network=network, name='src_port')
        dest_port = self.create_port(network=network, name='dest_port')

        FC1 = self._create_flow_classifier('FC1', src_port['id'], dest_port['id'], '10', 'icmp')
        p1 = self.create_port(
            network=network,
            name='p1',
            port_security_enabled=False)
        p2 = self.create_port(
            network=network,
            name='p2',
            port_security_enabled=False)
        srcvm = self.create_tenant_server(
            ports=[src_port], wait_until='ACTIVE', name='srcvm',guest_user='root',guest_password='tigris',guest_prompt='~#',image_id=image_id)
        srcvm_ip = srcvm.get_server_ip_in_network(network['name'])
        srcvm.configure_vlan_interface(srcvm_ip,interface='eth0',vlan='10')

        destvm = self.create_tenant_server(
            ports=[dest_port], wait_until='ACTIVE', name='destvm',guest_user='root',guest_password='tigris',guest_prompt='~#',image_id=image_id)
        destvm_ip = destvm.get_server_ip_in_network(network['name'])
        destvm.configure_vlan_interface(destvm_ip,interface='eth0',vlan='10')
        destvm.bringdown_interface('eth0')
        sfcvm1 = self.create_tenant_server(
            ports=[p1,p2], wait_until='ACTIVE', name='sfc-vm1',guest_user='root',guest_password='tigris',guest_prompt='~#',image_id=image_id)

        time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1,p2)
        ppg1 = self._create_port_pair_group('ppg1', pp1)
        PC1 = self. _create_port_chain('PC1', [ppg1], [FC1])
        redirectvlan = PC1['port_chain']['chain_parameters']['correlation_id']
        sfcvm1.configure_ip_fwd()
        self._configure_sfc_vm(vm=sfcvm1,vlan=redirectvlan)
        ppg_list = [ppg1]
        # verify
        self._verify_adv_fwd_rules_l3(network,subnet,router,src_port,dest_port,ppg_list,FC1,PC1,'10')
        cmd = 'tcpdump -i eth0.1 -n > log &'
        sfcvm1.console().send(cmd,timeout=5)
        self.assert_ping(srcvm, destvm, network, should_pass=True,interface='eth0.10',count=20)
        output = sfcvm1.console().send('cat log | grep "echo request"',timeout=5)
        msg = '%s > %s: ICMP echo request' %(srcvm_ip, destvm_ip)
        self.assertThat(output[3],Contains(msg))

    def test_update_port_chain_add_remove_ppg_reorder(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(data_utils.rand_name('router-'))
        self.create_router_interface(router['id'], subnet['id'])
        image_id = self.osc_get_image_id(image_name='alpine')
        PC1, FC1, ppg_list, pp_list, src_port, dest_port = self._create_l3_port_chain(
            network, subnet, router)

        p5 = self.create_port(
            network=network,
            name='p5',
            port_security_enabled=False)
        p6 = self.create_port(
            network=network,
            name='p6',
            port_security_enabled=False)
        sfcvm3 = self.create_tenant_server(
            ports=[p5, p6], wait_until='ACTIVE', name='sfc-vm3',image_id=image_id)
        time.sleep(5)
        ppg1 = ppg_list[0]
        ppg2 = ppg_list[1]

        pp3 = self._create_port_pair('pp3', p5, p6)
        ppg3 = self._create_port_pair_group('ppg3', pp3)

        ppg_list.append(ppg3)
        pp_list.append(pp3)
        update_pc_ppg_list = []
        for ppg in ppg_list:
            update_pc_ppg_list.append(ppg['port_pair_group']['id'])
        verify_ppg_list=[ppg1,ppg2,ppg3]
        PC1 = self.nsfc_client.update_port_chain(
            PC1['port_chain']['id'],
            port_pair_groups=update_pc_ppg_list,
            flow_classifiers=FC1['flow_classifier']['id'])
        self._verify_adv_fwd_rules_l3(network,subnet,router,src_port,dest_port,verify_ppg_list,FC1,PC1,'10')
        # reorder PC1 ppg
        update_pc_ppg_list.reverse()
        PC1 = self.nsfc_client.update_port_chain(
            PC1['port_chain']['id'],
            port_pair_groups=update_pc_ppg_list,
            flow_classifiers=FC1['flow_classifier']['id'])
        verify_ppg_list.reverse()
        self._verify_adv_fwd_rules_l3(network,subnet,router,src_port,dest_port,verify_ppg_list,FC1,PC1,'10')
        update_pc_ppg_list.reverse()
        verify_ppg_list.reverse()
        # remove ppg3 for PC1
        update_pc_ppg_list.remove(ppg3['port_pair_group']['id'])
        verify_ppg_list.remove(ppg3)
        PC1 = self.nsfc_client.update_port_chain(
            PC1['port_chain']['id'],
            port_pair_groups=update_pc_ppg_list,
            flow_classifiers=FC1['flow_classifier']['id'])

        self._verify_adv_fwd_rules_l3(network,subnet,router,src_port,dest_port,verify_ppg_list,FC1,PC1,'10')
        # update with 1 ppg
        update_pc_ppg_list.remove(ppg2['port_pair_group']['id'])
        verify_ppg_list.remove(ppg2)
        PC1 = self.nsfc_client.update_port_chain(
            PC1['port_chain']['id'],
            port_pair_groups=update_pc_ppg_list,
            flow_classifiers=FC1['flow_classifier']['id'])
        self._verify_adv_fwd_rules_l3(network,subnet,router,src_port,dest_port,verify_ppg_list,FC1,PC1,'10')

    def test_update_port_chain_update_ppg(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(data_utils.rand_name('router-'))
        self.create_router_interface(router['id'], subnet['id'])
        image_id = self.osc_get_image_id(image_name='alpine')
        PC1, FC1, ppg_list, pp_list, src_port, dest_port = self._create_l3_port_chain(
            network, subnet, router)
        p5 = self.create_port(
            network=network,
            name='p5',
            port_security_enabled=False)
        p6 = self.create_port(
            network=network,
            name='p6',
            port_security_enabled=False)
        sfcvm3 = self.create_tenant_server(
            ports=[p5, p6], wait_until='ACTIVE', name='sfc-vm3',image_id=image_id)

        time.sleep(5)
        ppg1 = ppg_list[0]
        ppg2 = ppg_list[1]
        pp3 = self._create_port_pair('pp3', p5, p6)
        pp1 = pp_list[0]
        rt_src, rt_dest, src_pg, dest_pg = self._verify_flow_classifier(
            network, subnet, FC1, src_port, dest_port, router=router)
        ppg1_rt_ingress, ppg1_rt_egress, ppg1_ingress_pg, ppg1_egress_pg = self._get_l3_port_pair_group_redirect_target_pg(
            ppg1, router=router)
        ppg2_rt_ingress, ppg2_rt_egress, ppg2_ingress_pg, ppg2_egress_pg = self._get_l3_port_pair_group_redirect_target_pg(
            ppg2, router=router)

        # update
        ppg1 = self.nsfc_client.update_port_pair_group(
            ppg1['port_pair_group']['id'], pp3)
        ppg1_ingress_rt_vport = self.nuage_vsd_client.get_redirection_target_vports(
            'redirectiontargets', ppg1_rt_ingress[0]['ID'])
        ppg1_egress_rt_vport = self.nuage_vsd_client.get_redirection_target_vports(
            'redirectiontargets', ppg1_rt_egress[0]['ID'])
        self.assertEqual(ppg1_ingress_rt_vport[0]['name'], p5['id'])
        self.assertEqual(ppg1_egress_rt_vport[0]['name'], p6['id'])
        # cleanup
        ppg1 = self.nsfc_client.update_port_pair_group(
            ppg1['port_pair_group']['id'], pp1)

    def test_multiple_PC(self):
        network1 = self.create_network()
        subnet1 = self.create_subnet(network1)
        router = self.create_router(data_utils.rand_name('router-'))
        self.create_router_interface(router['id'], subnet1['id'])
        gw = '2.10.0.1'
        cidr = '2.10.0.0/24'
        cidr1 = netaddr.IPNetwork(cidr)
        mask = 24
        network2 = self.create_network()
        subnet2 = self.create_subnet(
            network2, gateway=gw, cidr=cidr1, mask_bits=mask)
        self.create_router_interface(router['id'], subnet2['id'])
        PC1, FC1, ppg_list_1, pp_list_1, src_port_1, dest_port_1 = self._create_l3_port_chain(
            network1, subnet1, router)
        PC2, FC2, ppg_list_2, pp_list_2, src_port_2, dest_port_2 = self._create_l3_port_chain(
            network2, subnet2, router)
        PC3, FC3, ppg_list_3, pp_list_3, src_port_3, dest_port_3 = self._create_l3_port_chain(
            network1, subnet1, router)
        PC4, FC4, ppg_list_4, pp_list_4, src_port_4, dest_port_4 = self._create_l3_port_chain(
            network2, subnet2, router)

    def test_port_pair_diff_subnet_neg(self):
        network1 = self.create_network()
        subnet1 = self.create_subnet(network1)
        router = self.create_router(data_utils.rand_name('router-'))
        self.create_router_interface(router['id'], subnet1['id'])
        image_id = self.osc_get_image_id(image_name='alpine')
        gw = '2.10.0.1'
        cidr = '2.10.0.0/24'
        cidr1 = netaddr.IPNetwork(cidr)
        mask = 24
        network2 = self.create_network()
        subnet2 = self.create_subnet(
            network2, gateway=gw, cidr=cidr1, mask_bits=mask)
        router2 = self.create_router(data_utils.rand_name('router-'))
        self.create_router_interface(router2['id'], subnet2['id'])
        p1 = self.create_port(
            network=network1,
            name='p1',
            port_security_enabled=False)
        p2 = self.create_port(
            network=network2,
            name='p2',
            port_security_enabled=False)

        sfcvm1 = self.create_tenant_server(
            ports=[p1, p2], wait_until='ACTIVE', name='sfc-vm1',image_id=image_id)

        time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1, p2)
        self.assertRaises(
            lib_exec.BadRequest,
            self.nsfc_client.create_port_pair_group,
            name='ppg1',
            port_pair=pp1)
        # Details: {u'message': u'Bad request: Nuage only supports grouping of
        # ports belonging to one subnet', u'type': u'NuageBadRequest',
        # u'detail': u''}
        pass

    def test_port_pair_vm_shutoff(self):
        network1 = self.create_network()
        subnet1 = self.create_subnet(network1)
        router = self.create_router(data_utils.rand_name('router-'))
        self.create_router_interface(router['id'], subnet1['id'])
        image_id = self.osc_get_image_id(image_name='alpine')
        p1 = self.create_port(
            network=network1,
            name='p1',
            port_security_enabled=False)
        p2 = self.create_port(
            network=network1,
            name='p2',
            port_security_enabled=False)
        sfcvm1 = self.create_tenant_server(
            ports=[p1, p2], wait_until='ACTIVE', name='sfc-vm1',image_id=image_id)
        time.sleep(5)
        self.stop_tenant_server(
            sfcvm1.openstack_data['id'],
            wait_until='SHUTOFF')
        pp1 = self.nsfc_client.create_port_pair('pp1', p1['id'], p2['id'])
        ppg1 = self.nsfc_client.create_port_pair_group('ppg1', pp1)
        ppg1_rt_ingress, ppg1_rt_egress, ppg1_ingress_pg, ppg1_egress_pg = self._get_l3_port_pair_group_redirect_target_pg(
            ppg1, router=router)
        self.nsfc_client.delete_port_pair_group(ppg1['port_pair_group']['id'])
        self.nsfc_client.delete_port_pair(pp1['port_pair']['id'])

    def test_PC_multiple_FCs(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(data_utils.rand_name('router-'))
        self.create_router_interface(router['id'], subnet['id'])
        image_id = self.osc_get_image_id(image_name='alpine')
        src_port = self.create_port(network=network, name='src_port')
        dest_port = self.create_port(network=network, name='dest_port')
        FC1 = self._create_flow_classifier('FC1', src_port['id'], dest_port['id'], '10', 'tcp',
                                           source_port_range_max='23', source_port_range_min='23',
                                           destination_port_range_min='100', destination_port_range_max='100')

        src_port1 = self.create_port(network=network, name='src_port1')
        dest_port1 = self.create_port(network=network, name='dest_port1')
        FC2 = self._create_flow_classifier(
            'FC2', src_port1['id'], dest_port1['id'], '12', 'icmp')

        src_port2 = self.create_port(network=network, name='src_port2')
        dest_port2 = self.create_port(network=network, name='dest_port2')
        FC3 = self._create_flow_classifier(
            'FC3', src_port2['id'], dest_port2['id'], '14')

        p1 = self.create_port(
            network=network,
            name='p1',
            port_security_enabled=False)
        sfcvm1 = self.create_tenant_server(
            ports=[p1], wait_until='ACTIVE', name='sfc-vm1',image_id=image_id)
        p2 = self.create_port(
            network=network,
            name='p2',
            port_security_enabled=False)
        sfcvm2 = self.create_tenant_server(
            ports=[p2], wait_until='ACTIVE', name='sfc-vm2',image_id=image_id)
        time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1, p1)
        ppg1 = self._create_port_pair_group('ppg1', pp1)
        pp2 = self._create_port_pair('pp2', p2, p2)
        ppg2 = self._create_port_pair_group('ppg2', pp2)
        PC1 = self. _create_port_chain('PC1', [ppg1, ppg2], [FC1, FC2])
        ppg_list = [ppg1,ppg2]
        rt_src, rt_dest, src_pg, dest_pg = self._verify_flow_classifier(
            network, subnet, FC1, src_port, dest_port, router=router)
        rt_src1, rt_dest1, src_pg1, dest_pg1 = self._verify_flow_classifier(
            network, subnet, FC2, src_port1, dest_port1, router=router)
        ppg1_rt_ingress_egress, ppg1_ingress_egress_pg = self._get_l3_port_pair_group_redirect_target_pg(
            ppg1, router=router, bidirectional_port='true')
        ppg2_rt_ingress_egress, ppg2_ingress_egress_pg = self._get_l3_port_pair_group_redirect_target_pg(
            ppg2, router=router, bidirectional_port='true')
        rules = self._get_adv_fwd_rules_port_chain(PC1, router=router)
        for rule in rules:
            if (rule['locationID'] == src_pg[0]['ID']):
                rule_src_insfcvm1 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    ppg1_rt_ingress_egress[0]['ID'],
                    "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                self.assertEquals(
                    rule['vlanRange'],
                    '10-10',
                    "sfc to sfc-vm1 vlan range is wrong")
                self.assertEquals(rule['redirectRewriteType'], 'VLAN')
                self.assertEquals(
                    rule['redirectRewriteValue'], str(
                        PC1['port_chain']['chain_parameters']['correlation_id']))
            if (rule['locationID'] == ppg1_ingress_egress_pg[0]['ID']):
                rule_sfcvm1_sfcvm2 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    ppg2_rt_ingress_egress[0]['ID'],
                    "ssfc-vm1 to sfc-vm2 adv fwd rule redirect vport is wrong")
            if (rule['locationID'] == ppg2_ingress_egress_pg[0]
                    ['ID'] and rule['redirectRewriteValue'] == '10'):
                rule_sfcvm2_dest = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    rt_dest[0]['ID'],
                    "sfcvm1 to dest adv fwd rule redirect target is wrong")
            if (rule['locationID'] == src_pg1[0]['ID']):
                rule_src1_insfcvm1 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    ppg1_rt_ingress_egress[0]['ID'],
                    "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                self.assertEquals(
                    rule['vlanRange'],
                    '12-12',
                    "sfc to sfc-vm1 vlan range is wrong")
                self.assertEquals(rule['redirectRewriteType'], 'VLAN')
                self.assertEquals(
                    rule['redirectRewriteValue'], str(
                        PC1['port_chain']['chain_parameters']['correlation_id']))

            if (rule['locationID'] == ppg2_ingress_egress_pg[0]
                    ['ID'] and rule['redirectRewriteValue'] == '12'):
                rule_sfcvm2_dest1 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    rt_dest1[0]['ID'],
                    "sfcvm1 to dest1 adv fwd rule redirect target is wrong")

        self.assertIsNotNone(rule_src_insfcvm1)
        self.assertIsNotNone(rule_sfcvm1_sfcvm2)
        self.assertIsNotNone(rule_sfcvm2_dest)
        self.assertIsNotNone(rule_src1_insfcvm1)
        self.assertIsNotNone(rule_sfcvm2_dest1)

    def test_port_chain_create_delete_non_def_netpart(self):
        netpart_body = self.client.create_netpartition(
            data_utils.rand_name('Enterprise-'))
        nondef_netpart = netpart_body['net_partition']
        self.addCleanup(self.client.delete_netpartition, nondef_netpart['id'])
        nondef_network = self.create_network()
        nondef_subnet = self.create_subnet(
            nondef_network, net_partition=nondef_netpart['id'])
        src_port = self.create_port(network=nondef_network, name='src_port')
        dest_port = self.create_port(network=nondef_network, name='dest_port')
        image_id = self.osc_get_image_id(image_name='alpine')
        FC1 = self._create_flow_classifier('FC1', src_port['id'], dest_port['id'], '10', 'tcp',
                                           source_port_range_max='23', source_port_range_min='23',
                                           destination_port_range_min='100', destination_port_range_max='100')
        p1 = self.create_port(
            network=nondef_network,
            name='p1',
            port_security_enabled=False)
        p2 = self.create_port(
            network=nondef_network,
            name='p2',
            port_security_enabled=False)

        sfcvm1 = self.create_tenant_server(
            ports=[p1, p2], wait_until='ACTIVE', name='sfc-vm1',image_id=image_id)
        time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1, p2)
        ppg1 = self._create_port_pair_group('ppg1', pp1)
        PC1 = self. _create_port_chain('PC1', [ppg1], [FC1])
        # verify
        self.assertNotEquals(
            PC1, '', 'port chain is empty')
        rt_src, rt_dest, src_pg, dest_pg = self._verify_flow_classifier_l2(
            nondef_network, nondef_subnet, FC1, src_port, dest_port, netpart_name=nondef_netpart['name'])

        ppg1_rt_ingress, ppg1_rt_egress, ppg1_ingress_pg, ppg1_egress_pg = self._get_l2_port_pair_group_redirect_target_pg(
            ppg1, nondef_subnet, netpart_name=nondef_netpart['name'])
        rules = self._get_adv_fwd_rules_port_chain_l2(
            PC1, nondef_subnet, netpart_name=nondef_netpart['name'])
        for rule in rules:
            if (rule['locationID'] == src_pg[0]['ID']):
                rule_src_insfcvm1 = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    ppg1_rt_ingress[0]['ID'],
                    "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                self.assertEquals(
                    rule['vlanRange'],
                    '10-10',
                    "sfc to sfc-vm1 vlan range is wrong")
                self.assertEquals(rule['redirectRewriteType'], 'VLAN')
            if (rule['locationID'] == ppg1_egress_pg[0]['ID']):
                rule_sfcvm1_dest = rule
                self.assertEquals(
                    rule['redirectVPortTagID'],
                    rt_dest[0]['ID'],
                    "sfcvm1 to dest adv fwd rule redirect target is wrong")
        self.assertIsNotNone(rule_src_insfcvm1)
        self.assertIsNotNone(rule_sfcvm1_dest)

    def test_multi_PC_with_overlap_ppg(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(data_utils.rand_name('router-'))
        self.create_router_interface(router['id'], subnet['id'])
        image_id = self.osc_get_image_id(image_name='alpine')
        src_port = self.create_port(network=network, name='src_port')
        dest_port = self.create_port(network=network, name='dest_port')
        FC1 = self._create_flow_classifier(
            'FC1', src_port['id'], dest_port['id'], '11', 'icmp')
        src_port2 = self.create_port(network=network, name='src_port2')
        dest_port2 = self.create_port(network=network, name='dest_port2')
        FC2 = self._create_flow_classifier(
            'FC2', src_port2['id'], dest_port2['id'], '12', 'icmp')

        src_port3 = self.create_port(network=network, name='src_port3')
        dest_port3 = self.create_port(network=network, name='dest_port3')
        FC3 = self._create_flow_classifier(
            'FC3', src_port3['id'], dest_port3['id'], '14', 'icmp')
        p1 = self.create_port(
            network=network,
            name='p1',
            port_security_enabled=False)
        p2 = self.create_port(
            network=network,
            name='p2',
            port_security_enabled=False)
        p3 = self.create_port(
            network=network,
            name='p3',
            port_security_enabled=False)
        p4 = self.create_port(
            network=network,
            name='p4',
            port_security_enabled=False)
        p5 = self.create_port(
            network=network,
            name='p5',
            port_security_enabled=False)
        p6 = self.create_port(
            network=network,
            name='p6',
            port_security_enabled=False)
        sfcvm1 = self.create_tenant_server(
            ports=[p1, p2], wait_until='ACTIVE', name='sfc-vm1',image_id=image_id)
        sfcvm2 = self.create_tenant_server(
            ports=[p3, p4], wait_until='ACTIVE', name='sfc-vm2',image_id=image_id)
        sfcvm3 = self.create_tenant_server(
            ports=[p5, p6], wait_until='ACTIVE', name='sfc-vm3',image_id=image_id)

        time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1, p2)
        ppg1 = self._create_port_pair_group('ppg1', pp1)
        pp2 = self._create_port_pair('pp2', p3, p4)
        ppg2 = self._create_port_pair_group('ppg2', pp2)
        pp3 = self._create_port_pair('pp3', p5, p6)
        ppg3 = self._create_port_pair_group('ppg3', pp3)
        PC1 = self. _create_port_chain('PC1', [ppg1, ppg2, ppg3], [FC1])
        PC2 = self. _create_port_chain('PC2', [ppg1, ppg2], [FC2])
        PC3 = self. _create_port_chain('PC3', [ppg1, ppg3], [FC3])
        ppg_list_1=[ppg1,ppg2,ppg3]
        self._verify_adv_fwd_rules_l3(network,subnet,router,src_port,dest_port,ppg_list_1,FC1,PC1,'11')
        ppg_list_2 = [ppg1,ppg2]
        self._verify_adv_fwd_rules_l3(network,subnet,router,src_port2,dest_port2,ppg_list_2,FC2,PC2,'12')

        ppg_list_3 = [ppg1,ppg3]
        self._verify_adv_fwd_rules_l3(network,subnet,router,src_port3,dest_port3,ppg_list_3,FC2,PC3,'14')
