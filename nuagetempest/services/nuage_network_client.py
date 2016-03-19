# Copyright 2015 Alcatel-Lucent USA Inc.
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
#
#    -----------------------WARNING----------------------------
#     This file is present to support Legacy Test Code only.
#     DO not use this file for writing the new tests.
#    ----------------------------------------------------------
#
import json

from tempest.services.network.json import network_client
from tempest.lib.common import rest_client as service_client
import nuagetempest.lib.utils.constants as constants


class NuageNetworkClientJSON(network_client.NetworkClient):

    def _get_request(self, uri):
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_gateways(self):
        uri = '%s/nuage-gateways' % (self.uri_prefix)
        return self._get_request(uri)

    def show_gateway(self, gw_id):
        uri = ('%s/nuage-gateways/%s' % (self.uri_prefix, gw_id))
        return self._get_request(uri)

    def list_gateway_ports(self, gw_id):
        uri = '%s/nuage-gateway-ports?gateway=%s' % (self.uri_prefix, gw_id)
        return self._get_request(uri)

    def get_gateway_id_by_name(self, gw_name):
        uri = ('%s/nuage-gateways?name=%s' % (self.uri_prefix, gw_name))
        body = self._get_request(uri)
        gw_id = body['nuage_gateways'][0]['id']
        return gw_id

    def get_gateway_port_id_by_name(self, port_name, gw_name):
        gw_id = self.get_gateway_id_by_name(gw_name)
        uri = ('%s/nuage-gateway-ports?name=%s&gateway=%s' %
               (self.uri_prefix, port_name, gw_id))
        body = self._get_request(uri)
        return body['nuage_gateway_ports'][0]['id']

    def list_gateway_ports_by_gateway_name(self, gw_name):
        return self.list_gateway_ports(self.get_gateway_id_by_name(gw_name))

    def show_gateway_ports_by_gateway_name(self, port_name, gw_name):
        return self.show_gateway_port(
            self.get_gateway_port_id_by_name(port_name, gw_name))

    def list_gateway_vlans(self, gw_port_id):
        uri = '%s/nuage-gateway-vlans?gatewayport=%s' % (self.uri_prefix,
                                                         gw_port_id)
        return self._get_request(uri)

    def get_gateway_vlan_id_by_name(self, vlan_value, gw_port_id):
        uri = '%s/nuage-gateway-vlans?gatewayport=%s&name=%s' % (self.uri_prefix,
                                                                 gw_port_id, vlan_value)
        body = self._get_request(uri)
        return body['nuage_gateway_vlans'][0]['id']

    def show_gateway_vlan_by_name(self, vlan_value, port_name, gw_name):
        gw_id = self.get_gateway_id_by_name(gw_name)
        gw_port_id = self.get_gateway_port_id_by_name(port_name, gw_name)
        gw_vlan_id = self.get_gateway_vlan_id_by_name(vlan_value, gw_port_id)
        uri = '%s/nuage-gateway-vlans/%s?gatewayport=%s&gateway=%s' % (
            self.uri_prefix, gw_vlan_id, gw_port_id, gw_id)
        return self._get_request(uri)

    def list_gateway_vlans_by_name(self, port_name, gw_name):
        gw_id = self.get_gateway_id_by_name(gw_name)
        gw_port_id = self.get_gateway_port_id_by_name(port_name, gw_name)
        uri = '%s/nuage-gateway-vlans?gatewayport=%s&gateway=%s' % (
            self.uri_prefix, gw_port_id, gw_id)
        return self._get_request(uri)

    def show_gateway_port(self, gw_port_id):
        uri = ('%s/nuage-gateway-ports/%s' % (self.uri_prefix, gw_port_id))
        return self._get_request(uri)

    def show_gateway_vlan(self, vlan_id):
        uri = ('%s/nuage-gateway-vlans/%s' % (self.uri_prefix, vlan_id))
        return self._get_request(uri)

    def create_gateway_vlan(self, **kwargs):
        post_body = {'nuage_gateway_vlan': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-gateway-vlans' % (self.uri_prefix)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def create_gateway_vport(self, **kwargs):
        post_body = {'nuage_gateway_vport': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-gateway-vports' % (self.uri_prefix)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_gateway_vlan(self, id):
        uri = '%s/nuage-gateway-vlans/%s' % (self.uri_prefix, id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    # Add redirect target
    def create_redirection_target(self, **kwargs):
        post_body = {'nuage_redirect_target': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-redirect-targets' % (self.uri_prefix)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_redirection_target(self, id):
        uri = '%s/nuage-redirect-targets/%s' % (self.uri_prefix, id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_redirection_targets(self, id):
        uri = '%s/nuage-redirect-targets/%s' % (self.uri_prefix)
        return self._get_request(uri)

    def show_redirection_target(self, id):
        uri = ('%s/nuage-redirect-targets/%s' % (self.uri_prefix, id))
        return self._get_request(uri)

    def get_redirection_target_id_by_name(self, name):
        uri = ('%s/nuage-redirect-targets?name=%s' % (self.uri_prefix, name))
        body = self._get_request(uri)
        id = body['nuage-redirect-targets'][0]['id']
        return id

    # Add redirect target VIP
    def create_redirection_target_vip(self, **kwargs):
        post_body = {'nuage_redirect_target_vip': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-redirect-target-vips' % (self.uri_prefix)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    # Add redirect target rules
    def create_redirection_target_rule(self, **kwargs):
        post_body = {'nuage_redirect_target_rule': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-redirect-target-rules' % (self.uri_prefix)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_redirection_target_rule(self, id):
        uri = '%s/nuage-redirect-target-rules/%s' % (self.uri_prefix, id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def assign_gateway_vlan(self, id, **kwargs):
        post_body = {'nuage_gateway_vlan': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-gateway-vlans/%s' % (self.uri_prefix, id)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return resp, body

    def list_gateway_vport(self, subnet_id):
        uri = '%s/nuage-gateway-vports.json?subnet=%s' % (
            self.uri_prefix, subnet_id)
        return self._get_request(uri)

    def show_gateway_vport(self, vport_id, subnet_id):
        uri = '%s/nuage-gateway-vports/%s?subnet=%s' % (
            self.uri_prefix, vport_id, subnet_id)
        return self._get_request(uri)

    def create_netpartition(self, name, **kwargs):
        post_body = {'net_partition': kwargs}
        post_body['net_partition']['name'] = name
        body = json.dumps(post_body)
        uri = '%s/net-partitions' % (self.uri_prefix)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_netpartition(self, id):
        uri = '%s/net-partitions/%s' % (self.uri_prefix, id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_netpartition(self):
        uri = '%s/net-partitions' % (self.uri_prefix)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_tiers(self, app_id):
        uri = '%s/tiers?app_id=%s' % (self.uri_prefix, app_id)
        return self._get_request(uri)

    def list_flows(self, app_id):
        uri = '%s/flows?app_id=%s' % (self.uri_prefix, app_id)
        return self._get_request(uri)

    def create_nuage_external_security_group(self, **kwargs):
        post_body = {'nuage_external_security_group': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-external-security-groups' % self.uri_prefix
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_nuage_external_security_group(self, security_group_id):
        uri = '/nuage-external-security-groups/%s' % security_group_id
        return self.delete_resource(uri)

    def show_nuage_external_security_group(self, security_group_id):
        uri = '/nuage-external-security-groups/%s' % security_group_id
        return self.show_resource(uri)

    def create_nuage_external_security_group_rule(self, **kwargs):
        post_body = {'nuage_external_security_group_rule': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-external-security-group-rules' % self.uri_prefix
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_nuage_external_security_group_rule(self, security_group_rule_id):
        uri = '/nuage-external-security-group-rules/%s' % security_group_rule_id
        return self.delete_resource(uri)

    def show_nuage_external_security_group_rule(self, security_group_rule_id):
        uri = '/nuage-external-security-group-rules/%s' % security_group_rule_id
        return self.show_resource(uri)

    def list_nuage_external_security_group(self, router_id):
        uri = '%s/nuage-external-security-groups.json?router=%s' % (self.uri_prefix, router_id)
        return self._get_request(uri)

    def list_nuage_external_security_group_rule(self, remote_group_id):
        uri = '%s/nuage-external-security-group-rules.json?external_group=%s' % (self.uri_prefix,
                                                                                 remote_group_id)
        return self._get_request(uri)

    def list_nuage_external_security_group_l2domain(self, subnet_id):
        uri = '%s/nuage-external-security-groups.json?subnet=%s' % (self.uri_prefix, subnet_id)
        return self._get_request(uri)

    # FloatingIp
    def create_floatingip(self, parent_id, shared_netid,
                          address, parent=None, externalId=None,
                          extra_params=None):
        data = {
            "associatedSharedNetworkResourceID": shared_netid,
            "address": address
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if self.extra_params:
            data.update(self.extra_params)
        if not parent:
            parent = constants.DOMAIN
        res_path = self.build_resource_path(
            parent, parent_id, constants.FLOATINGIP)
        return self.post(res_path, data)

    def update_router_rdrt(self, router_id, **kwargs):
        uri = '/routers/%s' % router_id
        update_body = {}
        update_body['router'] = kwargs
        return self.update_resource(uri, update_body)

    def show_application_domain(self, domain_id):
        uri = ('%s/application-domains/%s' % (self.uri_prefix, domain_id))
        return self._get_request(uri)

    def show_application(self, id):
        uri = ('%s/applications/%s' % (self.uri_prefix, id))
        return self._get_request(uri)

    def show_service(self, id):
        uri = ('%s/services/%s' % (self.uri_prefix, id))
        return self._get_request(uri)

    def show_tier(self, id):
        uri = ('%s/tiers/%s' % (self.uri_prefix, id))
        return self._get_request(uri)

    def show_flow(self, id):
        uri = ('%s/flows/%s' % (self.uri_prefix, id))
        return self._get_request(uri)

    def show_appdport(self, id):
        uri = ('%s/appdports/%s' % (self.uri_prefix, id))
        return self._get_request(uri)
