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

import json

from tempest.services.network.json import network_client
from tempest.common import service_client


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


    # Add router interface
    def add_router_interface(self, router_id, subnet_id):
        uri = '%s/routers/%s/add_router_interface' % (self.uri_prefix,
                                                      router_id)
        post_data = json.dumps({"subnet_id": subnet_id})
        resp, body = self.put(uri, post_data)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    # Remove router interface
    def remove_router_interface(self, router_id, subnet_id):
        uri = '%s/routers/%s/remove_router_interface' % (self.uri_prefix,
                                                         router_id)
        post_data = json.dumps({"subnet_id": subnet_id})
        resp, body = self.put(uri, post_data)
        self.expected_success(200, resp.status)
        body = json.loads(body)
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
