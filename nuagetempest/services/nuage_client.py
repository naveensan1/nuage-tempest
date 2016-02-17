import netaddr

from tempest import config
from tempest import exceptions

from nuagetempest.lib.utils import constants
from nuagetempest.lib.utils import exceptions as n_exceptions
from nuagetempest.lib.utils import restproxy


CONF = config.CONF
SERVERSSL = True
SERVERTIMEOUT = 30
RESPONSECHOICE = '?responseChoice=1'
CMS_ID = None


class NuageRestClient(object):

    def __init__(self):
        server = CONF.nuage.nuage_vsd_server
        self.def_netpart_name = (
            CONF.nuage.nuage_default_netpartition
        )
        global CMS_ID
        CMS_ID = CONF.nuage.nuage_cms_id
        if not CMS_ID:
            raise exceptions.InvalidConfiguration("Missing cms_id in "
                                                  "configuration.")
        base_uri = CONF.nuage.nuage_base_uri
        auth_resource = CONF.nuage.nuage_auth_resource
        serverauth = (CONF.nuage.nuage_vsd_user + ":" +
                      CONF.nuage.nuage_vsd_password)
        nuage_vsd_org = CONF.nuage.nuage_vsd_org

        self.restproxy = restproxy.RESTProxyServer(server, base_uri, SERVERSSL,
                                                   serverauth, auth_resource,
                                                   nuage_vsd_org,
                                                   SERVERTIMEOUT)
        self.restproxy.generate_nuage_auth()

    @staticmethod
    def _error_checker(resp):

        # It is not an error response
        if resp.status < 400:
            return

        if resp.status == 401 or resp.status == 403:
            raise n_exceptions.Unauthorized(resp.data)

        if resp.status == 404:
            raise n_exceptions.NotFound(resp.data)

        if resp.status == 400:
            raise n_exceptions.BadRequest(resp.data)

        if resp.status == 409:
            raise n_exceptions.Conflict(resp.data)

        if resp.status == 422:
            raise n_exceptions.UnprocessableEntity(resp.data)

        if resp.status in (500, 501):
            message = resp.data

            raise n_exceptions.ServerFault(message)

        if resp.status >= 400:
            raise n_exceptions.UnexpectedResponseCode(str(resp.status))

    def request(self, method, url, body=None, extra_headers=None):
        resp = self.restproxy.rest_call(
            method, url, data=body, extra_headers=extra_headers)
        # Verify HTTP response codes
        self._error_checker(resp)
        return resp

    def delete(self, url, body=None, extra_headers=None):
        return self.request('DELETE', url, body, extra_headers)

    def get(self, url, extra_headers=None, body=None):
        resp = self.request('GET', url, extra_headers=extra_headers)
        return resp.data

    def post(self, url, body, extra_headers=None):
        resp = self.request('POST', url, body, extra_headers)
        return resp.data

    def put(self, url, body, extra_headers=None):
        return self.request('PUT', url, body, extra_headers)

    @staticmethod
    def get_extra_headers(attr, attr_value):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        if attr == 'externalID':
            attr_value = NuageRestClient.get_vsd_external_id(attr_value)

        if isinstance(attr_value, int):
            headers['X-Nuage-Filter'] = "%s IS %s" % (attr, attr_value)
        else:
            headers['X-Nuage-Filter'] = "%s IS '%s'" % (attr, attr_value)
        return headers

    @staticmethod
    def build_resource_path(resource=None, resource_id=None,
                            child_resource=None):
        res_path = None
        if resource:
            res_path = ("/%s" % resource +
                        (resource_id and "/%s" % resource_id or '') +
                        (child_resource and "/%s" % child_resource or ''))
        return res_path

    def get_global_resource(self, resource, filters=None,
                            filter_value=None):
        extra_headers = None
        res_path = "/%s" % resource
        if filters:
            extra_headers = self.get_extra_headers(filters, filter_value)
        return self.get(res_path, extra_headers)

    def get_resource(self, resource, filters=None,
                     filter_value=None,
                     netpart_name=None):
        extra_headers = None
        if not netpart_name:
            netpart_name = self.def_netpart_name

        net_part = self.get_net_partition(netpart_name)
        res_path = self.build_resource_path(
            resource=constants.NET_PARTITION, resource_id=net_part[0]['ID'],
            child_resource=resource)
        if filters:
            extra_headers = self.get_extra_headers(filters, filter_value)
        return self.get(res_path, extra_headers)

    def get_child_resource(self, resource, resource_id, child_resource,
                           filters=None, filter_value=None):
        extra_headers = None
        res_path = self.build_resource_path(
            resource, resource_id,
            child_resource)
        if filters:
            extra_headers = self.get_extra_headers(filters, filter_value)
        return self.get(res_path, extra_headers)

    def delete_resource(self, resource, resource_id, responseChoice=False):
        res_path = self.build_resource_path(resource, resource_id)
        if responseChoice:
            res_path = res_path + RESPONSECHOICE
        return self.delete(res_path)

    # Net Partition
    def create_net_partition(self, name, fip_quota, extra_params):
        data = {
            'name': name,
            'floatingIPsQuota': fip_quota,
            'allowedForwardingClasses': ['E', 'F', 'G', 'H']
        }
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(constants.NET_PARTITION)
        return self.post(res_path, data)

    def delete_net_partition(self):
        pass

    def get_net_partition(self, net_part_name):
        res_path = self.build_resource_path(constants.NET_PARTITION)
        extra_headers = self.get_extra_headers('name', net_part_name)
        return self.get(res_path, extra_headers)

    # Network
    # EnterpriseNetworkMacro
    def get_enterprise_net_macro(self, filters=None, filter_value=None,
                                 netpart_name=None):
        return self.get_resource(constants.ENTERPRISE_NET_MACRO,
                                 filters, filter_value, netpart_name)

    # Public Network Macro
    def get_public_net_macro(self, filters=None, filter_value=None,
                             netpart_name=None):
        return self.get_resource(constants.PUBLIC_NET_MACRO,
                                 filters, filter_value, netpart_name)

    # DomainTemplates
    def create_l3domaintemplate(self, name, extra_params=None,
                                netpart_name=None):
        data = {
            'name': name
        }
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)

        res_path = self.build_resource_path(
            constants.NET_PARTITION, net_part[0]['ID'],
            constants.DOMAIN_TEMPLATE)
        return self.post(res_path, data)

    def get_l3domaintemplate(self, filters=None,
                             filter_value=None, netpart_name=None):
        return self.get_resource(constants.DOMAIN_TEMPLATE,
                                 filters, filter_value,
                                 netpart_name)

    def delete_l3domaintemplate(self, l3dom_tid):
        return self.delete_resource(constants.DOMAIN_TEMPLATE, l3dom_tid)

    # Domain
    def create_domain(self, name, templateId, externalId=None,
                      netpart_name=None, extra_params=None):
        data = {
            'name': name,
            'templateID': templateId
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)
        res_path = self.build_resource_path(
            constants.NET_PARTITION, net_part[0]['ID'],
            constants.DOMAIN)
        return self.post(res_path, data)

    # If filters is not set, returns /enterprises/%s/domains
    def get_l3domain(self, filters=None, filter_value=None, netpart_name=None):
        return self.get_resource(constants.DOMAIN,
                                 filters, filter_value, netpart_name)

    def delete_domain(self, dom_id):
        return self.delete_resource(constants.DOMAIN, dom_id)

    # Zone Template
    def create_zonetemplate(self, parent_id, name, extra_params=None):
        data = {
            'name': name
        }
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            constants.DOMAIN_TEMPLATE, parent_id, constants.ZONE_TEMPLATE)
        return self.post(res_path, data)

    def get_zonetemplate(self, parent_id, filters=None, filter_value=None):
        return self.get_child_resource(constants.DOMAIN_TEMPLATE, parent_id,
                                       constants.ZONE_TEMPLATE, filters,
                                       filter_value)

    # Zone
    def create_zone(self, parent_id, name, externalId=None, extra_params=None):
        data = {
            'name': name
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            constants.DOMAIN, parent_id, constants.ZONE)
        return self.post(res_path, data)

    def get_zone(self, parent_id, filters=None, filter_value=None):
        return self.get_child_resource(constants.DOMAIN, parent_id,
                                       constants.ZONE, filters, filter_value)

    def delete_zone(self, zone_id):
        return self.delete_resource(constants.ZONE, zone_id)

    # Domain Subnet
    def create_domain_subnet(self, parent_id, name, net_address, netmask,
                             gateway, externalId=None, extra_params=None):
        data = {
            "name": name,
            "address": net_address,
            "netmask": netmask,
            "gateway": gateway
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            constants.ZONE, parent_id, constants.SUBNETWORK)
        return self.post(res_path, data)

    def get_domain_subnet(self, parent, parent_id, filters=None,
                          filter_value=None):
        if parent:
            return self.get_child_resource(
                parent, parent_id, constants.SUBNETWORK, filters, filter_value)
        else:
            return self.get_global_resource(constants.SUBNETWORK, filters,
                                            filter_value)

    def delete_domain_subnet(self, subnet_id):
        return self.delete_resource(constants.SUBNETWORK, subnet_id)

    # DHCPOption
    def create_dhcpoption(self):
        pass

    def get_dhcpoption(self, parent, parent_id):
        return self.get_child_resource(
            parent, parent_id, constants.DHCPOPTION, None, None)

    # Sharedresource
    def get_sharedresource(self, filters=None, filter_value=None):
        return self.get_global_resource(constants.SHARED_NET_RES,
                                        filters, filter_value)

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

    def get_floatingip(self, parent, parent_id):
        return self.get_child_resource(
            parent, parent_id, constants.FLOATINGIP, None, None)

    # Static Route
    def create_staticroute(self, parent, parent_id, netaddr, nexthop,
                           externalId=None, extra_params=None):
        data = {
            'address': netaddr.ip,
            'netmask': netaddr.netmask,
            'nextHopIp': nexthop
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if self.extra_params:
            data.update(self.extra_params)
        res_path = self.build_resource_path(
            parent, parent_id, constants.STATIC_ROUTE)
        return self.post(res_path, data)

    def get_staticroute(self, parent, parent_id, filters=None,
                        filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.STATIC_ROUTE, None, None)

    # L2Domain Template
    def create_l2domaintemplate(self, name, extra_params=None,
                                netpart_name=None):
        data = {
            'name': name
        }
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)

        res_path = self.build_resource_path(
            constants.NET_PARTITION, net_part[0]['ID'],
            constants.L2_DOMAIN_TEMPLATE)
        return self.post(res_path, data)

    def get_l2domaintemplate(self, filters=None, filter_value=None,
                             netpart_name=None):
        return self.get_resource(constants.L2_DOMAIN_TEMPLATE,
                                 filters, filter_value, netpart_name)

    def delete_l2domaintemplate(self, l2dom_tid):
        return self.delete_resource(constants.L2_DOMAIN_TEMPLATE, l2dom_tid)

    # L2Domain
    def create_l2domain(self, name, templateId=None, externalId=None,
                        extra_params=None, netpart_name=None):
        if not templateId:
            l2dom_template = self.create_l2domaintemplate(
                name + '-l2domtemplate')
            templateId = l2dom_template[0]['ID']
        data = {
            'name': name,
            'templateID': templateId
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)

        res_path = self.build_resource_path(
            constants.NET_PARTITION, net_part[0]['ID'],
            constants.L2_DOMAIN)
        return self.post(res_path, data)

    def delete_l2domain(self, l2dom_id):
        return self.delete_resource(constants.L2_DOMAIN, l2dom_id)

    def get_l2domain(self, filters=None, filter_value=None, netpart_name=None):
        return self.get_resource(constants.L2_DOMAIN,
                                 filters, filter_value, netpart_name)

    # Policy
    # Policygroup
    def create_policygroup(self, parent, parent_id, name, type,
                           externalId=None, extra_params=None):
        data = {
            'description': name,
            'type': type
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
            data['name'] = externalId
        else:
            data['name'] = name
        if self.extra_params:
            data.update(self.extra_params)
        res_path = self.build_resource_path(
            parent, parent_id, constants.POLICYGROUP)
        return self.post(res_path, data)

    def get_policygroup(self, parent, parent_id, filters=None,
                        filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.POLICYGROUP, filters, filter_value)

    # Redirection Target
    def get_redirection_target(self, parent, parent_id,
                               filters=None, filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.REDIRECTIONTARGETS,
            filters, filter_value)

    def get_redirection_target_vports(self, parent, parent_id,
                               filters=None, filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.VPORT, filters, filter_value)

    def get_redirection_target_vips(self, parent, parent_id,
                               filters=None, filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.VIRTUAL_IP, filters, filter_value)

    # ADVFWDTemplate
    def get_advfwd_entrytemplate(self, parent, parent_id,
                               filters=None, filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.INGRESS_ADV_FWD_ENTRY_TEMPLATE,
            filters, filter_value)

    def get_advfwd_template(self, parent, parent_id,
                               filters=None, filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.INGRESS_ADV_FWD_TEMPLATE,
            filters, filter_value)

    # ACLTemplate
    def get_ingressacl_template(self, parent, parent_id):
        return self.get_child_resource(parent, parent_id,
                                       constants.INGRESS_ACL_TEMPLATE, None,
                                       None)

    def get_egressacl_template(self, parent, parent_id):
        return self.get_child_resource(parent, parent_id,
                                       constants.EGRESS_ACL_TEMPLATE, None,
                                       None)

    # ACLRule
    def create_ingress_acl(self):
        pass

    def get_ingressacl_entytemplate(self, parent, parent_id,
                                    filters=None, filter_value=None):
        return self.get_child_resource(parent, parent_id,
                                       constants.INGRESS_ACL_ENTRY_TEMPLATE,
                                       filters, filter_value)

    def create_egress_acl(self):
        pass

    def get_egressacl_entytemplate(self, parent, parent_id,
                                   filters=None, filter_value=None):
        return self.get_child_resource(parent, parent_id,
                                       constants.EGRESS_ACL_ENTRY_TEMPLATE,
                                       filters, filter_value)

    # User Mgmt
    # User
    def get_user(self, filters=None, filter_value=None, netpart_name=None):
        return self.get_resource(constants.USER, filters,
                                 filter_value, netpart_name)

    # Group
    def get_usergroup(self, parent, parent_id, filters=None,
                      filter_value=None, netpart_name=None):
        if parent:
            return self.get_child_resource(parent, parent_id, constants.GROUP,
                                           filters, filter_value)
        else:
            return self.get_resource(constants.GROUP, filters,
                                     filter_value, netpart_name)

    # Permissions
    def get_permissions(self, parent, parent_id, filters=None,
                        filter_value=None):
        return self.get_child_resource(parent, parent_id,
                                       constants.PERMIT_ACTION, None, None)

    # VM Interface
    def get_vm_iface(self, parent, parent_id, filters=None, filter_value=None):
        return self.get_child_resource(parent, parent_id,
                                       constants.VM_IFACE, filters,
                                       filter_value)

    # VM
    def get_vm(self, parent, parent_id, filters=None,
               filter_value=None, netpart_name=None):
        if parent:
            return self.get_child_resource(parent, parent_id, constants.VM,
                                           filters, filter_value)
        else:
            return self.get_resource(constants.VM, filters,
                                     filter_value, netpart_name)

    # Vport
    # Bridge Interface
    def get_bridge_iface(self, parent, parent_id, filters=None,
                         filter_value=None):
        return self.get_child_resource(parent, parent_id,
                                       constants.BRIDGE_IFACE, filters,
                                       filter_value)

    # Vport
    def get_vport(self, parent, parent_id, filters=None, filter_value=None):
        return self.get_child_resource(parent, parent_id, constants.VPORT,
                                       filters, filter_value)

    # VirtualIP
    def get_virtual_ip(self, parent, parent_id, filters=None,
                       filter_value=None):
        return self.get_child_resource(parent, parent_id, constants.VIRTUAL_IP,
                                       filters, filter_value)

    # Gateway
    def create_gateway(self, name, system_id, personality,
                       np_id=None, extra_params=None):
        data = {
            'systemID': system_id,
            'name': name,
            'personality': personality
        }

        if extra_params:
            data.update(self.extra_params)

        if np_id:
            res_path = self.build_resource_path(
                resource=constants.NET_PARTITION, resource_id=np_id,
                child_resource=constants.GATEWAY)
        else:
            res_path = self.build_resource_path(resource=constants.GATEWAY)
        return self.post(res_path, data)

    def delete_gateway(self, gw_id):
        return self.delete_resource(constants.GATEWAY, gw_id)

    def get_global_gateways(self, filters=None, filter_value=None):
        res_path = self.build_resource_path(constants.GATEWAY)
        if filters:
            extra_headers = self.get_extra_headers(filters, filter_value)
            return self.get(res_path, extra_headers)
        return self.get(res_path)

    def get_gateway(self, filters=None, filter_value=None, netpart_name=None):
        return self.get_resource(constants.GATEWAY,
                                 filters, filter_value, netpart_name)

    # GatewayPort
    def create_gateway_port(self, name, userMnemonic, type, gw_id,
                            extra_params=None):
        data = {
            'userMnemonic': userMnemonic,
            'name': name,
            'physicalName': name,
            'portType': type,
            'VLANRange': '0-4094'
        }

        if extra_params:
            data.update(self.extra_params)
        res_path = self.build_resource_path(
            resource=constants.GATEWAY,
            resource_id=gw_id, child_resource=constants.GATEWAY_PORT)
        return self.post(res_path, data)

    def delete_gateway_port(self, port_id):
        return self.delete_resource(constants.GATEWAY_PORT, port_id)

    def get_gateway_port(self, filters=None, filter_value=None,
                         netpart_name=None):
        return self.get_resource(constants.GATEWAY_PORT,
                                 filters, filter_value, netpart_name)

    # GatewayVlan
    def create_gateway_vlan(self, gw_port_id, userMnemonic, value,
                            extra_params=None):
        data = {
            'userMnemonic': userMnemonic,
            'value': value
        }

        if extra_params:
            data.update(self.extra_params)
        res_path = self.build_resource_path(
            resource=constants.GATEWAY_PORT,
            resource_id=gw_port_id, child_resource=constants.VLAN)
        return self.post(res_path, data)

    def delete_gateway_vlan(self, vlan_id):
        return self.delete_resource(constants.VLAN, vlan_id)

    def get_gateway_vlan(self, parent, parent_id, filters=None,
                         filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.VLAN, filters, filter_value)

    def get_host_vport(self, vport_id):
        res_path = self.build_resource_path(constants.VPORT, vport_id)
        return self.get(res_path)

    def delete_host_interface(self, intf_id):
        return self.delete_resource(constants.HOST_IFACE, intf_id, True)

    def delete_bridge_interface(self, intf_id):
        return self.delete_resource(constants.BRIDGE_IFACE, intf_id, True)

    def delete_host_vport(self, vport_id):
        return self.delete_resource(constants.VPORT, vport_id, True)

    def create_gateway_redundancy_group(self, name,
                       peer1, peer2, extra_params=None):
        data = {
            'name': name,
            'gatewayPeer1ID': peer1,
            'gatewayPeer2ID': peer2
        }

        if extra_params:
            data.update(self.extra_params)

        res_path = self.build_resource_path(resource=constants.REDCY_GRP)
        return self.post(res_path, data)

    def create_vsg_redundant_port(self, name, userMnemonic, type, gw_id,
                            extra_params=None):
        data = {
            'userMnemonic': userMnemonic,
            'name': name,
            'physicalName': name,
            'portType': type,
            'VLANRange': '0-4094'
        }

        if extra_params:
            data.update(self.extra_params)
        res_path = self.build_resource_path(
            resource=constants.REDCY_GRP,
            resource_id=gw_id, child_resource=constants.GATEWAY_VSG_REDCY_PORT)
        return self.post(res_path, data)

    def list_ports_by_redundancy_group(self, gw_id, personality):
        if personality == 'VSG':
            child_resource=constants.GATEWAY_VSG_REDCY_PORT
        else:
            child_resource=constants.GATEWAY_PORT
        res_path = self.build_resource_path(
             resource=constants.REDCY_GRP,
             resource_id=gw_id,
             child_resource=child_resource)
        return self.get(res_path)


    def delete_gateway_redundancy_group(self, grp_id):
        return self.delete_resource(constants.REDCY_GRP, grp_id)

    def create_gateway_vlan_redundant_port(self, gw_port_id,
                                           userMnemonic, value,
                                           personality,
                                           extra_params=None):
        data = {
            'userMnemonic': userMnemonic,
            'value': value
        }
        if personality == 'VSG':
            resource = constants.GATEWAY_VSG_REDCY_PORT
        else:
            resource = constants.GATEWAY_PORT
        if extra_params:
            data.update(self.extra_params)
        res_path = self.build_resource_path(
            resource=resource,
            resource_id=gw_port_id,
            child_resource=constants.VLAN)
        return self.post(res_path, data)

    # QOS
    def get_qos(self, parent, parent_id, filters=None, filter_value=None):
        return self.get_child_resource(parent, parent_id, constants.QOS,
                                       filters, filter_value)

    def delete_vlan_permission(self, vlan_id):
        res_path = self.build_resource_path(
            resource=constants.VLAN,
            resource_id=vlan_id,
            child_resource=constants.PERMIT_ACTION)
        perm = self.get(res_path)
        if perm:
            return self.delete_resource(constants.PERMIT_ACTION,
                                        perm[0]['ID'], True)

    def get_vlan_permission(self, parent, parent_id, permission_type):
        return self.get_child_resource(
            parent, parent_id, permission_type)

    def create_default_appdomain_template(self, name, extra_params=None,
                                          netpart_name=None):
        data = {
            'name': name
        }
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)

        res_path = self.build_resource_path(
            constants.NET_PARTITION, net_part[0]['ID'],
            constants.DOMAIN_TEMPLATE)
        return self.post(res_path, data)

    def create_app_domain(self, name, templateId, externalId=None,
                          netpart_name=None, extra_params=None):
        data = {
            'name': name,
            'templateID': templateId
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)
        res_path = self.build_resource_path(
            constants.NET_PARTITION, net_part[0]['ID'],
            constants.DOMAIN)
        return self.post(res_path, data)

    def delete_app_domain(self, app_dom_id):
        return self.delete_resource(constants.DOMAIN, app_dom_id, True)

    def create_application(self, name, domain_id,
                           netpart_name=None, extra_params=None):
        data = {
            'name': name,
            'associatedDomainID': domain_id,
            'associatedDomainType': "DOMAIN"
        }
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)
        res_path = self.build_resource_path(
            constants.NET_PARTITION,
            resource_id=net_part[0]['ID'],
            child_resource=constants.APPLICATION)
        return self.post(res_path, data)

    def delete_application(self, app):
        return self.delete_resource(constants.APPLICATION, app, True)

    def create_tier(self, name, app_id, type, cidr=None,
                    externalId=None, extra_params=None):
        data = {
            'name': name,
            'type': type,
        }
        if type == 'STANDARD':
            net = netaddr.IPNetwork(cidr)
            data.update({'address': str(net.ip)})
            data.update({'netmask': str(net.netmask)})
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            constants.APPLICATION,
            resource_id=app_id,
            child_resource=constants.TIER)
        return self.post(res_path, data)

    def delete_tier(self, tier):
        return self.delete_resource(constants.TIER, tier, True)

    def create_flow(self, name, app_id, originTierID,
                    destinationTierID, extra_params=None):
        data = {
            'name': name,
            'originTierID': originTierID,
            'destinationTierID': destinationTierID
        }
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            constants.APPLICATION,
            resource_id=app_id,
            child_resource=constants.FLOW)
        return self.post(res_path, data)

    def delete_flow(self, flow):
        return self.delete_resource(constants.FLOW, flow, True)

    def create_service(self, name, netpart_name=None,
                       protocol=constants.PROTO_NAME_TO_NUM['tcp'],
                       etherType=constants.PROTO_NAME_TO_NUM['IPv4'],
                       direction='REFLEXIVE',
                       src_port='*', dscp='*',
                       dest_port='*',
                       extra_params=None):
        data = {
            'name': name,
            'description': direction,
            'sourcePort': src_port,
            'destinationPort': dest_port,
            'etherType': etherType,
            'DSCP': dscp,
            'protocol': protocol,
            'direction': direction,
        }
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)
        res_path = self.build_resource_path(
            constants.NET_PARTITION, net_part[0]['ID'],
            constants.SERVICE)
        return self.post(res_path, data)

    def delete_service(self, svc):
        return self.delete_resource(constants.SERVICE, svc, True)

    @staticmethod
    def get_vsd_external_id(neutron_id):
        if neutron_id and '@' not in neutron_id and CMS_ID:
            return neutron_id + '@' + CMS_ID
        return neutron_id
