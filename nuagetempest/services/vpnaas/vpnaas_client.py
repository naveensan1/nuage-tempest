from tempest.lib.common.utils import data_utils
from tempest import test
from tempest import config
from tempest.api.network import base
from nuagetempest.services.bgpvpn.bgpvpn_client import BaseNeutronResourceClient

CONF = config.CONF


class IKEPolicyClient(BaseNeutronResourceClient):

    """
    CRUD Operations for IKEPolicy
    """

    def __init__(self, auth_provider):
        super(IKEPolicyClient, self).__init__(auth_provider, 'ikepolicie',
                                           path_prefix='vpn')

    def create_ikepolicy(self, **kwargs):
        return super(IKEPolicyClient, name, self).create(**kwargs)

    def show_ikepolicy(self, id, fields=None):
        return super(IKEPolicyClient, self).show(id, fields)

    def list_ikepolicy(self, **filters):
        return super(IKEPolicyClient, self).list(**filters)

    def update_ikepolicy(self, id, **kwargs):
        return super(IKEPolicyClient, self).update(id, **kwargs)

    def delete_ikepolicy(self, id):
        super(IKEPolicyClient, self).delete(id)

class IPSecPolicyClient(BaseNeutronResourceClient):

    """
    CRUD Operations for IPSecPolicy
    """

    def __init__(self, auth_provider):
        super(IPSecPolicyClient, self).__init__(auth_provider, 'ipsecpolicie',
                                           path_prefix='vpn')

    def create_ipsecpolicy(self, name, **kwargs):
        return super(IPSecPolicyClient, name, self).create(**kwargs)

    def show_ipsecpolicy(self, id, fields=None):
        return super(IPSecPolicyClient, self).show(id, fields)

    def list_ipsecpolicy(self, **filters):
        return super(IPSecPolicyClient, self).list(**filters)

    def update_ipsecpolicy(self, id, **kwargs):
        return super(IPSecPolicyClient, self).update(id, **kwargs)

    def delete_ipsecpolicy(self, id):
        super(IPSecPolicyClient, self).delete(id)

class VPNServiceClient(BaseNeutronResourceClient):

    """
    CRUD Operations for VPNService
    """

    def __init__(self, auth_provider):
        super(VPNServiceClient, self).__init__(auth_provider, 'vpnservice',
                                           path_prefix='vpn')

    def create_vpnservice(self, router_id, subnet_id, **kwargs):
        return super(VPNServiceClient, self).create(**kwargs)

    def show_vpnservice(self, id, fields=None):
        return super(VPNServiceClient, self).show(id, fields)

    def list_vpnservice(self, **filters):
        return super(VPNServiceClient, self).list(**filters)

    def update_vpnservice(self, id, **kwargs):
        return super(VPNServiceClient, self).update(id, **kwargs)

    def delete_vpnservice(self, id):
        super(VPNServiceClient, self).delete(id)


class IPSecSiteConnectionClient(BaseNeutronResourceClient):

    """
    CRUD Operations for IPSecSiteConnection
    """

    def __init__(self, auth_provider):
        super(IPSecSiteConnectionClient, self).__init__(auth_provider, 'ipsec-site-connection',
                                           path_prefix='vpn')

    def create_ipsecsiteconnection(self, vpnservice_id, ikepolicy_id,
                                  ipsecpolicy_id, peer_address, peer_id,
                                  peer_cidrs, psk, **kwargs):
        return super(IPSecSiteConnectionClient, self).create(**kwargs)

    def show_ipsecsiteconnection(self, id, fields=None):
        return super(IPSecSiteConnectionClient, self).show(id, fields)

    def list_ipsecsiteconnection(self, **filters):
        return super(IPSecSiteConnectionClient, self).list(**filters)

    def update_ipsecsiteconnection(self, id, **kwargs):
        return super(IPSecSiteConnectionClient, self).update(id, **kwargs)

    def delete_ipsecsiteconnection(self, id):
        super(IPSecSiteConnectionClient, self).delete(id)

