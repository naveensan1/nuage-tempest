# VSD RESOURCE URI, not a complete list.
# list of resources currently used by nuage plugin

# GATEWAY
GATEWAY = 'gateways'
REDCY_GRP = 'redundancygroups'
GATEWAY_VSG_REDCY_PORT = 'vsgredundantports'
GATEWAY_PORT = 'ports'
VLAN = 'vlans'
ENTERPRISE_PERMS = 'enterprisepermissions'
NUMBER_OF_PORTS_PER_GATEWAY = 2
NUMBER_OF_VLANS_PER_PORT = 2
START_VLAN_VALUE = 100

# NETWORK
DHCPOPTION = 'dhcpoptions'
DOMAIN = 'domains'
DOMAIN_TEMPLATE = 'domaintemplates'
ENTERPRISE_NET_MACRO = 'enterprisenetworks'
FLOATINGIP = 'floatingips'
L2_DOMAIN = 'l2domains'
L2_DOMAIN_TEMPLATE = 'l2domaintemplates'
PUBLIC_NET_MACRO = 'publicnetworks'
SHARED_NET_RES = 'sharednetworkresources'
STATIC_ROUTE = 'staticroutes'
SUBNETWORK = 'subnets'
SUBNET_TEMPLATE = 'subnettemplates'
ZONE = 'zones'
ZONE_TEMPLATE = 'zonetemplates'

# POLICY
EGRESS_ACL_TEMPLATE = 'egressacltemplates'
EGRESS_ACL_ENTRY_TEMPLATE = 'egressaclentrytemplates'
INGRESS_ACL_TEMPLATE = 'ingressacltemplates'
INGRESS_ACL_ENTRY_TEMPLATE = 'ingressaclentrytemplates'
INGRESS_ADV_FWD_ENTRY_TEMPLATE = 'ingressadvfwdentrytemplates'
INGRESS_ADV_FWD_TEMPLATE = 'ingressadvfwdtemplates'

# USER MANAGEMENT
NET_PARTITION = 'enterprises'
USER = 'users'
GROUP = 'groups'
PERMIT_ACTION = 'permissions'

# VM
VM_IFACE = 'vminterfaces'
VM = 'vms'

# VPORT
BRIDGE_IFACE = 'bridgeinterfaces'
HOST_IFACE = 'hostinterfaces'
POLICYGROUP = 'policygroups'
VPORT = 'vports'
VIRTUAL_IP = 'virtualips'
REDIRECTIONTARGETS = 'redirectiontargets'

# GATEWAY
GATEWAY = 'gateways'

# Quality of Service
QOS = 'qos'

ENABLED = 'ENABLED'
DISABLED = 'DISABLED'
INHERITED = 'INHERITED'

# CIDR_TO_NETMASK
CIDR_TO_NETMASK = {
    '8': '255.0.0.0',
    '16': '255.255.0.0',
    '24': '255.255.255.0',
    '32': '255.255.255.0'
}


PROTO_NAME_TO_NUM = {
    'tcp': u'6',
    'udp': u'17',
    'icmp': u'1',
    'IPv4': u'0x0800'
}

# Application Designer
APPLICATION_DOMAIN = 'application-domains'
APPLICATION = 'applications'
TIER = 'tiers'
FLOW = 'flows'
SERVICE = 'applicationservices'

# GATEWAYPERSONALITY
PERSONALITY_LIST = ['VRSG', 'VSG']

# Vport type
HOST_VPORT = 'HOST'
BRIDGE_VPORT = 'BRIDGE'
