from oslo_config import cfg


NuageVsdGroup = [
    cfg.StrOpt('nuage_vsd_server',
               default="",
               help="Nuage vsd server"),
    cfg.StrOpt('nuage_default_netpartition',
               default="",
               help="default nuage netpartition name"),
    cfg.StrOpt('nuage_auth_resource',
               default="/me",
               help="api path to authenticate for nuage vsd"),
    cfg.StrOpt('nuage_base_uri',
               default="/nuage/api/v3_0",
               help="base nuage vsd api url"),
    cfg.StrOpt('nuage_vsd_user',
               default='csproot',
               help="nuage vsd user"),
    cfg.StrOpt('nuage_vsd_password',
               default='csproot',
               help='nuage vsd user password'),
    cfg.StrOpt('nuage_vsd_org',
               default='csp',
               help='nuage vsd organization name'),
    cfg.StrOpt('nuage_cms_id', default=None,
               help=('ID of a Cloud Management System on the VSD which '
                     'identifies this OpenStack instance'))
]

nuage_vsd_group = cfg.OptGroup(name='nuage',
                               title='Nuage VSD config options')

nuage_tempest_group = cfg.OptGroup(name='nuagext',
                                   title='Nuage Tempest config options')

NuageTempestGroup = [
    cfg.ListOpt('nuage_components',
                default=['vsd'],
                help="VSD/VSC/VRS"),
    cfg.StrOpt('nuage_ext_mode',
               default='api',
               help="api/scenario"),
    cfg.StrOpt('topologyfile',
               default='',
               help="Full path of topology file"),
    cfg.StrOpt('exec_server_user',
               default='',
               help="User name of execution server"),
    cfg.StrOpt('exec_server',
               default='',
               help="Host name of execution server")
]

nuage_sut_group = cfg.OptGroup(name='nuage_sut',
                               title='Nuage SUT config options')

NuageSutGroup = [
    cfg.StrOpt('nuage_plugin_configuration',
               default='/etc/neutron/plugins/nuage/plugin.ini',
               help="Full path for the Nuage plugin configuration file."),
    cfg.StrOpt('openstack_version',
               default='kilo',
               choices=['kilo', 'liberty', 'mitaka'],
               help="The mode for controlling services on controller node."),
    cfg.StrOpt('nuage_plugin_mode',
               default='monolytic',
               choices=['monolytic', 'ml2'],
               help="The mode for controlling services on controller node."),
    cfg.StrOpt('controller_service_management_mode',
               default='devstack',
               choices=['devstack', 'ubuntu', 'rhel'],
               help="The mode for controlling services on controller node."),
    cfg.StrOpt('controller_user',
               default='root',
               help="sudo user on controller node"),
    cfg.StrOpt('controller_password',
               default='password',
               help='password for controller_user')
]
