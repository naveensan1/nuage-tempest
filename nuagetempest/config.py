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
    cfg.StrOpt('esr_calls_file',
                default='',
                help="Full path of esrcalls file"),
    cfg.StrOpt('exec_server_user',
                default='',
                help="User name of execution server"),
    cfg.StrOpt('exec_server',
                default='',
                help="Host name of execution server")
]
