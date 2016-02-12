from oslo_config import cfg

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
