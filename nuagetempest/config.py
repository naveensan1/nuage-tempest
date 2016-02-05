from oslo_config import cfg

nuage_tempest_group = cfg.OptGroup(name='nuagext',
                               title='Nuage Tempest config options')

NuageTempestGroup = [
    cfg.ListOpt('nuage_components',
               default=['vsd'],
               help="VSD/VSC/VRS"),
    cfg.StrOpt('nuage_ext_mode',
               default='api',
               help="api/scenario"
               )
]
