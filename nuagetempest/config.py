from oslo_config import cfg
from tempest import config

third_party_verification = cfg.OptGroup(name='thirdpartyvendor',
                                        title="Third Party vendor verification")

thirdPartyVerificationGroup = [
    cfg.StrOpt('vendor',
               default="",
               help="name of vendor/plugin"),
    cfg.ListOpt('components',
               default="",
               help="name of all vendor components"),
    cfg.StrOpt('verification_mode',
               default="loose",
               help="Mode of verification strict or loose")
]
