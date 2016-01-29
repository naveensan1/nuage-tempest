import os

from tempest import config
from tempest.test_discover import plugins
from nuagetempest import config as config_share


class NuageTempestPlugin(plugins.TempestPlugin):
    def get_opt_lists(self):
        return [(
            config_share.third_party_verification.vendor,
            config_share.thirdPartyVerificationGroup)]

    def load_tests(self):
        base_path = os.path.split(os.path.dirname(
            os.path.abspath(__file__)))[0]
        test_dir = "nuagetempest/tests"
        full_test_dir = os.path.join(base_path, test_dir)
        return full_test_dir, base_path

    def register_opts(self, conf):
        config.register_opt_group(
            conf,
            config_share.third_party_verification,
            config_share.thirdPartyVerificationGroup)
