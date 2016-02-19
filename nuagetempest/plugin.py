import os

from tempest import config
from tempest.test_discover import plugins
from nuagetempest import config as project_config


class NuageTempestPlugin(plugins.TempestPlugin):
    def get_opt_lists(self):
        return [(project_config.nuage_tempest_group.name,
                 project_config.NuageTempestGroup),
                (project_config.nuage_sut_group.name,
                 project_config.NuageSutGroup),
                (project_config.nuage_vsd_group.name,
                 project_config.NuageVsdGroup)]

    def load_tests(self):
        base_path = os.path.split(os.path.dirname(
            os.path.abspath(__file__)))[0]
        test_dir = "nuagetempest/tests"
        full_test_dir = os.path.join(base_path, test_dir)
        return full_test_dir, base_path

    def register_opts(self, conf):
        config.register_opt_group(
            conf, project_config.nuage_vsd_group,
            project_config.NuageVsdGroup)
        config.register_opt_group(
            conf, project_config.nuage_tempest_group,
            project_config.NuageTempestGroup)
        config.register_opt_group(
            conf, project_config.nuage_sut_group,
            project_config.NuageSutGroup)
