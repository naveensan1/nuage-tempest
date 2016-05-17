from nuagetempest.lib import nuage_tempest_test_loader


def load_tests(loader, tests, pattern):
    return nuage_tempest_test_loader.nuage_load_tests(
        loader, pattern, 'nuagetempest/thirdparty')

