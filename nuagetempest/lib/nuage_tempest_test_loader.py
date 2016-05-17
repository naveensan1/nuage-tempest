import functools
import re
import os
import sys

from tempest import config

if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

CONF = config.CONF


def nuage_load_tests(loader, pattern, test_dir='nuagetempest/tests'):
    suite = unittest.TestSuite()
    base_path = os.path.split(os.path.dirname(os.path.abspath(__file__)))[0]
    base_path = os.path.split(base_path)[0]
    # Load local tempest tests
    full_test_dir = os.path.join(base_path, test_dir)
    if not pattern:
        suite.addTests(loader.discover(full_test_dir,
                                       top_level_dir=base_path))
    else:
        suite.addTests(loader.discover(full_test_dir, pattern=pattern,
                                       top_level_dir=base_path))
    _filter_suite_by_nuage_release(suite)
    return suite


def _filter_suite_by_nuage_release(suite):
    conf_release = CONF.nuage_sut.release
    current_release = Release(conf_release)
    for test_file in suite._tests:
        for test_class in test_file._tests:
            _filter_test_class_by_release(test_class, current_release)


def _filter_test_class_by_release(test_class, current_release):
    try:
        test_class._tests
    except AttributeError:
        return

    invalid = []
    for i, test in enumerate(test_class._tests):
        test_method = test._get_test_method()
        if getattr(test_method, "_since", False):
            since_release = Release(test_method._since)
            if since_release > current_release:
                invalid.append(i)
                continue
        if getattr(test_method, "_until", False):
            until_release = Release(test_method._until)
            if until_release <= current_release:
                invalid.append(i)

    for index in reversed(invalid):
        del test_class._tests[index]


@functools.total_ordering
class Release(object):
    release_regex = re.compile("((\d\.?)+)[\D]*(\d+)?")

    def __init__(self, release_string):
        self._parse_release(release_string)

    def _parse_release(self, release):
        parsed = Release.release_regex.search(release)
        if parsed is None:
            raise Exception("Can not parse release String '%s'" % release)
        self.major_release = parsed.group(1)
        self.sub_release = int(parsed.group(3)) if parsed.group(3) else None
        self.major_list = self.major_release.split(".")

    def __eq__(self, other):
        """ Compares self with another Release object.

        Releases are considered equal when the major part of the release is
        equal and the sub-release is equal. With 1 exception: if any of the sub
        releases is empty, two releases are still equal. Meaning 4.0R1 == 4.0
        evaluates to True.
        :param other: Release object to compare with
        :return: True when the releases are considered equal else False.
        """
        return (self.major_release == other.major_release and
                (self.sub_release is None or other.sub_release is None or
                 self.sub_release == other.sub_release))

    def __lt__(self, other):
        """ Compares self with another Release object to be 'less than'

        Major release is checked first, if equal, the sub releases are taken
        into account. 0.0 is an exception and 0.0 will always be greater than
        any other release (unless the other release is also 0.0).
        :param other: Release object to compare with
        :return: True when self is less than other..
        """
        comparison = cmp(other.major_list, self.major_list)
        if comparison > 0 and self.major_release != "0.0":
            return True
        if comparison == 0:
            return other.sub_release > self.sub_release
        return other.major_release == "0.0"
