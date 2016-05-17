# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

import copy
import functools
import inspect
import logging
import testtools

from tempest import config
from tempest import test
from nuagetempest.lib.test import tags as test_tags

CONF = config.CONF


def nuage_skip_because(*args, **kwargs):
    """A decorator useful to skip tests hitting known bugs

    @param bug: bug number causing the test to skip
    @param condition: optional condition to be True for the skip to have place
    @param interface: skip the test if it is the same as self._interface
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(self, *func_args, **func_kwargs):
            msg = "UNDEFINED"
            if "message" in kwargs:
                message = kwargs["message"]

                msg = "Skipped because: %s" % message
                if message.startswith("OPENSTACK_"):
                    uri = "http://mvjira.mv.usa.alcatel.com/browse/" + message
                    msg += "\n"
                    msg += uri

            raise testtools.TestCase.skipException(msg)
        return wrapper
    return decorator


def header(tags=None, since=None, until=None):
    """A decorator to log info on the test, add tags and release filtering.

    :param tags: A set of tags to tag the test with. header(tags=['smoke'])
    behaves the same as test.attr(type='smoke'). It exists for convenience.
    :param since: Optional. Mark a test with a 'since' release version to
    indicate this test should only run on setups with release >= since
    :param until: Optional. Mark a test with a 'until' release version to
    indicate this test should only run on setups with release < until
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(self, *func_args, **func_kwargs):

            logging.info("TESTCASE STARTED: %s" % f.func_code.co_name)

            # Dump the message + the name of this function to the log.
            logging.info("in %s:%i" % (
                f.func_code.co_filename,
                f.func_code.co_firstlineno
            ))

            result = f(self, *func_args, **func_kwargs)
            logging.info("TESTCASE COMPLETED: %s" % f.func_code.co_name)
            return result

        _add_tags_to_method(tags, wrapper)
        if since:
            wrapper._since = since
        if until:
            wrapper._until = until
        return wrapper
    return decorator


def _add_tags_to_method(tags, wrapper):
    if tags:
        if isinstance(tags, str):
            tags = {tags}
        else:
            tags = tags
        try:
            existing = copy.deepcopy(wrapper.__testtools_attrs)
            # deepcopy the original one, otherwise it will affect other
            # classes which extend this class.
            if test_tags.ML2 in tags and test_tags.MONOLITHIC in existing:
                existing.remove(test_tags.MONOLITHIC)
            if test_tags.MONOLITHIC in tags and test_tags.ML2 in existing:
                existing.remove(test_tags.ML2)
            existing.update(tags)
            wrapper.__testtools_attrs = existing
        except AttributeError:
            wrapper.__testtools_attrs = set(tags)


def class_header(tags=None, since=None, until=None):
    """Applies the header decorator to all test_ methods of this class.

    :param tags: Optional. A set of tags to tag the test with.
    header(tags=['smoke']) behaves the same as test.attr(type='smoke'). It
    exists for convenience.
    :param since: Optional. Mark a test with a 'since' release version to
    indicate this test should only run on setups with release >= since
    :param until: Optional. Mark a test with a 'until' release version to
    indicate this test should only run on setups with release < until
    """
    method_wrapper = header(tags=tags, since=since, until=until)

    def decorator(cls):
        for name, method in inspect.getmembers(cls, inspect.ismethod):
            if name.startswith('test_'):
                setattr(cls, name, method_wrapper(method))
        return cls
    return decorator


class NuageBaseTest(test.BaseTestCase):
    """
    """
    @classmethod
    def resource_setup(cls):
        super(NuageBaseTest, cls).resource_setup()
        if not CONF.service_available.neutron:
            raise cls.skipException("Neutron support is required")


