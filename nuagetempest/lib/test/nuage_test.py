# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

import functools
import testtools

from tempest import config
from tempest import test
import logging

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


def header(*args, **kwargs):
    """A decorator useful to log info on the test

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
        return wrapper
    return decorator


class NuageBaseTest(test.BaseTestCase):
    """
    """
    @classmethod
    def resource_setup(cls):
        super(NuageBaseTest, cls).resource_setup()
        if not CONF.service_available.neutron:
            raise cls.skipException("Neutron support is required")


