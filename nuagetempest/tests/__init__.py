#from oslo_log import log as logging
import unittest
#from nuagetempest.lib import nuage_ext
#from nuagetempest.lib import nuage_tempest_test_loader
#from nuagetempest.lib import topology
#import re
#import traceback
#from tempest import config

#conf = config.CONF
#LOG = logging.getLogger(__name__)

import inspect

#def setUpModule():
    #print "inside setupModule"
#    LOG.debug(("in setupmodule look here"))


def setup_package():
    print(__name__, '__init__.py : setup_package() ========================================')

def teardown_package():
    print(__name__, '__init__.py : teardown_package() ========================================')
