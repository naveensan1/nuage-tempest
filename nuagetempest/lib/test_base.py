import time
import re
import logging
from nuagetempest.tests import conf

LOG = logging.getLogger(__name__)

def get_external_id(id):
    return (id + '@' + conf.nuage.nuage_cms_id) \
        if conf.nuage.nuage_cms_id else id

def get_filter_str(key, value):
    return key + '  == "{}"'.format(value)
