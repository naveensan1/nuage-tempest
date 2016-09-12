# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
from oslo_log import log as logging
from tempest.lib import exceptions

import tempest.test
from tempest import config
from nuagetempest.lib.nuage_tempest_test_loader import Release
import upgrade_external_id_with_cms_id as upgrade_script


CONF = config.CONF
LOG = logging.getLogger(__name__)


class UpgradeScriptTest(tempest.test.BaseTestCase):
    test_upgrade = False

    def test_upgrade_script_external_id(self):
        conf_release = CONF.nuage_sut.release
        current_release = Release(conf_release)

        LOG.debug("Release %s", current_release)

        script_cmd = upgrade_script.SCRIPT_PATH + upgrade_script.SET_EXTERNAL_ID_UPGRADE_SCRIPT
        script_args = "--config-file /etc/neutron/neutron.conf /etc/neutron/plugin.ini"

        try:
            response = upgrade_script.execute("python -c 'import sys; print sys.path'")
            self.assertNotEmpty(response)
        except exceptions.SSHExecCommandFailed as e:
            LOG.debug("Failed. Exception %s", e)

        try:
            response = upgrade_script.execute("python " + script_cmd + " " + script_args)
            self.assertNotEmpty(response)
        except exceptions.SSHExecCommandFailed as e:
            LOG.debug("Failed. Exception %s", e)
            raise e


