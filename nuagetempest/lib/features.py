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

from tempest import config
from nuagetempest.lib.nuage_tempest_test_loader import Release

CONF = config.CONF


# this should never be called outside of this class
class NuageFeatures(object):
    """Provides information on supported features per release."""

    def _set_features(self):
        if self.current_release.major_release == "3.2":
            self.bidrectional_fip_rate_limit = self.current_release >= Release('3.2R10')
        else:
            self.full_external_id_support = self.current_release >= Release('4.0R5')
            self.bidrectional_fip_rate_limit = self.current_release >= Release('4.0R6')

    def __init__(self):
        """Initialize a feature set"""
        super(NuageFeatures, self).__init__()

        self.current_release = Release(CONF.nuage_sut.release)

        self.full_external_id_support = False
        self.bidrectional_fip_rate_limit = False

        self._set_features()

NUAGE_FEATURES = NuageFeatures()