# Copyright 2013 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import logging
import os
from tempest import config

CONF = config.CONF
LOG = logging.getLogger(__name__)


class CLIClient(object):
    """Class to use OpenStack official python client CLI's with auth
    :param username: The username to authenticate with
    :type username: string
    :param password: The password to authenticate with
    :type password: string
    :param tenant_name: The name of the tenant to use with the client calls
    :type tenant_name: string
    :param uri: The auth uri for the OpenStack Deployment
    :type uri: string
    """

    def __init__(self, osc, username='', password='', tenant_name='', uri=''):
        """Initialize a new CLIClient object."""
        super(CLIClient, self).__init__()
        self.username = username
        self.tenant_name = tenant_name
        self.password = password
        self.uri = uri
        self.osc = osc

    def nova(self, action, flags='', params='', fail_ok=False,
             endpoint_type='publicURL'):
        """Executes nova command for the given action.
        :param action: the cli command to run using nova
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        """
        flags += ' --endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'nova', action, flags, params, fail_ok)

    def nova_manage(self, action, flags='', params='', fail_ok=False, timeout=20):
        """Executes nova-manage command for the given action.
        :param action: the cli command to run using nova-manage
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        """
        creds = ('--os-username %s --os-tenant-name %s --os-password %s '
                 '--os-auth-url %s' %
                 (self.username,
                  self.tenant_name,
                  self.password,
                  self.uri))
        flags = creds + ' ' + flags
        cmd = 'nova-manage'
        cmd = ' '.join([os.path.join(cmd),
                        flags, action, params])
        if fail_ok:
            response = self.osc.cmd(cmd, strict=False, timeout=timeout)
            assert response[2] == 1
            return response[1]
        response = self.osc.cmd(cmd, timeout=timeout)
        response = response[0]
        resp = ''
        for line in response:
            resp = resp + line + '\n'
        return resp

    def keystone(self, action, flags='', params='', fail_ok=False):
        """Executes keystone command for the given action.
        :param action: the cli command to run using keystone
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        """
        return self.cmd_with_auth(
            'keystone', action, flags, params, fail_ok)

    def glance(self, action, flags='', params='', fail_ok=False,
               endpoint_type='publicURL', merge_stderr=False):
        """Executes glance command for the given action.
        :param action: the cli command to run using glance
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        """
        flags += ' --os-endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'glance', action, flags, params, fail_ok)

    def ceilometer(self, action, flags='', params='',
                   fail_ok=False, endpoint_type='publicURL',
                   merge_stderr=False):
        """Executes ceilometer command for the given action.
        :param action: the cli command to run using ceilometer
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        """
        flags += ' --os-endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'ceilometer', action, flags, params, fail_ok)

    def heat(self, action, flags='', params='',
             fail_ok=False, endpoint_type='publicURL'):
        """Executes heat command for the given action.
        :param action: the cli command to run using heat
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        """
        flags += ' --os-endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'heat', action, flags, params, fail_ok)

    def cinder(self, action, flags='', params='', fail_ok=False,
               endpoint_type='publicURL'):
        """Executes cinder command for the given action.
        :param action: the cli command to run using cinder
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        """
        flags += ' --endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'cinder', action, flags, params, fail_ok)

    def swift(self, action, flags='', params='', fail_ok=False,
              endpoint_type='publicURL'):
        """Executes swift command for the given action.
        :param action: the cli command to run using swift
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        """
        flags += ' --os-endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'swift', action, flags, params, fail_ok)

    def neutron(self, action, flags='', params='', fail_ok=False,
                endpoint_type='publicURL'):
        """Executes neutron command for the given action.
        :param action: the cli command to run using neutron
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        """
        flags += ' --endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'neutron', action, flags, params, fail_ok)

    def sahara(self, action, flags='', params='',
               fail_ok=False, endpoint_type='publicURL'):
        """Executes sahara command for the given action.
        :param action: the cli command to run using sahara
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        """
        flags += ' --endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'sahara', action, flags, params, fail_ok)

    def openstack(self, action, flags='', params='', fail_ok=False,
                  merge_stderr=False):
        """Executes openstack command for the given action.
        :param action: the cli command to run using openstack
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        """
        return self.cmd_with_auth(
            'openstack', action, flags, params, fail_ok)

    def cmd_with_auth(self, cmd, action, flags='', params='',
                      fail_ok=False, timeout=20):
        """Executes given command with auth attributes appended.
        :param cmd: command to be executed
        :type cmd: string
        :param action: command on cli to run
        :type action: string
        :param flags: optional cli flags to use
        :type flags: string
        :param params: optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the cli return
                        code is non-zero
        :type fail_ok: boolean
        """
        creds = ('--os-username %s --os-tenant-name %s --os-password %s '
                 '--os-auth-url %s' %
                 (self.username,
                  self.tenant_name,
                  self.password,
                  self.uri))
        flags = creds + ' ' + flags
        # return execute(cmd, action, flags, params, fail_ok, merge_stderr,
        #                self.cli_dir)
        cmd = ' '.join([os.path.join(cmd),
                        flags, action, params])
        LOG.debug("running: '%s'" % cmd)
        if fail_ok:
            response = self.osc.cmd(cmd, strict=False, timeout=timeout)
            assert response[2] == 1
            return response[1]
        response = self.osc.cmd(cmd, timeout=timeout)
        response = response[0]
        resp = ''
        for line in response:
            resp = resp + line + '\n'
        return resp
