# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.
#

import time
import urlparse
from tempest import config
from oslo_log import log as logging
from tempest_lib.common import ssh as ssh
from lib.utils import constants as constants
from tempest_lib import exceptions


CONF = config.CONF

LOG = logging.getLogger(__name__)


class ServiceManager():
    def __init__(self):
        self.service_start_cmd = constants.NEUTRON_KILODEVSTACK_UBUNTU_START_CMD

        if CONF.nuage_sut.controller_service_management_mode == "ubuntu":
            self.service_start_cmd = constants.NEUTRON_KILO_UBUNTU_START_CMD
            self.service_stop_cmd = constants.NEUTRON_KILO_UBUNTU_STOP_CMD

        pass

    @staticmethod
    def execute(cmd):

        """Executes specified command for the given action."""
        LOG.info("Executing: '%s" % cmd)

        ssh_timeout = 10
        ssh_channel_timeout = 10

        # TODO: derive from tempest.conf or nuage.conf
        uri = CONF.identity.uri

        uri_object = urlparse.urlparse(uri)
        netloc_parts = uri_object.netloc.rsplit(':')
        ip_address = netloc_parts[0]

        username = CONF.nuage_sut.controller_user
        password = CONF.nuage_sut.controller_password

        ssh_client = ssh.Client(ip_address, username, password,
                                ssh_timeout,
                                channel_timeout=ssh_channel_timeout)

        response = ssh_client.exec_command(cmd)
        LOG.debug("Response: \n'%s'" % response)

        return response

    def wait_for_service_status(self, service):
        start = time.time()
        timeout = 30.0

        while not self.is_service_running(service):
            time.sleep(5)

            if time.time() - start >= timeout:
                message = "Timeout when waiting for service"
                raise exceptions.TimeoutException(message)

    def start_service(self, service):
        """Starts the service

        :param service:
        """
        # TODO: This works only for neutron devstack
        # start_cmd = "nohup python /usr/local/bin/neutron-server " + \
        #             "--config-file /etc/neutron/neutron.conf " + \
        #             "--config-file /etc/neutron/plugins/nuage/nuage_plugin.ini " + \
        #             "--logfile /var/log/neutron/server.log " + \
        #             " > foo.out 2> foo.err < /dev/null &"

        # TODO: This works only for neutron kilo ubuntu1404
        # start_cmd = "service neutron-server restart"
        pid_cmd = "sudo ps ax | grep neutron-server | grep -v grep | awk '{print $1}'"

        self.execute(self.service_start_cmd)
        response = self.execute(pid_cmd)
        pid = response.rstrip('\n')
        LOG.debug("Started service '" + service + "' with PID " + pid)

        # TODO: test for successful start
        time.sleep(3)

    def is_service_running(self, service):
        is_running = False
        response = self.execute("sudo ps ax | grep '" + service + "' | grep -v grep | awk '{print $1}'")
        response = response.rstrip('\n')

        LOG.debug("Service '" + service + "' running with PID " + response)

        pids = response.split('\n')
        if len(response) > 0 and (len(pids) >= 1):
            is_running = True

            # TODO: having a PID is not enough, the service must be completely started!
            # Replace sleep with something better.
            time.sleep(2)

        return is_running

    def stop_service(self, service):
        response = self.execute("sudo ps ax | grep '" + service + "' | grep -v grep | awk '{print $1}'")
        response = response.rstrip('\n')
        pids = response.split('\n')

        LOG.debug("Stopping service " + service)
        if CONF.nuage_sut.controller_service_management_mode == "ubuntu":
            self.execute(self.service_stop_cmd)
        else:
            if len(response) > 0 and (len(pids) >= 1):
                for pid in pids:
                    LOG.debug("Stopping service '" + service + "' with PID " + pid)
                    try:
                        self.execute("sudo kill -9 " + pid)
                    except (exceptions.SSHExecCommandFailed) as e:
                        LOG.debug("Failed to kill process %s.Exception %s", pid, e)

            else:
                LOG.debug("No process found for service '" + service + "'")

    def get_configuration_attribute(self, config_file, config_group, config_key):
        if CONF.nuage_sut.controller_service_management_mode == "ubuntu":
            cmd = "source functions-common.sh; iniget " + config_file + ' ' + config_group + ' ' + config_key
            response = self.execute(cmd)
            response = response.rstrip('\n')
        else:
            try:
                cmd = "sudo crudini --get " + config_file + ' ' + config_group + ' ' + config_key
                response = self.execute(cmd)
                response = response.rstrip('\n')
            except (exceptions.SSHExecCommandFailed) as e:
                LOG.debug("Exception %s", e)
                response = ""

        return response

    def set_configuration_attribute(self, config_file, config_group, config_key, value):
        if CONF.nuage_sut.controller_service_management_mode == "ubuntu":
            cmd = "source functions-common.sh; iniset " + config_file + ' ' + config_group + ' ' + config_key + ' ' + value
        else:
            cmd = "sudo crudini --set " + config_file + ' ' + config_group + ' ' + config_key + ' ' + value

        response = self.execute(cmd)
        response = self.get_configuration_attribute(config_file, config_group, config_key)

        return response

    def comment_configuration_attribute(self, config_file, config_group, config_key):
        if CONF.nuage_sut.controller_service_management_mode == "ubuntu":
            cmd = "source functions-common.sh; inicomment " + config_file + ' ' + config_group + ' ' + config_key
        else:
            cmd = "sudo crudini --del " + config_file + ' ' + config_group + ' ' + config_key

        response = self.execute(cmd)
        response = response.rstrip('\n')

        return response

    def must_have_configuration_attribute(self, config_file, config_group, config_key, value):
        # Todo: add caching mechanism to remember the last read value, avoiding to fetch it from the system
        original_value = self.get_configuration_attribute(config_file, config_group, config_key)
        LOG.info("must_have_configuration_attribute expect " + config_group + ":" + config_key + "value = "
                 + str(value) + " while .in. file contains " + original_value + " .")
        # A "non-present" value is returned as empty string: convert to None
        if original_value == '':
            original_value = None
            LOG.info("Changed original_value into : " + str(original_value))
        # Watch out: convert to string to have a decent comparison
        if str(original_value) != str(value):

            self.stop_service(constants.NEUTRON_SERVICE)
            if value is None:
                self.comment_configuration_attribute(config_file, config_group, config_key)
            else:
                self.set_configuration_attribute(config_file, config_group, config_key, str(value))

            self.start_service(constants.NEUTRON_SERVICE)
            self.wait_for_service_status(constants.NEUTRON_SERVICE)

