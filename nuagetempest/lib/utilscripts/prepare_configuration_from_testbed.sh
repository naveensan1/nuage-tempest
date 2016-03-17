#!/bin/bash

source ini-config.sh

TESTBED=
CONTROLLER_IP=
PUBLIC_NETWORK_UUID=
IMAGE_UUID=
PASSWORD=tigris
PUBLIC_CIDR=
PUBLIC_START=
PUBLIC_END=
# Assume devstack based testbed
OSC="osc-1"
OS=devstack
TEMPEST_CONFIG_PATH=$PWD

for i in "$@"
do
#echo $i

case ${i} in

    -p=*|--password=*)
    PASSWORD="${i#*=}"
    shift # past argument=value
    ;;
    -c=*|--tempest-config=*)
    TEMPEST_CONFIG_PATH="${i#*=}"
    shift # past argument=value
    ;;
    -osc=*)
    OSC="${i#*=}"
    shift # past argument=value
    ;;
    *)
    # unknown option
      TESTBED=${i}
    ;;
esac
done

function showHelp () {
    echo "Prepares tempest.conf with actual data from a Nuage Testbed"
    echo "prepare_configuration_from_testbed <testbed name> -p=<password> -c=<config>"

}

if [ -z "$TESTBED" ]; then
    echo "ERROR: Testbed not defined"
    showHelp
    exit
fi

if [ -z "$PASSWORD" ]; then
    echo "ERROR: Password not defined"
    showHelp
    exit
fi


########################################################################################################################
# Shortcut function to get a newly generated ID

function execControllerTestOnly () {
    echo "Executing on OpenStack Controller"

    CONTROLLER_IP=`sshpass -p ${PASSWORD} ssh -oStrictHostKeyChecking=no root@${TESTBED_FULL} grep ${OSC} /${TESTBED}/images/esrcalls.tcl | awk '{print $3}'`
    echo "Controller IP" ${CONTROLLER_IP}
}

function execTestbed () {
    _COMMAND=$1

    OUTPUT=`sshpass -p "$PASSWORD" ssh -oStrictHostKeyChecking=no root@${TESTBED_FULL} ${_COMMAND}`

    echo "$OUTPUT";
}

function execController () {
    _COMMAND=$1
    OUTPUT=`sshpass -p "$PASSWORD" ssh -oStrictHostKeyChecking=no root@${CONTROLLER_IP} ${_COMMAND}`
    echo "$OUTPUT";
}

function getControllerIP () {
    CONTROLLER_IP=`execTestbed "grep $OSC /$TESTBED/images/esrcalls.tcl | awk '{print \\$3}'"`
    echo "$CONTROLLER_IP"
}

function createPublicNetwork() {
    _PUBLIC_NETWORK_UUID=`execController "$SOURCE_CMD; neutron net-show public | grep ' id ' | awk '{print \\$4}'"`

    # Temporary patch till we agree on having a separate classC address per testbed.
    # For now some arbitrary, non-overlapping allocation pools to avoid conflicts with FIP's
    case $TESTBED in
    andcvtb01)
        PUBLIC_CIDR=10.30.32.0/24
        PUBLIC_START=10.30.32.160
        PUBLIC_END=10.30.32.199
        ;;
    andcvtb02)
        PUBLIC_CIDR=10.30.33.0/24
        PUBLIC_START=10.30.33.160
        PUBLIC_END=10.30.33.199
        ;;
    andcvtb03)
        PUBLIC_CIDR=10.30.34.0/24
        PUBLIC_START=10.30.34.160
        PUBLIC_END=10.30.34.199
        ;;
    andcdev01)
        PUBLIC_CIDR=10.30.33.0/24
        PUBLIC_START=10.30.33.200
        PUBLIC_END=10.30.33.239
        ;;
    andcdev02)
        PUBLIC_CIDR=10.30.32.0/24
        PUBLIC_START=10.30.32.200
        PUBLIC_END=10.30.32.239
        ;;
    andcdev03)
        PUBLIC_CIDR=10.30.34.0/24
        PUBLIC_START=10.30.34.200
        PUBLIC_END=10.30.34.239
        ;;
    andce2e01)
        PUBLIC_CIDR=10.30.35.0/24
        PUBLIC_START=10.30.35.200
        PUBLIC_END=10.30.35.240
        ;;
    andce2e01)
        PUBLIC_CIDR=10.30.36.0/24
        PUBLIC_START=10.30.36.200
        PUBLIC_END=10.30.36.240
        ;;
    esac

    if [ -z "$_PUBLIC_NETWORK_UUID" ]; then
        _PUBLIC_NETWORK_UUID=`execController "$SOURCE_CMD; neutron net-create public --router:external  --shared | grep ' id ' | awk '{print \\$4}'"`

        if [ $OS == 'icehouse' ]; then
            # FOR RHEL7 ICEHOUSE : underlay only available from kilo onwards
            execController "$SOURCE_CMD; neutron subnet-create public $PUBLIC_CIDR --allocation-pool start=$PUBLIC_START,end=$PUBLIC_END --name public-subnet >> /dev/null"
        elif [ $OS == 'juno' ]; then
            execController "$SOURCE_CMD; neutron subnet-create public $PUBLIC_CIDR --allocation-pool start=$PUBLIC_START,end=$PUBLIC_END --name public-subnet >> /dev/null"
        else
            # for kilo and beyond
            execController "$SOURCE_CMD; neutron subnet-create public $PUBLIC_CIDR --allocation-pool start=$PUBLIC_START,end=$PUBLIC_END --name public-subnet --underlay=True>> /dev/null"
        fi
    fi

    echo "$_PUBLIC_NETWORK_UUID"
}

function updateEndpoints() {
    if [ $OSC == 'osc-1' ]; then
        LOCAL_IP=10.100.100.20
    else
        LOCAL_IP=10.100.100.21
    fi
    execController "mysql -uroot -p$PASSWORD -D keystone -e \"update endpoint set url=REPLACE(url,'$LOCAL_IP','$CONTROLLER_IP') where interface='public';\""

    # TODO: Requires binding 0.0.0.0 in /etc/keystone/keystone.conf at section [eventlet_server] admin_bind_host = 0.0.0.0
    execController "mysql -uroot -p$PASSWORD -D keystone -e \"update endpoint set url=REPLACE(url,'$LOCAL_IP','$CONTROLLER_IP') where interface='admin';\""
    #execController "mysql -uroot -p$PASSWORD -D keystone -e \"update endpoint set url=REPLACE(url,'$CONTROLLER_IP','10.100.100.20') where interface='admin';\""
}

function getImage() {
    # FOR openstackKiloUbuntu
    # _IMAGE_UUID=`execController "$SOURCE_CMD; glance image-show cirros  | grep ' id ' | awk '{print \\$4}'"`

    # FOR openstackKiloDevStack
    # _IMAGE_UUID=`execController "$SOURCE_CMD; glance image-show cirros-0.3.4-x86_64-uec  | grep ' id ' | awk '{print \\$4}'"`

    # FOR Ubuntu/RHEL7 ICEHOUSE
    _IMAGE_UUID=`execController "$SOURCE_CMD; glance image-list | grep 'cirros' | awk '{print \\$2}'"`

    echo "$_IMAGE_UUID"
}

function get_id () {
    echo `$@ | awk '/ id / { print $4 }'`
}

# DEPRECATED
function createDemoUser2() {
    # Users

    _DEMO_USER=`execController "$SOURCE_CMD; openstack user show demo -c id | awk '/ id / {print \\$4}'"`

    if [ -z $_DEMO_USER ]
        then
            DEMO_USER=`execController "$SOURCE_CMD; openstack user create demo --password tigris -c id | awk '/ id / {print \\$4}'"`;
            echo ${_DEMO_USER}
    fi

    # Tenants
    _DEMO_TENANT=`execController "$SOURCE_CMD; openstack project show demo | awk '/ id / {print \\$4}'"`

    if [ -z $_DEMO_TENANT ]
        then
            $_DEMO_TENANT=`execController "$SOURCE_CMD; openstack project create demo -c id | awk '/ id / {print \\$4}'"`;
            echo ${_DEMO_TENANT}
    fi

    # Role
    _DEMO_ROLE=`execController "$SOURCE_CMD; keystone role-get _member_ |  awk '/ id / {print \\$4}'"`

    if [ -z $_DEMO_ROLE ]
        then
            _DEMO_ROLE=`execController "$SOURCE_CMD; keystone user-role-add --user=demo --role=_member_ --tenant=demo | awk '/ id / {print \\$4}'"`;
            echo ${__DEMO_ROLE}
    fi

    echo "User: $_DEMO_USER for tenant $_DEMO_TENANT with role $_DEMO_ROLE"
}

function createDemoUser() {
    # Tenants
    _DEMO_TENANT=`execController "$SOURCE_CMD; keystone tenant-get demo | awk '/ id / {print \\$4}'"`
    if [ -z $_DEMO_TENANT ]
        then
            _DEMO_TENANT=`execController "$SOURCE_CMD; keystone tenant-create --name demo  | awk '/ id / {print \\$4}'"`;
            echo ${_DEMO_TENANT}
    fi

    # Users
    _DEMO_USER=`execController "$SOURCE_CMD; keystone user-get demo | awk '/ id / {print \\$4}'"`

    if [ -z $_DEMO_USER ]
        then
            _DEMO_USER=`execController "$SOURCE_CMD; keystone user-create --name demo --pass tigris --tenant demo | awk '/ id / {print \\$4}'"`;
            echo ${_DEMO_USER}
    fi

    # Role
    _DEMO_ROLE=`execController "$SOURCE_CMD; keystone role-get _member_ |  awk '/ id / {print \\$4}'"`

    if [ -z $_DEMO_ROLE ]
        then
            _DEMO_ROLE=`execController "$SOURCE_CMD; keystone user-role-add --user=demo --role=_member_ --tenant=demo | awk '/ id / {print \\$4}'"`;
            echo ${__DEMO_ROLE}
    fi

    echo "User: $_DEMO_USER for tenant $_DEMO_TENANT with role $_DEMO_ROLE"
}

function getVSD() {
    _VSD_IP=`execController "host vsd-1 | awk '{print \\$4}'"`

    echo "$_VSD_IP"
}

function getOS() {
    _VERSION=`execController "nova-manage version"`

    _OS="unknown"

    if [[ "$_VERSION" = *"2014.1"* ]]; then
        _OS="icehouse"
    fi

    if [[ "$_VERSION" = *"2014.2"* ]]; then
        _OS="juno"
    fi

    if [[ "$_VERSION" = *"2015.1"* ]]; then
        _OS="kilo"
    fi

    if [[ "$_VERSION" = *"12.0.0"* ]]; then
        _OS="liberty"
    fi

    echo "$_OS"
}

function fetchSetCMSid() {
    _CMS_ID=`execController "$SOURCE_CMD; grep cms_id /etc/neutron/plugins/nuage/plugin.ini | cut -d\" \" -f3"`

    iniset ${TEMPEST_CONF} nuage nuage_cms_id   $_CMS_ID

    echo "$_CMS_ID"
}

########################################################################################################################
TESTBED_FULL=$TESTBED.be.alcatel-lucent.com
echo "Running testbed preparation for tempest execution for testbed $TESTBED_FULL - $OSC"

# Updating tempest
echo "PWD $PWD"

TEMPEST_CONF="$TEMPEST_CONFIG_PATH/tempest.conf"
ACCOUNTS="$TEMPEST_CONFIG_PATH/accounts.yaml"

if [ -f $TEMPEST_CONF ]; then
    echo "Adapting existing tempest.conf"
else
    echo "Generating tempest.conf from tempest.conf.sample"
    cp $TEMPEST_CONF.sample $TEMPEST_CONF
fi

echo "Creating configuration at: $TEMPEST_CONF"

if [ ! -f $TEMPEST_CONF ]; then
    echo "Can't find tempest.conf"
    exit 1
fi


CONTROLLER_IP=`getControllerIP`
echo "Controller IP: $CONTROLLER_IP"

# FOR openstackKiloDevStack
# SOURCE_CMD='source /opt/devstack/openrc admin admin'

# For openstackKiloUbuntu1404, Ubuntu/RHEL7 ICEHOUSE
SOURCE_CMD='source /root/admin_rc'

ssh-keygen -f "$HOME/.ssh/known_hosts" -R ${CONTROLLER_IP}

OS=`getOS`
echo "Running for OpenStack $OS"

export PUBLIC_NETWORK_UUID=`createPublicNetwork`
echo "Public network: $PUBLIC_NETWORK_UUID"

# Copy the "functions-common.sh" file to the root directory as with the new topo's it is not guaranteed that
# RunRemoteScript is executed.
echo "Copying functions-common.sh to /root"

execController "cp /${TESTBED}/ws/gash/testsuites/dc_openstack/configScripts/functions-common.sh /root/."

echo "Updating endpoints to provide testbed access for tempest"
updateEndpoints

IMAGE_UUID=`getImage`
echo "Test image UUID $IMAGE_UUID"

VSD_IP=`getVSD`
echo "VSD at $VSD_IP"

DEMO_USER=`createDemoUser`
echo "$DEMO_USER"

# Fetch CMS_id from plugin
CMS_ID=`fetchSetCMSid`


iniset ${TEMPEST_CONF} DEFAULT debug true
iniset ${TEMPEST_CONF} DEFAULT log_file tempest.log

# [auth]
#iniset ${TEMPEST_CONF} auth allow_tenant_isolation true
#iniset ${TEMPEST_CONF} auth test_accounts_file ${ACCOUNTS}
iniset ${TEMPEST_CONF} auth use_dynamic_credentials true

# [validation]
iniset ${TEMPEST_CONF} validation network_for_ssh public
iniset ${TEMPEST_CONF} validation image_ssh_user cirros
iniset ${TEMPEST_CONF} validation image_ssh_password "cubswin:)"

# [Compute]
iniset ${TEMPEST_CONF} compute image_ref "${IMAGE_UUID}"
iniset ${TEMPEST_CONF} compute-admin password tigris
iniset ${TEMPEST_CONF} compute-admin tenant_name admin

# [Auth]
iniset ${TEMPEST_CONF} auth admin_domain_name regionOne
iniset ${TEMPEST_CONF} auth admin_password    tigris
iniset ${TEMPEST_CONF} auth admin_role        admin
iniset ${TEMPEST_CONF} auth admin_username    admin
iniset ${TEMPEST_CONF} auth admin_tenant_name admin

# deprecated
#iniset ${TEMPEST_CONF} identity alt_username    demo
#iniset ${TEMPEST_CONF} identity alt_password    tigris
#iniset ${TEMPEST_CONF} identity alt_tenant_name demo

iniset ${TEMPEST_CONF} identity region      regionOne

# depreciated
#iniset ${TEMPEST_CONF} identity username    admin
#iniset ${TEMPEST_CONF} identity password    tigris
#iniset ${TEMPEST_CONF} identity tenant_name admin

iniset ${TEMPEST_CONF} identity uri "http:\/\/$CONTROLLER_IP:5000\/v2.0"
iniset ${TEMPEST_CONF} identity uri_v3 "http:\/\/$CONTROLLER_IP:5000\/v2.0\/tokens"

iniset ${TEMPEST_CONF} identity-feature-enabled api_v3 false

# [network]
iniset ${TEMPEST_CONF} network public_network_id ${PUBLIC_NETWORK_UUID}
iniset ${TEMPEST_CONF} network region regionOne

## need larger network
iniset ${TEMPEST_CONF} network tenant_network_cidr 13.100.0.0/16
iniset ${TEMPEST_CONF} network tenant_network_mask_bits 24

# TODO: get the list of capabilities from the testbed
#API_EXT_LIST='router, binding, external-net, net-partition, nuage-router, nuage-subnet, quotas, security-group, compute, network, image'
#API_EXT_LIST="security-group, provider, binding, quotas, nuage-router, external-net, router, nuage-subnet, net-partition, extraroute"
NUAGE_EXT_LIST="net-partition, nuage-router, nuage-subnet, nuage-floatingip, nuage-gateway, vsd-resource, nuage-redirect-target, appdesigner"
API_EXT_LIST="security-group, provider, binding, quotas, external-net, router, extraroute, ext-gw-mode, extra_dhcp_opt, allowed-address-pairs"
API_EXT_LIST="$API_EXT_LIST, $NUAGE_EXT_LIST"

iniset ${TEMPEST_CONF} network-feature-enabled api_extensions "$API_EXT_LIST"
iniset ${TEMPEST_CONF} network-feature-enabled ipv6 false

# [nuage]
# TODO: get the nuage configuration from the testbed
iniset ${TEMPEST_CONF} nuage nuage_vsd_server  "${VSD_IP}:8443"
iniset ${TEMPEST_CONF} nuage nuage_default_netpartition "${TESTBED}"
iniset ${TEMPEST_CONF} nuage nuage_auth_resource /me
iniset ${TEMPEST_CONF} nuage nuage_vsd_user csproot
iniset ${TEMPEST_CONF} nuage nuage_vsd_password csproot
iniset ${TEMPEST_CONF} nuage nuage_vsd_org csp
iniset ${TEMPEST_CONF} nuage nuage_cms_id "${CMS_ID}"
iniset ${TEMPEST_CONF} nuage nuage_base_uri /nuage/api/v3_2

iniset ${TEMPEST_CONF} nuage_sut controller_user root
iniset ${TEMPEST_CONF} nuage_sut controller_password tigris
iniset ${TEMPEST_CONF} nuage_sut controller_service_management_mode ubuntu
iniset ${TEMPEST_CONF} nuage_sut nuage_plugin_configuration /etc/neutron/plugins/nuage/plugin.ini

# [orchestration]
iniset ${TEMPEST_CONF} orchestration instance_type m1.tiny
#iniset ${TEMPEST_CONF} orchestration stack_owner_role admin
iniset ${TEMPEST_CONF} orchestration stack_owner_role _member_
iniset ${TEMPEST_CONF} orchestration region regionOne


# [object-storage]
iniset ${TEMPEST_CONF} object-storage region regionOne

# [oslo]
iniset ${TEMPEST_CONF} oslo_concurrency lock_path /tmp

# [scenario]
iniset ${TEMPEST_CONF} scenario large_ops_number "3"

# [service_available]
iniset ${TEMPEST_CONF} service_available neutron    true
iniset ${TEMPEST_CONF} service_available heat       true
iniset ${TEMPEST_CONF} service_available ceilometer false
iniset ${TEMPEST_CONF} service_available swift      false

# [validation]
iniset ${TEMPEST_CONF} validation run_validation true

# [volume]
iniset ${TEMPEST_CONF} volume region regionOne
