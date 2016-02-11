import time
import re

def setup_tempest_public_network(osc):

    out = osc.cmd("source ~/admin_rc;neutron net-list", timeout=30, strict=False)

    cmds = [
        'source ~/admin_rc',
        'neutron net-create tempestPublicNw --router:external',
        'neutron subnet-create tempestPublicNw 172.20.0.0/24 --name tempestPublicSubnet',
        'neutron net-list',
        'neutron subnet-list'
    ]
    osc.cmd(' ; '.join(cmds), timeout=60)

    out = osc.cmd("source ~/admin_rc;neutron net-list", timeout=30, strict=False)
    m = re.search(r"(\w+\-\w+\-\w+\-\w+\-\w+)", out[0][3])
    if m:
        net_id = m.group(0)
    else:
        print "Network id not found"
        return None

    return net_id

def setup_tempest_tenant_user(osc, tenant, user, password, role):

    def ks_cmd(cmd):
        ks_base_cmd = 'source ~/admin_rc ; keystone'
        awk_cmd = 'awk "/ id / {print $4}"'
        command = '{} {} | {}'.format(ks_base_cmd, cmd, awk_cmd)
        return osc.cmd(command, timeout=30)

    tenantid = ks_cmd('tenant-get {}'.format(tenant))
    if not tenantid[0]:
        tenantid = ks_cmd('tenant-create --name {}'.format(tenant))
    tenantid = tenantid[0][0]
    LOG.info('Tenant: {}  ID: {}'.format(tenant, tenantid))

    userid = ks_cmd('user-get {}'.format(user))
    if not userid[0]:
        cmd = 'user-create --name {} --pass {} --tenant {}'
        userid = ks_cmd(cmd.format(user, password, tenant))
    userid = userid[0][0]
    LOG.info('User: {} ID: {}'.format(user, userid))

    roleid = ks_cmd('keystone role-get {}'.format(role))
    if not roleid[0]:
        cmd = 'user-role-add --name {} --pass {} --tenant {} --role {}'
        roleid = ks_cmd(cmd.format(user, password, tenant, role))
    roleid = userid[0][0]
    LOG.info('Role: {} ID: {}'.format(role, roleid))


def setup_cmsid(osc):
    plugin_file = "/etc/neutron/plugins/nuage/plugin.ini"
    audit_cmd = ('python set_and_audit_cms.py '
                 '--plugin-config-file ' + plugin_file +
                 ' --neutron-config-file /etc/neutron/neutron.conf')
    path = '/opt/upgrade-script/upgrade-scripts'
    cmd = 'cd {} ; {}'.format(path, audit_cmd)
    osc.cmd(cmd, timeout=30, strict=False)

    osc.cmd('service neutron-server restart', strict=False)
    time.sleep(5)
    osc.cmd('service neutron-server status')

    cmd = "cat {} | grep cms_id".format(plugin_file)
    out = osc.cmd(cmd, timeout=30, strict=False)
    m = re.search(r"cms_id = (\w+\-\w+\-\w+\-\w+\-\w+)", out[0][0])
    if m:
        cms_id = m.group(1)
    else:
        raise Exception('Could not retrieve CMS ID')
    return cms_id

def setup_accountsyaml():
    accounts_file = '/etc/accounts.yaml'
    accounts = [
        {
            'username': 'admin',
            'tenant': 'admin',
            'password': 'tigris',
            'roles': ['admin']
        },
        {
            'username': 'demo',
            'tenant': 'demo',
            'password': 'tigris',
            'roles': ['_member_']
        }
    ]
    with open(accounts_file, 'w') as f:
        yaml.dump(accounts, f)


def write_tempest_conf_file(cms_id, net_id):

    config = configparser.ConfigParser()
    tempest_log_file = 'tempest.log'
    tempest_log_path = config.LOG_DIR
    tempest_config_file = '/etc/tempest.conf'
    exec_server_user = config.TESTBED_USER
    exec_server = config.TESTBED_USER
    esr_calls_file = config.ESRCALLS_FILE
    osc_ip = '10.100.100.20'
    def_netpartition = config.TESTBED_USER
    nuage_api_ver = '3_2'
    api_extensions = ', '.join(
        ["security-group", "provider", "binding", "quotas", "external-net",
         "router", "extraroute", "ext-gw-mode", "allowed-address-pairs",
         "extra_dhcp_opt", "net-partition", "nuage-router", "nuage-subnet",
         "nuage-floatingip", "nuage-gateway", "vsd-resource",
         "nuage-redirect-target", "nuage-external-security-group",
         "appdesigner"])
    nuage_plugin_file = "/etc/neutron/plugins/nuage/plugin.ini"
    accounts_file = "/etc/accounts.yaml"

    config.add_section('DEFAULT')
    config.set('DEFAULT', 'debug', True)
    config.set('DEFAULT', 'verbose', True)
    config.set('DEFAULT', 'log_file', tempest_log_file)
    config.set('DEFAULT', 'log_dir', tempest_log_path)

    config.add_section('compute')
    img_id = 'f635ab12-830c-474e-a8f3-3b4d2f27c98c'
    config.set('compute', 'image_ref', img_id)
    config.set('compute', 'image_ref_alt', img_id)

    config.add_section('dashboard')
    config.set(
        'dashboard', 'login_url', 'http://{}/auth/login/'.format(osc_ip))
    config.set('dashboard', 'dashboard_url', 'http://{}/'.format(osc_ip))

    config.add_section('identity')
    config.set('identity', 'uri', 'http://{}:5000/v2.0/'.format(osc_ip))
    config.set('identity', 'uri_v3', 'http://{}:5000/v3/'.format(osc_ip))
    config.set('identity', 'region', 'regionOne')
    config.set('identity', 'username', 'admin')
    config.set('identity', 'tenant_name', 'services')
    config.set('identity', 'password', 'tigris')
    config.set('identity', 'admin_username', 'admin')
    config.set('identity', 'admin_tenant_name', 'admin')
    config.set('identity', 'admin_password', 'tigris')
    config.set('identity', 'admin_domain_name', 'Default')
    config.set('identity', 'alt_tenant_name', 'demo')
    config.set('identity', 'alt_password', 'tigris')
    config.set('identity', 'alt_username', 'demo')
    config.set('identity', 'tenant_name', 'admin')

    config.add_section('identity-feature-enabled')
    config.set('identity-feature-enabled', 'api_v3', False)

    config.add_section('network')
    config.set('network', 'public_network_id', net_id)
    config.set('network', 'tenant_network_cidr', '13.100.0.0/16')
    config.set('network', 'tenant_network_mask_bits', '16')
    config.set('network', 'region', 'regionOne')
    config.set('network', 'build_timeout', '10')
    config.set('network', 'build_interval', '1')

    config.add_section('network-feature-enabled')
    config.set('network-feature-enabled', 'ipv6', False)
    config.set('network-feature-enabled', 'api_extensions', api_extensions)

    config.add_section('object-storage')
    config.set('object-storage', 'region', 'regionOne')

    config.add_section('orchestration')
    config.set('orchestration', 'region', 'regionOne')
    config.set('orchestration', 'instance_type', 'm1.tiny')
    config.set('orchestration', 'image_ref', img_id)
    config.set('orchestration', 'stack_owner_role', '_member_')

    config.add_section('scenario')
    config.set('scenario', 'large_ops_number', '3')

    config.add_section('nuage')
    config.set('nuage', 'nuage_vsd_server', 'vsd-1:8443')
    config.set('nuage', 'nuage_default_netpartition', def_netpartition)
    config.set('nuage', 'nuage_auth_resource', '/me')
    config.set(
        'nuage', 'nuage_base_uri', '/nuage/api/v{}'.format(nuage_api_ver))
    config.set('nuage', 'nuage_vsd_user', 'csproot')
    config.set('nuage', 'nuage_vsd_password', 'csproot')
    config.set('nuage', 'nuage_vsd_org', 'csp')
    config.set('nuage', 'nuage_cms_id', '{cms_id}')

    config.add_section('oslo_concurrency')
    config.set('oslo_concurrency', 'lock_path', tempest_log_path)

    config.add_section('service_available')
    config.set('service_available', 'heat', 'True')
    config.set('service_available', 'neutron', 'True')
    config.set('service_available', 'swift', 'False')
    config.set('service_available', 'ceilometer', 'false')

    config.add_section('auth')
    config.set('auth', 'test_accounts_file', accounts_file)

    config.add_section('volume')
    config.set('volume', 'region', 'regionOne')

    config.add_section('compute-admin')
    config.set('compute-admin', 'tenant_name', 'admin')
    config.set('compute-admin', 'password', 'tigris')

    config.add_section('validation')
    config.set('validation', 'run_validation', True)

    config.add_section('cli')
    config.set('cli', 'enabled', True)

    config.add_section('nuage_sut')
    config.set('nuage_sut', 'nuage_plugin_configuration', nuage_plugin_file)
    config.set('nuage_sut', 'controller_service_management_mode', 'ubuntu')
    config.set('nuage_sut', 'controller_password', 'tigris')
    config.set('nuage_sut', 'controller_user', 'root')

    config.add_section('nuagext')
    config.set('nuagext', 'nuage_components', 'vsd, vrs, vsc')
    config.set('nuagext', 'nuage_ext_mode', 'all')
    config.set('nuagext', 'esr_calls_file', esr_calls_file)
    config.set('nuagext', 'exec_server_user', exec_server_user)
    config.set('nuagext', 'exec_server', exec_server)

    with open(tempest_config_file, 'w') as f:
        config.dump(f)
