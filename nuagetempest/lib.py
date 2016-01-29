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

def setup_cmsid(osc):

    plugin_file = "/etc/neutron/plugins/nuage/plugin.ini"
    audit_cmd = ('python set_and_audit_cms.py '
                 '--plugin-config-file ' + plugin_file
                 '--neutron-config-file /etc/neutron/neutron.conf')
    path = '/opt/upgrade-script/upgrade-scripts'
    cmd = 'cd {path} ; {audit_cmd}'.format(path=path, audit_cmd=audit_cmd)
    osc.cmd(cmd, timeout=30, strict=False)

    osc.cmd('service neutron-server restart')
    time.sleep(5)
    osc.cmd('service neutron-server status')

    cmd = "cat " + plugin_file + " | grep cms_id"
    out = osc.cmd(cmd, timeout=30, strict=False)
    m = re.search(r"cms_id = (\w+\-\w+\-\w+\-\w+\-\w+)", out[0][0])
    if m:
        cms_id = m.group(1)
    else:
        print "CMS id not found in %s" % plugin_file
        return None

    return cms_id

def setup_tempestcfg(**kwargs):

    api_extensions = "security-group, provider, binding, quotas, external-net, router, extraroute, ext-gw-mode, allowed-address-pairs, extra_dhcp_opt, net-partition, nuage-router, nuage-subnet, nuage-floatingip, nuage-gateway, vsd-resource, nuage-redirect-target, nuage-external-security-group, appdesigner"
    nuage_plugin_file = "/etc/neutron/plugins/nuage/plugin.ini" 
    accounts_file = "tempest/etc/accounts.yaml"

    file = open(kwargs['tempest_cfg_file'], "w")
    file.write("[DEFAULT]\n")
    file.write("debug = True\n")
    file.write("verbose = True\n")
    file.write("log_file = " + kwargs['tempest_log_file'] + "\n")
    file.write("log_dir = " + kwargs['tempest_log_path'] + "\n")
    file.write("[compute]\n")
    file.write("image_ref = f635ab12-830c-474e-a8f3-3b4d2f27c98c\n")
    file.write("image_ref_alt = f635ab12-830c-474e-a8f3-3b4d2f27c98c\n")
    file.write("[dashboard]\n")
    file.write("login_url = http://%s/auth/login/\n" % kwargs['osc_ip'])
    file.write("dashboard_url = http://%s/\n" % kwargs['osc_ip'])
    file.write("[identity]\n")
    file.write("uri = http://%s:5000/v2.0/\n" % kwargs['osc_ip'])
    file.write("uri_v3 = http://%s:5000/v3/\n" % kwargs['osc_ip'])
    file.write("region = regionOne\n")
    file.write("username = admin\n")
    #file.write("tenant_name = services\n")
    file.write("password = tigris\n")
    file.write("admin_username = admin\n")
    file.write("admin_tenant_name = admin\n")
    file.write("admin_password = tigris\n")
    file.write("admin_domain_name = Default\n")
    file.write("alt_tenant_name = demo\n")
    file.write("alt_password = tigris\n")
    file.write("alt_username = demo\n")
    file.write("tenant_name = admin\n")
    file.write("[identity-feature-enabled]\n")
    file.write("api_v3 = false\n")
    file.write("[network]\n")
    file.write("public_network_id = %s\n" % kwargs['net_id'])
    #file.write("tenant_network_cidr = 13.100.0.0/16\n")
    #file.write("tenant_network_mask_bits = 16\n")
    file.write("region = regionOne\n")
    file.write("build_timeout = 10\n")
    file.write("build_interval = 1\n")
    file.write("[network-feature-enabled]\n")
    file.write("ipv6 = false\n")
    file.write("api_extensions = %s\n" % api_extensions)
    file.write("[object-storage]\n")
    file.write("region = regionOne\n")
    file.write("[orchestration]\n")
    file.write("region = regionOne\n")
    file.write("instance_type = m1.tiny\n")
    file.write("image_ref = f635ab12-830c-474e-a8f3-3b4d2f27c98c\n")
    file.write("stack_owner_role = _member_\n")
    file.write("[scenario]\n")
    file.write("large_ops_number = 3\n")
    file.write("[nuage]\n")
    file.write("nuage_vsd_server = vsd-1:8443\n")
    file.write("nuage_default_netpartition = %s\n" % kwargs['def_netpartition'])
    file.write("nuage_auth_resource = /me\n")
    file.write("nuage_base_uri = /nuage/api/v%s\n" % kwargs['nuage_api_ver'])
    file.write("nuage_vsd_user = csproot\n")
    file.write("nuage_vsd_password = csproot\n")
    file.write("nuage_vsd_org = csp\n")
    file.write("nuage_cms_id = %s\n" % kwargs['cms_id'])
    file.write("[oslo_concurrency]\n")
    file.write("lock_path = %s\n" % kwargs['tempest_log_path'])
    file.write("[service_available]\n")
    file.write("heat = True\n")
    file.write("neutron = True\n")
    file.write("swift = False\n")
    file.write("ceilometer = false\n")
    file.write("[auth]\n")
    file.write("test_accounts_file = %s\n" % accounts_file)    
    file.write("[volume]\n")
    file.write("region = regionOne\n")
    file.write("[compute-admin]\n")
    file.write("tenant_name = admin\n")
    file.write("password = tigris\n")
    file.write("[validation]\n")
    file.write("run_validation = true\n")
    file.write("[cli]\n")
    file.write("enabled = true\n")
    file.write("[nuage_sut]\n")
    file.write("nuage_plugin_configuration = %s\n" % nuage_plugin_file)
    file.write("controller_service_management_mode = ubuntu\n")
    file.write("controller_password = tigris\n")
    file.write("controller_user = root\n")

    file.close()

