import time
import re

def setup_tempest_public_network(osc):

    cmds = [
        'source ~/admin_rc',
        'neutron net-create tempestPublicNw --router:external',
        'neutron subnet-create tempestPublicNw 10.10.100.0/24 --name tempestPublicSubnet',
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

    plugin_file = "/etc/neutron/plugin.ini"
    audit_cmd = ('python set_and_audit_cms.py '
                 '--plugin-config-file /etc/neutron/plugin.ini '
                 '--neutron-config-file /etc/neutron/neutron.conf')
    path = '/opt/upgrade-script/upgrade-scripts'
    cmd = 'cd {path} ; {audit_cmd}'.format(path=path, audit_cmd=audit_cmd)
    osc.cmd(cmd, timeout=30, strict=False)

    osc.cmd('service neutron-server restart')
    time.sleep(5)
    osc.cmd('service neutron-server status')

    cmd = "cat /etc/neutron/plugin.ini | grep cms_id"
    out = osc.cmd(cmd, timeout=30, strict=False)
    m = re.search(r"cms_id = (\w+\-\w+\-\w+\-\w+\-\w+)", out[0][0])
    if m:
        cms_id = m.group(1)
    else:
        print "CMS id not found in %s" % plugin_file
        return None

    return cms_id

def setup_tempestcfg(**kwargs):

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
    file.write("tenant_name = services\n")
    file.write("password = tigris\n")
    file.write("admin_username = admin\n")
    file.write("admin_tenant_name = admin\n")
    file.write("admin_password = tigris\n")
    file.write("admin_domain_name = Default\n")
    file.write("[network]\n")
    file.write("public_network_id = %s\n" % kwargs['net_id'])
    file.write("[nuage]\n")
    file.write("nuage_vsd_server = vsd-1:8443\n")
    file.write("nuage_default_netpartition = %s\n" % kwargs['def_netpartition'])
    file.write("nuage_auth_resource = /me\n")
    file.write("nuage_base_uri = /nuage/api/v%s\n" % kwargs['nuage_api_ver'])
    file.write("nuage_vsd_user = csproot\n")
    file.write("nuage_vsd_password = csproot\n")
    file.write("nuage_vsd_org = csp\n")
    file.write("cms_id = %s\n" % kwargs['cms_id'])
    file.write("[oslo_concurrency]\n")
    file.write("lock_path = %s\n" % kwargs['tempest_log_path'])
    file.write("[service_available]\n")
    file.write("neutron = True\n")
    file.write("swift = False\n")

    file.close()

