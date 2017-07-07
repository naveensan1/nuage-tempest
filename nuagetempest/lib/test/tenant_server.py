from libduts import ssh
from netaddr import IPNetwork
from oslo_log import log as logging


class Console(object):
    def __init__(self):
        self.username = None
        self.password = None
        self.telnet_port = None
        self.telnet_host = None

        self.is_initialized = False
        self.session = None

    def init_telnet(self, host, port, username=None, password=None,prompt=None):
        self.telnet_port = port
        self.telnet_host = host

        if not username:
            self.username = 'cirros'
        else:
            self.username = username
        if not password:
            self.password = 'cubswin:)'
        else :
            self.password = password
        
        if not prompt:
            self.login_prompt = '\$'
        else:
            self.login_prompt = prompt
        self.is_initialized = True
        
        
    def close(self):
        if self.session:
            self.session.close()

    def __call__(self, *args, **kwargs):
        if self.is_initialized:
            if self.session:
                return self.session
            else:
                self.session = ssh.ExpectTelnetSession(
                    address=self.telnet_host,
                    user=self.username,
                    password=self.password,
                    port=self.telnet_port,
                    prompt=self.login_prompt)

                self.session.open_while(timeout=180, retry_interval=5)

                return self.session
        else:
            assert "Session not initialized"


class TenantServer(object):
    LOG = logging.getLogger(__name__)

    """
    Object to represent a server managed by the CMS to be consumed by tenants.
    Can be:
    - a tenant VM on a KVM hypervisor
    - a baremetal server
    """

    tenant_client = None
    admin_client = None

    # A console session to the server
    console = None

    # The attributes as managed by OpenStack
    openstack_data = None

    def __init__(self, client, admin_client):
        self.tenant_client = client
        self.admin_client = admin_client
        self.console = Console()
#        self.console.init_telnet()

    def get_telnet_host_port(self):
        """List server using admin creds else provide client"""
        server_id = self.openstack_data['id']
        server_list = self.admin_client.show_server(server_id)
        server_output = server_list['server']

        vm_name = server_output.get('OS-EXT-SRV-ATTR:instance_name')
        instance, number = vm_name.split('-')
        telnet_port = int(number, 16) + 2000

        host = server_output.get('OS-EXT-SRV-ATTR:host')

        self.LOG.info("VM details:\n"
                      "  VM ID  : {}\n"
                      "  VM name: {}\n"
                      "  VM host: {}\n"
                      "  VM port: {}\n"
                      .format(server_id, vm_name, host, telnet_port))

        return host, telnet_port

    def osc_list_server(self, server_id, client=None):
        """List server using admin creds else provide client"""
        server_list = self.admin_client.show_server(server_id)
        return server_list['server']

    def get_server_ip_in_network(self, network_name, ip_type=4):
        server_detail = self.osc_list_server(self.openstack_data['id'])
        ip_address = None
        for subnet_interface in server_detail['addresses'][network_name]:
            if subnet_interface['version'] == ip_type:
                ip_address = subnet_interface['addr']
                break
        return ip_address

    def init_console(self,username=None,password=None,prompt=None):
        # TODO: initialize the default console flavor supported by the actual configuration
        host, port = self.get_telnet_host_port()
        self.console.init_telnet(host, port,username=username,password=password,prompt=prompt)

    def close_console(self):
        self.console.close()

    def ping(self, ip_address, should_pass=True,count=2,interface=None):
        if interface:
            cmd_sent = 'ping -c %s %s -I %s' % (count,ip_address,interface)
            output = self.console().send(cmd=cmd_sent,timeout=50)
        else:
            output = self.console().send(cmd='ping -c %s %s ' % (count,ip_address), timeout=50)
        complete_output = str(output).strip('[]')
        if should_pass:
            expectedresult = "%s packets received" % count
        else:
            expectedresult = "0 packets received"

        return expectedresult in complete_output

    def configure_vlan_interface(self,ip,interface,vlan):
        
        cmd = 'ip link add link %s name %s.%s type vlan id %s ' % (interface,interface,vlan,vlan)
        self.console().send(cmd=cmd, timeout=5)
        cmd = 'ifconfig %s.%s %s  up' % (interface,vlan,ip)
        self.console().send(cmd=cmd, timeout=5)
        cmd = 'ifconfig'
        self.console().send(cmd=cmd, timeout=5)

    def configure_ip_fwd(self):
        cmd = 'sysctl -w net.ipv4.ip_forward=1'
        self.console().send(cmd=cmd, timeout=10)

    def bringdown_interface(self,interface):
        cmd = 'ifconfig %s 0.0.0.0' % interface
        self.console().send(cmd=cmd, timeout=10)
        cmd = 'ifconfig'
        self.console().send(cmd=cmd, timeout=5)

    def configure_dualstack_interface(self, ip, subnet, device="eth0"):
        maskbits=IPNetwork(subnet['cidr']).prefixlen
        gateway_ip=subnet['gateway_ip']

        # console, ip, maskbits, gateway_ip, device="eth0" ):
        cmd = 'sudo ip -6 addr add {}/{} dev {}'.format(ip, maskbits, device)
        self.console().send(cmd=cmd, timeout=5)

        cmd = 'sudo ip link set dev {} up'.format(device)
        self.console().send(cmd=cmd, timeout=5)

        cmd = 'sudo ip -6 route add default via {}'.format(gateway_ip)
        self.console().send(cmd=cmd, timeout=5)

        self.console().send(cmd='sudo ip a', timeout=5)
        self.console().send(cmd='sudo route -n -A inet6', timeout=5)

    def ping6(self, ip_address, should_pass=True):
        output = self.console().send(cmd='ping6 -c 2 ' + ip_address, timeout=50)
        complete_output = str(output).strip('[]')
        if should_pass:
            expectedresult = "2 packets received"
        else:
            expectedresult = "0 packets received"
        return expectedresult in complete_output
