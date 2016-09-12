# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from fabric.api import local, lcd
from fabric import colors
from fabric.utils import indent
from fabric.state import env, output
from docker import Client
from pyroute2 import IPRoute
from nsenter import Namespace

import netaddr
import os
import time
import itertools
import string
import random

DEFAULT_TEST_PREFIX = ''
DEFAULT_TEST_BASE_DIR = '/tmp/gobgp'
TEST_PREFIX = DEFAULT_TEST_PREFIX
TEST_BASE_DIR = DEFAULT_TEST_BASE_DIR

BGP_FSM_IDLE = 'BGP_FSM_IDLE'
BGP_FSM_ACTIVE = 'BGP_FSM_ACTIVE'
BGP_FSM_ESTABLISHED = 'BGP_FSM_ESTABLISHED'

BGP_ATTR_TYPE_ORIGIN = 1
BGP_ATTR_TYPE_AS_PATH = 2
BGP_ATTR_TYPE_NEXT_HOP = 3
BGP_ATTR_TYPE_MULTI_EXIT_DISC = 4
BGP_ATTR_TYPE_LOCAL_PREF = 5
BGP_ATTR_TYPE_COMMUNITIES = 8
BGP_ATTR_TYPE_ORIGINATOR_ID = 9
BGP_ATTR_TYPE_CLUSTER_LIST = 10
BGP_ATTR_TYPE_MP_REACH_NLRI = 14
BGP_ATTR_TYPE_EXTENDED_COMMUNITIES = 16

env.abort_exception = RuntimeError
output.stderr = False

random_str = lambda n : ''.join([random.choice(string.ascii_letters + string.digits) for i in range(n)])
dckr = Client(version='auto')

def try_several_times(f, t=3, s=1):
    e = None
    for i in range(t):
        try:
            r = f()
        except RuntimeError as e:
            time.sleep(s)
        else:
            return r
    raise e


def get_bridges():
    return try_several_times(lambda : local("ip li show type bridge | gawk -e '/^[0-9]+:/{ gsub(\":\", \"\", $2); print $2 }'", capture=True)).split('\n')


def get_containers():
    return try_several_times(lambda : local("docker ps -a | awk 'NR > 1 {print $NF}'", capture=True)).split('\n')


class CmdBuffer(list):
    def __init__(self, delim='\n'):
        super(CmdBuffer, self).__init__()
        self.delim = delim

    def __lshift__(self, value):
        self.append(value)

    def __str__(self):
        return self.delim.join(self)


def make_gobgp_ctn(tag='gobgp', local_gobgp_path='', from_image='osrg/quagga'):
    if local_gobgp_path == '':
        local_gobgp_path = os.getcwd()

    c = CmdBuffer()
    c << 'FROM {0}'.format(from_image)
    c << 'ADD gobgp /go/src/github.com/osrg/gobgp/'
    c << 'RUN go get github.com/osrg/gobgp/gobgpd'
    c << 'RUN go install github.com/osrg/gobgp/gobgpd'
    c << 'RUN go get github.com/osrg/gobgp/gobgp'
    c << 'RUN go install github.com/osrg/gobgp/gobgp'

    rindex = local_gobgp_path.rindex('gobgp')
    if rindex < 0:
        raise Exception('{0} seems not gobgp dir'.format(local_gobgp_path))

    workdir = local_gobgp_path[:rindex]
    with lcd(workdir):
        local('echo \'{0}\' > Dockerfile'.format(str(c)))
        local('docker build -t {0} .'.format(tag))
        local('rm Dockerfile')


class docker_netns(object):
    def __init__(self, name):
        pid = int(dckr.inspect_container(name)['State']['Pid'])
        if pid == 0:
            raise Exception('no container named {0}'.format(name))
        self.pid = pid

    def __enter__(self):
        pid = self.pid
        if not os.path.exists('/var/run/netns'):
            os.mkdir('/var/run/netns')
        os.symlink('/proc/{0}/ns/net'.format(pid), '/var/run/netns/{0}'.format(pid))
        return str(pid)

    def __exit__(self, type, value, traceback):
        pid = self.pid
        os.unlink('/var/run/netns/{0}'.format(pid))


class Bridge(object):
    def __init__(self, name, subnet='', with_ip=True):
        name = '{0}_{1}'.format(TEST_PREFIX, name)
        ip = IPRoute()
        br = ip.link_lookup(ifname=name)
        if len(br) != 0:
            ip.link('del', index=br[0])
        ip.link('add', ifname=name, kind='bridge')
        br = ip.link_lookup(ifname=name)
        br = br[0]
        ip.link('set', index=br, state='up')

        if with_ip:
            self.subnet = netaddr.IPNetwork(subnet)

            def f():
                for host in self.subnet:
                    yield host
            self._ip_generator = f()
            # throw away first network address
            self.next_ip_address()
            self.ip_addr = self.next_ip_address()
            address, prefixlen = self.ip_addr.split('/')
            ip.addr('add', index=br, address=address, prefixlen=int(prefixlen))

        self.name = name
        self.with_ip = with_ip
        self.br = br
        self.ctns = []

    def next_ip_address(self):
        return "{0}/{1}".format(self._ip_generator.next(),
                                self.subnet.prefixlen)

    def addif(self, ctn, ifname='', mac=''):
        with docker_netns(ctn.docker_name()) as pid:
            host_ifname = '{0}_{1}'.format(self.name, ctn.name)
            guest_ifname = 'if' + random_str(5)
            ip = IPRoute()
            host = ip.link_lookup(ifname=host_ifname)
            if len(host) != 0:
                ip.link('del', index=host[0])

            # this somehow fails on travis, call ip command for workaround
            # ip.link('add', ifname=host_ifname, kind='veth', peer=guest_ifname)
            print local('ip link add {0} type veth peer name {1}'.format(host_ifname, guest_ifname), capture=True)
            host = ip.link_lookup(ifname=host_ifname)[0]
            ip.link('set', index=host, master=self.br)
            ip.link('set', index=host, state='up')

            self.ctns.append(ctn)

            guest = ip.link_lookup(ifname=guest_ifname)[0]
            ip.link('set', index=guest, net_ns_fd=pid)
            with Namespace(pid, 'net'):
                ip = IPRoute()
                if ifname == '':
                    links = [x.get_attr('IFLA_IFNAME') for x in ip.get_links()]
                    n = [int(l[len('eth'):]) for l in links if l.startswith('eth')]
                    idx = 0
                    if len(n) > 0:
                        idx = max(n) + 1
                    ifname = 'eth{0}'.format(idx)
                ip.link('set', index=guest, ifname=ifname)
                ip.link('set', index=guest, state='up')

                if mac != '':
                    ip.link('set', index=guest, address=mac)

                if self.with_ip:
                    address, mask = self.next_ip_address().split('/')
                    ip.addr('add', index=guest, address=address, mask=int(mask))
                    ctn.ip_addrs.append((ifname, address, self.name))
            return ifname


class Container(object):
    def __init__(self, name, image):
        self.name = name
        self.image = image
        self.shared_volumes = []
        self.ip_addrs = []
        self.ip6_addrs = []
        self.is_running = False
        self.eths = []
        self.tcpdump_running = False

        if self.docker_name() in get_containers():
            self.remove()

    def docker_name(self):
        if TEST_PREFIX == DEFAULT_TEST_PREFIX:
            return self.name
        return '{0}_{1}'.format(TEST_PREFIX, self.name)

    def next_if_name(self):
        name = 'eth{0}'.format(len(self.eths)+1)
        self.eths.append(name)
        return name

    def run(self):
        c = CmdBuffer(' ')
        c << "docker run --privileged=true"
        for sv in self.shared_volumes:
            c << "-v {0}:{1}".format(sv[0], sv[1])
        c << "--name {0} -id {1}".format(self.docker_name(), self.image)
        self.id = try_several_times(lambda : local(str(c), capture=True))
        self.is_running = True
        self.local("ip li set up dev lo")
        for line in self.local("ip a show dev eth0", capture=True).split('\n'):
            if line.strip().startswith("inet "):
                elems = [e.strip() for e in line.strip().split(' ')]
                self.ip_addrs.append(('eth0', elems[1], 'docker0'))
            elif line.strip().startswith("inet6 "):
                elems = [e.strip() for e in line.strip().split(' ')]
                self.ip6_addrs.append(('eth0', elems[1], 'docker0'))
        return 0

    def stop(self):
        ret = try_several_times(lambda : local("docker stop -t 0 " + self.docker_name(), capture=True))
        self.is_running = False
        return ret

    def remove(self):
        ret = try_several_times(lambda : local("docker rm -f " + self.docker_name(), capture=True))
        self.is_running = False
        return ret


    def local(self, cmd, capture=False, stream=False, detach=False):
        if stream:
            dckr = Client(timeout=120, version='auto')
            i = dckr.exec_create(container=self.docker_name(), cmd=cmd)
            return dckr.exec_start(i['Id'], tty=True, stream=stream, detach=detach)
        else:
            flag = '-d' if detach else ''
            return local('docker exec {0} {1} {2}'.format(flag, self.docker_name(), cmd), capture)

    def get_pid(self):
        if self.is_running:
            cmd = "docker inspect -f '{{.State.Pid}}' " + self.docker_name()
            return int(local(cmd, capture=True))
        return -1

    def start_tcpdump(self, interface=None, filename=None, expr='tcp port 179'):
        if self.tcpdump_running:
            raise Exception('tcpdump already running')
        self.tcpdump_running = True
        if not interface:
            interface = "eth0"
        if not filename:
            filename = '{0}.dump'.format(interface)
        self.local("tcpdump -U -i {0} -w {1}/{2} {3}".format(interface, self.shared_volumes[0][1], filename, expr), detach=True)
        return '{0}/{1}'.format(self.shared_volumes[0][0], filename)

    def stop_tcpdump(self):
        self.local("pkill tcpdump")
        self.tcpdump_running = False


class BGPContainer(Container):

    WAIT_FOR_BOOT = 1
    RETRY_INTERVAL = 5

    def __init__(self, name, asn, router_id, ctn_image_name):
        self.config_dir = '/'.join((TEST_BASE_DIR, TEST_PREFIX, name))
        local('if [ -e {0} ]; then rm -r {0}; fi'.format(self.config_dir))
        local('mkdir -p {0}'.format(self.config_dir))
        local('chmod 777 {0}'.format(self.config_dir))
        self.asn = asn
        self.router_id = router_id
        self.peers = {}
        self.routes = {}
        self.policies = {}
        super(BGPContainer, self).__init__(name, ctn_image_name)

    def __repr__(self):
        return str({'name':self.name, 'asn':self.asn, 'router_id':self.router_id})

    def run(self):
        self.create_config()
        super(BGPContainer, self).run()
        return self.WAIT_FOR_BOOT

    def add_peer(self, peer, passwd=None, vpn=False, is_rs_client=False,
                 policies=None, passive=False,
                 is_rr_client=False, cluster_id=None,
                 flowspec=False, bridge='', reload_config=True, as2=False,
                 graceful_restart=None, local_as=None, prefix_limit=None,
                 v6=False):
        neigh_addr = ''
        local_addr = ''
        it = itertools.product(self.ip_addrs, peer.ip_addrs)
        if v6:
            it = itertools.product(self.ip6_addrs, peer.ip6_addrs)

        for me, you in it:
            if bridge != '' and bridge != me[2]:
                continue
            if me[2] == you[2]:
                neigh_addr = you[1]
                local_addr = me[1]
                if v6:
                    addr, mask = local_addr.split('/')
                    local_addr = "{0}%{1}/{2}".format(addr, me[0], mask)
                break

        if neigh_addr == '':
            raise Exception('peer {0} seems not ip reachable'.format(peer))

        if not policies:
            policies = {}

        self.peers[peer] = {'neigh_addr': neigh_addr,
                            'passwd': passwd,
                            'vpn': vpn,
                            'flowspec': flowspec,
                            'is_rs_client': is_rs_client,
                            'is_rr_client': is_rr_client,
                            'cluster_id': cluster_id,
                            'policies': policies,
                            'passive': passive,
                            'local_addr': local_addr,
                            'as2': as2,
                            'graceful_restart': graceful_restart,
                            'local_as': local_as,
                            'prefix_limit': prefix_limit}
        if self.is_running and reload_config:
            self.create_config()
            self.reload_config()

    def del_peer(self, peer, reload_config=True):
        del self.peers[peer]
        if self.is_running and reload_config:
            self.create_config()
            self.reload_config()

    def disable_peer(self, peer):
        raise Exception('implement disable_peer() method')

    def enable_peer(self, peer):
        raise Exception('implement enable_peer() method')

    def log(self):
        return local('cat {0}/*.log'.format(self.config_dir), capture=True)

    def add_route(self, route, rf='ipv4', attribute=None, aspath=None,
                  community=None, med=None, extendedcommunity=None,
                  nexthop=None, matchs=None, thens=None,
                  local_pref=None, reload_config=True):
        self.routes[route] = {'prefix': route,
                              'rf': rf,
                              'attr': attribute,
                              'next-hop': nexthop,
                              'as-path': aspath,
                              'community': community,
                              'med': med,
                              'local-pref': local_pref,
                              'extended-community': extendedcommunity,
                              'matchs': matchs,
                              'thens' : thens}
        if self.is_running and reload_config:
            self.create_config()
            self.reload_config()

    def add_policy(self, policy, peer, typ, default='accept', reload_config=True):
        self.set_default_policy(peer, typ, default)
        self.define_policy(policy)
        self.assign_policy(peer, policy, typ)
        if self.is_running and reload_config:
            self.create_config()
            self.reload_config()

    def set_default_policy(self, peer, typ, default):
        if typ in ['in', 'out', 'import', 'export'] and default in ['reject', 'accept']:
            if 'default-policy' not in self.peers[peer]:
                self.peers[peer]['default-policy'] = {}
            self.peers[peer]['default-policy'][typ] = default
        else:
            raise Exception('wrong type or default')

    def define_policy(self, policy):
        self.policies[policy['name']] = policy

    def assign_policy(self, peer, policy, typ):
        if peer not in self.peers:
            raise Exception('peer {0} not found'.format(peer.name))
        name = policy['name']
        if name not in self.policies:
            raise Exception('policy {0} not found'.format(name))
        self.peers[peer]['policies'][typ] = policy

    def get_local_rib(self, peer, rf):
        raise Exception('implement get_local_rib() method')

    def get_global_rib(self, rf):
        raise Exception('implement get_global_rib() method')

    def get_neighbor_state(self, peer_id):
        raise Exception('implement get_neighbor() method')

    def get_reachablily(self, prefix, timeout=20):
            version = netaddr.IPNetwork(prefix).version
            addr = prefix.split('/')[0]
            if version == 4:
                ping_cmd = 'ping'
            elif version == 6:
                ping_cmd = 'ping6'
            else:
                raise Exception('unsupported route family: {0}'.format(version))
            cmd = '/bin/bash -c "/bin/{0} -c 1 -w 1 {1} | xargs echo"'.format(ping_cmd, addr)
            interval = 1
            count = 0
            while True:
                res = self.local(cmd, capture=True)
                print colors.yellow(res)
                if '1 packets received' in res and '0% packet loss':
                    break
                time.sleep(interval)
                count += interval
                if count >= timeout:
                    raise Exception('timeout')
            return True

    def wait_for(self, expected_state, peer, timeout=120):
        interval = 1
        count = 0
        while True:
            state = self.get_neighbor_state(peer)
            y = colors.yellow
            print y("{0}'s peer {1} state: {2}".format(self.router_id,
                                                       peer.router_id,
                                                       state))
            if state == expected_state:
                return

            time.sleep(interval)
            count += interval
            if count >= timeout:
                raise Exception('timeout')

    def add_static_route(self, network, next_hop):
        cmd = '/sbin/ip route add {0} via {1}'.format(network, next_hop)
        self.local(cmd)

    def set_ipv6_forward(self):
        cmd = 'sysctl -w net.ipv6.conf.all.forwarding=1'
        self.local(cmd)

    def create_config(self):
        raise Exception('implement create_config() method')

    def reload_config(self):
        raise Exception('implement reload_config() method')
