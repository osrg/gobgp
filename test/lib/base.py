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


import os
import subprocess
import time
import itertools
import math

import textwrap
from colored import fg, attr

from docker import APIClient as Client
import netaddr

from lib.noseplugin import parser_option


DEFAULT_TEST_PREFIX = ''
DEFAULT_TEST_BASE_DIR = '/tmp/gobgp'
TEST_PREFIX = DEFAULT_TEST_PREFIX
TEST_BASE_DIR = DEFAULT_TEST_BASE_DIR
DEFAULT_WAIT_TIMEOUT = 120
DEFAULT_REACHABILITY_TIMEOUT = 20
DEFAULT_ASSERT_RETRIES = 30

BGP_FSM_IDLE = 'idle'
BGP_FSM_ACTIVE = 'active'
BGP_FSM_ESTABLISHED = 'established'

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

GRACEFUL_RESTART_TIME = 30
LONG_LIVED_GRACEFUL_RESTART_TIME = 30

FLOWSPEC_NAME_TO_TYPE = {
    "destination": 1,
    "source": 2,
    "protocol": 3,
    "port": 4,
    "destination-port": 5,
    "source-port": 6,
    "icmp-type": 7,
    "icmp-code": 8,
    "tcp-flags": 9,
    "packet-length": 10,
    "dscp": 11,
    "fragment": 12,
    "label": 13,
    "ether-type": 14,
    "source-mac": 15,
    "destination-mac": 16,
    "llc-dsap": 17,
    "llc-ssap": 18,
    "llc-control": 19,
    "snap": 20,
    "vid": 21,
    "cos": 22,
    "inner-vid": 23,
    "inner-cos": 24,
}

# with this label, we can do filtering in `docker ps` and `docker network prune`
TEST_CONTAINER_LABEL = 'gobgp-test'
TEST_NETWORK_LABEL = TEST_CONTAINER_LABEL
DOCKER_NETWORK_CREATE_RETRIES = 5
# Scenario containers are attached to Docker bridges created during the test.
# It may be disabled or delayed by Duplicate Address detection defaults inherited
# from the daemon namespace; make the container side deterministic because tests
# start peering immediately after attach.
DOCKER_RUN_IPV6_SYSCTLS = (
    'net.ipv6.conf.all.disable_ipv6=0',
    'net.ipv6.conf.default.disable_ipv6=0',
    'net.ipv6.conf.all.accept_dad=0',
    'net.ipv6.conf.default.accept_dad=0',
)


def _timeout_scale():
    return max(float(getattr(parser_option, 'timeout_scale', 1.0)), 1.0)


def scale_timeout(timeout):
    if timeout is None:
        return None
    return int(math.ceil(float(timeout) * _timeout_scale()))


def scale_count(count):
    return int(math.ceil(float(count) * _timeout_scale()))


def local(s, capture=False, timeout=None):
    print('[localhost] local:', s)
    _env = {'NOSE_NOLOGCAPTURE': '1' if capture else '0'}
    # Keep stderr visible in pytest logs. The Docker CLI often puts the useful
    # failure reason there, while check_output only preserved stdout.
    result = subprocess.run(
        s,
        shell=True,
        env=_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=scale_timeout(timeout),
    )
    stdout = result.stdout.decode('utf-8')
    stderr = result.stderr.decode('utf-8')
    if stderr:
        print(stderr, end='')
    if result.returncode != 0:
        if stdout:
            print(stdout, end='')
        raise subprocess.CalledProcessError(
            result.returncode,
            s,
            output=result.stdout,
            stderr=result.stderr,
        )
    return stdout.strip()


def yellow(s):
    return fg('yellow') + str(s) + attr('reset')


def indent(s):
    return textwrap.indent(str(s), ' '*4, lambda line: True)


def community_str(i):
    """
    Converts integer in to colon separated two bytes decimal strings like
    BGP Community or Large Community representation.

    For example, this function converts 13107300 = ((200 << 16) | 100)
    into "200:100".
    """
    values = []
    while i > 0:
        values.append(str(i & 0xffff))
        i >>= 16
    return ':'.join(reversed(values))


def wait_for(f, timeout=DEFAULT_WAIT_TIMEOUT, interval=1, timeout_message='timeout'):
    timeout = scale_timeout(timeout)
    count = 0
    while True:
        if f():
            return

        time.sleep(interval)
        if timeout is not None:
            count += interval
        if timeout is not None and count >= timeout:
            if callable(timeout_message):
                timeout_message = timeout_message()
            raise Exception('{0} after {1}s'.format(timeout_message, timeout))


def wait_for_completion(f, timeout=DEFAULT_WAIT_TIMEOUT):
    wait_for(f, timeout=timeout)


def try_several_times(f, t=3, s=1):
    for _ in range(scale_count(t)):
        try:
            r = f()
        except RuntimeError:
            time.sleep(s)
        else:
            return r
    raise Exception


def assert_several_times(f, t=DEFAULT_ASSERT_RETRIES, s=1):
    e = AssertionError
    for _ in range(scale_count(t)):
        try:
            f()
        except AssertionError as ae:
            time.sleep(s)
            e = ae
        else:
            return
    raise e


def get_bridges():
    return try_several_times(lambda: local("docker network ls | awk 'NR > 1{print $2}'", capture=True)).split('\n')


def get_containers():
    return try_several_times(lambda: local("docker ps -a | awk 'NR > 1 {print $NF}'", capture=True)).split('\n')


def docker_run_ipv6_sysctl_args():
    return ' '.join('--sysctl={0}'.format(s) for s in DOCKER_RUN_IPV6_SYSCTLS)


def _best_effort_local(s, capture=True):
    try:
        return local(s, capture=capture)
    except subprocess.CalledProcessError:
        pass
    except subprocess.TimeoutExpired as e:
        print('command timed out: {0}'.format(e.cmd))
    return ''


def cleanup_docker_leftovers():
    # Scenario-owned Docker objects are labeled; clean only that label so a
    # failed setup cannot poison the next pytest session or the next CI retry.
    containers = local(
        'docker ps -aq -f label={0}'.format(TEST_CONTAINER_LABEL),
        capture=True,
    ).split()
    if containers:
        local('docker rm -f {0}'.format(' '.join(containers)), capture=True)

    networks = local(
        'docker network ls -q -f label={0}'.format(TEST_NETWORK_LABEL),
        capture=True,
    ).split()
    if networks:
        local('docker network rm {0}'.format(' '.join(networks)), capture=True)


def dump_docker_diagnostics(context, network_names=None, container_names=None):
    # Network-create and IPv6 link-local failures are usually environment
    # dependent. Dump Docker and kernel network state before teardown removes
    # the evidence.
    print('[docker diagnostics] {0}'.format(context))
    commands = [
        'docker version',
        'docker info',
        'docker ps -a',
        'docker network ls',
        'ip link',
        'ip -6 route',
        'tail -120 /tmp/gobgp/dockerd.log',
    ]
    for command in commands:
        output = _best_effort_local(command, capture=True)
        if output:
            print('[{0}]\n{1}'.format(command, output))

    network_names = network_names or []
    for name in network_names:
        output = _best_effort_local(
            'docker network inspect {0}'.format(name),
            capture=True,
        )
        if output:
            print('[docker network inspect {0}]\n{1}'.format(name, output))

    labeled_networks = _best_effort_local(
        'docker network ls -q -f label={0}'.format(TEST_NETWORK_LABEL),
        capture=True,
    ).split()
    if labeled_networks:
        output = _best_effort_local(
            'docker network inspect {0}'.format(' '.join(labeled_networks)),
            capture=True,
        )
        if output:
            print('[labeled docker network inspect]\n{0}'.format(output))

    container_names = container_names or []
    for name in container_names:
        for command in (
            'docker inspect {0}'.format(name),
            'docker exec {0} ip -6 -o addr'.format(name),
            'docker exec {0} ip -6 neigh'.format(name),
        ):
            output = _best_effort_local(command, capture=True)
            if output:
                print('[{0}]\n{1}'.format(command, output))


def scenario_docker_preflight(gobgp_image):
    # Fail before collection if the Docker daemon cannot provide the two IPv6
    # primitives these scenarios depend on: a policy-test-sized IPv6 bridge and
    # bidirectional link-local reachability between containers.
    suffix = '{0}_{1}'.format(os.getpid(), int(time.time() * 1000))
    policy_network = 'gobgp_ipv6_policy_preflight_{0}'.format(suffix)
    ll_network = 'gobgp_ipv6_ll_preflight_{0}'.format(suffix)
    c1 = 'gobgp_ipv6_preflight_a_{0}'.format(suffix)
    c2 = 'gobgp_ipv6_preflight_b_{0}'.format(suffix)
    sysctls = docker_run_ipv6_sysctl_args()

    try:
        local(
            'docker network create --driver bridge --ipv6 --subnet 2001::/96 '
            '--label {0} {1}'.format(TEST_NETWORK_LABEL, policy_network),
            capture=True,
        )
        local('docker network rm {0}'.format(policy_network), capture=True)
        local(
            'docker network create --driver bridge --ipv6 '
            '--subnet fd00:ffff:1::/64 --label {0} {1}'.format(
                TEST_NETWORK_LABEL,
                ll_network,
            ),
            capture=True,
        )
        for name in (c1, c2):
            local(
                'docker run --privileged=true {0} --name {1} -l {2} -id {3}'.format(
                    sysctls,
                    name,
                    TEST_CONTAINER_LABEL,
                    gobgp_image,
                ),
                capture=True,
            )
            local('docker network connect {0} {1}'.format(ll_network, name))

        time.sleep(2)
        c1_lladdr = local(
            "docker exec {0} sh -c \"ip -6 -o addr show dev eth1 scope link "
            "| awk '/ fe80:/ {{print \\$4; exit}}' | cut -d/ -f1\"".format(c1),
            capture=True,
        )
        c2_lladdr = local(
            "docker exec {0} sh -c \"ip -6 -o addr show dev eth1 scope link "
            "| awk '/ fe80:/ {{print \\$4; exit}}' | cut -d/ -f1\"".format(c2),
            capture=True,
        )
        if not c1_lladdr or not c2_lladdr:
            raise RuntimeError('IPv6 link-local address was not assigned')

        local(
            'docker exec {0} ping6 -c 1 -W 1 {1}%eth1'.format(c1, c2_lladdr),
            timeout=5,
        )
        local(
            'docker exec {0} ping6 -c 1 -W 1 {1}%eth1'.format(c2, c1_lladdr),
            timeout=5,
        )
    except Exception:
        dump_docker_diagnostics(
            'scenario Docker IPv6 preflight failed',
            network_names=[policy_network, ll_network],
            container_names=[c1, c2],
        )
        raise
    finally:
        _best_effort_local('docker rm -f {0} {1}'.format(c1, c2), capture=True)
        for name in (policy_network, ll_network):
            # The policy network is removed during the positive path; check
            # existence here so successful preflight cleanup stays quiet.
            if name in _best_effort_local(
                'docker network ls --format "{{.Name}}"',
                capture=True,
            ).split():
                _best_effort_local('docker network rm {0}'.format(name), capture=True)


class CmdBuffer(list):
    def __init__(self, delim='\n'):
        super(CmdBuffer, self).__init__()
        self.delim = delim

    def __lshift__(self, value):
        self.append(value)

    def __str__(self):
        return self.delim.join(self)


class Bridge(object):
    def __init__(self, name, subnet='', with_ip=True, self_ip=False):
        self.name = name
        if TEST_PREFIX != '':
            self.name = '{0}_{1}'.format(TEST_PREFIX, name)
        self.with_ip = with_ip
        if with_ip:
            self.subnet = netaddr.IPNetwork(subnet)

            def _f():
                for host in self.subnet:
                    yield host
            self._ip_generator = _f()
            # throw away first network address
            self.next_ip_address()

        self._create_network(subnet)

        self.self_ip = self_ip
        if self_ip:
            self.ip_addr = self.next_ip_address()
            try_several_times(lambda: local("ip addr add {0} dev {1}".format(self.ip_addr, self.name)))
        self.ctns = []

        # Note: Here removes routes from the container host to prevent traffic
        # from going through the container host's routing table.
        if with_ip:
            local('ip route del {0}; echo $?'.format(subnet),
                  capture=True)
            # When IPv6, 2 routes will be installed to the container host's
            # routing table.
            if self.subnet.version == 6:
                local('ip -6 route del {0}; echo $?'.format(subnet),
                      capture=True)

    def _bridge_link_name(self):
        if not getattr(self, 'id', ''):
            return ''
        return 'br-{0}'.format(self.id[:12])

    def _set_bridge_link_up(self):
        bridge_link = self._bridge_link_name()
        if bridge_link:
            # Network object can exist while the Linux bridge is
            # still DOWN. Bring it up before route cleanup and container attach.
            _best_effort_local(
                'ip link set {0} up >/dev/null 2>&1 || true'.format(bridge_link),
                capture=True,
            )

    def _remove_existing_network(self):
        if self.name in get_bridges():
            self.delete()

    def _recover_created_network(self):
        # docker network create can return non-zero after creating the network
        # object when bridge setup races with kernel route/link initialization.
        # Reuse that object instead of retrying into a name conflict.
        try:
            self.id = local(
                "docker network inspect -f '{{{{.Id}}}}' {0}".format(self.name),
                capture=True,
            )
        except subprocess.CalledProcessError:
            return False
        if not self.id:
            return False
        self._set_bridge_link_up()
        return True

    def _create_network(self, subnet):
        v6 = ''
        if self.subnet.version == 6:
            v6 = '--ipv6'

        command = (
            'docker network create --driver bridge {0} --subnet {1} '
            '--label {2} {3}'.format(v6, subnet, TEST_NETWORK_LABEL, self.name)
        )
        last_error = None
        for attempt in range(1, DOCKER_NETWORK_CREATE_RETRIES + 1):
            self._remove_existing_network()
            try:
                self.id = local(command, capture=True)
                self._set_bridge_link_up()
                return
            except subprocess.CalledProcessError as e:
                last_error = e
                if self._recover_created_network():
                    return
                print(
                    'docker network create failed for {0} '
                    '(attempt {1}/{2})'.format(
                        self.name,
                        attempt,
                        DOCKER_NETWORK_CREATE_RETRIES,
                    )
                )
                _best_effort_local(
                    'docker network rm {0}'.format(self.name),
                    capture=True,
                )
                if attempt < DOCKER_NETWORK_CREATE_RETRIES:
                    time.sleep(min(attempt, 5))

        # Print diagnostics only after all recovery paths failed, otherwise
        # transient Docker startup races would drown normal test logs.
        dump_docker_diagnostics(
            'docker network create failed for {0}'.format(self.name),
            network_names=[self.name],
        )
        if last_error:
            raise last_error
        raise RuntimeError('docker network create failed for {0}'.format(self.name))

    def next_ip_address(self):
        return "{0}/{1}".format(next(self._ip_generator),
                                self.subnet.prefixlen)

    def addif(self, ctn, ip_addr=''):
        _name = ctn.next_if_name()
        self.ctns.append(ctn)
        ip = ''
        if not ip_addr == '':
            ip = '--ip {0}'.format(ip_addr)
            if self.subnet.version == 6:
                ip = '--ip6 {0}'.format(ip_addr)
        local("docker network connect {0} {1} {2}".format(ip, self.name, ctn.docker_name()))
        i = [x for x in list(Client(timeout=scale_timeout(60), version='auto').inspect_network(self.id)['Containers'].values()) if x['Name'] == ctn.docker_name()][0]
        if self.subnet.version == 4:
            eth = 'eth{0}'.format(len(ctn.ip_addrs))
            addr = i['IPv4Address']
            ctn.ip_addrs.append((eth, addr, self.name))
        else:
            eth = 'eth{0}'.format(len(ctn.ip6_addrs))
            addr = i['IPv6Address']
            ctn.ip6_addrs.append((eth, addr, self.name))

    def delete(self):
        try_several_times(lambda: local("docker network rm {0}".format(self.name)))


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
            return '{0}'.format(self.name)
        return '{0}_{1}'.format(TEST_PREFIX, self.name)

    def next_if_name(self):
        name = 'eth{0}'.format(len(self.eths) + 1)
        self.eths.append(name)
        return name

    def run(self):
        c = CmdBuffer(' ')
        c << "docker run --privileged=true"
        # Keep IPv6 behavior identical for every scenario container; otherwise
        # per-image defaults leak into route-server and unnumbered tests.
        c << docker_run_ipv6_sysctl_args()
        for sv in self.shared_volumes:
            c << "-v {0}:{1}".format(sv[0], sv[1])
        c << "--name {0} -l {1} -id {2}".format(self.docker_name(), TEST_CONTAINER_LABEL, self.image)
        self.id = try_several_times(lambda: local(str(c), capture=True))
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
        ret = try_several_times(lambda: local("docker stop -t 0 " + self.docker_name(), capture=True))
        self.is_running = False
        return ret

    def remove(self):
        ret = try_several_times(lambda: local("docker rm -f " + self.docker_name(), capture=True))
        self.is_running = False
        return ret

    def local(self, cmd, capture=False, stream=False, detach=False, tty=True,
              timeout=None):
        if stream:
            dckr = Client(timeout=scale_timeout(120), version='auto')
            i = dckr.exec_create(container=self.docker_name(), cmd=cmd)
            return dckr.exec_start(i['Id'], tty=tty, stream=stream, detach=detach)
        else:
            flag = '-d' if detach else ''
            return local(
                'docker exec {0} {1} {2}'.format(flag, self.docker_name(), cmd),
                capture,
                timeout=timeout,
            )

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
        local('if [ -e {0} ]; then rm -rf {0}; fi'.format(self.config_dir))
        local('mkdir -p {0}'.format(self.config_dir))
        local('chmod 777 {0}'.format(self.config_dir))
        self.asn = asn
        self.router_id = router_id
        self.peers = {}
        self.routes = {}
        self.policies = {}
        super(BGPContainer, self).__init__(name, ctn_image_name)

    def __repr__(self):
        return str({'name': self.name, 'asn': self.asn, 'router_id': self.router_id})

    def run(self):
        self.create_config()
        super(BGPContainer, self).run()
        return self.WAIT_FOR_BOOT

    def peer_name(self, peer):
        if peer not in self.peers:
            raise Exception('not found peer {0}'.format(peer.router_id))
        name = self.peers[peer]['interface']
        if name == '':
            name = self.peers[peer]['neigh_addr'].split('/')[0]
        return name

    def update_peer(self, peer, **kwargs):
        if peer not in self.peers:
            raise Exception('peer not exists')
        self.add_peer(peer, **kwargs)

    def add_peer(
        self,
        peer,
        passwd=None,
        vpn=False,
        is_rs_client=False,
        policies=None,
        passive=False,
        is_rr_client=False,
        cluster_id=None,
        flowspec=False,
        bridge="",
        reload_config=True,
        as2=False,
        graceful_restart=None,
        local_as=None,
        prefix_limit=None,
        v6=False,
        llgr=None,
        vrf="",
        interface="",
        allow_as_in=0,
        remove_private_as=None,
        replace_peer_as=False,
        addpath=0,
        treat_as_withdraw=False,
        remote_as=None,
        mup=False,
        bind_interface="",
    ):
        neigh_addr = ''
        local_addr = ''
        it = itertools.product(self.ip_addrs, peer.ip_addrs)
        if v6:
            it = itertools.product(self.ip6_addrs, peer.ip6_addrs)

        if interface == '':
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
                            'interface': interface,
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
                            'prefix_limit': prefix_limit,
                            'llgr': llgr,
                            'vrf': vrf,
                            'allow_as_in': allow_as_in,
                            'remove_private_as': remove_private_as,
                            'replace_peer_as': replace_peer_as,
                            'addpath': addpath,
                            'treat_as_withdraw': treat_as_withdraw,
                            'remote_as': remote_as or peer.asn,
                            'mup': mup,
                            'bind_interface': bind_interface}
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

    def _extract_routes(self, families):
        routes = {}
        for prefix, paths in list(self.routes.items()):
            if paths and paths[0]['rf'] in families:
                routes[prefix] = paths
        return routes

    def add_route(self, route, rf='ipv4', attribute=None, aspath=None,
                  community=None, med=None, extendedcommunity=None,
                  nexthop=None, matchs=None, thens=None,
                  local_pref=None, identifier=None, reload_config=True):
        if route not in self.routes:
            self.routes[route] = []
        prefix = route
        if 'flowspec' in rf:
            prefix = ' '.join(['match'] + matchs)
        self.routes[route].append({
            'prefix': prefix,
            'rf': rf,
            'attr': attribute,
            'next-hop': nexthop,
            'as-path': aspath,
            'community': community,
            'med': med,
            'local-pref': local_pref,
            'extended-community': extendedcommunity,
            'identifier': identifier,
            'matchs': matchs,
            'thens': thens,
        })
        if self.is_running and reload_config:
            self.create_config()
            self.reload_config()

    def del_route(self, route, identifier=None, reload_config=True):
        if route not in self.routes:
            return
        self.routes[route] = [p for p in self.routes[route] if p['identifier'] != identifier]
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

    def get_reachability(self, prefix, timeout=DEFAULT_REACHABILITY_TIMEOUT):
        version = netaddr.IPNetwork(prefix).version
        addr = prefix.split('/')[0]
        if version == 4:
            ping_cmd = 'ping'
        elif version == 6:
            ping_cmd = 'ping6'
        else:
            raise Exception('unsupported route family: {0}'.format(version))
        cmd = '/bin/bash -c "/bin/{0} -c 1 -w 1 {1} | xargs echo"'.format(ping_cmd, addr)

        def _reachable():
            res = self.local(cmd, capture=True)
            print(yellow(res))
            return ('1 packets received' in res or '1 received' in res) and '0% packet loss' in res

        wait_for(_reachable, timeout=timeout, timeout_message='reachability timeout')
        return True

    def wait_for(self, expected_state, peer, timeout=DEFAULT_WAIT_TIMEOUT):
        def _state_matches():
            state = self.get_neighbor_state(peer)
            print(yellow("{0}'s peer {1} state: {2}".format(self.router_id,
                                                            peer.router_id,
                                                            state)))
            return state == expected_state

        wait_for(
            _state_matches,
            timeout=timeout,
            timeout_message="timeout waiting for {0}'s peer {1} to be {2}".format(
                self.router_id, peer.router_id, expected_state,
            ),
        )

    def add_static_route(self, network, next_hop):
        cmd = '/sbin/ip route add {0} via {1}'.format(network, next_hop)
        self.local(cmd, capture=True)

    def set_ipv6_forward(self):
        cmd = 'sysctl -w net.ipv6.conf.all.forwarding=1'
        self.local(cmd, capture=True)

    def create_config(self):
        raise Exception('implement create_config() method')

    def reload_config(self):
        raise Exception('implement reload_config() method')

    def show_addr(self):
        cmd = '/sbin/ip addr'
        res = self.local(cmd, capture=True)
        print(yellow(res))

    def show_route(self, ipv6=False):
        if ipv6:
            cmd = '/sbin/ip -6 route'
        else:
            cmd = '/sbin/ip route'
        res = self.local(cmd, capture=True)
        print(yellow(res))

class OSPFContainer(Container):
    WAIT_FOR_BOOT = 1

    def __init__(self, name, ctn_image_name):
        self.config_dir = '/'.join((TEST_BASE_DIR, TEST_PREFIX, name))
        local('if [ -e {0} ]; then rm -rf {0}; fi'.format(self.config_dir))
        local('mkdir -p {0}'.format(self.config_dir))
        local('chmod 777 {0}'.format(self.config_dir))

        # Example:
        # networks = {
        #     '192.168.1.0/24': '0.0.0.0',  # <network>: <area>
        # }
        self.networks = {}
        super(OSPFContainer, self).__init__(name, ctn_image_name)

    def __repr__(self):
        return str({'name': self.name, 'networks': self.networks})

    def run(self):
        self.create_config()
        super(OSPFContainer, self).run()
        return self.WAIT_FOR_BOOT

    def create_config(self):
        raise NotImplementedError
