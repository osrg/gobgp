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

from base import *
import telnetlib


class QuaggaTelnetDaemon(object):
    TELNET_PASSWORD = "zebra"
    TELNET_PORT = 2605

    def __init__(self, ctn):
        ip_addr = None
        for _, ip_addr, br in ctn.ip_addrs:
            if br.ip_addr:
                break

        if not ip_addr:
            Exception('quagga telnet daemon {0}'
                      ' is not ip reachable'.format(self.name))

        self.host = ip_addr.split('/')[0]

    def __enter__(self):
        self.tn = telnetlib.Telnet(self.host, self.TELNET_PORT)
        self.tn.read_until("Password: ")
        self.tn.write(self.TELNET_PASSWORD + "\n")
        self.tn.write("enable\n")
        self.tn.read_until('bgpd#')
        return self.tn

    def __exit__(self, type, value, traceback):
        self.tn.close()


class QuaggaBGPContainer(BGPContainer):

    WAIT_FOR_BOOT = 1
    SHARED_VOLUME = '/etc/quagga'

    def __init__(self, name, asn, router_id, ctn_image_name='osrg/quagga'):
        super(QuaggaBGPContainer, self).__init__(name, asn, router_id,
                                                 ctn_image_name)
        self.shared_volumes.append((self.config_dir, self.SHARED_VOLUME))

    def run(self):
        super(QuaggaBGPContainer, self).run()
        return self.WAIT_FOR_BOOT

    def get_global_rib(self, prefix='', rf='ipv4'):
        rib = []
        if prefix != '':
            return self.get_global_rib_with_prefix(prefix, rf)
        with QuaggaTelnetDaemon(self) as tn:
            tn.write('show bgp {0} unicast\n'.format(rf))
            tn.read_until('   Network          Next Hop            Metric '
                          'LocPrf Weight Path')
            for line in tn.read_until('bgpd#').split('\n'):
                if line[:2] == '*>':
                    line = line[2:]
                    ibgp = False
                    if line[0] == 'i':
                        line = line[1:]
                        ibgp = True
                    elems = line.split()
                    rib.append({'prefix': elems[0], 'nexthop': elems[1],
                                'ibgp': ibgp})

        return rib

    def get_global_rib_with_prefix(self, prefix, rf):
        rib = []
        with QuaggaTelnetDaemon(self) as tn:
            tn.write('show bgp {0} unicast {1}\n'.format(rf, prefix))
            lines = [line.strip() for line in tn.read_until('bgpd#').split('\n')]
            lines.pop(0)  # throw away first line contains 'show bgp...'
            if lines[0] == '% Network not in table':
                return rib

            lines = lines[2:]

            if lines[0].startswith('Not advertised'):
                lines.pop(0)  # another useless line
            elif lines[0].startswith('Advertised to non peer-group peers:'):
                lines = lines[2:]  # other useless lines
            else:
                raise Exception('unknown output format {0}'.format(lines))
            nexthop = lines[1].split()[0].strip()
            aspath = [int(asn) for asn in lines[0].split()]
            rib.append({'prefix': prefix, 'nexthop': nexthop,
                        'aspath': aspath})
        return rib

    def get_neighbor_state(self, peer):
        if peer not in self.peers:
            raise Exception('not found peer {0}'.format(peer.router_id))

        neigh_addr = self.peers[peer]['neigh_addr'].split('/')[0]

        with QuaggaTelnetDaemon(self) as tn:
            tn.write('show bgp neighbors\n')
            neighbor_info = []
            curr_info = []
            for line in tn.read_until('bgpd#').split('\n'):
                line = line.strip()
                if line.startswith('BGP neighbor is'):
                    neighbor_info.append(curr_info)
                    curr_info = []
                curr_info.append(line)
            neighbor_info.append(curr_info)

            for info in neighbor_info:
                if not info[0].startswith('BGP neighbor is'):
                    continue
                idx1 = info[0].index('BGP neighbor is ')
                idx2 = info[0].index(',')
                n_addr = info[0][idx1+len('BGP neighbor is '):idx2]
                if n_addr == neigh_addr:
                    idx1 = info[2].index('= ')
                    state = info[2][idx1+len('= '):]
                    if state.startswith('Idle'):
                        return BGP_FSM_IDLE
                    elif state.startswith('Active'):
                        return BGP_FSM_ACTIVE
                    elif state.startswith('Established'):
                        return BGP_FSM_ESTABLISHED
                    else:
                        return state

            raise Exception('not found peer {0}'.format(peer.router_id))

    def create_config(self):
        c = CmdBuffer()
        c << 'hostname bgpd'
        c << 'password zebra'
        c << 'router bgp {0}'.format(self.asn)
        c << 'bgp router-id {0}'.format(self.router_id)

        for peer, info in self.peers.iteritems():
            version = netaddr.IPNetwork(info['neigh_addr']).version
            n_addr = info['neigh_addr'].split('/')[0]
            if version == 6:
                c << 'no bgp default ipv4-unicast'

            c << 'neighbor {0} remote-as {1}'.format(n_addr, peer.asn)
            for policy in info['policies']:
                name = policy['name']
                direction = policy['direction']
                c << 'neighbor {0} route-map {1} {2}'.format(n_addr, name,
                                                             direction)
            if info['passwd'] != '':
                c << 'neighbor {0} password {1}'.format(n_addr, info['passwd'])
            if version == 6:
                c << 'address-family ipv6 unicast'
                c << 'neighbor {0} activate'.format(n_addr)
                c << 'exit-address-family'

        for route in self.routes.iterkeys():
            version = netaddr.IPNetwork(route).version
            if version == 4:
                c << 'network {0}'.format(route)
            elif version == 6:
                c << 'address-family ipv6 unicast'
                c << 'network {0}'.format(route)
                c << 'exit-address-family'

        for name, policy in self.policies.iteritems():
            c << 'access-list {0} {1} {2}'.format(name, policy['type'],
                                                  policy['match'])
            c << 'route-map {0} permit 10'.format(name)
            c << 'match ip address {0}'.format(name)
            c << 'set metric {0}'.format(policy['med'])

        c << 'debug bgp as4'
        c << 'debug bgp fsm'
        c << 'debug bgp updates'
        c << 'debug bgp events'
        c << 'log file /tmp/bgpd.log'.format(self.SHARED_VOLUME)

        with open('{0}/bgpd.conf'.format(self.config_dir), 'w') as f:
            print colors.yellow('[{0}\'s new config]'.format(self.name))
            print colors.yellow(indent(str(c)))
            f.writelines(str(c))

    def reload_config(self):
        cmd = 'docker exec {0} /usr/bin/pkill bgpd -SIGHUP'.format(self.name)
        local(cmd, capture=True)
