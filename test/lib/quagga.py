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
from nsenter import Namespace


class QuaggaTelnetDaemon(object):
    TELNET_PASSWORD = "zebra"
    TELNET_PORT = 2605

    def __init__(self, ctn):
        self.ns = Namespace(ctn.get_pid(), 'net')

    def __enter__(self):
        self.ns.__enter__()
        self.tn = telnetlib.Telnet('127.0.0.1', self.TELNET_PORT)
        self.tn.read_until("Password: ")
        self.tn.write(self.TELNET_PASSWORD + "\n")
        self.tn.write("enable\n")
        self.tn.read_until('bgpd#')
        return self.tn

    def __exit__(self, type, value, traceback):
        self.tn.close()
        self.ns.__exit__(type, value, traceback)


class QuaggaBGPContainer(BGPContainer):

    WAIT_FOR_BOOT = 1
    SHARED_VOLUME = '/etc/quagga'

    def __init__(self, name, asn, router_id, ctn_image_name='osrg/quagga', zebra=False):
        super(QuaggaBGPContainer, self).__init__(name, asn, router_id,
                                                 ctn_image_name)
        self.shared_volumes.append((self.config_dir, self.SHARED_VOLUME))
        self.zebra = zebra

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
            read_next = False
            for line in tn.read_until('bgpd#').split('\n'):
                if line[:2] == '*>':
                    line = line[2:]
                    ibgp = False
                    if line[0] == 'i':
                        line = line[1:]
                        ibgp = True
                elif not read_next:
                    continue

                elems = line.split()

                if len(elems) == 1:
                    read_next = True
                    prefix = elems[0]
                    continue
                elif read_next:
                    nexthop = elems[0]
                else:
                    prefix = elems[0]
                    nexthop = elems[1]
                read_next = False

                rib.append({'prefix': prefix, 'nexthop': nexthop,
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
            aspath = [int(asn) for asn in lines[0].split()]
            nexthop = lines[1].split()[0].strip()
            info = [s.strip(',') for s in lines[2].split()]
            attrs = []
            if 'metric' in info:
                med = info[info.index('metric') + 1]
                attrs.append({'type': BGP_ATTR_TYPE_MULTI_EXIT_DISC, 'metric': int(med)})
            if 'localpref' in info:
                localpref = info[info.index('localpref') + 1]
                attrs.append({'type': BGP_ATTR_TYPE_LOCAL_PREF, 'value': int(localpref)})

            rib.append({'prefix': prefix, 'nexthop': nexthop,
                        'aspath': aspath, 'attrs': attrs})
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

    def send_route_refresh(self):
        with QuaggaTelnetDaemon(self) as tn:
            tn.write('clear ip bgp * soft\n')
            #tn.read_until('bgpd#')

    def create_config(self):
        self._create_config_bgp()
        if self.zebra:
            self._create_config_zebra()

    def _create_config_bgp(self):

        c = CmdBuffer()
        c << 'hostname bgpd'
        c << 'password zebra'
        c << 'router bgp {0}'.format(self.asn)
        c << 'bgp router-id {0}'.format(self.router_id)
        if any(info['graceful_restart'] for info in self.peers.itervalues()):
            c << 'bgp graceful-restart'

        version = 4
        for peer, info in self.peers.iteritems():
            version = netaddr.IPNetwork(info['neigh_addr']).version
            n_addr = info['neigh_addr'].split('/')[0]
            if version == 6:
                c << 'no bgp default ipv4-unicast'

            c << 'neighbor {0} remote-as {1}'.format(n_addr, peer.asn)
            if info['is_rs_client']:
                c << 'neighbor {0} route-server-client'.format(n_addr)
            for name, policy in info['policies'].iteritems():
                direction = policy['direction']
                c << 'neighbor {0} route-map {1} {2}'.format(n_addr, name,
                                                             direction)
            if info['passwd']:
                c << 'neighbor {0} password {1}'.format(n_addr, info['passwd'])
            if info['passive']:
                c << 'neighbor {0} passive'.format(n_addr)
            if version == 6:
                c << 'address-family ipv6 unicast'
                c << 'neighbor {0} activate'.format(n_addr)
                c << 'exit-address-family'

        for route in self.routes.itervalues():
            if route['rf'] == 'ipv4':
                c << 'network {0}'.format(route['prefix'])
            elif route['rf'] == 'ipv6':
                c << 'address-family ipv6 unicast'
                c << 'network {0}'.format(route['prefix'])
                c << 'exit-address-family'
            else:
                raise Exception('unsupported route faily: {0}'.format(route['rf']))

        if self.zebra:
            if version == 6:
                c << 'address-family ipv6 unicast'
                c << 'redistribute connected'
                c << 'exit-address-family'
            else:
                c << 'redistribute connected'

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
        c << 'log file {0}/bgpd.log'.format(self.SHARED_VOLUME)

        with open('{0}/bgpd.conf'.format(self.config_dir), 'w') as f:
            print colors.yellow('[{0}\'s new config]'.format(self.name))
            print colors.yellow(indent(str(c)))
            f.writelines(str(c))

    def _create_config_zebra(self):
        c = CmdBuffer()
        c << 'hostname zebra'
        c << 'password zebra'
        c << 'log file {0}/zebra.log'.format(self.SHARED_VOLUME)
        c << 'debug zebra packet'
        c << 'debug zebra kernel'
        c << 'debug zebra rib'
        c << ''

        with open('{0}/zebra.conf'.format(self.config_dir), 'w') as f:
            print colors.yellow('[{0}\'s new config]'.format(self.name))
            print colors.yellow(indent(str(c)))
            f.writelines(str(c))

    def reload_config(self):
        daemon = []
        daemon.append('bgpd')
        if self.zebra:
            daemon.append('zebra')
        for d in daemon:
            cmd = '/usr/bin/pkill {0} -SIGHUP'.format(d)
            self.local(cmd, capture=True)
