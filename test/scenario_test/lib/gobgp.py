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
import json
import toml
from itertools import chain


class GoBGPContainer(BGPContainer):

    PEER_TYPE_INTERNAL = 0
    PEER_TYPE_EXTERNAL = 1
    SHARED_VOLUME = '/root/shared_volume'

    def __init__(self, name, asn, router_id, ctn_image_name='gobgp',
                 log_level='debug'):
        super(GoBGPContainer, self).__init__(name, asn, router_id,
                                             ctn_image_name)
        self.shared_volumes.append((self.config_dir, self.SHARED_VOLUME))
        self.log_level = log_level

    def _start_gobgp(self):
        c = CmdBuffer()
        c << '#!/bin/bash'
        c << '/go/bin/gobgpd -f {0}/gobgpd.conf -l {1} -p > ' \
             '{0}/gobgpd.log 2>&1'.format(self.SHARED_VOLUME, self.log_level)

        cmd = 'echo "{0:s}" > {1}/start.sh'.format(c, self.config_dir)
        local(cmd, capture=True)
        cmd = "chmod 755 {0}/start.sh".format(self.config_dir)
        local(cmd, capture=True)
        cmd = 'docker exec -d {0} {1}/start.sh'.format(self.name,
                                                       self.SHARED_VOLUME)
        local(cmd, capture=True)

    def run(self):
        super(GoBGPContainer, self).run()
        self._start_gobgp()
        return self.WAIT_FOR_BOOT

    def _get_as_path(self, path):
        asps = (p['as_paths'] for p in path['attrs'] if
                p['type'] == BGP_ATTR_TYPE_AS_PATH and 'as_paths' in p)
        asps = chain.from_iterable(asps)
        asns = (asp['asns'] for asp in asps)
        return list(chain.from_iterable(asns))

    def _trigger_peer_cmd(self, cmd, peer):
        if peer not in self.peers:
            raise Exception('not found peer {0}'.format(peer.router_id))
        peer_addr = self.peers[peer]['neigh_addr'].split('/')[0]
        cmd = "docker exec {0} gobgp neighbor {1} {2}".format(self.name,
                                                              peer_addr,
                                                              cmd)
        local(str(cmd), capture=True)

    def disable_peer(self, peer):
        self._trigger_peer_cmd('disable', peer)

    def enable_peer(self, peer):
        self._trigger_peer_cmd('enable', peer)

    def get_local_rib(self, peer, rf='ipv4'):
        if peer not in self.peers:
            raise Exception('not found peer {0}'.format(peer.router_id))
        peer_addr = self.peers[peer]['neigh_addr'].split('/')[0]
        gobgp = '/go/bin/gobgp'
        cmd = CmdBuffer(' ')
        cmd << "docker exec {0} {1}".format(self.name, gobgp)
        cmd << "-j neighbor {0} local -a {1}".format(peer_addr, rf)
        output = local(str(cmd), capture=True)
        n = json.loads(output)
        return n

    def get_global_rib(self, prefix='', rf='ipv4'):
        gobgp = '/go/bin/gobgp'
        cmd = 'docker exec {0} {1} -j global rib {2} -a {3}'.format(self.name,
                                                                    gobgp,
                                                                    prefix,
                                                                    rf)
        output = local(cmd, capture=True)
        return json.loads(output)

    def _get_adj_rib(self, adj_type, peer, prefix='', rf='ipv4'):
        if peer not in self.peers:
            raise Exception('not found peer {0}'.format(peer.router_id))
        peer_addr = self.peers[peer]['neigh_addr'].split('/')[0]
        gobgp = '/go/bin/gobgp'
        cmd = 'docker exec {0} {1} neighbor {2}'\
              ' adj-{3} {4} -a {5} -j'.format(self.name, gobgp, peer_addr,
                                              adj_type, prefix, rf)
        output = local(cmd, capture=True)
        return json.loads(output)

    def get_adj_rib_in(self, peer, prefix='', rf='ipv4'):
        return self._get_adj_rib('in', peer, prefix, rf)

    def get_adj_rib_out(self, peer, prefix='', rf='ipv4'):
        return self._get_adj_rib('out', peer, prefix, rf)

    def get_neighbor_state(self, peer):
        if peer not in self.peers:
            raise Exception('not found peer {0}'.format(peer.router_id))
        peer_addr = self.peers[peer]['neigh_addr'].split('/')[0]
        gobgp = '/go/bin/gobgp'
        cmd = 'docker exec {0} {1} -j neighbor {2}'.format(self.name,
                                                           gobgp,
                                                           peer_addr)
        output = local(cmd, capture=True)
        return json.loads(output)['info']['bgp_state']

    def create_config(self):
        config = {'Global': {'As': self.asn, 'RouterId': self.router_id}}
        for peer, info in self.peers.iteritems():
            if self.asn == peer.asn:
                peer_type = self.PEER_TYPE_INTERNAL
            else:
                peer_type = self.PEER_TYPE_EXTERNAL

            afi_safi_list = []
            version = netaddr.IPNetwork(info['neigh_addr']).version
            if version == 4:
                afi_safi_list.append({'AfiSafiName': 'ipv4-unicast'})
            elif version == 6:
                afi_safi_list.append({'AfiSafiName': 'ipv6-unicast'})
            else:
                Exception('invalid ip address version. {0}'.format(version))

            if info['evpn']:
                afi_safi_list.append({'AfiSafiName': 'l2vpn-evpn'})
                afi_safi_list.append({'AfiSafiName': 'encap'})
                afi_safi_list.append({'AfiSafiName': 'rtc'})

            n = {'NeighborAddress': info['neigh_addr'].split('/')[0],
                 'PeerAs': peer.asn,
                 'AuthPassword': info['passwd'],
                 'PeerType': peer_type,
                 'AfiSafiList': afi_safi_list}

            if info['passive']:
                n['TransportOptions'] = {'PassiveMode': True}

            if info['is_rs_client']:
                n['RouteServer'] = {'RouteServerClient': True}

            if info['is_rr_client']:
                clusterId = info['cluster_id']
                n['RouteReflector'] = {'RouteReflectorClient': True,
                                       'RouteReflectorClusterId': clusterId}

            if 'NeighborList' not in config:
                config['NeighborList'] = []

            config['NeighborList'].append(n)

        with open('{0}/gobgpd.conf'.format(self.config_dir), 'w') as f:
            print colors.yellow('[{0}\'s new config]'.format(self.name))
            print colors.yellow(indent(toml.dumps(config)))
            f.write(toml.dumps(config))

    def reload_config(self):
        cmd = 'docker exec {0} /usr/bin/pkill gobgpd -SIGHUP'.format(self.name)
        local(cmd, capture=True)
        for v in self.routes.itervalues():
            cmd = 'docker exec {0} gobgp global '\
                  'rib add {1} -a {2}'.format(self.name, v['prefix'], v['rf'])
            local(cmd, capture=True)
