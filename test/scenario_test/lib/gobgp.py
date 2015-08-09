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
        self.local("{0}/start.sh".format(self.SHARED_VOLUME), flag='-d')

    def run(self):
        super(GoBGPContainer, self).run()
        self._start_gobgp()
        return self.WAIT_FOR_BOOT

    def _get_as_path(self, path):
        asps = (p['as_paths'] for p in path['attrs'] if
                p['type'] == BGP_ATTR_TYPE_AS_PATH and 'as_paths' in p
                and p['as_paths'] != None)
        asps = chain.from_iterable(asps)
        asns = (asp['asns'] for asp in asps)
        return list(chain.from_iterable(asns))

    def _get_nexthop(self, path):
        for p in path['attrs']:
            if p['type'] == BGP_ATTR_TYPE_NEXT_HOP or p['type'] == BGP_ATTR_TYPE_MP_REACH_NLRI:
                return p['nexthop']

    def _trigger_peer_cmd(self, cmd, peer):
        if peer not in self.peers:
            raise Exception('not found peer {0}'.format(peer.router_id))
        peer_addr = self.peers[peer]['neigh_addr'].split('/')[0]
        cmd = 'gobgp neighbor {0} {1}'.format(peer_addr, cmd)
        self.local(cmd)

    def disable_peer(self, peer):
        self._trigger_peer_cmd('disable', peer)

    def enable_peer(self, peer):
        self._trigger_peer_cmd('enable', peer)

    def get_local_rib(self, peer, rf='ipv4'):
        if peer not in self.peers:
            raise Exception('not found peer {0}'.format(peer.router_id))
        peer_addr = self.peers[peer]['neigh_addr'].split('/')[0]
        cmd = 'gobgp -j neighbor {0} local -a {1}'.format(peer_addr, rf)
        output = self.local(cmd, capture=True)
        ret = json.loads(output)
        for d in ret:
            for p in d["paths"]:
                p["nexthop"] = self._get_nexthop(p)
                p["as_path"] = self._get_as_path(p)
        return ret

    def get_global_rib(self, prefix='', rf='ipv4'):
        cmd = 'gobgp -j global rib {0} -a {1}'.format(prefix, rf)
        output = self.local(cmd, capture=True)
        ret = json.loads(output)
        for d in ret:
            for p in d["paths"]:
                p["nexthop"] = self._get_nexthop(p)
                p["as_path"] = self._get_as_path(p)
        return ret

    def _get_adj_rib(self, adj_type, peer, prefix='', rf='ipv4'):
        if peer not in self.peers:
            raise Exception('not found peer {0}'.format(peer.router_id))
        peer_addr = self.peers[peer]['neigh_addr'].split('/')[0]
        cmd = 'gobgp neighbor {0} adj-{1} {2} -a {3} -j'.format(peer_addr,
                                                                adj_type,
                                                                prefix, rf)
        output = self.local(cmd, capture=True)
        ret = [p["paths"][0] for p in json.loads(output)]
        for p in ret:
            p["nexthop"] = self._get_nexthop(p)
            p["as_path"] = self._get_as_path(p)
        return ret

    def get_adj_rib_in(self, peer, prefix='', rf='ipv4'):
        return self._get_adj_rib('in', peer, prefix, rf)

    def get_adj_rib_out(self, peer, prefix='', rf='ipv4'):
        return self._get_adj_rib('out', peer, prefix, rf)

    def get_neighbor_state(self, peer):
        if peer not in self.peers:
            raise Exception('not found peer {0}'.format(peer.router_id))
        peer_addr = self.peers[peer]['neigh_addr'].split('/')[0]
        cmd = 'gobgp -j neighbor {0}'.format(peer_addr)
        output = self.local(cmd, capture=True)
        return json.loads(output)['info']['bgp_state']

    def create_config(self):
        config = {'Global': {'GlobalConfig': {'As': self.asn, 'RouterId': self.router_id}}}
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

            if info['flowspec']:
                afi_safi_list.append({'AfiSafiName': 'ipv4-flowspec'})

            n = {'NeighborConfig':
                 {'NeighborAddress': info['neigh_addr'].split('/')[0],
                  'PeerAs': peer.asn,
                  'AuthPassword': info['passwd'],
                  'PeerType': peer_type,
                  },
                 'AfiSafis': {'AfiSafiList': afi_safi_list}
                 }

            if info['passive']:
                n['Transport'] = {'TransportConfig': {'PassiveMode': True}}

            if info['is_rs_client']:
                n['RouteServer'] = {'RouteServerConfig': {'RouteServerClient': True}}

            if info['is_rr_client']:
                clusterId = info['cluster_id']
                n['RouteReflector'] = {'RouteReflectorClient': True,
                                       'RouteReflectorClusterId': clusterId}

            if 'Neighbors' not in config:
                config['Neighbors'] = {'NeighborList': []}

            config['Neighbors']['NeighborList'].append(n)

        with open('{0}/gobgpd.conf'.format(self.config_dir), 'w') as f:
            print colors.yellow('[{0}\'s new config]'.format(self.name))
            print colors.yellow(indent(toml.dumps(config)))
            f.write(toml.dumps(config))

    def reload_config(self):
        cmd = '/usr/bin/pkill gobgpd -SIGHUP'
        self.local(cmd)
        for v in self.routes.itervalues():
            if v['rf'] == 'ipv4' or v['rf'] == 'ipv6':
                cmd = 'gobgp global '\
                      'rib add {0} -a {1}'.format(v['prefix'], v['rf'])
            elif v['rf']== 'ipv4-flowspec':
                cmd = 'gobgp global '\
                      'rib add match {0} then {1} -a flow-ipv4'.format(' '.join(v['matchs']), ' '.join(v['thens']))
            else:
                raise Exception('unsupported route faily: {0}'.format(rf))
            self.local(cmd)
