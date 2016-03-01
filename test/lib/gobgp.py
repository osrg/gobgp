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

def extract_path_attribute(path, typ):
    for a in path['attrs']:
        if a['type'] == typ:
            return a
    return None

class GoBGPContainer(BGPContainer):

    SHARED_VOLUME = '/root/shared_volume'
    QUAGGA_VOLUME = '/etc/quagga'

    def __init__(self, name, asn, router_id, ctn_image_name='gobgp',
                 log_level='debug', zebra=False):
        super(GoBGPContainer, self).__init__(name, asn, router_id,
                                             ctn_image_name)
        self.shared_volumes.append((self.config_dir, self.SHARED_VOLUME))

        self.log_level = log_level
        self.prefix_set = None
        self.neighbor_set = None
        self.bgp_set = None
        self.default_policy = None
        self.zebra = zebra

    def _start_gobgp(self, graceful_restart=False):
        c = CmdBuffer()
        c << '#!/bin/bash'
        c << '/go/bin/gobgpd -f {0}/gobgpd.conf -l {1} -p {2} > ' \
             '{0}/gobgpd.log 2>&1'.format(self.SHARED_VOLUME, self.log_level, '-r' if graceful_restart else '')

        cmd = 'echo "{0:s}" > {1}/start.sh'.format(c, self.config_dir)
        local(cmd, capture=True)
        cmd = "chmod 755 {0}/start.sh".format(self.config_dir)
        local(cmd, capture=True)
        self.local("{0}/start.sh".format(self.SHARED_VOLUME), flag='-d')

    def graceful_restart(self):
        self.local("pkill -INT gobgpd")

    def _start_zebra(self):
        cmd = 'cp {0}/zebra.conf {1}/'.format(self.SHARED_VOLUME, self.QUAGGA_VOLUME)
        self.local(cmd)
        cmd = '/usr/lib/quagga/zebra -f {0}/zebra.conf'.format(self.QUAGGA_VOLUME)
        self.local(cmd, flag='-d')

    def run(self):
        super(GoBGPContainer, self).run()
        if self.zebra:
            self._start_zebra()
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

    def reset(self, peer):
        self._trigger_peer_cmd('reset', peer)

    def softreset(self, peer, rf='ipv4', type='in'):
        self._trigger_peer_cmd('softreset{0} -a {1}'.format(type, rf), peer)

    def get_local_rib(self, peer, prefix='', rf='ipv4'):
        if peer not in self.peers:
            raise Exception('not found peer {0}'.format(peer.router_id))
        peer_addr = self.peers[peer]['neigh_addr'].split('/')[0]
        cmd = 'gobgp -j neighbor {0} local {1} -a {2}'.format(peer_addr, prefix, rf)
        output = self.local(cmd, capture=True)
        ret = json.loads(output)
        for d in ret:
            for p in d["paths"]:
                p["nexthop"] = self._get_nexthop(p)
                p["aspath"] = self._get_as_path(p)
        return ret

    def get_global_rib(self, prefix='', rf='ipv4'):
        cmd = 'gobgp -j global rib {0} -a {1}'.format(prefix, rf)
        output = self.local(cmd, capture=True)
        ret = json.loads(output)
        for d in ret:
            for p in d["paths"]:
                p["nexthop"] = self._get_nexthop(p)
                p["aspath"] = self._get_as_path(p)
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
            p["aspath"] = self._get_as_path(p)
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

    def clear_policy(self):
        self.policies = {}
        for info in self.peers.itervalues():
            info['policies'] = {}
        self.prefix_set = []
        self.neighbor_set = []
        self.statements = []

    def set_prefix_set(self, ps):
        self.prefix_set = ps

    def set_neighbor_set(self, ns):
        self.neighbor_set = ns

    def set_bgp_defined_set(self, bs):
        self.bgp_set = bs

    def create_config(self):
        self._create_config_bgp()
        if self.zebra:
            self._create_config_zebra()

    def _create_config_bgp(self):
        config = {'global': {'config': {'as': self.asn, 'router-id': self.router_id}}}
        for peer, info in self.peers.iteritems():
            afi_safi_list = []
            version = netaddr.IPNetwork(info['neigh_addr']).version
            if version == 4:
                afi_safi_list.append({'afi-safi-name': 'ipv4-unicast'})
            elif version == 6:
                afi_safi_list.append({'afi-safi-name': 'ipv6-unicast'})
            else:
                Exception('invalid ip address version. {0}'.format(version))

            if info['evpn']:
                afi_safi_list.append({'afi-safi-name': 'l2vpn-evpn'})
                afi_safi_list.append({'afi-safi-name': 'encap'})
                afi_safi_list.append({'afi-safi-name': 'rtc'})

            if info['flowspec']:
                afi_safi_list.append({'afi-safi-name': 'ipv4-flowspec'})
                afi_safi_list.append({'afi-safi-name': 'l3vpn-ipv4-flowspec'})
                afi_safi_list.append({'afi-safi-name': 'ipv6-flowspec'})
                afi_safi_list.append({'afi-safi-name': 'l3vpn-ipv6-flowspec'})

            n = {'config':
                 {'neighbor-address': info['neigh_addr'].split('/')[0],
                  'peer-as': peer.asn,
                  'auth-password': info['passwd'],
                  },
                 'afi-safis': afi_safi_list,
                 'timers': {'config': {
                     'connect-retry': 10,
                    }},
                 }

            if info['passive']:
                n['transport'] = {'config': {'passive-mode': True}}

            if info['is_rs_client']:
                n['route-server'] = {'config': {'route-server-client': True}}

            if info['local_as']:
                n['config']['local-as'] = info['local_as']

            if info['graceful_restart'] is not None:
                n['graceful-restart'] = {'config': {'enabled': True, 'restart-time': 20}}
                for afi_safi in afi_safi_list:
                    afi_safi['mp-graceful-restart'] = {'config': {'enabled': True}}

            if info['is_rr_client']:
                clusterId = self.router_id
                if 'cluster_id' in info and info['cluster_id'] is not None:
                    clusterId = info['cluster_id']
                n['route-reflector'] = {'config' : {'route-reflector-client': True,
                                                   'route-reflector-cluster-id': clusterId}}

            f = lambda typ: [p for p in info['policies'].itervalues() if p['type'] == typ]
            import_policies = f('import')
            export_policies = f('export')
            in_policies = f('in')
            f = lambda typ: [p['default'] for p in info['policies'].itervalues() if p['type'] == typ and 'default' in p]
            default_import_policy = f('import')
            default_export_policy = f('export')
            default_in_policy  = f('in')

            if len(import_policies) + len(export_policies) + len(in_policies) + len(default_import_policy) \
                + len(default_export_policy) + len(default_in_policy) > 0:
                n['apply-policy'] = {'config': {}}

            if len(import_policies) > 0:
                n['apply-policy']['config']['import-policy-list'] = [p['name'] for p in import_policies]

            if len(export_policies) > 0:
                n['apply-policy']['config']['export-policy-list'] = [p['name'] for p in export_policies]

            if len(in_policies) > 0:
                n['apply-policy']['config']['in-policy-list'] = [p['name'] for p in in_policies]

            def f(v):
                if v == 'reject':
                    return 'reject-route'
                elif v == 'accept':
                    return 'accept-route'
                raise Exception('invalid default policy type {0}'.format(v))

            if len(default_import_policy) > 0:
               n['apply-policy']['config']['default-import-policy'] = f(default_import_policy[0])

            if len(default_export_policy) > 0:
               n['apply-policy']['config']['default-export-policy'] = f(default_export_policy[0])

            if len(default_in_policy) > 0:
               n['apply-policy']['config']['default-in-policy'] = f(default_in_policy[0])

            if 'neighbors' not in config:
                config['neighbors'] = []

            config['neighbors'].append(n)

        config['defined-sets'] = {}
        if self.prefix_set:
            config['defined-sets']['prefix-sets'] = [self.prefix_set]

        if self.neighbor_set:
            config['defined-sets']['neighbor-sets'] = [self.neighbor_set]

        if self.bgp_set:
            config['defined-sets']['bgp-defined-sets'] = self.bgp_set

        policy_list = []
        for p in self.policies.itervalues():
            policy = {'name': p['name'],
                      'statements': p['statements']}
            policy_list.append(policy)

        if len(policy_list) > 0:
            config['policy-definitions'] = policy_list

        if self.zebra:
            config['global']['zebra'] = {'enabled': True,
                                         'redistribute-route-type-list':['connect']}

        with open('{0}/gobgpd.conf'.format(self.config_dir), 'w') as f:
            print colors.yellow('[{0}\'s new config]'.format(self.name))
            print colors.yellow(indent(toml.dumps(config)))
            f.write(toml.dumps(config))

    def _create_config_zebra(self):
        c = CmdBuffer()
        c << 'hostname zebra'
        c << 'password zebra'
        c << 'log file {0}/zebra.log'.format(self.QUAGGA_VOLUME)
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
        daemon.append('gobgpd')
        if self.zebra:
            daemon.append('zebra')
        for d in daemon:
            cmd = '/usr/bin/pkill {0} -SIGHUP'.format(d)
            self.local(cmd)
        for v in self.routes.itervalues():
            if v['rf'] == 'ipv4' or v['rf'] == 'ipv6':
                r = CmdBuffer(' ')
                r << 'gobgp global -a {0}'.format(v['rf'])
                r << 'rib add {0}'.format(v['prefix'])
                if v['next-hop']:
                    r << 'nexthop {0}'.format(v['next-hop'])
                if v['local-pref']:
                    r << 'local-pref {0}'.format(v['local-pref'])
                if v['med']:
                    r << 'med {0}'.format(v['med'])
                cmd = str(r)
            elif v['rf'] == 'ipv4-flowspec' or v['rf'] == 'ipv6-flowspec':
                cmd = 'gobgp global '\
                      'rib add match {0} then {1} -a {2}'.format(' '.join(v['matchs']), ' '.join(v['thens']), v['rf'])
            else:
                raise Exception('unsupported route faily: {0}'.format(rf))
            self.local(cmd)
