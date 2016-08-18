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
import yaml
from itertools import chain
from threading import Thread
import socket
import subprocess
import os

def extract_path_attribute(path, typ):
    for a in path['attrs']:
        if a['type'] == typ:
            return a
    return None

class GoBGPContainer(BGPContainer):

    SHARED_VOLUME = '/root/shared_volume'
    QUAGGA_VOLUME = '/etc/quagga'

    def __init__(self, name, asn, router_id, ctn_image_name='osrg/gobgp',
                 log_level='debug', zebra=False, config_format='toml'):
        super(GoBGPContainer, self).__init__(name, asn, router_id,
                                             ctn_image_name)
        self.shared_volumes.append((self.config_dir, self.SHARED_VOLUME))

        self.log_level = log_level
        self.prefix_set = None
        self.neighbor_set = None
        self.bgp_set = None
        self.default_policy = None
        self.zebra = zebra
        self.config_format = config_format

    def _start_gobgp(self, graceful_restart=False):
        c = CmdBuffer()
        c << '#!/bin/bash'
        c << '/go/bin/gobgpd -f {0}/gobgpd.conf -l {1} -p {2} -t {3} > ' \
             '{0}/gobgpd.log 2>&1'.format(self.SHARED_VOLUME, self.log_level, '-r' if graceful_restart else '', self.config_format)

        cmd = 'echo "{0:s}" > {1}/start.sh'.format(c, self.config_dir)
        local(cmd, capture=True)
        cmd = "chmod 755 {0}/start.sh".format(self.config_dir)
        local(cmd, capture=True)
        self.local("{0}/start.sh".format(self.SHARED_VOLUME), detach=True)

    def graceful_restart(self):
        self.local("pkill -INT gobgpd")

    def _start_zebra(self):
        cmd = 'cp {0}/zebra.conf {1}/'.format(self.SHARED_VOLUME, self.QUAGGA_VOLUME)
        self.local(cmd)
        cmd = '/usr/lib/quagga/zebra -f {0}/zebra.conf'.format(self.QUAGGA_VOLUME)
        self.local(cmd, detach=True)

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

    def _get_local_pref(self, path):
        for p in path['attrs']:
            if p['type'] == BGP_ATTR_TYPE_LOCAL_PREF:
                return p['value']
        return None

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
                p["local-pref"] = self._get_local_pref(p)
        return ret

    def get_global_rib(self, prefix='', rf='ipv4'):
        cmd = 'gobgp -j global rib {0} -a {1}'.format(prefix, rf)
        output = self.local(cmd, capture=True)
        ret = json.loads(output)
        for d in ret:
            for p in d["paths"]:
                p["nexthop"] = self._get_nexthop(p)
                p["aspath"] = self._get_as_path(p)
                p["local-pref"] = self._get_local_pref(p)
        return ret

    def monitor_global_rib(self, queue, rf='ipv4'):
        host = self.ip_addrs[0][1].split('/')[0]

        if not os.path.exists('{0}/gobgp'.format(self.config_dir)):
            self.local('cp /go/bin/gobgp {0}/'.format(self.SHARED_VOLUME))

        args = '{0}/gobgp -u {1} -j monitor global rib -a {2}'.format(self.config_dir, host, rf).split(' ')

        def monitor():
            process = subprocess.Popen(args, stdout=subprocess.PIPE)
            for line in iter(process.stdout.readline, ''):
                p = json.loads(line)[0]
                p["nexthop"] = self._get_nexthop(p)
                p["aspath"] = self._get_as_path(p)
                p["local-pref"] = self._get_local_pref(p)
                queue.put(p)

        t = Thread(target=monitor)
        t.daemon = True
        t.start()

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
            p["prefix"] = p['nlri']['prefix']
            p["local-pref"] = self._get_local_pref(p)
        return ret

    def get_adj_rib_in(self, peer, prefix='', rf='ipv4'):
        return self._get_adj_rib('in', peer, prefix, rf)

    def get_adj_rib_out(self, peer, prefix='', rf='ipv4'):
        return self._get_adj_rib('out', peer, prefix, rf)

    def get_neighbor(self, peer):
        if peer not in self.peers:
            raise Exception('not found peer {0}'.format(peer.router_id))
        peer_addr = self.peers[peer]['neigh_addr'].split('/')[0]
        cmd = 'gobgp -j neighbor {0}'.format(peer_addr)
        return json.loads(self.local(cmd, capture=True))

    def get_neighbor_state(self, peer):
        return self.get_neighbor(peer)['info']['bgp_state']

    def clear_policy(self):
        self.policies = {}
        for info in self.peers.itervalues():
            info['policies'] = {}
        self.prefix_set = []
        self.neighbor_set = []
        self.statements = []

    def set_prefix_set(self, ps):
        if type(ps) is not list:
            ps = [ps]
        self.prefix_set = ps

    def add_prefix_set(self, ps):
        if self.prefix_set is None:
            self.prefix_set = []
        self.prefix_set.append(ps)

    def set_neighbor_set(self, ns):
        if type(ns) is not list:
            ns = [ns]
        self.neighbor_set = ns

    def add_neighbor_set(self, ns):
        if self.neighbor_set is None:
            self.neighbor_set = []
        self.neighbor_set.append(ns)

    def set_bgp_defined_set(self, bs):
        self.bgp_set = bs

    def create_config(self):
        self._create_config_bgp()
        if self.zebra:
            self._create_config_zebra()

    def _create_config_bgp(self):
        config = {'global': {'config': {'as': self.asn, 'router-id': self.router_id},
                'route-selection-options':{
                    'config': {
                        'external-compare-router-id': True,
                    },
                },
        }}

        if self.zebra:
            config['global']['use-multiple-paths'] = {'config': {'enabled': True}}

        for peer, info in self.peers.iteritems():
            afi_safi_list = []
            version = netaddr.IPNetwork(info['neigh_addr']).version
            if version == 4:
                afi_safi_list.append({'config':{'afi-safi-name': 'ipv4-unicast'}})
            elif version == 6:
                afi_safi_list.append({'config':{'afi-safi-name': 'ipv6-unicast'}})
            else:
                Exception('invalid ip address version. {0}'.format(version))

            if info['vpn']:
                afi_safi_list.append({'config': {'afi-safi-name': 'l3vpn-ipv4-unicast'}})
                afi_safi_list.append({'config': {'afi-safi-name': 'l3vpn-ipv6-unicast'}})
                afi_safi_list.append({'config': {'afi-safi-name': 'l2vpn-evpn'}})
                afi_safi_list.append({'config': {'afi-safi-name': 'rtc'}, 'route-target-membership': {'config': {'deferral-time': 10}}})

            if info['flowspec']:
                afi_safi_list.append({'config': {'afi-safi-name': 'ipv4-flowspec'}})
                afi_safi_list.append({'config': {'afi-safi-name': 'l3vpn-ipv4-flowspec'}})
                afi_safi_list.append({'config': {'afi-safi-name': 'ipv6-flowspec'}})
                afi_safi_list.append({'config': {'afi-safi-name': 'l3vpn-ipv6-flowspec'}})

            n = {'config':
                 {'neighbor-address': info['neigh_addr'].split('/')[0],
                  'peer-as': peer.asn,
                  'auth-password': info['passwd'],
                  },
                 'afi-safis': afi_safi_list,
                 'timers': {'config': {
                     'connect-retry': 10,
                  }},
                 'transport': {'config': {}},
                 }

            if ':' in info['local_addr']:
                n['transport']['config']['local-address'] = info['local_addr'].split('/')[0]

            if info['passive']:
                n['transport']['config']['passive-mode'] = True

            if info['is_rs_client']:
                n['route-server'] = {'config': {'route-server-client': True}}

            if info['local_as']:
                n['config']['local-as'] = info['local_as']

            if info['prefix_limit']:
                for v in afi_safi_list:
                    v['prefix-limit'] = {'config': {'max-prefixes': info['prefix_limit'], 'shutdown-threshold-pct': 80 }}

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

            if len(info.get('default-policy', [])) + len(info.get('policies', [])) > 0:
                n['apply-policy'] = {'config': {}}

            for typ, p in info.get('policies', {}).iteritems():
                n['apply-policy']['config']['{0}-policy-list'.format(typ)] = [p['name']]

            def f(v):
                if v == 'reject':
                    return 'reject-route'
                elif v == 'accept':
                    return 'accept-route'
                raise Exception('invalid default policy type {0}'.format(v))

            for typ, d in info.get('default-policy', {}).iteritems():
                n['apply-policy']['config']['default-{0}-policy'.format(typ)] = f(d)

            if 'neighbors' not in config:
                config['neighbors'] = []

            config['neighbors'].append(n)

        config['defined-sets'] = {}
        if self.prefix_set:
            config['defined-sets']['prefix-sets'] = self.prefix_set

        if self.neighbor_set:
            config['defined-sets']['neighbor-sets'] = self.neighbor_set

        if self.bgp_set:
            config['defined-sets']['bgp-defined-sets'] = self.bgp_set

        policy_list = []
        for p in self.policies.itervalues():
            policy = {'name': p['name']}
            if 'statements' in p:
                policy['statements'] = p['statements']
            policy_list.append(policy)

        if len(policy_list) > 0:
            config['policy-definitions'] = policy_list

        if self.zebra:
            config['zebra'] = {'config':{'enabled': True,
                                         'redistribute-route-type-list':['connect']}}

        with open('{0}/gobgpd.conf'.format(self.config_dir), 'w') as f:
            print colors.yellow('[{0}\'s new config]'.format(self.name))
            if self.config_format is 'toml':
                raw = toml.dumps(config)
            elif self.config_format is 'yaml':
                raw = yaml.dump(config)
            elif self.config_format is 'json':
                raw = json.dumps(config)
            else:
                raise Exception('invalid config_format {0}'.format(self.config_format))
            print colors.yellow(indent(raw))
            f.write(raw)

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


class RawGoBGPContainer(GoBGPContainer):
    def __init__(self, name, config, ctn_image_name='osrg/gobgp',
                 log_level='debug', zebra=False, config_format='yaml'):
        if config_format is 'toml':
            d = toml.loads(config)
        elif config_format is 'yaml':
            d = yaml.load(config)
        elif config_format is 'json':
            d = json.loads(config)
        else:
            raise Exception('invalid config format {0}'.format(config_format))
        asn = d['global']['config']['as']
        router_id = d['global']['config']['router-id']
        self.config = config
        super(RawGoBGPContainer, self).__init__(name, asn, router_id,
                                                ctn_image_name, log_level,
                                                zebra, config_format)
    def create_config(self):
        with open('{0}/gobgpd.conf'.format(self.config_dir), 'w') as f:
            print colors.yellow('[{0}\'s new config]'.format(self.name))
            print colors.yellow(indent(self.config))
            f.write(self.config)
