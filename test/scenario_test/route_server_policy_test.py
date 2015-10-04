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

import unittest
from fabric.api import local
from lib import base
from lib.gobgp import *
from lib.quagga import *
from lib.exabgp import *
import sys
import os
import time
import nose
from noseplugin import OptionParser, parser_option


scenarios = {}


def scenario(idx):
    def wrapped(f):
        if idx not in scenarios:
            scenarios[idx] = {}
        if f.__name__ in scenarios[idx]:
            raise Exception('scenario index {0}. already exists'.format(idx))

        scenarios[idx][f.__name__] = f
    return wrapped


def wait_for(f, timeout=120):
    interval = 1
    count = 0
    while True:
        if f():
            return

        time.sleep(interval)
        count += interval
        if count >= timeout:
            raise Exception('timeout')


"""
  No.1 import-policy test
                          --------------------------------
  e1 ->(192.168.2.0/24)-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                          |                              |
                          | ->x q2-rib                   |
                          --------------------------------
"""
@scenario(1)
def boot(env):
    gobgp_ctn_image_name = env.parser_option.gobgp_image
    log_level = env.parser_option.gobgp_log_level
    g1 = GoBGPContainer(name='g1', asn=65000, router_id='192.168.0.1',
                        ctn_image_name=gobgp_ctn_image_name,
                        log_level=log_level)
    e1 = ExaBGPContainer(name='e1', asn=65001, router_id='192.168.0.2')
    q1 = QuaggaBGPContainer(name='q1', asn=65002, router_id='192.168.0.3')
    q2 = QuaggaBGPContainer(name='q2', asn=65003, router_id='192.168.0.4')

    ctns = [g1, e1, q1, q2]
    initial_wait_time = max(ctn.run() for ctn in ctns)
    time.sleep(initial_wait_time)

    br01 = Bridge(name='br01', subnet='192.168.10.0/24')
    [br01.addif(ctn) for ctn in ctns]

    for q in [e1, q1, q2]:
        g1.add_peer(q, is_rs_client=True)
        q.add_peer(g1)

    env.g1 = g1
    env.e1 = e1
    env.q1 = q1
    env.q2 = q2

@scenario(1)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '192.168.0.0/16',
          'MasklengthRange': '16..24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    n0 = {'Address': g1.peers[e1]['neigh_addr'].split('/')[0]}

    ns0 = {'NeighborSetName': 'ns0',
           'NeighborInfoList': [n0]}
    g1.set_neighbor_set(ns0)

    st0 = {'Name': 'st0',
           'Conditions': {
               'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']},
               'MatchNeighborSet': {'NeighborSet': ns0['NeighborSetName']}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    # this will be blocked
    e1.add_route('192.168.2.0/24')
    # this will pass
    e1.add_route('192.168.2.0/15')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)


@scenario(1)
def check(env):
    wait_for(lambda: len(env.g1.get_local_rib(env.q1)) == 2)
    wait_for(lambda: len(env.g1.get_adj_rib_out(env.q1)) == 2)
    wait_for(lambda: len(env.q1.get_global_rib()) == 2)
    wait_for(lambda: len(env.g1.get_local_rib(env.q2)) == 1)
    wait_for(lambda: len(env.g1.get_adj_rib_out(env.q2)) == 1)
    wait_for(lambda: len(env.q2.get_global_rib()) == 1)

"""
  No.2 export-policy test
                          --------------------------------
  e1 ->(192.168.2.0/24)-> | -> q1-rib ->  q1-adj-rib-out | --> q1
                          |                              |
                          | -> q2-rib ->x q2-adj-rib-out |
                          --------------------------------
"""
@scenario(2)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(2)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '192.168.0.0/16',
          'MasklengthRange': '16..24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    n0 = {'Address': g1.peers[q2]['neigh_addr'].split('/')[0]}

    ns0 = {'NeighborSetName': 'ns0',
           'NeighborInfoList': [n0]}
    g1.set_neighbor_set(ns0)

    st0 = {'Name': 'st0',
           'Conditions': {
               'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']},
               'MatchNeighborSet': {'NeighborSet': ns0['NeighborSetName']}}}

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    # this will be blocked
    e1.add_route('192.168.2.0/24')
    # this will pass
    e1.add_route('192.168.2.0/15')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(2)
def check(env):
    g1 = env.g1
    q1 = env.q1
    q2 = env.q2
    wait_for(lambda : len(g1.get_local_rib(q1)) == 2)
    wait_for(lambda : len(g1.get_adj_rib_out(q1)) == 2)
    wait_for(lambda : len(q1.get_global_rib()) == 2)
    wait_for(lambda : len(g1.get_local_rib(q2)) == 2)
    wait_for(lambda : len(g1.get_adj_rib_out(q2)) == 1)
    wait_for(lambda : len(q2.get_global_rib()) == 1)

"""
  No.3 import-policy update test

  r1:192.168.2.0/24
  r2:192.168.20.0/24
  r3:192.168.200.0/24
                    -------------------------------------------------
                    | q1                                            |
  e1 ->(r1,r2,r3)-> | ->(r1,r2,r3)-> rib ->(r1,r2,r3)-> adj-rib-out | ->(r1,r2,r3)-> q1
                    |                                               |
                    | q2                                            |
                    | ->(r1)->       rib ->(r1)->       adj-rib-out | ->(r1)-> q2
                    -------------------------------------------------
               |
       update gobgp.conf
               |
               V
                    -------------------------------------------------
                    | q1                                            |
  e1 ->(r1,r2,r3)-> | ->(r1,r2,r3)-> rib ->(r1,r2,r3)-> adj-rib-out | ->(r1,r2,r3)-> q1
                    |                                               |
                    | q2                                            |
                    | ->(r1,r3)->    rib ->(r1,r3)->    adj-rib-out | ->(r1,r3)-> q2
                    -------------------------------------------------
"""
@scenario(3)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(3)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '192.168.20.0/24'}
    p1 = {'IpPrefix': '192.168.200.0/24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0, p1]}
    g1.set_prefix_set(ps0)

    n0 = {'Address': g1.peers[e1]['neigh_addr'].split('/')[0]}

    ns0 = {'NeighborSetName': 'ns0',
           'NeighborInfoList': [n0]}
    g1.set_neighbor_set(ns0)

    st0 = {'Name': 'st0',
           'Conditions': {
               'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']},
               'MatchNeighborSet': {'NeighborSet': ns0['NeighborSetName']}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.2.0/24')
    e1.add_route('192.168.20.0/24')
    e1.add_route('192.168.200.0/24')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(3)
def check(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    wait_for(lambda : len(g1.get_local_rib(q1)) == 3)
    wait_for(lambda : len(g1.get_adj_rib_out(q1)) == 3)
    wait_for(lambda : len(q1.get_global_rib()) == 3)
    wait_for(lambda : len(g1.get_local_rib(q2)) == 1)
    wait_for(lambda : len(g1.get_adj_rib_out(q2)) == 1)
    wait_for(lambda : len(q2.get_global_rib()) == 1)

@scenario(3)
def setup2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    g1.clear_policy()

    p0 = {'IpPrefix': '192.168.20.0/24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    n0 = {'Address': g1.peers[e1]['neigh_addr'].split('/')[0]}

    ns0 = {'NeighborSetName': 'ns0',
           'NeighborInfoList': [n0]}
    g1.set_neighbor_set(ns0)

    st0 = {'Name': 'st0',
           'Conditions': {'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']},
                          'MatchNeighborSet': {'NeighborSet': ns0['NeighborSetName']}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)
    g1.softreset(e1)

@scenario(3)
def check2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    wait_for(lambda : len(g1.get_local_rib(q1)) == 3)
    wait_for(lambda : len(g1.get_adj_rib_out(q1)) == 3)
    wait_for(lambda : len(q1.get_global_rib()) == 3)
    wait_for(lambda : len(g1.get_local_rib(q2)) == 2)
    wait_for(lambda : len(g1.get_adj_rib_out(q2)) == 2)
    wait_for(lambda : len(q2.get_global_rib()) == 2)

"""
  No.4 export-policy update test

  r1:192.168.2.0
  r2:192.168.20.0
  r3:192.168.200.0
                    -------------------------------------------------
                    | q1                                            |
  e1 ->(r1,r2,r3)-> | ->(r1,r2,r3)-> rib ->(r1,r2,r3)-> adj-rib-out | ->(r1,r2,r3)-> q1
                    |                                               |
                    | q2                                            |
                    | ->(r1,r2,r3)-> rib ->(r1)->       adj-rib-out | ->(r1)-> q2
                    -------------------------------------------------
               |
       update gobgp.conf
               |
               V
                    -------------------------------------------------
                    | q1                                            |
  e1 ->(r1,r2,r3)-> | ->(r1,r2,r3)-> rib ->(r1,r2,r3)-> adj-rib-out | ->(r1,r2,r3)-> q1
                    |                                               |
                    | q2                                            |
                    | ->(r1,r2,r3)-> rib ->(r1,r3)->    adj-rib-out | ->(r1,r3)-> q2
                    -------------------------------------------------
"""
@scenario(4)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(4)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    p0 = {'IpPrefix': '192.168.20.0/24'}
    p1 = {'IpPrefix': '192.168.200.0/24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0, p1]}
    g1.set_prefix_set(ps0)

    n0 = {'Address': g1.peers[q2]['neigh_addr'].split('/')[0]}

    ns0 = {'NeighborSetName': 'ns0',
           'NeighborInfoList': [n0]}
    g1.set_neighbor_set(ns0)

    st0 = {'Name': 'st0',
           'Conditions': {'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']},
                          'MatchNeighborSet': {'NeighborSet': ns0['NeighborSetName']}}}

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.2.0/24')
    e1.add_route('192.168.20.0/24')
    e1.add_route('192.168.200.0/24')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(4)
def check(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    wait_for(lambda : len(g1.get_local_rib(q1)) == 3)
    wait_for(lambda : len(g1.get_adj_rib_out(q1)) == 3)
    wait_for(lambda : len(q1.get_global_rib()) == 3)
    wait_for(lambda : len(g1.get_local_rib(q2)) == 3)
    wait_for(lambda : len(g1.get_adj_rib_out(q2)) == 1)
    wait_for(lambda : len(q2.get_global_rib()) == 1)

@scenario(4)
def setup2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    g1.clear_policy()

    p0 = {'IpPrefix': '192.168.20.0/24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    n0 = {'Address': g1.peers[q2]['neigh_addr'].split('/')[0]}

    ns0 = {'NeighborSetName': 'ns0',
           'NeighborInfoList': [n0]}
    g1.set_neighbor_set(ns0)

    st0 = {'Name': 'st0',
           'Conditions': {'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']},
                          'MatchNeighborSet': {'NeighborSet': ns0['NeighborSetName']}}}

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    # we need hard reset to flush q2's local rib
    g1.reset(e1)

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)


@scenario(4)
def check2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    wait_for(lambda : len(g1.get_local_rib(q1)) == 3)
    wait_for(lambda : len(g1.get_adj_rib_out(q1)) == 3)
    wait_for(lambda : len(q1.get_global_rib()) == 3)
    wait_for(lambda : len(g1.get_local_rib(q2)) == 3)
    wait_for(lambda : len(g1.get_adj_rib_out(q2)) == 2)
    wait_for(lambda : len(q2.get_global_rib()) == 2)

"""
   No.5 IPv6 import-policy test

   r1=2001::/64
   r2=2001::/63
                  -------------------------------------------------
   e1 ->(r1,r2)-> | ->(r1,r2)-> q1-rib ->(r1,r2)-> q1-adj-rib-out | ->(r1,r2)-> q1
                  |                                               |
                  | ->(r2)   -> q2-rib ->(r2)   -> q2-adj-rib-out | ->(r2)-> q2
                  -------------------------------------------------
"""
@scenario(5)
def boot(env):
    gobgp_ctn_image_name = env.parser_option.gobgp_image
    log_level = env.parser_option.gobgp_log_level
    g1 = GoBGPContainer(name='g1', asn=65000, router_id='192.168.0.1',
                        ctn_image_name=gobgp_ctn_image_name,
                        log_level=log_level)
    e1 = ExaBGPContainer(name='e1', asn=65001, router_id='192.168.0.2')
    q1 = QuaggaBGPContainer(name='q1', asn=65002, router_id='192.168.0.3')
    q2 = QuaggaBGPContainer(name='q2', asn=65003, router_id='192.168.0.4')

    ctns = [g1, e1, q1, q2]
    initial_wait_time = max(ctn.run() for ctn in ctns)
    time.sleep(initial_wait_time)

    br01 = Bridge(name='br01', subnet='2001::/96')
    [br01.addif(ctn) for ctn in ctns]

    for q in [e1, q1, q2]:
        g1.add_peer(q, is_rs_client=True)
        q.add_peer(g1)

    env.g1 = g1
    env.e1 = e1
    env.q1 = q1
    env.q2 = q2

@scenario(5)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '2001::/32',
          'MasklengthRange': '64..128'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    n0 = {'Address': g1.peers[e1]['neigh_addr'].split('/')[0]}

    ns0 = {'NeighborSetName': 'ns0',
           'NeighborInfoList': [n0]}
    g1.set_neighbor_set(ns0)

    st0 = {'Name': 'st0',
           'Conditions': {
               'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']},
               'MatchNeighborSet': {'NeighborSet': ns0['NeighborSetName']}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    # this will be blocked
    e1.add_route('2001::/64', rf='ipv6')
    # this will pass
    e1.add_route('2001::/63', rf='ipv6')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(5)
def check(env):
    wait_for(lambda: len(env.g1.get_local_rib(env.q1, rf='ipv6')) == 2)
    wait_for(lambda: len(env.g1.get_adj_rib_out(env.q1, rf='ipv6')) == 2)
    wait_for(lambda: len(env.q1.get_global_rib(rf='ipv6')) == 2)
    wait_for(lambda: len(env.g1.get_local_rib(env.q2, rf='ipv6')) == 1)
    wait_for(lambda: len(env.g1.get_adj_rib_out(env.q2, rf='ipv6')) == 1)
    wait_for(lambda: len(env.q2.get_global_rib(rf='ipv6')) == 1)

"""
   No.6 IPv6 export-policy test

   r1=2001::/64
   r2=2001::/63
                  -------------------------------------------------
   e1 ->(r1,r2)-> | ->(r1,r2)-> q1-rib ->(r1,r2)-> q1-adj-rib-out | ->(r1,r2)-> q1
                  |                                               |
                  | ->(r1,r2)-> q2-rib ->(r2)   -> q2-adj-rib-out | ->(r2)-> q2
                  -------------------------------------------------
"""
@scenario(6)
def boot(env):
    scenarios[5]['boot'](env)

@scenario(6)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '2001::/32',
          'MasklengthRange': '64..128'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    n0 = {'Address': g1.peers[q2]['neigh_addr'].split('/')[0]}

    ns0 = {'NeighborSetName': 'ns0',
           'NeighborInfoList': [n0]}
    g1.set_neighbor_set(ns0)

    st0 = {'Name': 'st0',
           'Conditions': {
               'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']},
               'MatchNeighborSet': {'NeighborSet': ns0['NeighborSetName']}}}

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    # this will be blocked
    e1.add_route('2001::/64', rf='ipv6')
    # this will pass
    e1.add_route('2001::/63', rf='ipv6')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(6)
def check(env):
    wait_for(lambda: len(env.g1.get_local_rib(env.q1, rf='ipv6')) == 2)
    wait_for(lambda: len(env.g1.get_adj_rib_out(env.q1, rf='ipv6')) == 2)
    wait_for(lambda: len(env.q1.get_global_rib(rf='ipv6')) == 2)
    wait_for(lambda: len(env.g1.get_local_rib(env.q2, rf='ipv6')) == 2)
    wait_for(lambda: len(env.g1.get_adj_rib_out(env.q2, rf='ipv6')) == 1)
    wait_for(lambda: len(env.q2.get_global_rib(rf='ipv6')) == 1)

"""
  No.7 IPv6 import-policy update test
  r1=2001:0:10:2::/64
  r2=2001:0:10:20::/64
  r3=2001:0:10:200::/64
                    -------------------------------------------------
                    | q1                                            |
  e1 ->(r1,r2,r3)-> | ->(r1,r2,r3)-> rib ->(r1,r2,r3)-> adj-rib-out | ->(r1,r2,r3)-> q1
                    |                                               |
                    | q2                                            |
                    | ->(r1)->       rib ->(r1)->       adj-rib-out | ->(r1)-> q2
                    -------------------------------------------------
               |
       update gobgp.conf
               |
               V
                    -------------------------------------------------
                    | q1                                            |
  e1 ->(r1,r2,r3)-> | ->(r1,r2,r3)-> rib ->(r1,r2,r3)-> adj-rib-out | ->(r1,r2,r3)-> q1
                    |                                               |
                    | q2                                            |
                    | ->(r1,r3)->    rib ->(r1,r3)->    adj-rib-out | ->(r1,r3)-> q2
                    -------------------------------------------------
"""
@scenario(7)
def boot(env):
    scenarios[5]['boot'](env)

@scenario(7)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '2001:0:10:2::/64'}
    p1 = {'IpPrefix': '2001:0:10:20::/64'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0, p1]}
    g1.set_prefix_set(ps0)

    n0 = {'Address': g1.peers[e1]['neigh_addr'].split('/')[0]}

    ns0 = {'NeighborSetName': 'ns0',
           'NeighborInfoList': [n0]}
    g1.set_neighbor_set(ns0)

    st0 = {'Name': 'st0',
           'Conditions': {
               'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']},
               'MatchNeighborSet': {'NeighborSet': ns0['NeighborSetName']}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('2001:0:10:2::/64', rf='ipv6')
    e1.add_route('2001:0:10:20::/64', rf='ipv6')
    e1.add_route('2001:0:10:200::/64', rf='ipv6')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(7)
def check(env):
    wait_for(lambda: len(env.g1.get_local_rib(env.q1, rf='ipv6')) == 3)
    wait_for(lambda: len(env.g1.get_adj_rib_out(env.q1, rf='ipv6')) == 3)
    wait_for(lambda: len(env.q1.get_global_rib(rf='ipv6')) == 3)
    wait_for(lambda: len(env.g1.get_local_rib(env.q2, rf='ipv6')) == 1)
    wait_for(lambda: len(env.g1.get_adj_rib_out(env.q2, rf='ipv6')) == 1)
    wait_for(lambda: len(env.q2.get_global_rib(rf='ipv6')) == 1)

@scenario(7)
def setup2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '2001:0:10:2::/64'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    n0 = {'Address': g1.peers[e1]['neigh_addr'].split('/')[0]}

    ns0 = {'NeighborSetName': 'ns0',
           'NeighborInfoList': [n0]}
    g1.set_neighbor_set(ns0)

    st0 = {'Name': 'st0',
           'Conditions': {
               'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']},
               'MatchNeighborSet': {'NeighborSet': ns0['NeighborSetName']}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)
    g1.softreset(e1, rf='ipv6')

@scenario(7)
def check2(env):
    wait_for(lambda: len(env.g1.get_local_rib(env.q1, rf='ipv6')) == 3)
    wait_for(lambda: len(env.g1.get_adj_rib_out(env.q1, rf='ipv6')) == 3)
    wait_for(lambda: len(env.q1.get_global_rib(rf='ipv6')) == 3)
    wait_for(lambda: len(env.g1.get_local_rib(env.q2, rf='ipv6')) == 2)
    wait_for(lambda: len(env.g1.get_adj_rib_out(env.q2, rf='ipv6')) == 2)
    wait_for(lambda: len(env.q2.get_global_rib(rf='ipv6')) == 2)

"""
  No.8 IPv6 export-policy update test
  r1=2001:0:10:2::/64
  r2=2001:0:10:20::/64
  r3=2001:0:10:200::/64
                    -------------------------------------------------
                    | q1                                            |
  e1 ->(r1,r2,r3)-> | ->(r1,r2,r3)-> rib ->(r1,r2,r3)-> adj-rib-out | ->(r1,r2,r3)-> q1
                    |                                               |
                    | q2                                            |
                    | ->(r1,r2,r3)-> rib ->(r1)->       adj-rib-out | ->(r1)-> q2
                    -------------------------------------------------
               |
       update gobgp.conf
               |
               V
                    -------------------------------------------------
                    | q1                                            |
  e1 ->(r1,r2,r3)-> | ->(r1,r2,r3)-> rib ->(r1,r2,r3)-> adj-rib-out | ->(r1,r2,r3)-> q1
                    |                                               |
                    | q2                                            |
                    | ->(r1,r2,r3)-> rib ->(r1,r3)->    adj-rib-out | ->(r1,r3)-> q2
                    -------------------------------------------------
"""
@scenario(8)
def boot(env):
    scenarios[5]['boot'](env)

@scenario(8)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '2001:0:10:2::/64'}
    p1 = {'IpPrefix': '2001:0:10:20::/64'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0, p1]}
    g1.set_prefix_set(ps0)

    n0 = {'Address': g1.peers[q2]['neigh_addr'].split('/')[0]}

    ns0 = {'NeighborSetName': 'ns0',
           'NeighborInfoList': [n0]}
    g1.set_neighbor_set(ns0)

    st0 = {'Name': 'st0',
           'Conditions': {
               'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']},
               'MatchNeighborSet': {'NeighborSet': ns0['NeighborSetName']}}}

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('2001:0:10:2::/64', rf='ipv6')
    e1.add_route('2001:0:10:20::/64', rf='ipv6')
    e1.add_route('2001:0:10:200::/64', rf='ipv6')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(8)
def check(env):
    wait_for(lambda: len(env.g1.get_local_rib(env.q1, rf='ipv6')) == 3)
    wait_for(lambda: len(env.g1.get_adj_rib_out(env.q1, rf='ipv6')) == 3)
    wait_for(lambda: len(env.q1.get_global_rib(rf='ipv6')) == 3)
    wait_for(lambda: len(env.g1.get_local_rib(env.q2, rf='ipv6')) == 3)
    wait_for(lambda: len(env.g1.get_adj_rib_out(env.q2, rf='ipv6')) == 1)
    wait_for(lambda: len(env.q2.get_global_rib(rf='ipv6')) == 1)

@scenario(8)
def setup2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '2001:0:10:2::/64'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    n0 = {'Address': g1.peers[q2]['neigh_addr'].split('/')[0]}

    ns0 = {'NeighborSetName': 'ns0',
           'NeighborInfoList': [n0]}
    g1.set_neighbor_set(ns0)

    st0 = {'Name': 'st0',
           'Conditions': {
               'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']},
               'MatchNeighborSet': {'NeighborSet': ns0['NeighborSetName']}}}

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)
    g1.reset(e1)

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(8)
def check2(env):
    wait_for(lambda: len(env.g1.get_local_rib(env.q1, rf='ipv6')) == 3)
    wait_for(lambda: len(env.g1.get_adj_rib_out(env.q1, rf='ipv6')) == 3)
    wait_for(lambda: len(env.q1.get_global_rib(rf='ipv6')) == 3)
    wait_for(lambda: len(env.g1.get_local_rib(env.q2, rf='ipv6')) == 3)
    wait_for(lambda: len(env.g1.get_adj_rib_out(env.q2, rf='ipv6')) == 2)
    wait_for(lambda: len(env.q2.get_global_rib(rf='ipv6')) == 2)

"""
  No.9 aspath length condition import-policy test
                            --------------------------------
  e1 ->(aspath_length=10)-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                            |                              |
                            | ->x q2-rib                   |
                            --------------------------------

"""
@scenario(9)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(9)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'AsPathLength':{'Operator': 'ge',
                                                          'Value': 10}}}}


    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    # this will be blocked
    e1.add_route('192.168.100.0/24', aspath=range(e1.asn, e1.asn-10, -1))
    # this will pass
    e1.add_route('192.168.200.0/24', aspath=range(e1.asn, e1.asn-8, -1))

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(9)
def check(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    wait_for(lambda : len(g1.get_local_rib(q1)) == 2)
    wait_for(lambda : len(g1.get_adj_rib_out(q1)) == 2)
    wait_for(lambda : len(q1.get_global_rib()) == 2)
    wait_for(lambda : len(g1.get_local_rib(q2)) == 1)
    wait_for(lambda : len(g1.get_adj_rib_out(q2)) == 1)
    wait_for(lambda : len(q2.get_global_rib()) == 1)


"""
  No.10 aspath from condition import-policy test
                              --------------------------------
  e1 ->(aspath=[65100,...])-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                              |                              |
                              | ->x q2-rib                   |
                              --------------------------------

"""
@scenario(10)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(10)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    as0 = {'AsPathSets': {'AsPathSetList': [{'AsPathSetName': 'as0', 'AsPathList': [{'AsPath': '^{0}'.format(e1.asn)}]}]}}

    g1.set_bgp_defined_set(as0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchAsPathSet':{'AsPathSet': 'as0'}}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    # this will be blocked
    e1.add_route('192.168.100.0/24', aspath=range(e1.asn, e1.asn-10, -1))
    # this will pass
    e1.add_route('192.168.200.0/24', aspath=range(e1.asn-1, e1.asn-10, -1))

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(10)
def check(env):
    # same check function as previous No.1 scenario
    scenarios[1]['check'](env)

"""
  No.11 aspath any condition import-policy test
                                 --------------------------------
  e1 ->(aspath=[...65098,...])-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                                 |                              |
                                 | ->x q2-rib                   |
                                 --------------------------------

"""
@scenario(11)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(11)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    as0 = {'AsPathSets': {'AsPathSetList': [{'AsPathSetName': 'as0', 'AsPathList': [{'AsPath': '65098'}]}]}}

    g1.set_bgp_defined_set(as0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchAsPathSet':{'AsPathSet': 'as0'}}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    # this will be blocked
    e1.add_route('192.168.100.0/24', aspath=[65000, 65098, 65010])
    # this will pass
    e1.add_route('192.168.200.0/24', aspath=[65000, 65100, 65010])

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(11)
def check(env):
    # same check function as previous No.1 scenario
    scenarios[1]['check'](env)

"""
  No.12 aspath origin condition import-policy test
                              --------------------------------
  e1 ->(aspath=[...,65090])-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                              |                              |
                              | ->x q2-rib                   |
                              --------------------------------

"""
@scenario(12)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(12)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    as0 = {'AsPathSets': {'AsPathSetList': [{'AsPathSetName': 'as0', 'AsPathList': [{'AsPath': '65090$'}]}]}}

    g1.set_bgp_defined_set(as0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchAsPathSet':{'AsPathSet': 'as0'}}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    # this will be blocked
    e1.add_route('192.168.100.0/24', aspath=[65000, 65098, 65090])
    # this will pass
    e1.add_route('192.168.200.0/24', aspath=[65000, 65100, 65010])

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)



@scenario(12)
def check(env):
    # same check function as previous No.1 scenario
    scenarios[1]['check'](env)

"""
  No.13 aspath only condition import-policy test
                            --------------------------------
  e1 -> (aspath=[65100]) -> | ->  q1-rib -> q1-adj-rib-out | --> q1
                            |                              |
                            | ->x q2-rib                   |
                            --------------------------------

"""
@scenario(13)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(13)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    as0 = {'AsPathSets': {'AsPathSetList': [{'AsPathSetName': 'as0', 'AsPathList': [{'AsPath': '^65100$'}]}]}}

    g1.set_bgp_defined_set(as0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchAsPathSet':{'AsPathSet': 'as0'}}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    # this will be blocked
    e1.add_route('192.168.100.0/24', aspath=[65100])
    # this will pass
    e1.add_route('192.168.200.0/24', aspath=[65000, 65100, 65010])

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(13)
def check(env):
    # same check function as previous No.1 scenario
    scenarios[1]['check'](env)

"""
  No.14 aspath condition mismatch import-policy test
                                 -------------------------------
  exabgp ->(aspath=[...,65090])->| -> q1-rib -> q1-adj-rib-out | --> q1
                                 |                             |
                                 | -> q2-rib -> q2-adj-rib-out | --> q2
                                 -------------------------------
  This case check if policy passes the path to e1 because of condition mismatch.
"""
@scenario(14)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(14)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    cs0 = {'CommunitySets': {'CommunitySetList': [{'CommunitySetName': 'cs0', 'CommunityList': [{'Community': '65100:10'}]}]}}

    g1.set_bgp_defined_set(cs0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchCommunitySet':{'CommunitySet': 'cs0'}}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    # this will be blocked
    e1.add_route('192.168.100.0/24', aspath=[65100, 65090])
    # this will pass
    e1.add_route('192.168.200.0/24', aspath=[65000, 65100, 65010])

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(14)
def check(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    wait_for(lambda : len(g1.get_local_rib(q1)) == 2)
    wait_for(lambda : len(g1.get_adj_rib_out(q1)) == 2)
    wait_for(lambda : len(q1.get_global_rib()) == 2)
    wait_for(lambda : len(g1.get_local_rib(q2)) == 2)
    wait_for(lambda : len(g1.get_adj_rib_out(q2)) == 2)
    wait_for(lambda : len(q2.get_global_rib()) == 2)


"""
  No.15 community condition import-policy test
                              --------------------------------
  e1 ->(community=65100:10)-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                              |                              |
                              | ->x q2-rib                   |
                              --------------------------------
"""
@scenario(15)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(15)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    cs0 = {'CommunitySets': {'CommunitySetList': [{'CommunitySetName': 'cs0', 'CommunityList': [{'Community': '65100:10'}]}]}}

    g1.set_bgp_defined_set(cs0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchCommunitySet':{'CommunitySet': 'cs0'}}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    # this will be blocked
    e1.add_route('192.168.100.0/24', community=['65100:10'])
    # this will pass
    e1.add_route('192.168.200.0/24', community=['65100:20'])

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)



@scenario(15)
def check(env):
    # same check function as previous No.1 scenario
    scenarios[1]['check'](env)

"""
  No.16 community condition regexp import-policy test
                              --------------------------------
  e1 ->(community=65100:10)-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                              |                              |
                              | ->x q2-rib                   |
                              --------------------------------
"""
@scenario(16)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(16)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    cs0 = {'CommunitySets': {'CommunitySetList': [{'CommunitySetName': 'cs0', 'CommunityList': [{'Community': '6[0-9]+:[0-9]+'}]}]}}

    g1.set_bgp_defined_set(cs0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchCommunitySet':{'CommunitySet': 'cs0'}}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    # this will be blocked
    e1.add_route('192.168.100.0/24', community=['65100:10'])
    # this will pass
    e1.add_route('192.168.200.0/24', community=['55100:20'])

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(16)
def check(env):
    # same check function as previous No.4 scenario
    scenarios[1]['check'](env)

"""
  No.17 community add action import-policy test
                              -------------------------------
  e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)->          q1
                              |                             |
                              | -> q2-rib -> q2-adj-rib-out | ->(community=65100:10,65100:20)-> q2
                              |    apply action             |
                              -------------------------------
"""
@scenario(17)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(17)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    cs0 = {'CommunitySets': {'CommunitySetList': [{'CommunitySetName': 'cs0', 'CommunityList': [{'Community': '65100:10'}]}]}}

    g1.set_bgp_defined_set(cs0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchCommunitySet':{'CommunitySet': 'cs0'}}},
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetCommunity': {'Options': 'ADD',
                                      'SetCommunityMethod': {'Communities': ['65100:20']}}}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.100.0/24', community=['65100:10'])

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

def community_exists(path, com):
    a, b = com.split(':')
    com = (int(a) << 16) + int(b)
    for a in path['attrs']:
        if a['type'] == BGP_ATTR_TYPE_COMMUNITIES and com in a['communities']:
            return True
    return False

@scenario(17)
def check(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    wait_for(lambda : len(g1.get_local_rib(q1)) == 1)
    wait_for(lambda : len(g1.get_adj_rib_out(q1)) == 1)
    wait_for(lambda : len(q1.get_global_rib()) == 1)
    wait_for(lambda : len(g1.get_local_rib(q2)) == 1)
    wait_for(lambda : len(g1.get_adj_rib_out(q2)) == 1)
    wait_for(lambda : len(q2.get_global_rib()) == 1)

@scenario(17)
def check2(env):
    g1 = env.g1
    q1 = env.q1
    q2 = env.q2
    path = g1.get_adj_rib_out(q1)[0]
    env.assertTrue(community_exists(path, '65100:10'))
    env.assertFalse(community_exists(path, '65100:20'))
    path = g1.get_adj_rib_out(q2)[0]
    env.assertTrue(community_exists(path, '65100:10'))
    env.assertTrue(community_exists(path, '65100:20'))

"""
  No.18 community replace action import-policy test
                              -------------------------------
  e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)-> q1
                              |                             |
                              | -> q2-rib -> q2-adj-rib-out | ->(community=65100:20)-> q2
                              |    apply action             |
                              -------------------------------
"""
@scenario(18)
def boot(env):
    scenarios[1]['boot'](env)


@scenario(18)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    cs0 = {'CommunitySets': {'CommunitySetList': [{'CommunitySetName': 'cs0', 'CommunityList': [{'Community': '65100:10'}]}]}}

    g1.set_bgp_defined_set(cs0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchCommunitySet':{'CommunitySet': 'cs0'}}},
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetCommunity': {'Options': 'REPLACE',
                                      'SetCommunityMethod': {'Communities': ['65100:20']}}}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.100.0/24', community=['65100:10'])

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)



@scenario(18)
def check(env):
    # same check function as previous No.17 scenario
    scenarios[17]['check'](env)

@scenario(18)
def check2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    path = g1.get_adj_rib_out(q1)[0]
    env.assertTrue(community_exists(path, '65100:10'))
    env.assertFalse(community_exists(path, '65100:20'))
    path = g1.get_adj_rib_out(q2)[0]
    env.assertFalse(community_exists(path, '65100:10'))
    env.assertTrue(community_exists(path, '65100:20'))

"""
  No.19 community remove action import-policy test
                              -------------------------------
  e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)-> q1
                              |                             |
                              | -> q2-rib -> q2-adj-rib-out | ->(community=null)->     q2
                              |    apply action             |
                              -------------------------------
"""
@scenario(19)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(19)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    cs0 = {'CommunitySets': {'CommunitySetList': [{'CommunitySetName': 'cs0', 'CommunityList': [{'Community': '65100:10'}]}]}}

    g1.set_bgp_defined_set(cs0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchCommunitySet':{'CommunitySet': 'cs0'}}},
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetCommunity': {'Options': 'REMOVE',
                                      'SetCommunityMethod': {'Communities': ['65100:10', '65100:20']}}}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.100.0/24', community=['65100:10'])
    e1.add_route('192.168.110.0/24', community=['65100:10', '65100:20'])
    e1.add_route('192.168.120.0/24', community=['65100:10', '65100:30'])

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(19)
def check(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    wait_for(lambda : len(g1.get_local_rib(q1)) == 3)
    wait_for(lambda : len(g1.get_adj_rib_out(q1)) == 3)
    wait_for(lambda : len(q1.get_global_rib()) == 3)
    wait_for(lambda : len(g1.get_local_rib(q2)) == 3)
    wait_for(lambda : len(g1.get_adj_rib_out(q2)) == 3)
    wait_for(lambda : len(q2.get_global_rib()) == 3)

@scenario(19)
def check2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    adj_out = g1.get_adj_rib_out(q1)
    for path in adj_out:
        env.assertTrue(community_exists(path, '65100:10'))
        if path['nlri']['prefix'] == '192.168.110.0/24':
            env.assertTrue(community_exists(path, '65100:20'))
        if path['nlri']['prefix'] == '192.168.120.0/24':
            env.assertTrue(community_exists(path, '65100:30'))
    adj_out = g1.get_adj_rib_out(q2)
    for path in adj_out:
        env.assertFalse(community_exists(path, '65100:10'))
        if path['nlri']['prefix'] == '192.168.110.0/24':
            env.assertFalse(community_exists(path, '65100:20'))
        if path['nlri']['prefix'] == '192.168.120.0/24':
            env.assertTrue(community_exists(path, '65100:30'))

"""
  No.20 community null action import-policy test
                              -------------------------------
  e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)-> q1
                              |                             |
                              | -> q2-rib -> q2-adj-rib-out | ->(community=null)->     q2
                              |    apply action             |
                              -------------------------------
"""
@scenario(20)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(20)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    cs0 = {'CommunitySets': {'CommunitySetList': [{'CommunitySetName': 'cs0', 'CommunityList': [{'Community': '65100:10'}]}]}}

    g1.set_bgp_defined_set(cs0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchCommunitySet':{'CommunitySet': 'cs0'}}},
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetCommunity': {'Options': 'REPLACE',
                                      'SetCommunityMethod': {'Communities': []}}}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.100.0/24', community=['65100:10'])
    e1.add_route('192.168.110.0/24', community=['65100:10', '65100:20'])
    e1.add_route('192.168.120.0/24', community=['65100:10', '65100:30'])

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(20)
def check(env):
    scenarios[19]['check'](env)

@scenario(20)
def check2(env):
    g1 = env.g1
    q1 = env.q1
    q2 = env.q2
    adj_out = g1.get_adj_rib_out(q1)
    for path in adj_out:
        env.assertTrue(community_exists(path, '65100:10'))
        if path['nlri']['prefix'] == '192.168.110.0/24':
            env.assertTrue(community_exists(path, '65100:20'))
        if path['nlri']['prefix'] == '192.168.120.0/24':
            env.assertTrue(community_exists(path, '65100:30'))
    adj_out = g1.get_adj_rib_out(q2)
    for path in adj_out:
        env.assertFalse(community_exists(path, '65100:10'))
        if path['nlri']['prefix'] == '192.168.110.0/24':
            env.assertFalse(community_exists(path, '65100:20'))
        if path['nlri']['prefix'] == '192.168.120.0/24':
            env.assertFalse(community_exists(path, '65100:30'))


"""
  No.21 community add action export-policy test
                              -------------------------------
  e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)-> q1
                              |                             |
                              | -> q2-rib -> q2-adj-rib-out | ->(community=null)->     q2
                              |              apply action   |
                              -------------------------------
"""
@scenario(21)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(21)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    cs0 = {'CommunitySets': {'CommunitySetList': [{'CommunitySetName': 'cs0', 'CommunityList': [{'Community': '65100:10'}]}]}}

    g1.set_bgp_defined_set(cs0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchCommunitySet':{'CommunitySet': 'cs0'}}},
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetCommunity': {'Options': 'ADD',
                                      'SetCommunityMethod': {'Communities': ['65100:20']}}}}}

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.100.0/24', community=['65100:10'])

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(21)
def check(env):
    scenarios[17]['check'](env)

@scenario(21)
def check2(env):
    g1 = env.g1
    q1 = env.q1
    q2 = env.q2

    adj_out = g1.get_adj_rib_out(q1)
    for path in adj_out:
        env.assertTrue(community_exists(path, '65100:10'))
        env.assertFalse(community_exists(path, '65100:20'))

    local_rib = g1.get_local_rib(q2)
    for path in local_rib[0]['paths']:
        env.assertTrue(community_exists(path, '65100:10'))
        env.assertFalse(community_exists(path, '65100:20'))

    adj_out = g1.get_adj_rib_out(q2)
    for path in adj_out:
        env.assertTrue(community_exists(path, '65100:10'))
        env.assertTrue(community_exists(path, '65100:20'))

"""
  No.22 community replace action export-policy test
                              -------------------------------
  e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)-> q1
                              |                             |
                              | -> q2-rib -> q2-adj-rib-out | ->(community=65100:20)-> q2
                              |              apply action   |
                              -------------------------------
"""
@scenario(22)
def boot(env):
    scenarios[1]['boot'](env)


@scenario(22)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    cs0 = {'CommunitySets': {'CommunitySetList': [{'CommunitySetName': 'cs0', 'CommunityList': [{'Community': '65100:10'}]}]}}

    g1.set_bgp_defined_set(cs0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchCommunitySet':{'CommunitySet': 'cs0'}}},
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetCommunity': {'Options': 'REPLACE',
                                      'SetCommunityMethod': {'Communities': ['65100:20']}}}}}

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.100.0/24', community=['65100:10'])

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(22)
def check(env):
    scenarios[17]['check'](env)

@scenario(22)
def check2(env):
    g1 = env.g1
    q1 = env.q1
    q2 = env.q2

    adj_out = g1.get_adj_rib_out(q1)
    for path in adj_out:
        env.assertTrue(community_exists(path, '65100:10'))
        env.assertFalse(community_exists(path, '65100:20'))

    local_rib = g1.get_local_rib(q2)
    for path in local_rib[0]['paths']:
        env.assertTrue(community_exists(path, '65100:10'))
        env.assertFalse(community_exists(path, '65100:20'))

    adj_out = g1.get_adj_rib_out(q2)
    for path in adj_out:
        env.assertFalse(community_exists(path, '65100:10'))
        env.assertTrue(community_exists(path, '65100:20'))

"""
  No.23 community replace action export-policy test
                              -------------------------------
  e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)-> q1
                              |                             |
                              | -> q2-rib -> q2-adj-rib-out | ->(community=null)->     q2
                              |              apply action   |
                              -------------------------------
"""
@scenario(23)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(23)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    cs0 = {'CommunitySets': {'CommunitySetList': [{'CommunitySetName': 'cs0', 'CommunityList': [{'Community': '65100:10'}]}]}}

    g1.set_bgp_defined_set(cs0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchCommunitySet':{'CommunitySet': 'cs0'}}},
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetCommunity': {'Options': 'REMOVE',
                                      'SetCommunityMethod': {'Communities': ['65100:20', '65100:30']}}}}}

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.100.0/24', community=['65100:10', '65100:20', '65100:30'])

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(23)
def check(env):
    scenarios[17]['check'](env)

@scenario(23)
def check2(env):
    g1 = env.g1
    q1 = env.q1
    q2 = env.q2

    adj_out = g1.get_adj_rib_out(q1)
    for path in adj_out:
        env.assertTrue(community_exists(path, '65100:10'))
        env.assertTrue(community_exists(path, '65100:20'))
        env.assertTrue(community_exists(path, '65100:30'))

    local_rib = g1.get_local_rib(q2)
    for path in local_rib[0]['paths']:
        env.assertTrue(community_exists(path, '65100:10'))
        env.assertTrue(community_exists(path, '65100:20'))
        env.assertTrue(community_exists(path, '65100:30'))

    adj_out = g1.get_adj_rib_out(q2)
    for path in adj_out:
        env.assertTrue(community_exists(path, '65100:10'))
        env.assertFalse(community_exists(path, '65100:20'))
        env.assertFalse(community_exists(path, '65100:30'))

"""
  No.24 community null action export-policy test
                              -------------------------------
  e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)-> q1
                              |                             |
                              | -> q2-rib -> q2-adj-rib-out | ->(community=null)->     q2
                              |              apply action   |
                              -------------------------------
"""
@scenario(24)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(24)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    cs0 = {'CommunitySets': {'CommunitySetList': [{'CommunitySetName': 'cs0', 'CommunityList': [{'Community': '65100:10'}]}]}}

    g1.set_bgp_defined_set(cs0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchCommunitySet':{'CommunitySet': 'cs0'}}},
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetCommunity': {'Options': 'REPLACE',
                                      'SetCommunityMethod': {'Communities': []}}}}}

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.100.0/24', community=['65100:10', '65100:20', '65100:30'])

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(24)
def check(env):
    scenarios[17]['check'](env)

@scenario(24)
def check2(env):
    g1 = env.g1
    q1 = env.q1
    q2 = env.q2

    adj_out = g1.get_adj_rib_out(q1)
    for path in adj_out:
        env.assertTrue(community_exists(path, '65100:10'))
        env.assertTrue(community_exists(path, '65100:20'))
        env.assertTrue(community_exists(path, '65100:30'))

    local_rib = g1.get_local_rib(q2)
    for path in local_rib[0]['paths']:
        env.assertTrue(community_exists(path, '65100:10'))
        env.assertTrue(community_exists(path, '65100:20'))
        env.assertTrue(community_exists(path, '65100:30'))

    adj_out = g1.get_adj_rib_out(q2)
    for path in adj_out:
        env.assertFalse(community_exists(path, '65100:10'))
        env.assertFalse(community_exists(path, '65100:20'))
        env.assertFalse(community_exists(path, '65100:30'))

"""
  No.25 med replace action import-policy test
                   -------------------------------
  e1 ->(med=300)-> | -> q1-rib -> q1-adj-rib-out | ->(med=300)-> q1
                   |                             |
                   | -> q2-rib -> q2-adj-rib-out | ->(med=100)-> q2
                   |    apply action             |
                   -------------------------------
"""
@scenario(25)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(25)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    st0 = {'Name': 'st0',
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetMed': '100'}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.100.0/24', med=300)

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)



def metric(path):
    for a in path['attrs']:
        if 'metric' in a:
            return a['metric']
    return -1

@scenario(25)
def check(env):
    scenarios[17]['check'](env)

@scenario(25)
def check2(env):
    g1 = env.g1
    q1 = env.q1
    q2 = env.q2

    adj_out = g1.get_adj_rib_out(q1)
    env.assertTrue(metric(adj_out[0]) == 300)

    local_rib = g1.get_local_rib(q2)
    env.assertTrue(metric(local_rib[0]['paths'][0]) == 100)

    adj_out = g1.get_adj_rib_out(q2)
    env.assertTrue(metric(adj_out[0]) == 100)

"""
  No.26 med add action import-policy test
                   -------------------------------
  e1 ->(med=300)-> | -> q1-rib -> q1-adj-rib-out | ->(med=300)->     q1
                   |                             |
                   | -> q2-rib -> q2-adj-rib-out | ->(med=300+100)-> q2
                   |    apply action             |
                   -------------------------------
"""
@scenario(26)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(26)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    st0 = {'Name': 'st0',
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetMed': '+100'}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.100.0/24', med=300)

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(26)
def check(env):
    scenarios[17]['check'](env)

@scenario(26)
def check2(env):
    g1 = env.g1
    q1 = env.q1
    q2 = env.q2

    adj_out = g1.get_adj_rib_out(q1)
    env.assertTrue(metric(adj_out[0]) == 300)

    local_rib = g1.get_local_rib(q2)
    env.assertTrue(metric(local_rib[0]['paths'][0]) == 400)

    adj_out = g1.get_adj_rib_out(q2)
    env.assertTrue(metric(adj_out[0]) == 400)

"""
  No.27 med subtract action import-policy test
                   -------------------------------
  e1 ->(med=300)-> | -> q1-rib -> q1-adj-rib-out | ->(med=300)->     q1
                   |                             |
                   | -> q2-rib -> q2-adj-rib-out | ->(med=300-100)-> q2
                   |    apply action             |
                   -------------------------------
"""
@scenario(27)
def boot(env):
    scenarios[1]['boot'](env)


@scenario(27)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    st0 = {'Name': 'st0',
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetMed': '-100'}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.100.0/24', med=300)

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(27)
def check(env):
    scenarios[17]['check'](env)

@scenario(27)
def check2(env):
    g1 = env.g1
    q1 = env.q1
    q2 = env.q2

    adj_out = g1.get_adj_rib_out(q1)
    env.assertTrue(metric(adj_out[0]) == 300)

    local_rib = g1.get_local_rib(q2)
    env.assertTrue(metric(local_rib[0]['paths'][0]) == 200)

    adj_out = g1.get_adj_rib_out(q2)
    env.assertTrue(metric(adj_out[0]) == 200)

"""
  No.28 med replace action export-policy test
                   -------------------------------
  e1 ->(med=300)-> | -> q1-rib -> q1-adj-rib-out | ->(med=300)-> q1
                   |                             |
                   | -> q2-rib -> q2-adj-rib-out | ->(med=100)-> q2
                   |              apply action   |
                   -------------------------------
"""
@scenario(28)
def boot(env):
    scenarios[1]['boot'](env)


@scenario(28)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    st0 = {'Name': 'st0',
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetMed': '100'}}}

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.100.0/24', med=300)

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(28)
def check(env):
    scenarios[17]['check'](env)

@scenario(28)
def check2(env):
    g1 = env.g1
    q1 = env.q1
    q2 = env.q2

    adj_out = g1.get_adj_rib_out(q1)
    env.assertTrue(metric(adj_out[0]) == 300)

    local_rib = g1.get_local_rib(q2)
    env.assertTrue(metric(local_rib[0]['paths'][0]) == 300)

    adj_out = g1.get_adj_rib_out(q2)
    env.assertTrue(metric(adj_out[0]) == 100)

"""
  No.29 med add action export-policy test
                   -------------------------------
  e1 ->(med=300)-> | -> q1-rib -> q1-adj-rib-out | ->(med=300)->     q1
                   |                             |
                   | -> q2-rib -> q2-adj-rib-out | ->(med=300+100)-> q2
                   |              apply action   |
                   -------------------------------
"""
@scenario(29)
def boot(env):
    scenarios[1]['boot'](env)


@scenario(29)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    st0 = {'Name': 'st0',
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetMed': '+100'}}}

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.100.0/24', med=300)

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(29)
def check(env):
    scenarios[17]['check'](env)

@scenario(29)
def check2(env):
    g1 = env.g1
    q1 = env.q1
    q2 = env.q2

    adj_out = g1.get_adj_rib_out(q1)
    env.assertTrue(metric(adj_out[0]) == 300)

    local_rib = g1.get_local_rib(q2)
    env.assertTrue(metric(local_rib[0]['paths'][0]) == 300)

    adj_out = g1.get_adj_rib_out(q2)
    env.assertTrue(metric(adj_out[0]) == 400)

"""
  No.30 med subtract action export-policy test
                   -------------------------------
  e1 ->(med=300)-> | -> q1-rib -> q1-adj-rib-out | ->(med=300)->     q1
                   |                             |
                   | -> q2-rib -> q2-adj-rib-out | ->(med=300-100)-> q2
                   |              apply action   |
                   -------------------------------
"""
@scenario(30)
def boot(env):
    scenarios[1]['boot'](env)


@scenario(30)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    st0 = {'Name': 'st0',
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetMed': '-100'}}}

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.100.0/24', med=300)

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(30)
def check(env):
    scenarios[17]['check'](env)

@scenario(30)
def check2(env):
    g1 = env.g1
    q1 = env.q1
    q2 = env.q2

    adj_out = g1.get_adj_rib_out(q1)
    env.assertTrue(metric(adj_out[0]) == 300)

    local_rib = g1.get_local_rib(q2)
    env.assertTrue(metric(local_rib[0]['paths'][0]) == 300)

    adj_out = g1.get_adj_rib_out(q2)
    env.assertTrue(metric(adj_out[0]) == 200)

"""
  No.31 in-policy reject test
                                    ----------------
  e1 ->r1(community=65100:10) ->  x | -> q1-rib -> | -> r2 --> q1
       r2(192.168.10.0/24)    ->  o |              |
                                    | -> q2-rib -> | -> r2 --> q2
                                    ----------------
"""
@scenario(31)
def boot(env):
    scenarios[1]['boot'](env)


@scenario(31)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    cs0 = {'CommunitySets': {'CommunitySetList': [{'CommunitySetName': 'cs0', 'CommunityList': [{'Community': '65100:10'}]}]}}

    g1.set_bgp_defined_set(cs0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchCommunitySet':{'CommunitySet': 'cs0'}}}}

    policy = {'name': 'policy0',
              'type': 'in',
              'statements': [st0]}
    g1.add_policy(policy, e1)

    e1.add_route('192.168.100.0/24', community=['65100:10'])
    e1.add_route('192.168.10.0/24')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(31)
def check(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    wait_for(lambda : len(g1.get_adj_rib_in(e1)) == 2)
    wait_for(lambda : len(g1.get_local_rib(q1)) == 1)
    wait_for(lambda : len(g1.get_adj_rib_out(q1)) == 1)
    wait_for(lambda : len(q1.get_global_rib()) == 1)
    wait_for(lambda : len(g1.get_local_rib(q2)) == 1)
    wait_for(lambda : len(g1.get_adj_rib_out(q2)) == 1)
    wait_for(lambda : len(q2.get_global_rib()) == 1)

"""
  No.32 in-policy accept test
                                    ----------------
  e1 ->r1(community=65100:10) ->  x | -> q1-rib -> | -> r2 --> q1
       r2(192.168.10.0/24)    ->  o |              |
                                    | -> q2-rib -> | -> r2 --> q2
                                    ----------------
"""
@scenario(32)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(32)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    cs0 = {'CommunitySets': {'CommunitySetList': [{'CommunitySetName': 'cs0', 'CommunityList': [{'Community': '65100:10'}]}]}}

    g1.set_bgp_defined_set(cs0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchCommunitySet':{'CommunitySet': 'cs0'}}},
           'Actions':{'RouteDisposition': {'AcceptRoute': True}}}

    policy = {'name': 'policy0',
              'type': 'in',
              'statements': [st0],
              'default': 'reject'}
    g1.add_policy(policy, e1)

    e1.add_route('192.168.100.0/24', community=['65100:10'])
    e1.add_route('192.168.10.0/24')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(32)
def check(env):
    scenarios[31]['check'](env)

"""
  No.33 in-policy set community action
                                    ----------------
  e1 ->r1(community=65100:10) ->  o | -> q1-rib -> | -> r1(community=65100:10, 65100:20), r2 --> q1
       r2(192.168.10.0/24)    ->  o |              |
                                    | -> q2-rib -> | -> r1(community=65100:10, 65100:20), r2 --> q2
                                    ----------------
"""
@scenario(33)
def boot(env):
    scenarios[1]['boot'](env)


@scenario(33)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    cs0 = {'CommunitySets': {'CommunitySetList': [{'CommunitySetName': 'cs0', 'CommunityList': [{'Community': '65100:10'}]}]}}

    g1.set_bgp_defined_set(cs0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchCommunitySet':{'CommunitySet': 'cs0'}}},
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetCommunity': {'Options': 'ADD',
                                      'SetCommunityMethod': {'Communities': ['65100:20']}}}}}

    policy = {'name': 'policy0',
              'type': 'in',
              'statements': [st0]}
    g1.add_policy(policy, e1)

    e1.add_route('192.168.100.0/24', community=['65100:10'])
    e1.add_route('192.168.10.0/24')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(33)
def check(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    wait_for(lambda : len(g1.get_adj_rib_in(e1)) == 2)
    wait_for(lambda : len(g1.get_local_rib(q1)) == 2)
    wait_for(lambda : len(g1.get_adj_rib_out(q1)) == 2)
    wait_for(lambda : len(q1.get_global_rib()) == 2)
    wait_for(lambda : len(g1.get_local_rib(q2)) == 2)
    wait_for(lambda : len(g1.get_adj_rib_out(q2)) == 2)
    wait_for(lambda : len(q2.get_global_rib()) == 2)

@scenario(33)
def check2(env):
    g1 = env.g1
    q1 = env.q1
    q2 = env.q2
    for q in [q1, q2]:
        adj_out = g1.get_adj_rib_out(q, prefix='192.168.100.0/24')
        env.assertTrue(len(adj_out) == 1)
        env.assertTrue(community_exists(adj_out[0], '65100:10'))
        env.assertTrue(community_exists(adj_out[0], '65100:20'))

        adj_out = g1.get_adj_rib_out(q, prefix='192.168.10.0/24')
        env.assertTrue(len(adj_out) == 1)
        env.assertFalse(community_exists(adj_out[0], '65100:10'))
        env.assertFalse(community_exists(adj_out[0], '65100:20'))

"""
  No.34 in-policy med add action
                                  -----------------
  e1 -> r1(med=300)         ->  o | -> q1-rib ->  | -> r1(med=400), r2 --> q1
        r2(192.168.10.0/24) ->  o |               |
                                  | -> q2-rib ->  | -> r1(med=400), r2 --> q2
                                  -----------------
"""
@scenario(34)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(34)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    cs0 = {'CommunitySets': {'CommunitySetList': [{'CommunitySetName': 'cs0', 'CommunityList': [{'Community': '65100:10'}]}]}}

    g1.set_bgp_defined_set(cs0)

    st0 = {'Name': 'st0',
           'Conditions':{'BgpConditions':{'MatchCommunitySet':{'CommunitySet': 'cs0'}}},
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetMed': '+100'}}}

    policy = {'name': 'policy0',
              'type': 'in',
              'statements': [st0]}
    g1.add_policy(policy, e1)

    e1.add_route('192.168.100.0/24', community=['65100:10'])
    e1.add_route('192.168.10.0/24')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(34)
def check(env):
    scenarios[33]['check'](env)

@scenario(34)
def check2(env):
    g1 = env.g1
    q1 = env.q1
    q2 = env.q2
    for q in [q1, q2]:
        adj_out = g1.get_adj_rib_out(q, prefix='192.168.100.0/24')
        env.assertTrue(len(adj_out) == 1)
        env.assertTrue(metric(adj_out[0]) == 100)

        adj_out = g1.get_adj_rib_out(q, prefix='192.168.10.0/24')
        env.assertTrue(len(adj_out) == 1)
        env.assertTrue(metric(adj_out[0]) == -1)

"""
  No.35 in-policy update test
  r1:192.168.2.0
  r2:192.168.20.0
  r3:192.168.200.0
                    -------------------------------------
                    | q1                                |
  e1 ->(r1,r2,r3)-> | ->(r1)-> rib ->(r1)-> adj-rib-out | ->(r1)-> q1
                    |                                   |
                    | q2                                |
                    | ->(r1)-> rib ->(r1)-> adj-rib-out | ->(r1)-> q2
                    -------------------------------------
               |
    update distribute policy
               |
               V
                    -------------------------------------------
                    | q1                                      |
  e1 ->(r1,r2,r3)-> | ->(r1,r2)-> rib ->(r1,r2)-> adj-rib-out | ->(r1,r2)-> q1
                    |                                         |
                    | q2                                      |
                    | ->(r1,r3)-> rib ->(r1,r3)-> adj-rib-out | ->(r1,r3)-> q2
                    -------------------------------------------
"""
@scenario(35)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(35)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '192.168.20.0/24'}
    p1 = {'IpPrefix': '192.168.200.0/24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0, p1]}
    g1.set_prefix_set(ps0)

    n0 = {'Address': g1.peers[e1]['neigh_addr'].split('/')[0]}

    ns0 = {'NeighborSetName': 'ns0',
           'NeighborInfoList': [n0]}
    g1.set_neighbor_set(ns0)

    st0 = {'Name': 'st0',
           'Conditions': {
               'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']},
               'MatchNeighborSet': {'NeighborSet': ns0['NeighborSetName']}}}

    policy = {'name': 'policy0',
              'type': 'in',
              'statements': [st0]}
    g1.add_policy(policy, e1)

    e1.add_route('192.168.2.0/24')
    e1.add_route('192.168.20.0/24')
    e1.add_route('192.168.200.0/24')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(35)
def check(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    wait_for(lambda : len(g1.get_adj_rib_in(e1)) == 3)
    wait_for(lambda : len(g1.get_local_rib(q1)) == 1)
    wait_for(lambda : len(g1.get_adj_rib_out(q1)) == 1)
    wait_for(lambda : len(q1.get_global_rib()) == 1)
    wait_for(lambda : len(g1.get_local_rib(q2)) == 1)
    wait_for(lambda : len(g1.get_adj_rib_out(q2)) == 1)
    wait_for(lambda : len(q2.get_global_rib()) == 1)

@scenario(35)
def setup2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    g1.clear_policy()

    p0 = {'IpPrefix': '192.168.20.0/24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    n0 = {'Address': g1.peers[e1]['neigh_addr'].split('/')[0]}

    ns0 = {'NeighborSetName': 'ns0',
           'NeighborInfoList': [n0]}
    g1.set_neighbor_set(ns0)

    st0 = {'Name': 'st0',
           'Conditions': {'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']},
                          'MatchNeighborSet': {'NeighborSet': ns0['NeighborSetName']}}}

    policy = {'name': 'policy0',
              'type': 'in',
              'statements': [st0]}
    g1.add_policy(policy, e1)
    g1.softreset(e1)

@scenario(35)
def check2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    wait_for(lambda : len(g1.get_adj_rib_in(e1)) == 3)
    wait_for(lambda : len(g1.get_local_rib(q1)) == 2)
    wait_for(lambda : len(g1.get_adj_rib_out(q1)) == 2)
    wait_for(lambda : len(q1.get_global_rib()) == 2)
    wait_for(lambda : len(g1.get_local_rib(q2)) == 2)
    wait_for(lambda : len(g1.get_adj_rib_out(q2)) == 2)
    wait_for(lambda : len(q2.get_global_rib()) == 2)

"""
  No.36 aspath prepend action import
                          --------------------------------
  e1 ->(aspath=[65001])-> | ->  p1-rib -> p1-adj-rib-out | -> p1
                          |                              |
                          | ->  p2-rib -> p2-adj-rib-out | -> p2
                          |     apply action             |
                          --------------------------------
"""
@scenario(36)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(36)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '192.168.20.0/24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    st0 = {'Name': 'st0',
           'Conditions': {'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']}},
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetAsPathPrepend': {'RepeatN': 5, 'As': "65005"}}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.20.0/24')
    e1.add_route('192.168.200.0/24')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(36)
def check(env):
    scenarios[33]['check'](env)

@scenario(36)
def check2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    path = g1.get_adj_rib_out(q1, prefix='192.168.20.0/24')[0]
    env.assertTrue(path['as_path'] == [e1.asn])

    path = g1.get_adj_rib_out(q1, prefix='192.168.200.0/24')[0]
    env.assertTrue(path['as_path'] == [e1.asn])

    path = g1.get_local_rib(q2, prefix='192.168.20.0/24')[0]['paths'][0]
    env.assertTrue(path['as_path'] == [65005]*5 + [e1.asn])

    path = g1.get_adj_rib_out(q2, prefix='192.168.20.0/24')[0]
    env.assertTrue(path['as_path'] == [65005]*5 + [e1.asn])

    path = g1.get_adj_rib_out(q2, prefix='192.168.200.0/24')[0]
    env.assertTrue(path['as_path'] == [e1.asn])


"""
  No.37 aspath prepend action export
                          --------------------------------
  e1 ->(aspath=[65001])-> | ->  p1-rib -> p1-adj-rib-out | -> p1
                          |                              |
                          | ->  p2-rib -> p2-adj-rib-out | -> p2
                          |               apply action   |
                          --------------------------------
"""
@scenario(37)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(37)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '192.168.20.0/24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    st0 = {'Name': 'st0',
           'Conditions': {'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']}},
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetAsPathPrepend': {'RepeatN': 5, 'As': "65005"}}}}

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.20.0/24')
    e1.add_route('192.168.200.0/24')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(37)
def check(env):
    scenarios[33]['check'](env)

@scenario(37)
def check2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    path = g1.get_adj_rib_out(q1, prefix='192.168.20.0/24')[0]
    env.assertTrue(path['as_path'] == [e1.asn])

    path = g1.get_adj_rib_out(q1, prefix='192.168.200.0/24')[0]
    env.assertTrue(path['as_path'] == [e1.asn])

    path = g1.get_local_rib(q2, prefix='192.168.20.0/24')[0]['paths'][0]
    env.assertTrue(path['as_path'] == [e1.asn])

    path = g1.get_adj_rib_out(q2, prefix='192.168.20.0/24')[0]
    env.assertTrue(path['as_path'] == [65005]*5 + [e1.asn])

    path = g1.get_adj_rib_out(q2, prefix='192.168.200.0/24')[0]
    env.assertTrue(path['as_path'] == [e1.asn])

"""
  No.38 aspath prepend action lastas import
                          --------------------------------
  e1 ->(aspath=[65001])-> | ->  p1-rib -> p1-adj-rib-out | -> p1
                          |                              |
                          | ->  p2-rib -> p2-adj-rib-out | -> p2
                          |     apply action             |
                          --------------------------------
"""
@scenario(38)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(38)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '192.168.20.0/24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    st0 = {'Name': 'st0',
           'Conditions': {'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']}},
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetAsPathPrepend': {'RepeatN': 5, 'As': "last-as"}}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.20.0/24')
    e1.add_route('192.168.200.0/24')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(38)
def check(env):
    scenarios[33]['check'](env)

@scenario(38)
def check2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    path = g1.get_adj_rib_out(q1, prefix='192.168.20.0/24')[0]
    env.assertTrue(path['as_path'] == [e1.asn])

    path = g1.get_adj_rib_out(q1, prefix='192.168.200.0/24')[0]
    env.assertTrue(path['as_path'] == [e1.asn])

    path = g1.get_local_rib(q2, prefix='192.168.20.0/24')[0]['paths'][0]
    env.assertTrue(path['as_path'] == [e1.asn]*5 + [e1.asn])

    path = g1.get_adj_rib_out(q2, prefix='192.168.20.0/24')[0]
    env.assertTrue(path['as_path'] == [e1.asn]*5 + [e1.asn])

    path = g1.get_adj_rib_out(q2, prefix='192.168.200.0/24')[0]
    env.assertTrue(path['as_path'] == [e1.asn])

"""
  No.39 aspath prepend action lastas export
                          --------------------------------
  e1 ->(aspath=[65001])-> | ->  p1-rib -> p1-adj-rib-out | -> p1
                          |                              |
                          | ->  p2-rib -> p2-adj-rib-out | -> p2
                          |     apply action             |
                          --------------------------------
"""
@scenario(39)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(39)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '192.168.20.0/24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    st0 = {'Name': 'st0',
           'Conditions': {'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']}},
           'Actions': {'RouteDisposition': {'AcceptRoute': True},
                       'BgpActions': {'SetAsPathPrepend': {'RepeatN': 5, 'As': "last-as"}}}}

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.20.0/24')
    e1.add_route('192.168.200.0/24')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(39)
def check(env):
    scenarios[33]['check'](env)

@scenario(39)
def check2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    path = g1.get_adj_rib_out(q1, prefix='192.168.20.0/24')[0]
    env.assertTrue(path['as_path'] == [e1.asn])

    path = g1.get_adj_rib_out(q1, prefix='192.168.200.0/24')[0]
    env.assertTrue(path['as_path'] == [e1.asn])

    path = g1.get_local_rib(q2, prefix='192.168.20.0/24')[0]['paths'][0]
    env.assertTrue(path['as_path'] == [e1.asn])

    path = g1.get_adj_rib_out(q2, prefix='192.168.20.0/24')[0]
    env.assertTrue(path['as_path'] == [e1.asn]*5 + [e1.asn])

    path = g1.get_adj_rib_out(q2, prefix='192.168.200.0/24')[0]
    env.assertTrue(path['as_path'] == [e1.asn])


"""
  No.40 extended community origin condition import
                                               --------------------------------
  e1 ->(extcommunity=origin:65001.65100:200)-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                                               |                              |
                                               | ->x q2-rib                   |
                                               --------------------------------
"""
@scenario(40)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(40)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    es0 = {'ExtCommunitySets': {'ExtCommunitySetList': [{'ExtCommunitySetName': 'es0',
                                'ExtCommunityList': [{'ExtCommunity': 'SoO:65001.65100:200'}]}]}}

    g1.set_bgp_defined_set(es0)

    st0 = {'Name': 'st0',
            'Conditions': {'BgpConditions':{'MatchExtCommunitySet':{'ExtCommunitySet': 'es0'}}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.20.0/24', extendedcommunity='origin:{0}:200'.format((65001 << 16) + 65100))
    e1.add_route('192.168.200.0/24', extendedcommunity='origin:{0}:100'.format((65001 << 16) + 65200))

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(40)
def check(env):
    scenarios[1]['check'](env)

"""
  No.41 extended community origin condition import
                                         --------------------------------
  e1 ->(extcommunity=target:65010:320)-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                                         |                              |
                                         | ->x q2-rib                   |
                                         --------------------------------
"""
@scenario(41)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(41)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    es0 = {'ExtCommunitySets': {'ExtCommunitySetList': [{'ExtCommunitySetName': 'es0',
                                'ExtCommunityList': [{'ExtCommunity': 'RT:6[0-9]+:3[0-9]+'}]}]}}

    g1.set_bgp_defined_set(es0)

    st0 = {'Name': 'st0',
            'Conditions': {'BgpConditions':{'MatchExtCommunitySet':{'ExtCommunitySet': 'es0'}}}}

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.20.0/24', extendedcommunity='target:65010:320')
    e1.add_route('192.168.200.0/24', extendedcommunity='target:55000:320')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(41)
def check(env):
    scenarios[1]['check'](env)


"""
  No.42 prefix only condition accept in
                                    -----------------
  e1 ->r1(192.168.100.0/24)   ->  o | -> q1-rib ->  | -> r2 --> q1
       r2(192.168.10.0/24)    ->  x |               |
                                    | -> q2-rib ->  | -> r2 --> q2
                                    -----------------
"""
@scenario(42)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(42)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '192.168.10.0/24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    st0 = {'Name': 'st0',
           'Conditions': {
               'MatchPrefixSet': {'PrefixSet': ps0['PrefixSetName']}}}

    policy = {'name': 'policy0',
              'type': 'in',
              'statements': [st0]}
    g1.add_policy(policy, e1)

    # this will be blocked
    e1.add_route('192.168.100.0/24')
    # this will pass
    e1.add_route('192.168.10.0/24')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(42)
def check(env):
    scenarios[31]['check'](env)


"""
  No.43 extended community add action import-policy test
                             ---------------------------------
  e1 ->(extcommunity=none) ->| ->  q1-rib ->  q1-adj-rib-out | --> q1
                             |                               |
                             | ->  q2-rib ->  q2-adj-rib-out | --> q2
                             |     add ext-community         |
                             ---------------------------------
"""
@scenario(43)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(43)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '192.168.10.0/24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    st0 = {
            'Name': 'st0',
            'Conditions': {
                'MatchPrefixSet': {
                    'PrefixSet': ps0['PrefixSetName']
                }
            },
           'Actions': {
               'RouteDisposition': {'AcceptRoute': True},
               'BgpActions': {
                   'SetExtCommunity': {
                       'Options': 'ADD',
                       'SetExtCommunityMethod': {
                           'Communities': ['0:2:0xfd:0xe8:0:0:0:1']
                        }
                    },
                }
            }
        }

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.10.0/24')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(43)
def check(env):
    scenarios[17]['check'](env)

def ext_community_exists(path, extcomm):
    typ = extcomm.split(':')[0]
    value = ':'.join(extcomm.split(':')[1:])
    for a in path['attrs']:
        if a['type'] == BGP_ATTR_TYPE_EXTENDED_COMMUNITIES:
            for c in a['value']:
                if typ == 'RT' and c['type'] == 0 and c['subtype'] == 2 and c['value'] == value:
                    return True
    return False

@scenario(43)
def check2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    path = g1.get_adj_rib_out(q1)[0]
    env.assertFalse(ext_community_exists(path, 'RT:65000:1'))
    path = g1.get_adj_rib_out(q2)[0]
    env.assertTrue(ext_community_exists(path, 'RT:65000:1'))

"""
  No.44 extended community add action import-policy test
                                    --------------------------------
  e1 ->(extcommunity=RT:65000:1) -> | ->  q1-rib -> q1-adj-rib-out | --> q1
                                    |                              |
                                    | ->  q2-rib -> q2-adj-rib-out | --> q2
                                    |     add ext-community        |
                                    --------------------------------
"""
@scenario(44)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(44)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '192.168.10.0/24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    st0 = {
            'Name': 'st0',
            'Conditions': {
                'MatchPrefixSet': {
                    'PrefixSet': ps0['PrefixSetName']
                }
            },
           'Actions': {
               'RouteDisposition': {'AcceptRoute': True},
               'BgpActions': {
                   'SetExtCommunity': {
                       'Options': 'ADD',
                       'SetExtCommunityMethod': {
                           'Communities': ['0:2:0xfe:0x4c:0:0:0:0x64']
                        }
                    },
                }
            }
        }

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.10.0/24', extendedcommunity='target:65000:1')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(44)
def check(env):
    scenarios[17]['check'](env)

@scenario(44)
def check2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    path = g1.get_adj_rib_out(q1)[0]
    env.assertTrue(ext_community_exists(path, 'RT:65000:1'))
    env.assertFalse(ext_community_exists(path, 'RT:65100:100'))
    path = g1.get_local_rib(q2)[0]['paths'][0]
    env.assertTrue(ext_community_exists(path, 'RT:65000:1'))
    env.assertTrue(ext_community_exists(path, 'RT:65100:100'))
    path = g1.get_adj_rib_out(q2)[0]
    env.assertTrue(ext_community_exists(path, 'RT:65000:1'))
    env.assertTrue(ext_community_exists(path, 'RT:65100:100'))

"""
  No.45 extended community add action multiple import-policy test
                                 ---------------------------------------
  exabgp ->(extcommunity=none) ->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                 |                                     |
                                 | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                 |     add ext-community               |
                                 ---------------------------------------
"""
@scenario(45)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(45)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '192.168.10.0/24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    st0 = {
            'Name': 'st0',
            'Conditions': {
                'MatchPrefixSet': {
                    'PrefixSet': ps0['PrefixSetName']
                }
            },
           'Actions': {
               'RouteDisposition': {'AcceptRoute': True},
               'BgpActions': {
                   'SetExtCommunity': {
                       'Options': 'ADD',
                       'SetExtCommunityMethod': {
                           'Communities': ['0:2:0xfe:0x4c:0:0:0:0x64', '0:2:0:0x64:0:0:0:0x64']
                        }
                    },
                }
            }
        }

    policy = {'name': 'policy0',
              'type': 'import',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.10.0/24')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(45)
def check(env):
    scenarios[17]['check'](env)

@scenario(45)
def check2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    path = g1.get_adj_rib_out(q1)[0]
    env.assertFalse(ext_community_exists(path, 'RT:65100:100'))
    env.assertFalse(ext_community_exists(path, 'RT:100:100'))
    path = g1.get_local_rib(q2)[0]['paths'][0]
    env.assertTrue(ext_community_exists(path, 'RT:65100:100'))
    env.assertTrue(ext_community_exists(path, 'RT:100:100'))
    path = g1.get_adj_rib_out(q2)[0]
    env.assertTrue(ext_community_exists(path, 'RT:65100:100'))
    env.assertTrue(ext_community_exists(path, 'RT:100:100'))

"""
  No.46 extended comunity add action export-policy test
                             ------------------------------------
  e1 ->(extcommunity=none) ->| ->  q1-rib ->  q1-adj-rib-out    | --> q1
                             |                                  |
                             | ->  q2-rib ->  q2-adj-rib-out    | --> q2
                             |                add ext-community |
                             ------------------------------------
"""
@scenario(46)
def boot(env):
    scenarios[1]['boot'](env)

@scenario(46)
def setup(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2

    p0 = {'IpPrefix': '192.168.10.0/24'}

    ps0 = {'PrefixSetName': 'ps0',
           'PrefixList': [p0]}
    g1.set_prefix_set(ps0)

    st0 = {
            'Name': 'st0',
            'Conditions': {
                'MatchPrefixSet': {
                    'PrefixSet': ps0['PrefixSetName']
                }
            },
           'Actions': {
               'RouteDisposition': {'AcceptRoute': True},
               'BgpActions': {
                   'SetExtCommunity': {
                       'Options': 'ADD',
                       'SetExtCommunityMethod': {
                           'Communities': ['0:2:0xfd:0xe8:0:0:0:1'],
                        }
                    },
                }
            }
        }

    policy = {'name': 'policy0',
              'type': 'export',
              'statements': [st0]}
    g1.add_policy(policy, q2)

    e1.add_route('192.168.10.0/24')

    for c in [e1, q1, q2]:
        g1.wait_for(BGP_FSM_ESTABLISHED, c)

@scenario(46)
def check(env):
    scenarios[17]['check'](env)

@scenario(46)
def check2(env):
    g1 = env.g1
    e1 = env.e1
    q1 = env.q1
    q2 = env.q2
    path = g1.get_adj_rib_out(q1)[0]
    env.assertFalse(ext_community_exists(path, 'RT:65000:1'))
    path = g1.get_local_rib(q2)[0]['paths'][0]
    env.assertFalse(ext_community_exists(path, 'RT:65000:1'))
    path = g1.get_adj_rib_out(q2)[0]
    env.assertTrue(ext_community_exists(path, 'RT:65000:1'))


class GoBGPTestBase(unittest.TestCase):

    wait_per_retry = 5
    retry_limit = 10

    @classmethod
    def setUpClass(cls):
        idx = parser_option.test_index
        base.TEST_PREFIX = parser_option.test_prefix
        cls.parser_option = parser_option

        if idx not in scenarios:
            print 'invalid test-index. # of scenarios: {0}'.format(len(scenarios))
            sys.exit(1)

        cls.boot = scenarios[idx]['boot']
        cls.setup = scenarios[idx]['setup']
        cls.check = scenarios[idx]['check']
        cls.setup2 = scenarios[idx]['setup2'] if 'setup2' in scenarios[idx] else None
        cls.check2 = scenarios[idx]['check2'] if 'check2' in scenarios[idx] else None

    def test(self):

        self.boot()

        self.setup()

        self.check()

        if self.setup2:
            self.setup2()

        if self.check2:
            self.check2()

if __name__ == '__main__':
    if os.geteuid() is not 0:
        print "you are not root."
        sys.exit(1)
    output = local("which docker 2>&1 > /dev/null ; echo $?", capture=True)
    if int(output) is not 0:
        print "docker not found"
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
