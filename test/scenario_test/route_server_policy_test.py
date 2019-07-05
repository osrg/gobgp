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



import sys
import time
import unittest
import inspect

import nose
from nose.tools import (
    assert_true,
    assert_false,
)

from lib.noseplugin import OptionParser, parser_option

from lib import base
from lib.base import (
    Bridge,
    BGP_FSM_ESTABLISHED,
    BGP_ATTR_TYPE_COMMUNITIES,
    BGP_ATTR_TYPE_EXTENDED_COMMUNITIES,
    local,
)
from lib.gobgp import GoBGPContainer
from lib.quagga import QuaggaBGPContainer
from lib.exabgp import ExaBGPContainer


counter = 1
_SCENARIOS = {}


def register_scenario(cls):
    global counter
    _SCENARIOS[counter] = cls
    counter += 1


def lookup_scenario(name):
    for value in list(_SCENARIOS.values()):
        if value.__name__ == name:
            return value
    return None


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


@register_scenario
class ImportPolicy(object):
    """
    No.1 import-policy test
                            --------------------------------
    e1 ->(192.168.2.0/24)-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                            |                              |
                            | ->x q2-rib                   |
                            --------------------------------
    """
    @staticmethod
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

        for q in [e1, q1, q2]:
            g1.add_peer(q, is_rs_client=True)
            q.add_peer(g1)

        env.g1 = g1
        env.e1 = e1
        env.q1 = q1
        env.q2 = q2

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '192.168.0.0/16',
              'masklength-range': '16..24'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0]}
        g1.set_prefix_set(ps0)

        ns0 = {'neighbor-set-name': 'ns0',
               'neighbor-info-list': [g1.peers[e1]['neigh_addr'].split('/')[0]]}
        g1.set_neighbor_set(ns0)

        st0 = {'name': 'st0',
               'conditions': {
                   'match-prefix-set': {'prefix-set': ps0['prefix-set-name']},
                   'match-neighbor-set': {'neighbor-set': ns0['neighbor-set-name']}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        # this will be blocked
        e1.add_route('192.168.2.0/24')
        # this will pass
        e1.add_route('192.168.2.0/15')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        wait_for(lambda: len(env.g1.get_local_rib(env.q1)) == 2)
        wait_for(lambda: len(env.g1.get_adj_rib_out(env.q1)) == 2)
        wait_for(lambda: len(env.q1.get_global_rib()) == 2)
        wait_for(lambda: len(env.g1.get_local_rib(env.q2)) == 1)
        wait_for(lambda: len(env.g1.get_adj_rib_out(env.q2)) == 1)
        wait_for(lambda: len(env.q2.get_global_rib()) == 1)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicy").boot(env)
        lookup_scenario("ImportPolicy").setup(env)
        lookup_scenario("ImportPolicy").check(env)


@register_scenario
class ExportPolicy(object):
    """
    No.2 export-policy test
                            --------------------------------
    e1 ->(192.168.2.0/24)-> | -> q1-rib ->  q1-adj-rib-out | --> q1
                            |                              |
                            | -> q2-rib ->x q2-adj-rib-out |
                            --------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '192.168.0.0/16',
              'masklength-range': '16..24'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0]}
        g1.set_prefix_set(ps0)

        ns0 = {'neighbor-set-name': 'ns0',
               'neighbor-info-list': [g1.peers[q2]['neigh_addr'].split('/')[0]]}
        g1.set_neighbor_set(ns0)

        st0 = {'name': 'st0',
               'conditions': {
                   'match-prefix-set': {'prefix-set': ps0['prefix-set-name']},
                   'match-neighbor-set': {'neighbor-set': ns0['neighbor-set-name']}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        # this will be blocked
        e1.add_route('192.168.2.0/24')
        # this will pass
        e1.add_route('192.168.2.0/15')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        g1 = env.g1
        q1 = env.q1
        q2 = env.q2
        wait_for(lambda: len(g1.get_local_rib(q1)) == 2)
        wait_for(lambda: len(g1.get_adj_rib_out(q1)) == 2)
        wait_for(lambda: len(q1.get_global_rib()) == 2)
        wait_for(lambda: len(g1.get_local_rib(q2)) == 2)
        wait_for(lambda: len(g1.get_adj_rib_out(q2)) == 1)
        wait_for(lambda: len(q2.get_global_rib()) == 1)

    @staticmethod
    def executor(env):
        lookup_scenario("ExportPolicy").boot(env)
        lookup_scenario("ExportPolicy").setup(env)
        lookup_scenario("ExportPolicy").check(env)


@register_scenario
class ImportPolicyUpdate(object):
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
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '192.168.20.0/24'}
        p1 = {'ip-prefix': '192.168.200.0/24'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0, p1]}
        g1.set_prefix_set(ps0)

        ns0 = {'neighbor-set-name': 'ns0',
               'neighbor-info-list': [g1.peers[e1]['neigh_addr'].split('/')[0]]}
        g1.set_neighbor_set(ns0)

        st0 = {'name': 'st0',
               'conditions': {
                   'match-prefix-set': {'prefix-set': ps0['prefix-set-name']},
                   'match-neighbor-set': {'neighbor-set': ns0['neighbor-set-name']}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        e1.add_route('192.168.2.0/24')
        e1.add_route('192.168.20.0/24')
        e1.add_route('192.168.200.0/24')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        g1 = env.g1
        # e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        wait_for(lambda: len(g1.get_local_rib(q1)) == 3)
        wait_for(lambda: len(g1.get_adj_rib_out(q1)) == 3)
        wait_for(lambda: len(q1.get_global_rib()) == 3)
        wait_for(lambda: len(g1.get_local_rib(q2)) == 1)
        wait_for(lambda: len(g1.get_adj_rib_out(q2)) == 1)
        wait_for(lambda: len(q2.get_global_rib()) == 1)

    @staticmethod
    def setup2(env):
        g1 = env.g1
        e1 = env.e1
        # q1 = env.q1
        q2 = env.q2
        g1.clear_policy()

        p0 = {'ip-prefix': '192.168.20.0/24'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0]}
        g1.set_prefix_set(ps0)

        ns0 = {'neighbor-set-name': 'ns0',
               'neighbor-info-list': [g1.peers[e1]['neigh_addr'].split('/')[0]]}
        g1.set_neighbor_set(ns0)

        st0 = {'name': 'st0',
               'conditions': {
                   'match-prefix-set': {'prefix-set': ps0['prefix-set-name']},
                   'match-neighbor-set': {'neighbor-set': ns0['neighbor-set-name']}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')
        g1.softreset(e1)

    @staticmethod
    def check2(env):
        g1 = env.g1
        # e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        wait_for(lambda: len(g1.get_local_rib(q1)) == 3)
        wait_for(lambda: len(g1.get_adj_rib_out(q1)) == 3)
        wait_for(lambda: len(q1.get_global_rib()) == 3)
        wait_for(lambda: len(g1.get_local_rib(q2)) == 2)
        wait_for(lambda: len(g1.get_adj_rib_out(q2)) == 2)
        wait_for(lambda: len(q2.get_global_rib()) == 2)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyUpdate").boot(env)
        lookup_scenario("ImportPolicyUpdate").setup(env)
        lookup_scenario("ImportPolicyUpdate").check(env)
        lookup_scenario("ImportPolicyUpdate").setup2(env)
        lookup_scenario("ImportPolicyUpdate").check2(env)


@register_scenario
class ExportPolicyUpdate(object):
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
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        p0 = {'ip-prefix': '192.168.20.0/24'}
        p1 = {'ip-prefix': '192.168.200.0/24'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0, p1]}
        g1.set_prefix_set(ps0)

        ns0 = {'neighbor-set-name': 'ns0',
               'neighbor-info-list': [g1.peers[q2]['neigh_addr'].split('/')[0]]}
        g1.set_neighbor_set(ns0)

        st0 = {'name': 'st0',
               'conditions': {
                   'match-prefix-set': {'prefix-set': ps0['prefix-set-name']},
                   'match-neighbor-set': {'neighbor-set': ns0['neighbor-set-name']}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        e1.add_route('192.168.2.0/24')
        e1.add_route('192.168.20.0/24')
        e1.add_route('192.168.200.0/24')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        g1 = env.g1
        # e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        wait_for(lambda: len(g1.get_local_rib(q1)) == 3)
        wait_for(lambda: len(g1.get_adj_rib_out(q1)) == 3)
        wait_for(lambda: len(q1.get_global_rib()) == 3)
        wait_for(lambda: len(g1.get_local_rib(q2)) == 3)
        wait_for(lambda: len(g1.get_adj_rib_out(q2)) == 1)
        wait_for(lambda: len(q2.get_global_rib()) == 1)

    @staticmethod
    def setup2(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        g1.clear_policy()

        p0 = {'ip-prefix': '192.168.20.0/24'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0]}
        g1.set_prefix_set(ps0)

        ns0 = {'neighbor-set-name': 'ns0',
               'neighbor-info-list': [g1.peers[q2]['neigh_addr'].split('/')[0]]}
        g1.set_neighbor_set(ns0)

        st0 = {'name': 'st0',
               'conditions': {
                   'match-prefix-set': {'prefix-set': ps0['prefix-set-name']},
                   'match-neighbor-set': {'neighbor-set': ns0['neighbor-set-name']}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        # we need hard reset to flush q2's local rib
        g1.reset(e1)

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check2(env):
        g1 = env.g1
        # e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        wait_for(lambda: len(g1.get_local_rib(q1)) == 3)
        wait_for(lambda: len(g1.get_adj_rib_out(q1)) == 3)
        wait_for(lambda: len(q1.get_global_rib()) == 3)
        wait_for(lambda: len(g1.get_local_rib(q2)) == 3)
        wait_for(lambda: len(g1.get_adj_rib_out(q2)) == 2)
        wait_for(lambda: len(q2.get_global_rib()) == 2)

    @staticmethod
    def executor(env):
        lookup_scenario("ExportPolicyUpdate").boot(env)
        lookup_scenario("ExportPolicyUpdate").setup(env)
        lookup_scenario("ExportPolicyUpdate").check(env)
        lookup_scenario("ExportPolicyUpdate").setup2(env)
        lookup_scenario("ExportPolicyUpdate").check2(env)


@register_scenario
class ImportPolicyIPV6(object):
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
    @staticmethod
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
            g1.add_peer(q, is_rs_client=True, bridge=br01.name)
            q.add_peer(g1, bridge=br01.name)

            env.g1 = g1
            env.e1 = e1
            env.q1 = q1
            env.q2 = q2

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '2001::/32',
              'masklength-range': '64..128'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0]}
        g1.set_prefix_set(ps0)

        ns0 = {'neighbor-set-name': 'ns0',
               'neighbor-info-list': [g1.peers[e1]['neigh_addr'].split('/')[0]]}
        g1.set_neighbor_set(ns0)

        st0 = {'name': 'st0',
               'conditions': {
                   'match-prefix-set': {'prefix-set': ps0['prefix-set-name']},
                   'match-neighbor-set': {'neighbor-set': ns0['neighbor-set-name']}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        # this will be blocked
        e1.add_route('2001::/64', rf='ipv6')
        # this will pass
        e1.add_route('2001::/63', rf='ipv6')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        wait_for(lambda: len(env.g1.get_local_rib(env.q1, rf='ipv6')) == 2)
        wait_for(lambda: len(env.g1.get_adj_rib_out(env.q1, rf='ipv6')) == 2)
        wait_for(lambda: len(env.q1.get_global_rib(rf='ipv6')) == 2)
        wait_for(lambda: len(env.g1.get_local_rib(env.q2, rf='ipv6')) == 1)
        wait_for(lambda: len(env.g1.get_adj_rib_out(env.q2, rf='ipv6')) == 1)
        wait_for(lambda: len(env.q2.get_global_rib(rf='ipv6')) == 1)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyIPV6").boot(env)
        lookup_scenario("ImportPolicyIPV6").setup(env)
        lookup_scenario("ImportPolicyIPV6").check(env)


@register_scenario
class ExportPolicyIPV6(object):
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
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicyIPV6').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '2001::/32',
              'masklength-range': '64..128'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0]}
        g1.set_prefix_set(ps0)

        ns0 = {'neighbor-set-name': 'ns0',
               'neighbor-info-list': [g1.peers[q2]['neigh_addr'].split('/')[0]]}
        g1.set_neighbor_set(ns0)

        st0 = {'name': 'st0',
               'conditions': {
                   'match-prefix-set': {'prefix-set': ps0['prefix-set-name']},
                   'match-neighbor-set': {'neighbor-set': ns0['neighbor-set-name']}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        # this will be blocked
        e1.add_route('2001::/64', rf='ipv6')
        # this will pass
        e1.add_route('2001::/63', rf='ipv6')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        wait_for(lambda: len(env.g1.get_local_rib(env.q1, rf='ipv6')) == 2)
        wait_for(lambda: len(env.g1.get_adj_rib_out(env.q1, rf='ipv6')) == 2)
        wait_for(lambda: len(env.q1.get_global_rib(rf='ipv6')) == 2)
        wait_for(lambda: len(env.g1.get_local_rib(env.q2, rf='ipv6')) == 2)
        wait_for(lambda: len(env.g1.get_adj_rib_out(env.q2, rf='ipv6')) == 1)
        wait_for(lambda: len(env.q2.get_global_rib(rf='ipv6')) == 1)

    @staticmethod
    def executor(env):
        lookup_scenario("ExportPolicyIPV6").boot(env)
        lookup_scenario("ExportPolicyIPV6").setup(env)
        lookup_scenario("ExportPolicyIPV6").check(env)


@register_scenario
class ImportPolicyIPV6Update(object):
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
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicyIPV6').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '2001:0:10:2::/64'}
        p1 = {'ip-prefix': '2001:0:10:20::/64'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0, p1]}
        g1.set_prefix_set(ps0)

        ns0 = {'neighbor-set-name': 'ns0',
               'neighbor-info-list': [g1.peers[e1]['neigh_addr'].split('/')[0]]}
        g1.set_neighbor_set(ns0)

        st0 = {'name': 'st0',
               'conditions': {
                   'match-prefix-set': {'prefix-set': ps0['prefix-set-name']},
                   'match-neighbor-set': {'neighbor-set': ns0['neighbor-set-name']}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        e1.add_route('2001:0:10:2::/64', rf='ipv6')
        e1.add_route('2001:0:10:20::/64', rf='ipv6')
        e1.add_route('2001:0:10:200::/64', rf='ipv6')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        wait_for(lambda: len(env.g1.get_local_rib(env.q1, rf='ipv6')) == 3)
        wait_for(lambda: len(env.g1.get_adj_rib_out(env.q1, rf='ipv6')) == 3)
        wait_for(lambda: len(env.q1.get_global_rib(rf='ipv6')) == 3)
        wait_for(lambda: len(env.g1.get_local_rib(env.q2, rf='ipv6')) == 1)
        wait_for(lambda: len(env.g1.get_adj_rib_out(env.q2, rf='ipv6')) == 1)
        wait_for(lambda: len(env.q2.get_global_rib(rf='ipv6')) == 1)

    @staticmethod
    def setup2(env):
        g1 = env.g1
        e1 = env.e1
        # q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '2001:0:10:2::/64'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0]}
        g1.set_prefix_set(ps0)

        ns0 = {'neighbor-set-name': 'ns0',
               'neighbor-info-list': [g1.peers[e1]['neigh_addr'].split('/')[0]]}
        g1.set_neighbor_set(ns0)

        st0 = {'name': 'st0',
               'conditions': {
                   'match-prefix-set': {'prefix-set': ps0['prefix-set-name']},
                   'match-neighbor-set': {'neighbor-set': ns0['neighbor-set-name']}},
               'actions': {
                   'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')
        g1.softreset(e1, rf='ipv6')

    @staticmethod
    def check2(env):
        wait_for(lambda: len(env.g1.get_local_rib(env.q1, rf='ipv6')) == 3)
        wait_for(lambda: len(env.g1.get_adj_rib_out(env.q1, rf='ipv6')) == 3)
        wait_for(lambda: len(env.q1.get_global_rib(rf='ipv6')) == 3)
        wait_for(lambda: len(env.g1.get_local_rib(env.q2, rf='ipv6')) == 2)
        wait_for(lambda: len(env.g1.get_adj_rib_out(env.q2, rf='ipv6')) == 2)
        wait_for(lambda: len(env.q2.get_global_rib(rf='ipv6')) == 2)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyIPV6Update").boot(env)
        lookup_scenario("ImportPolicyIPV6Update").setup(env)
        lookup_scenario("ImportPolicyIPV6Update").check(env)
        lookup_scenario("ImportPolicyIPV6Update").setup2(env)
        lookup_scenario("ImportPolicyIPV6Update").check2(env)


@register_scenario
class ExportPolicyIPv6Update(object):
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
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicyIPV6').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '2001:0:10:2::/64'}
        p1 = {'ip-prefix': '2001:0:10:20::/64'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0, p1]}
        g1.set_prefix_set(ps0)

        ns0 = {'neighbor-set-name': 'ns0',
               'neighbor-info-list': [g1.peers[q2]['neigh_addr'].split('/')[0]]}
        g1.set_neighbor_set(ns0)

        st0 = {'name': 'st0',
               'conditions': {
                   'match-prefix-set': {'prefix-set': ps0['prefix-set-name']},
                   'match-neighbor-set': {'neighbor-set': ns0['neighbor-set-name']}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        e1.add_route('2001:0:10:2::/64', rf='ipv6')
        e1.add_route('2001:0:10:20::/64', rf='ipv6')
        e1.add_route('2001:0:10:200::/64', rf='ipv6')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        wait_for(lambda: len(env.g1.get_local_rib(env.q1, rf='ipv6')) == 3)
        wait_for(lambda: len(env.g1.get_adj_rib_out(env.q1, rf='ipv6')) == 3)
        wait_for(lambda: len(env.q1.get_global_rib(rf='ipv6')) == 3)
        wait_for(lambda: len(env.g1.get_local_rib(env.q2, rf='ipv6')) == 3)
        wait_for(lambda: len(env.g1.get_adj_rib_out(env.q2, rf='ipv6')) == 1)
        wait_for(lambda: len(env.q2.get_global_rib(rf='ipv6')) == 1)

    @staticmethod
    def setup2(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '2001:0:10:2::/64'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0]}
        g1.set_prefix_set(ps0)

        ns0 = {'neighbor-set-name': 'ns0',
               'neighbor-info-list': [g1.peers[q2]['neigh_addr'].split('/')[0]]}
        g1.set_neighbor_set(ns0)

        st0 = {'name': 'st0',
               'conditions': {
                   'match-prefix-set': {'prefix-set': ps0['prefix-set-name']},
                   'match-neighbor-set': {'neighbor-set': ns0['neighbor-set-name']}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')
        g1.reset(e1)

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check2(env):
        wait_for(lambda: len(env.g1.get_local_rib(env.q1, rf='ipv6')) == 3)
        wait_for(lambda: len(env.g1.get_adj_rib_out(env.q1, rf='ipv6')) == 3)
        wait_for(lambda: len(env.q1.get_global_rib(rf='ipv6')) == 3)
        wait_for(lambda: len(env.g1.get_local_rib(env.q2, rf='ipv6')) == 3)
        wait_for(lambda: len(env.g1.get_adj_rib_out(env.q2, rf='ipv6')) == 2)
        wait_for(lambda: len(env.q2.get_global_rib(rf='ipv6')) == 2)

    @staticmethod
    def executor(env):
        lookup_scenario("ExportPolicyIPv6Update").boot(env)
        lookup_scenario("ExportPolicyIPv6Update").setup(env)
        lookup_scenario("ExportPolicyIPv6Update").check(env)
        lookup_scenario("ExportPolicyIPv6Update").setup2(env)
        lookup_scenario("ExportPolicyIPv6Update").check2(env)


@register_scenario
class ImportPolicyAsPathLengthCondition(object):
    """
    No.9 aspath length condition import-policy test
                              --------------------------------
    e1 ->(aspath_length=10)-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                              |                              |
                              | ->x q2-rib                   |
                              --------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'as-path-length': {'operator': 'ge',
                                                                    'value': 10}}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        # this will be blocked
        e1.add_route('192.168.100.0/24', aspath=list(range(e1.asn, e1.asn - 10, -1)))
        # this will pass
        e1.add_route('192.168.200.0/24', aspath=list(range(e1.asn, e1.asn - 8, -1)))

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        g1 = env.g1
        # e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        wait_for(lambda: len(g1.get_local_rib(q1)) == 2)
        wait_for(lambda: len(g1.get_adj_rib_out(q1)) == 2)
        wait_for(lambda: len(q1.get_global_rib()) == 2)
        wait_for(lambda: len(g1.get_local_rib(q2)) == 1)
        wait_for(lambda: len(g1.get_adj_rib_out(q2)) == 1)
        wait_for(lambda: len(q2.get_global_rib()) == 1)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyAsPathLengthCondition").boot(env)
        lookup_scenario("ImportPolicyAsPathLengthCondition").setup(env)
        lookup_scenario("ImportPolicyAsPathLengthCondition").check(env)


@register_scenario
class ImportPolicyAsPathCondition(object):
    """
    No.10 aspath from condition import-policy test
                                --------------------------------
    e1 ->(aspath=[65100,...])-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                                |                              |
                                | ->x q2-rib                   |
                                --------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        as0 = {'as-path-sets': [{'as-path-set-name': 'as0', 'as-path-list': ['^{0}'.format(e1.asn)]}]}

        g1.set_bgp_defined_set(as0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-as-path-set': {'as-path-set': 'as0'}}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        # this will be blocked
        e1.add_route('192.168.100.0/24', aspath=list(range(e1.asn, e1.asn - 10, -1)))
        # this will pass
        e1.add_route('192.168.200.0/24', aspath=list(range(e1.asn - 1, e1.asn - 10, -1)))

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        # same check function as previous No.1 scenario
        lookup_scenario("ImportPolicy").check(env)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyAsPathCondition").boot(env)
        lookup_scenario("ImportPolicyAsPathCondition").setup(env)
        lookup_scenario("ImportPolicyAsPathCondition").check(env)


@register_scenario
class ImportPolicyAsPathAnyCondition(object):
    """
    No.11 aspath any condition import-policy test
                                   --------------------------------
    e1 ->(aspath=[...65098,...])-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                                   |                              |
                                   | ->x q2-rib                   |
                                   --------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        as0 = {'as-path-sets': [{'as-path-set-name': 'as0', 'as-path-list': ['65098']}]}

        g1.set_bgp_defined_set(as0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-as-path-set': {'as-path-set': 'as0'}}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        # this will be blocked
        e1.add_route('192.168.100.0/24', aspath=[65000, 65098, 65010])
        # this will pass
        e1.add_route('192.168.200.0/24', aspath=[65000, 65100, 65010])

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        # same check function as previous No.1 scenario
        lookup_scenario("ImportPolicy").check(env)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyAsPathAnyCondition").boot(env)
        lookup_scenario("ImportPolicyAsPathAnyCondition").setup(env)
        lookup_scenario("ImportPolicyAsPathAnyCondition").check(env)


@register_scenario
class ImportPolicyAsPathOriginCondition(object):
    """
    No.12 aspath origin condition import-policy test
                                --------------------------------
    e1 ->(aspath=[...,65090])-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                                |                              |
                                | ->x q2-rib                   |
                                --------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        as0 = {'as-path-sets': [{'as-path-set-name': 'as0', 'as-path-list': ['65090$']}]}

        g1.set_bgp_defined_set(as0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-as-path-set': {'as-path-set': 'as0'}}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        # this will be blocked
        e1.add_route('192.168.100.0/24', aspath=[65000, 65098, 65090])
        # this will pass
        e1.add_route('192.168.200.0/24', aspath=[65000, 65100, 65010])

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        # same check function as previous No.1 scenario
        lookup_scenario("ImportPolicy").check(env)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyAsPathOriginCondition").boot(env)
        lookup_scenario("ImportPolicyAsPathOriginCondition").setup(env)
        lookup_scenario("ImportPolicyAsPathOriginCondition").check(env)


@register_scenario
class ImportPolicyAsPathOnlyCondition(object):
    """
    No.13 aspath only condition import-policy test
                              --------------------------------
    e1 -> (aspath=[65100]) -> | ->  q1-rib -> q1-adj-rib-out | --> q1
                              |                              |
                              | ->x q2-rib                   |
                              --------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        as0 = {'as-path-sets': [{'as-path-set-name': 'as0', 'as-path-list': ['^65100$']}]}

        g1.set_bgp_defined_set(as0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-as-path-set': {'as-path-set': 'as0'}}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        # this will be blocked
        e1.add_route('192.168.100.0/24', aspath=[65100])
        # this will pass
        e1.add_route('192.168.200.0/24', aspath=[65000, 65100, 65010])

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        # same check function as previous No.1 scenario
        lookup_scenario("ImportPolicy").check(env)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyAsPathOnlyCondition").boot(env)
        lookup_scenario("ImportPolicyAsPathOnlyCondition").setup(env)
        lookup_scenario("ImportPolicyAsPathOnlyCondition").check(env)


@register_scenario
class ImportPolicyAsPathMismatchCondition(object):
    """
    No.14 aspath condition mismatch import-policy test
                                   -------------------------------
    exabgp ->(aspath=[...,65090])->| -> q1-rib -> q1-adj-rib-out | --> q1
                                   |                             |
                                   | -> q2-rib -> q2-adj-rib-out | --> q2
                                   -------------------------------
    This case check if policy passes the path to e1 because of condition mismatch.
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        cs0 = {'community-sets': [{'community-set-name': 'cs0',
                                   'community-list': ['65100:10']}]}

        g1.set_bgp_defined_set(cs0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-community-set': {'community-set': 'cs0'}}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        # this will be blocked
        e1.add_route('192.168.100.0/24', aspath=[65100, 65090])
        # this will pass
        e1.add_route('192.168.200.0/24', aspath=[65000, 65100, 65010])

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        g1 = env.g1
        # e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        wait_for(lambda: len(g1.get_local_rib(q1)) == 2)
        wait_for(lambda: len(g1.get_adj_rib_out(q1)) == 2)
        wait_for(lambda: len(q1.get_global_rib()) == 2)
        wait_for(lambda: len(g1.get_local_rib(q2)) == 2)
        wait_for(lambda: len(g1.get_adj_rib_out(q2)) == 2)
        wait_for(lambda: len(q2.get_global_rib()) == 2)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyAsPathMismatchCondition").boot(env)
        lookup_scenario("ImportPolicyAsPathMismatchCondition").setup(env)
        lookup_scenario("ImportPolicyAsPathMismatchCondition").check(env)


@register_scenario
class ImportPolicyCommunityCondition(object):
    """
    No.15 community condition import-policy test
                                --------------------------------
    e1 ->(community=65100:10)-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                                |                              |
                                | ->x q2-rib                   |
                                --------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        cs0 = {'community-sets': [{'community-set-name': 'cs0', 'community-list': ['65100:10']}]}

        g1.set_bgp_defined_set(cs0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-community-set': {'community-set': 'cs0'}}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        # this will be blocked
        e1.add_route('192.168.100.0/24', community=['65100:10'])
        # this will pass
        e1.add_route('192.168.200.0/24', community=['65100:20'])

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario("ImportPolicy").check(env)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyCommunityCondition").boot(env)
        lookup_scenario("ImportPolicyCommunityCondition").setup(env)
        lookup_scenario("ImportPolicyCommunityCondition").check(env)


@register_scenario
class ImportPolicyCommunityRegexp(object):
    """
    No.16 community condition regexp import-policy test
                                --------------------------------
    e1 ->(community=65100:10)-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                                |                              |
                                | ->x q2-rib                   |
                                --------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        cs0 = {'community-sets': [{'community-set-name': 'cs0', 'community-list': ['6[0-9]+:[0-9]+']}]}

        g1.set_bgp_defined_set(cs0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-community-set': {'community-set': 'cs0'}}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        # this will be blocked
        e1.add_route('192.168.100.0/24', community=['65100:10'])
        # this will pass
        e1.add_route('192.168.200.0/24', community=['55100:20'])

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario("ImportPolicy").check(env)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyCommunityRegexp").boot(env)
        lookup_scenario("ImportPolicyCommunityRegexp").setup(env)
        lookup_scenario("ImportPolicyCommunityRegexp").check(env)


def community_exists(path, com):
    a, b = com.split(':')
    com = (int(a) << 16) + int(b)
    for a in path['attrs']:
        if a['type'] == BGP_ATTR_TYPE_COMMUNITIES and com in a['communities']:
            return True
    return False


@register_scenario
class ImportPolicyCommunityAction(object):
    """
    No.17 community add action import-policy test
                                -------------------------------
    e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)->          q1
                                |                             |
                                | -> q2-rib -> q2-adj-rib-out | ->(community=65100:10,65100:20)-> q2
                                |    apply action             |
                                -------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        cs0 = {'community-sets': [{'community-set-name': 'cs0', 'community-list': ['65100:10']}]}

        g1.set_bgp_defined_set(cs0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-community-set': {'community-set': 'cs0', 'match-set-options': 'any'}}},
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {
                               'set-community': {
                                   'options': 'add',
                                   'set-community-method': {'communities-list': ['65100:20']}}}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        e1.add_route('192.168.100.0/24', community=['65100:10'])

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        g1 = env.g1
        # e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        wait_for(lambda: len(g1.get_local_rib(q1)) == 1)
        wait_for(lambda: len(g1.get_adj_rib_out(q1)) == 1)
        wait_for(lambda: len(q1.get_global_rib()) == 1)
        wait_for(lambda: len(g1.get_local_rib(q2)) == 1)
        wait_for(lambda: len(g1.get_adj_rib_out(q2)) == 1)
        wait_for(lambda: len(q2.get_global_rib()) == 1)

    @staticmethod
    def check2(env):
        g1 = env.g1
        q1 = env.q1
        q2 = env.q2
        path = g1.get_adj_rib_out(q1)[0]
        assert_true(community_exists(path, '65100:10'))
        assert_false(community_exists(path, '65100:20'))
        path = g1.get_adj_rib_out(q2)[0]
        assert_true(community_exists(path, '65100:10'))
        assert_true(community_exists(path, '65100:20'))

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyCommunityAction").boot(env)
        lookup_scenario("ImportPolicyCommunityAction").setup(env)
        lookup_scenario("ImportPolicyCommunityAction").check(env)
        lookup_scenario("ImportPolicyCommunityAction").check2(env)


@register_scenario
class ImportPolicyCommunityReplace(object):
    """
    No.18 community replace action import-policy test
                                -------------------------------
    e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)-> q1
                                |                             |
                                | -> q2-rib -> q2-adj-rib-out | ->(community=65100:20)-> q2
                                |    apply action             |
                                -------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        cs0 = {'community-sets': [{'community-set-name': 'cs0', 'community-list': ['65100:10']}]}

        g1.set_bgp_defined_set(cs0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-community-set': {'community-set': 'cs0'}}},
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {
                               'set-community': {
                                   'options': 'REPLACE',
                                   'set-community-method': {'communities-list': ['65100:20']}}}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        e1.add_route('192.168.100.0/24', community=['65100:10'])

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityAction').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        # e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        path = g1.get_adj_rib_out(q1)[0]
        assert_true(community_exists(path, '65100:10'))
        assert_false(community_exists(path, '65100:20'))
        path = g1.get_adj_rib_out(q2)[0]
        assert_false(community_exists(path, '65100:10'))
        assert_true(community_exists(path, '65100:20'))

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyCommunityReplace").boot(env)
        lookup_scenario("ImportPolicyCommunityReplace").setup(env)
        lookup_scenario("ImportPolicyCommunityReplace").check(env)
        lookup_scenario("ImportPolicyCommunityReplace").check2(env)


@register_scenario
class ImportPolicyCommunityRemove(object):
    """
    No.19 community remove action import-policy test
                                -------------------------------
    e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)-> q1
                                |                             |
                                | -> q2-rib -> q2-adj-rib-out | ->(community=null)->     q2
                                |    apply action             |
                                -------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        cs0 = {'community-sets': [{'community-set-name': 'cs0', 'community-list': ['65100:10']}]}

        g1.set_bgp_defined_set(cs0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-community-set': {'community-set': 'cs0'}}},
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {
                               'set-community': {
                                   'options': 'REMOVE',
                                   'set-community-method': {'communities-list': ['65100:10', '65100:20']}}}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        e1.add_route('192.168.100.0/24', community=['65100:10'])
        e1.add_route('192.168.110.0/24', community=['65100:10', '65100:20'])
        e1.add_route('192.168.120.0/24', community=['65100:10', '65100:30'])

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        g1 = env.g1
        # e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        wait_for(lambda: len(g1.get_local_rib(q1)) == 3)
        wait_for(lambda: len(g1.get_adj_rib_out(q1)) == 3)
        wait_for(lambda: len(q1.get_global_rib()) == 3)
        wait_for(lambda: len(g1.get_local_rib(q2)) == 3)
        wait_for(lambda: len(g1.get_adj_rib_out(q2)) == 3)
        wait_for(lambda: len(q2.get_global_rib()) == 3)

    @staticmethod
    def check2(env):
        g1 = env.g1
        # e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        adj_out = g1.get_adj_rib_out(q1)
        for path in adj_out:
            assert_true(community_exists(path, '65100:10'))
            if path['nlri']['prefix'] == '192.168.110.0/24':
                assert_true(community_exists(path, '65100:20'))
            if path['nlri']['prefix'] == '192.168.120.0/24':
                assert_true(community_exists(path, '65100:30'))
        adj_out = g1.get_adj_rib_out(q2)
        for path in adj_out:
            assert_false(community_exists(path, '65100:10'))
            if path['nlri']['prefix'] == '192.168.110.0/24':
                assert_false(community_exists(path, '65100:20'))
            if path['nlri']['prefix'] == '192.168.120.0/24':
                assert_true(community_exists(path, '65100:30'))

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyCommunityRemove").boot(env)
        lookup_scenario("ImportPolicyCommunityRemove").setup(env)
        lookup_scenario("ImportPolicyCommunityRemove").check(env)
        lookup_scenario("ImportPolicyCommunityRemove").check2(env)


@register_scenario
class ImportPolicyCommunityNull(object):
    """
    No.20 community null action import-policy test
                                -------------------------------
    e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)-> q1
                                |                             |
                                | -> q2-rib -> q2-adj-rib-out | ->(community=null)->     q2
                                |    apply action             |
                                -------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        cs0 = {'community-sets': [{'community-set-name': 'cs0', 'community-list': ['65100:10']}]}

        g1.set_bgp_defined_set(cs0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-community-set': {'community-set': 'cs0'}}},
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {
                               'set-community': {
                                   'options': 'REPLACE',
                                   'set-community-method': {'communities-list': []}}}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        e1.add_route('192.168.100.0/24', community=['65100:10'])
        e1.add_route('192.168.110.0/24', community=['65100:10', '65100:20'])
        e1.add_route('192.168.120.0/24', community=['65100:10', '65100:30'])

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityRemove').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        q1 = env.q1
        q2 = env.q2
        adj_out = g1.get_adj_rib_out(q1)
        for path in adj_out:
            assert_true(community_exists(path, '65100:10'))
            if path['nlri']['prefix'] == '192.168.110.0/24':
                assert_true(community_exists(path, '65100:20'))
            if path['nlri']['prefix'] == '192.168.120.0/24':
                assert_true(community_exists(path, '65100:30'))
        adj_out = g1.get_adj_rib_out(q2)
        for path in adj_out:
            assert_false(community_exists(path, '65100:10'))
            if path['nlri']['prefix'] == '192.168.110.0/24':
                assert_false(community_exists(path, '65100:20'))
            if path['nlri']['prefix'] == '192.168.120.0/24':
                assert_false(community_exists(path, '65100:30'))

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyCommunityNull").boot(env)
        lookup_scenario("ImportPolicyCommunityNull").setup(env)
        lookup_scenario("ImportPolicyCommunityNull").check(env)
        lookup_scenario("ImportPolicyCommunityNull").check2(env)


@register_scenario
class ExportPolicyCommunityAdd(object):
    """
    No.21 community add action export-policy test
                                -------------------------------
    e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)-> q1
                                |                             |
                                | -> q2-rib -> q2-adj-rib-out | ->(community=null)->     q2
                                |              apply action   |
                                -------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicy').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        cs0 = {'community-sets': [{'community-set-name': 'cs0', 'community-list': ['65100:10']}]}

        g1.set_bgp_defined_set(cs0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-community-set': {'community-set': 'cs0'}}},
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {
                               'set-community': {
                                   'options': 'add',
                                   'set-community-method': {'communities-list': ['65100:20']}}}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        e1.add_route('192.168.100.0/24', community=['65100:10'])

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityAction').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        q1 = env.q1
        q2 = env.q2

        adj_out = g1.get_adj_rib_out(q1)
        for path in adj_out:
            assert_true(community_exists(path, '65100:10'))
            assert_false(community_exists(path, '65100:20'))

        local_rib = g1.get_local_rib(q2)
        for path in local_rib[0]['paths']:
            assert_true(community_exists(path, '65100:10'))
            assert_false(community_exists(path, '65100:20'))

        adj_out = g1.get_adj_rib_out(q2)
        for path in adj_out:
            assert_true(community_exists(path, '65100:10'))
            assert_true(community_exists(path, '65100:20'))

    @staticmethod
    def executor(env):
        lookup_scenario("ExportPolicyCommunityAdd").boot(env)
        lookup_scenario("ExportPolicyCommunityAdd").setup(env)
        lookup_scenario("ExportPolicyCommunityAdd").check(env)
        lookup_scenario("ExportPolicyCommunityAdd").check2(env)


@register_scenario
class ExportPolicyCommunityReplace(object):
    """
    No.22 community replace action export-policy test
                                -------------------------------
    e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)-> q1
                                |                             |
                                | -> q2-rib -> q2-adj-rib-out | ->(community=65100:20)-> q2
                                |              apply action   |
                                -------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicy').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        cs0 = {'community-sets': [{'community-set-name': 'cs0', 'community-list': ['65100:10']}]}

        g1.set_bgp_defined_set(cs0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-community-set': {'community-set': 'cs0'}}},
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {
                               'set-community': {
                                   'options': 'REPLACE',
                                   'set-community-method': {'communities-list': ['65100:20']}}}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        e1.add_route('192.168.100.0/24', community=['65100:10'])

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityAction').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        q1 = env.q1
        q2 = env.q2

        adj_out = g1.get_adj_rib_out(q1)
        for path in adj_out:
            assert_true(community_exists(path, '65100:10'))
            assert_false(community_exists(path, '65100:20'))

        local_rib = g1.get_local_rib(q2)
        for path in local_rib[0]['paths']:
            assert_true(community_exists(path, '65100:10'))
            assert_false(community_exists(path, '65100:20'))

        adj_out = g1.get_adj_rib_out(q2)
        for path in adj_out:
            assert_false(community_exists(path, '65100:10'))
            assert_true(community_exists(path, '65100:20'))

    @staticmethod
    def executor(env):
        lookup_scenario("ExportPolicyCommunityReplace").boot(env)
        lookup_scenario("ExportPolicyCommunityReplace").setup(env)
        lookup_scenario("ExportPolicyCommunityReplace").check(env)
        lookup_scenario("ExportPolicyCommunityReplace").check2(env)


@register_scenario
class ExportPolicyCommunityRemove(object):
    """
    No.23 community replace action export-policy test
                                -------------------------------
    e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)-> q1
                                |                             |
                                | -> q2-rib -> q2-adj-rib-out | ->(community=null)->     q2
                                |              apply action   |
                                -------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicy').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        cs0 = {'community-sets': [{'community-set-name': 'cs0', 'community-list': ['65100:10']}]}

        g1.set_bgp_defined_set(cs0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-community-set': {'community-set': 'cs0'}}},
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {
                               'set-community': {
                                   'options': 'REMOVE',
                                   'set-community-method': {'communities-list': ['65100:20', '65100:30']}}}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        e1.add_route('192.168.100.0/24', community=['65100:10', '65100:20', '65100:30'])

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityAction').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        q1 = env.q1
        q2 = env.q2

        adj_out = g1.get_adj_rib_out(q1)
        for path in adj_out:
            assert_true(community_exists(path, '65100:10'))
            assert_true(community_exists(path, '65100:20'))
            assert_true(community_exists(path, '65100:30'))

        local_rib = g1.get_local_rib(q2)
        for path in local_rib[0]['paths']:
            assert_true(community_exists(path, '65100:10'))
            assert_true(community_exists(path, '65100:20'))
            assert_true(community_exists(path, '65100:30'))

        adj_out = g1.get_adj_rib_out(q2)
        for path in adj_out:
            assert_true(community_exists(path, '65100:10'))
            assert_false(community_exists(path, '65100:20'))
            assert_false(community_exists(path, '65100:30'))

    @staticmethod
    def executor(env):
        lookup_scenario("ExportPolicyCommunityRemove").boot(env)
        lookup_scenario("ExportPolicyCommunityRemove").setup(env)
        lookup_scenario("ExportPolicyCommunityRemove").check(env)
        lookup_scenario("ExportPolicyCommunityRemove").check2(env)


@register_scenario
class ExportPolicyCommunityNull(object):
    """
    No.24 community null action export-policy test
                                -------------------------------
    e1 ->(community=65100:10)-> | -> q1-rib -> q1-adj-rib-out | ->(community=65100:10)-> q1
                                |                             |
                                | -> q2-rib -> q2-adj-rib-out | ->(community=null)->     q2
                                |              apply action   |
                                -------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicy').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        cs0 = {'community-sets': [{'community-set-name': 'cs0', 'community-list': ['65100:10']}]}

        g1.set_bgp_defined_set(cs0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-community-set': {'community-set': 'cs0'}}},
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {
                               'set-community': {
                                   'options': 'REPLACE',
                                   'set-community-method': {'communities-list': []}}}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        e1.add_route('192.168.100.0/24', community=['65100:10', '65100:20', '65100:30'])

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityAction').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        q1 = env.q1
        q2 = env.q2

        adj_out = g1.get_adj_rib_out(q1)
        for path in adj_out:
            assert_true(community_exists(path, '65100:10'))
            assert_true(community_exists(path, '65100:20'))
            assert_true(community_exists(path, '65100:30'))

        local_rib = g1.get_local_rib(q2)
        for path in local_rib[0]['paths']:
            assert_true(community_exists(path, '65100:10'))
            assert_true(community_exists(path, '65100:20'))
            assert_true(community_exists(path, '65100:30'))

        adj_out = g1.get_adj_rib_out(q2)
        for path in adj_out:
            assert_false(community_exists(path, '65100:10'))
            assert_false(community_exists(path, '65100:20'))
            assert_false(community_exists(path, '65100:30'))

    @staticmethod
    def executor(env):
        lookup_scenario("ExportPolicyCommunityNull").boot(env)
        lookup_scenario("ExportPolicyCommunityNull").setup(env)
        lookup_scenario("ExportPolicyCommunityNull").check(env)
        lookup_scenario("ExportPolicyCommunityNull").check2(env)


def metric(path):
    for a in path['attrs']:
        if 'metric' in a:
            return a['metric']
    return -1


@register_scenario
class ImportPolicyMedReplace(object):
    """
    No.25 med replace action import-policy test
                     -------------------------------
    e1 ->(med=300)-> | -> q1-rib -> q1-adj-rib-out | ->(med=300)-> q1
                     |                             |
                     | -> q2-rib -> q2-adj-rib-out | ->(med=100)-> q2
                     |    apply action             |
                     -------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicy').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        st0 = {'name': 'st0',
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {'set-med': '100'}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        e1.add_route('192.168.100.0/24', med=300)

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityAction').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        q1 = env.q1
        q2 = env.q2

        adj_out = g1.get_adj_rib_out(q1)
        assert_true(metric(adj_out[0]) == 300)

        local_rib = g1.get_local_rib(q2)
        assert_true(metric(local_rib[0]['paths'][0]) == 100)

        adj_out = g1.get_adj_rib_out(q2)
        assert_true(metric(adj_out[0]) == 100)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyMedReplace").boot(env)
        lookup_scenario("ImportPolicyMedReplace").setup(env)
        lookup_scenario("ImportPolicyMedReplace").check(env)
        lookup_scenario("ImportPolicyMedReplace").check2(env)


@register_scenario
class ImportPolicyMedAdd(object):
    """
    No.26 med add action import-policy test
                     -------------------------------
    e1 ->(med=300)-> | -> q1-rib -> q1-adj-rib-out | ->(med=300)->     q1
                     |                             |
                     | -> q2-rib -> q2-adj-rib-out | ->(med=300+100)-> q2
                     |    apply action             |
                     -------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicy').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        st0 = {'name': 'st0',
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {'set-med': '+100'}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        e1.add_route('192.168.100.0/24', med=300)

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityAction').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        q1 = env.q1
        q2 = env.q2

        adj_out = g1.get_adj_rib_out(q1)
        assert_true(metric(adj_out[0]) == 300)

        local_rib = g1.get_local_rib(q2)
        assert_true(metric(local_rib[0]['paths'][0]) == 400)

        adj_out = g1.get_adj_rib_out(q2)
        assert_true(metric(adj_out[0]) == 400)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyMedAdd").boot(env)
        lookup_scenario("ImportPolicyMedAdd").setup(env)
        lookup_scenario("ImportPolicyMedAdd").check(env)
        lookup_scenario("ImportPolicyMedAdd").check2(env)


@register_scenario
class ImportPolicyMedSub(object):
    """
    No.27 med subtract action import-policy test
                     -------------------------------
    e1 ->(med=300)-> | -> q1-rib -> q1-adj-rib-out | ->(med=300)->     q1
                     |                             |
                     | -> q2-rib -> q2-adj-rib-out | ->(med=300-100)-> q2
                     |    apply action             |
                     -------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicy').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        st0 = {'name': 'st0',
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {'set-med': '-100'}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        e1.add_route('192.168.100.0/24', med=300)

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityAction').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        q1 = env.q1
        q2 = env.q2

        adj_out = g1.get_adj_rib_out(q1)
        assert_true(metric(adj_out[0]) == 300)

        local_rib = g1.get_local_rib(q2)
        assert_true(metric(local_rib[0]['paths'][0]) == 200)

        adj_out = g1.get_adj_rib_out(q2)
        assert_true(metric(adj_out[0]) == 200)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyMedSub").boot(env)
        lookup_scenario("ImportPolicyMedSub").setup(env)
        lookup_scenario("ImportPolicyMedSub").check(env)
        lookup_scenario("ImportPolicyMedSub").check2(env)


@register_scenario
class ExportPolicyMedReplace(object):
    """
    No.28 med replace action export-policy test
                     -------------------------------
    e1 ->(med=300)-> | -> q1-rib -> q1-adj-rib-out | ->(med=300)-> q1
                     |                             |
                     | -> q2-rib -> q2-adj-rib-out | ->(med=100)-> q2
                     |              apply action   |
                     -------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicy').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        st0 = {'name': 'st0',
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {'set-med': '100'}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        e1.add_route('192.168.100.0/24', med=300)

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityAction').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        q1 = env.q1
        q2 = env.q2

        adj_out = g1.get_adj_rib_out(q1)
        assert_true(metric(adj_out[0]) == 300)

        local_rib = g1.get_local_rib(q2)
        assert_true(metric(local_rib[0]['paths'][0]) == 300)

        adj_out = g1.get_adj_rib_out(q2)
        assert_true(metric(adj_out[0]) == 100)

    @staticmethod
    def executor(env):
        lookup_scenario("ExportPolicyMedReplace").boot(env)
        lookup_scenario("ExportPolicyMedReplace").setup(env)
        lookup_scenario("ExportPolicyMedReplace").check(env)
        lookup_scenario("ExportPolicyMedReplace").check2(env)


@register_scenario
class ExportPolicyMedAdd(object):
    """
    No.29 med add action export-policy test
                     -------------------------------
    e1 ->(med=300)-> | -> q1-rib -> q1-adj-rib-out | ->(med=300)->     q1
                     |                             |
                     | -> q2-rib -> q2-adj-rib-out | ->(med=300+100)-> q2
                     |              apply action   |
                     -------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicy').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        st0 = {'name': 'st0',
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {'set-med': '+100'}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        e1.add_route('192.168.100.0/24', med=300)

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityAction').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        q1 = env.q1
        q2 = env.q2

        adj_out = g1.get_adj_rib_out(q1)
        assert_true(metric(adj_out[0]) == 300)

        local_rib = g1.get_local_rib(q2)
        assert_true(metric(local_rib[0]['paths'][0]) == 300)

        adj_out = g1.get_adj_rib_out(q2)
        assert_true(metric(adj_out[0]) == 400)

    @staticmethod
    def executor(env):
        lookup_scenario("ExportPolicyMedAdd").boot(env)
        lookup_scenario("ExportPolicyMedAdd").setup(env)
        lookup_scenario("ExportPolicyMedAdd").check(env)
        lookup_scenario("ExportPolicyMedAdd").check2(env)


@register_scenario
class ExportPolicyMedSub(object):
    """
    No.30 med subtract action export-policy test
                     -------------------------------
    e1 ->(med=300)-> | -> q1-rib -> q1-adj-rib-out | ->(med=300)->     q1
                     |                             |
                     | -> q2-rib -> q2-adj-rib-out | ->(med=300-100)-> q2
                     |              apply action   |
                     -------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicy').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        st0 = {'name': 'st0',
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {'set-med': '-100'}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        e1.add_route('192.168.100.0/24', med=300)

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityAction').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        q1 = env.q1
        q2 = env.q2

        adj_out = g1.get_adj_rib_out(q1)
        assert_true(metric(adj_out[0]) == 300)

        local_rib = g1.get_local_rib(q2)
        assert_true(metric(local_rib[0]['paths'][0]) == 300)

        adj_out = g1.get_adj_rib_out(q2)
        assert_true(metric(adj_out[0]) == 200)

    @staticmethod
    def executor(env):
        lookup_scenario("ExportPolicyMedSub").boot(env)
        lookup_scenario("ExportPolicyMedSub").setup(env)
        lookup_scenario("ExportPolicyMedSub").check(env)
        lookup_scenario("ExportPolicyMedSub").check2(env)


@register_scenario
class ExportPolicyAsPathPrepend(object):
    """
    No.37 aspath prepend action export
                            --------------------------------
    e1 ->(aspath=[65001])-> | ->  p1-rib -> p1-adj-rib-out | -> p1
                            |                              |
                            | ->  p2-rib -> p2-adj-rib-out | -> p2
                            |               apply action   |
                            --------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '192.168.20.0/24'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0]}
        g1.set_prefix_set(ps0)

        st0 = {'name': 'st0',
               'conditions': {'match-prefix-set': {'prefix-set': ps0['prefix-set-name']}},
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {'set-as-path-prepend': {'repeat-n': 5, 'as': "65005"}}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        e1.add_route('192.168.20.0/24')
        e1.add_route('192.168.200.0/24')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        wait_for(lambda: len(g1.get_adj_rib_in(e1)) == 2)
        wait_for(lambda: len(g1.get_local_rib(q1)) == 2)
        wait_for(lambda: len(g1.get_adj_rib_out(q1)) == 2)
        wait_for(lambda: len(q1.get_global_rib()) == 2)
        wait_for(lambda: len(g1.get_local_rib(q2)) == 2)
        wait_for(lambda: len(g1.get_adj_rib_out(q2)) == 2)
        wait_for(lambda: len(q2.get_global_rib()) == 2)

    @staticmethod
    def check2(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        path = g1.get_adj_rib_out(q1, prefix='192.168.20.0/24')[0]
        assert_true(path['aspath'] == [e1.asn])

        path = g1.get_adj_rib_out(q1, prefix='192.168.200.0/24')[0]
        assert_true(path['aspath'] == [e1.asn])

        path = g1.get_local_rib(q2, prefix='192.168.20.0/24')[0]['paths'][0]
        assert_true(path['aspath'] == [e1.asn])

        path = g1.get_adj_rib_out(q2, prefix='192.168.20.0/24')[0]
        assert_true(path['aspath'] == ([65005] * 5) + [e1.asn])

        path = g1.get_adj_rib_out(q2, prefix='192.168.200.0/24')[0]
        assert_true(path['aspath'] == [e1.asn])

    @staticmethod
    def executor(env):
        lookup_scenario("ExportPolicyAsPathPrepend").boot(env)
        lookup_scenario("ExportPolicyAsPathPrepend").setup(env)
        lookup_scenario("ExportPolicyAsPathPrepend").check(env)
        lookup_scenario("ExportPolicyAsPathPrepend").check2(env)


@register_scenario
class ImportPolicyAsPathPrependLastAS(object):
    """
    No.38 aspath prepend action lastas import
                            --------------------------------
    e1 ->(aspath=[65001])-> | ->  p1-rib -> p1-adj-rib-out | -> p1
                            |                              |
                            | ->  p2-rib -> p2-adj-rib-out | -> p2
                            |     apply action             |
                            --------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '192.168.20.0/24'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0]}
        g1.set_prefix_set(ps0)

        st0 = {'name': 'st0',
               'conditions': {'match-prefix-set': {'prefix-set': ps0['prefix-set-name']}},
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {'set-as-path-prepend': {'repeat-n': 5, 'as': "last-as"}}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        e1.add_route('192.168.20.0/24')
        e1.add_route('192.168.200.0/24')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ExportPolicyAsPathPrepend').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        path = g1.get_adj_rib_out(q1, prefix='192.168.20.0/24')[0]
        assert_true(path['aspath'] == [e1.asn])

        path = g1.get_adj_rib_out(q1, prefix='192.168.200.0/24')[0]
        assert_true(path['aspath'] == [e1.asn])

        path = g1.get_local_rib(q2, prefix='192.168.20.0/24')[0]['paths'][0]
        assert_true(path['aspath'] == ([e1.asn] * 5) + [e1.asn])

        path = g1.get_adj_rib_out(q2, prefix='192.168.20.0/24')[0]
        assert_true(path['aspath'] == ([e1.asn] * 5) + [e1.asn])

        path = g1.get_adj_rib_out(q2, prefix='192.168.200.0/24')[0]
        assert_true(path['aspath'] == [e1.asn])

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyAsPathPrependLastAS").boot(env)
        lookup_scenario("ImportPolicyAsPathPrependLastAS").setup(env)
        lookup_scenario("ImportPolicyAsPathPrependLastAS").check(env)
        lookup_scenario("ImportPolicyAsPathPrependLastAS").check2(env)


@register_scenario
class ExportPolicyAsPathPrependLastAS(object):
    """
    No.39 aspath prepend action lastas export
                            --------------------------------
    e1 ->(aspath=[65001])-> | ->  p1-rib -> p1-adj-rib-out | -> p1
                            |                              |
                            | ->  p2-rib -> p2-adj-rib-out | -> p2
                            |     apply action             |
                            --------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '192.168.20.0/24'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0]}
        g1.set_prefix_set(ps0)

        st0 = {'name': 'st0',
               'conditions': {'match-prefix-set': {'prefix-set': ps0['prefix-set-name']}},
               'actions': {'route-disposition': 'accept-route',
                           'bgp-actions': {'set-as-path-prepend': {'repeat-n': 5, 'as': "last-as"}}}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        e1.add_route('192.168.20.0/24')
        e1.add_route('192.168.200.0/24')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ExportPolicyAsPathPrepend').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        path = g1.get_adj_rib_out(q1, prefix='192.168.20.0/24')[0]
        assert_true(path['aspath'] == [e1.asn])

        path = g1.get_adj_rib_out(q1, prefix='192.168.200.0/24')[0]
        assert_true(path['aspath'] == [e1.asn])

        path = g1.get_local_rib(q2, prefix='192.168.20.0/24')[0]['paths'][0]
        assert_true(path['aspath'] == [e1.asn])

        path = g1.get_adj_rib_out(q2, prefix='192.168.20.0/24')[0]
        assert_true(path['aspath'] == ([e1.asn] * 5) + [e1.asn])

        path = g1.get_adj_rib_out(q2, prefix='192.168.200.0/24')[0]
        assert_true(path['aspath'] == [e1.asn])

    @staticmethod
    def executor(env):
        lookup_scenario("ExportPolicyAsPathPrependLastAS").boot(env)
        lookup_scenario("ExportPolicyAsPathPrependLastAS").setup(env)
        lookup_scenario("ExportPolicyAsPathPrependLastAS").check(env)
        lookup_scenario("ExportPolicyAsPathPrependLastAS").check2(env)


@register_scenario
class ImportPolicyExCommunityOriginCondition(object):
    """
    No.40 extended community origin condition import
                                                 --------------------------------
    e1 ->(extcommunity=origin:65001.65100:200)-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                                                 |                              |
                                                 | ->x q2-rib                   |
                                                 --------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario("ImportPolicy").boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        es0 = {'ext-community-sets': [{'ext-community-set-name': 'es0',
                                       'ext-community-list': ['SoO:65001.65100:200']}]}

        g1.set_bgp_defined_set(es0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-ext-community-set': {'ext-community-set': 'es0'}}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        e1.add_route('192.168.20.0/24', extendedcommunity='origin:{0}:200'.format((65001 << 16) + 65100))
        e1.add_route('192.168.200.0/24', extendedcommunity='origin:{0}:100'.format((65001 << 16) + 65200))

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario("ImportPolicy").check(env)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyExCommunityOriginCondition").boot(env)
        lookup_scenario("ImportPolicyExCommunityOriginCondition").setup(env)
        lookup_scenario("ImportPolicyExCommunityOriginCondition").check(env)


@register_scenario
class ImportPolicyExCommunityTargetCondition(object):
    """
    No.41 extended community origin condition import
                                           --------------------------------
    e1 ->(extcommunity=target:65010:320)-> | ->  q1-rib -> q1-adj-rib-out | --> q1
                                           |                              |
                                           | ->x q2-rib                   |
                                           --------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicy').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        es0 = {'ext-community-sets': [{'ext-community-set-name': 'es0',
                                       'ext-community-list': ['RT:6[0-9]+:3[0-9]+']}]}

        g1.set_bgp_defined_set(es0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-ext-community-set': {'ext-community-set': 'es0'}}},
               'actions': {'route-disposition': 'reject-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        e1.add_route('192.168.20.0/24', extendedcommunity='target:65010:320')
        e1.add_route('192.168.200.0/24', extendedcommunity='target:55000:320')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario("ImportPolicy").check(env)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyExCommunityTargetCondition").boot(env)
        lookup_scenario("ImportPolicyExCommunityTargetCondition").setup(env)
        lookup_scenario("ImportPolicyExCommunityTargetCondition").check(env)


def ext_community_exists(path, extcomm):
    typ = extcomm.split(':')[0]
    value = ':'.join(extcomm.split(':')[1:])
    for a in path['attrs']:
        if a['type'] == BGP_ATTR_TYPE_EXTENDED_COMMUNITIES:
            for c in a['value']:
                if typ == 'RT' and c['type'] == 0 and c['subtype'] == 2 and c['value'] == value:
                    return True
    return False


@register_scenario
class ImportPolicyExCommunityAdd(object):
    """
    No.43 extended community add action import-policy test
                               ---------------------------------
    e1 ->(extcommunity=none) ->| ->  q1-rib ->  q1-adj-rib-out | --> q1
                               |                               |
                               | ->  q2-rib ->  q2-adj-rib-out | --> q2
                               |     add ext-community         |
                               ---------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicy').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '192.168.10.0/24'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0]}
        g1.set_prefix_set(ps0)

        st0 = {
            'name': 'st0',
            'conditions': {
                'match-prefix-set': {
                    'prefix-set': ps0['prefix-set-name']
                }
            },
            'actions': {
                'route-disposition': 'accept-route',
                'bgp-actions': {
                    'set-ext-community': {
                        'options': 'add',
                        'set-ext-community-method': {
                            'communities-list': ['rt:65000:1'],
                        }
                    },
                }
            }
        }

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        e1.add_route('192.168.10.0/24')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityAction').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        # e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        path = g1.get_adj_rib_out(q1)[0]
        assert_false(ext_community_exists(path, 'RT:65000:1'))
        path = g1.get_adj_rib_out(q2)[0]
        assert_true(ext_community_exists(path, 'RT:65000:1'))

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyExCommunityAdd").boot(env)
        lookup_scenario("ImportPolicyExCommunityAdd").setup(env)
        lookup_scenario("ImportPolicyExCommunityAdd").check(env)
        lookup_scenario("ImportPolicyExCommunityAdd").check2(env)


@register_scenario
class ImportPolicyExCommunityAdd2(object):
    """
    No.44 extended community add action import-policy test
                                      --------------------------------
    e1 ->(extcommunity=RT:65000:1) -> | ->  q1-rib -> q1-adj-rib-out | --> q1
                                      |                              |
                                      | ->  q2-rib -> q2-adj-rib-out | --> q2
                                      |     add ext-community        |
                                      --------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicy').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '192.168.10.0/24'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0]}
        g1.set_prefix_set(ps0)

        st0 = {
            'name': 'st0',
            'conditions': {
                'match-prefix-set': {
                    'prefix-set': ps0['prefix-set-name']
                }
            },
            'actions': {
                'route-disposition': 'accept-route',
                'bgp-actions': {
                    'set-ext-community': {
                        'options': 'add',
                        'set-ext-community-method': {
                            'communities-list': ['rt:65100:100'],
                        }
                    },
                }
            }
        }

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        e1.add_route('192.168.10.0/24', extendedcommunity='target:65000:1')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityAction').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        # e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        path = g1.get_adj_rib_out(q1)[0]
        assert_true(ext_community_exists(path, 'RT:65000:1'))
        assert_false(ext_community_exists(path, 'RT:65100:100'))
        path = g1.get_local_rib(q2)[0]['paths'][0]
        assert_true(ext_community_exists(path, 'RT:65000:1'))
        assert_true(ext_community_exists(path, 'RT:65100:100'))
        path = g1.get_adj_rib_out(q2)[0]
        assert_true(ext_community_exists(path, 'RT:65000:1'))
        assert_true(ext_community_exists(path, 'RT:65100:100'))

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyExCommunityAdd2").boot(env)
        lookup_scenario("ImportPolicyExCommunityAdd2").setup(env)
        lookup_scenario("ImportPolicyExCommunityAdd2").check(env)
        lookup_scenario("ImportPolicyExCommunityAdd2").check2(env)


@register_scenario
class ImportPolicyExCommunityMultipleAdd(object):
    """
    No.45 extended community add action multiple import-policy test
                                   ---------------------------------------
    exabgp ->(extcommunity=none) ->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                   |                                     |
                                   | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                   |     add ext-community               |
                                   ---------------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicy').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '192.168.10.0/24'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0]}
        g1.set_prefix_set(ps0)

        st0 = {
            'name': 'st0',
            'conditions': {
                'match-prefix-set': {
                    'prefix-set': ps0['prefix-set-name']
                }
            },
            'actions': {
                'route-disposition': 'accept-route',
                'bgp-actions': {
                    'set-ext-community': {
                        'options': 'add',
                        'set-ext-community-method': {
                            'communities-list': ['rt:65100:100', 'rt:100:100'],
                        }
                    },
                }
            }
        }

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'import')

        e1.add_route('192.168.10.0/24')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityAction').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        # e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        path = g1.get_adj_rib_out(q1)[0]
        assert_false(ext_community_exists(path, 'RT:65100:100'))
        assert_false(ext_community_exists(path, 'RT:100:100'))
        path = g1.get_local_rib(q2)[0]['paths'][0]
        assert_true(ext_community_exists(path, 'RT:65100:100'))
        assert_true(ext_community_exists(path, 'RT:100:100'))
        path = g1.get_adj_rib_out(q2)[0]
        assert_true(ext_community_exists(path, 'RT:65100:100'))
        assert_true(ext_community_exists(path, 'RT:100:100'))

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyExCommunityMultipleAdd").boot(env)
        lookup_scenario("ImportPolicyExCommunityMultipleAdd").setup(env)
        lookup_scenario("ImportPolicyExCommunityMultipleAdd").check(env)
        lookup_scenario("ImportPolicyExCommunityMultipleAdd").check2(env)


@register_scenario
class ExportPolicyExCommunityAdd(object):
    """
    No.46 extended comunity add action export-policy test
                               ------------------------------------
    e1 ->(extcommunity=none) ->| ->  q1-rib ->  q1-adj-rib-out    | --> q1
                               |                                  |
                               | ->  q2-rib ->  q2-adj-rib-out    | --> q2
                               |                add ext-community |
                               ------------------------------------
    """
    @staticmethod
    def boot(env):
        lookup_scenario('ImportPolicy').boot(env)

    @staticmethod
    def setup(env):
        g1 = env.g1
        e1 = env.e1
        q1 = env.q1
        q2 = env.q2

        p0 = {'ip-prefix': '192.168.10.0/24'}

        ps0 = {'prefix-set-name': 'ps0',
               'prefix-list': [p0]}
        g1.set_prefix_set(ps0)

        st0 = {
            'name': 'st0',
            'conditions': {
                'match-prefix-set': {
                    'prefix-set': ps0['prefix-set-name']
                }
            },
            'actions': {
                'route-disposition': 'accept-route',
                'bgp-actions': {
                    'set-ext-community': {
                        'options': 'add',
                        'set-ext-community-method': {
                            'communities-list': ['rt:65000:1'],
                        }
                    },
                }
            }
        }

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, q2, 'export')

        e1.add_route('192.168.10.0/24')

        for c in [e1, q1, q2]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

    @staticmethod
    def check(env):
        lookup_scenario('ImportPolicyCommunityAction').check(env)

    @staticmethod
    def check2(env):
        g1 = env.g1
        # e1 = env.e1
        q1 = env.q1
        q2 = env.q2
        path = g1.get_adj_rib_out(q1)[0]
        assert_false(ext_community_exists(path, 'RT:65000:1'))
        path = g1.get_local_rib(q2)[0]['paths'][0]
        assert_false(ext_community_exists(path, 'RT:65000:1'))
        path = g1.get_adj_rib_out(q2)[0]
        assert_true(ext_community_exists(path, 'RT:65000:1'))

    @staticmethod
    def executor(env):
        lookup_scenario("ExportPolicyExCommunityAdd").boot(env)
        lookup_scenario("ExportPolicyExCommunityAdd").setup(env)
        lookup_scenario("ExportPolicyExCommunityAdd").check(env)
        lookup_scenario("ExportPolicyExCommunityAdd").check2(env)


@register_scenario
class ImportPolicyRejectImplicitWithdraw(object):
    """
    No.48 in-policy reject test
    g2 (asn: 65002)
    g3 (asn: 65003)

    g2's in-policy only accepts routes with origin asn 65002

    r1:192.168.10.0/24

    1.

         r1
          |                                  g1(rs)
          v                             ----------------
    g3 - g2 ->(r1(aspath=[65002]))->  o | -> g4-rib -> | -> r1(aspath=[65002]) --> g4
                                        ----------------

    2. g3 also sends prefix r1 (the prefix from g2 is still the best for the prefix)

    r1   r1
    |     |                                  g1(rs)
    v     v                             ----------------
    g3 - g2 ->(r1(aspath=[65002]))->  o | -> g4-rib -> | -> r1(aspath=[65002]) --> g4
                                        ----------------

    3. g2 withdraws r1, then the path from g3 becomes the best (implicit withdrawal happens).
       Since g2's in-policy only accepts routes with origin asn 2, rs must send withdrawal to g4.

    r1   r1
    |     x                                        g1(rs)
    v                                         ----------------
    g3 - g2 ->(r1(aspath=[65002,65003]))->  x | -> g4-rib -> | -> r1(withdrawal) --> g4
                                              ----------------
    """
    @staticmethod
    def boot(env):
        gobgp_ctn_image_name = env.parser_option.gobgp_image
        log_level = env.parser_option.gobgp_log_level
        g1 = GoBGPContainer(name='g1', asn=65001, router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=log_level)
        g2 = GoBGPContainer(name='g2', asn=65002, router_id='192.168.0.2',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=log_level)
        g3 = GoBGPContainer(name='g3', asn=65003, router_id='192.168.0.3',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=log_level)
        g4 = GoBGPContainer(name='g4', asn=65004, router_id='192.168.0.4',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=log_level)

        ctns = [g1, g2, g3, g4]
        initial_wait_time = max(ctn.run() for ctn in ctns)
        time.sleep(initial_wait_time)

        for cli in [g2, g4]:
            g1.add_peer(cli, is_rs_client=True)
            cli.add_peer(g1)

        g3.add_peer(g2)
        g2.add_peer(g3)

        env.g1 = g1
        env.g2 = g2
        env.g3 = g3
        env.g4 = g4

    @staticmethod
    def setup(env):
        g1 = env.g1
        g2 = env.g2
        # g3 = env.g3
        g4 = env.g4

        as0 = {'as-path-sets': [{'as-path-set-name': 'as0', 'as-path-list': ['_65002$']}]}

        g1.set_bgp_defined_set(as0)

        st0 = {'name': 'st0',
               'conditions': {'bgp-conditions': {'match-as-path-set': {'as-path-set': 'as0'}}},
               'actions': {'route-disposition': 'accept-route'}}

        policy = {'name': 'policy0',
                  'statements': [st0]}
        g1.add_policy(policy, g2, 'import', 'reject')

        g2.add_route('192.168.0.0/24')

        for c in [g2, g4]:
            g1.wait_for(BGP_FSM_ESTABLISHED, c)

        g2.wait_for(BGP_FSM_ESTABLISHED, g1)

    @staticmethod
    def check(env):
        g1 = env.g1
        # g2 = env.g2
        g4 = env.g4
        wait_for(lambda: len(g1.get_local_rib(g4)) == 1)
        wait_for(lambda: len(g1.get_local_rib(g4)[0]['paths']) == 1)
        wait_for(lambda: len(g4.get_global_rib()) == 1)
        wait_for(lambda: len(g4.get_global_rib()[0]['paths']) == 1)

    @staticmethod
    def setup2(env):
        env.g3.add_route('192.168.0.0/24')

    @staticmethod
    def check2(env):
        g1 = env.g1
        g2 = env.g2
        g4 = env.g4
        wait_for(lambda: len(g2.get_global_rib()) == 1)
        wait_for(lambda: len(g2.get_global_rib()[0]['paths']) == 2)
        wait_for(lambda: len(g1.get_local_rib(g4)) == 1)
        wait_for(lambda: len(g1.get_local_rib(g4)[0]['paths']) == 1)
        wait_for(lambda: len(g1.get_adj_rib_in(g2)) == 1)
        wait_for(lambda: len(g4.get_global_rib()) == 1)
        wait_for(lambda: len(g4.get_global_rib()[0]['paths']) == 1)

    @staticmethod
    def setup3(env):
        env.g2.local('gobgp global rib del 192.168.0.0/24')

    @staticmethod
    def check3(env):
        g1 = env.g1
        g2 = env.g2
        g4 = env.g4
        wait_for(lambda: len(g2.get_global_rib()) == 1)
        wait_for(lambda: len(g2.get_global_rib()[0]['paths']) == 1)
        wait_for(lambda: len(g1.get_adj_rib_in(g2)) == 1)
        wait_for(lambda: len(g1.get_local_rib(g4)) == 0)
        wait_for(lambda: len(g4.get_global_rib()) == 0)

    @staticmethod
    def executor(env):
        lookup_scenario("ImportPolicyRejectImplicitWithdraw").boot(env)
        lookup_scenario("ImportPolicyRejectImplicitWithdraw").setup(env)
        lookup_scenario("ImportPolicyRejectImplicitWithdraw").check(env)
        lookup_scenario("ImportPolicyRejectImplicitWithdraw").setup2(env)
        lookup_scenario("ImportPolicyRejectImplicitWithdraw").check2(env)
        lookup_scenario("ImportPolicyRejectImplicitWithdraw").setup3(env)
        lookup_scenario("ImportPolicyRejectImplicitWithdraw").check3(env)


class TestGoBGPBase(unittest.TestCase):

    wait_per_retry = 5
    retry_limit = 10

    @classmethod
    def setUpClass(cls):
        idx = parser_option.test_index
        base.TEST_PREFIX = parser_option.test_prefix
        cls.parser_option = parser_option
        cls.executors = []
        if idx == 0:
            print('unset test-index. run all test sequential')
            for _, v in list(_SCENARIOS.items()):
                for k, m in inspect.getmembers(v, inspect.isfunction):
                    if k == 'executor':
                        cls.executor = m
                cls.executors.append(cls.executor)
        elif idx not in _SCENARIOS:
            print('invalid test-index. # of scenarios: {0}'.format(len(_SCENARIOS)))
            sys.exit(1)
        else:
            for k, m in inspect.getmembers(_SCENARIOS[idx], inspect.isfunction):
                if k == 'executor':
                    cls.executor = m
            cls.executors.append(cls.executor)

    def test(self):
        for e in self.executors:
            yield e


if __name__ == '__main__':
    output = local("which docker 2>&1 > /dev/null ; echo $?", capture=True)
    if int(output) is not 0:
        print("docker not found")
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
