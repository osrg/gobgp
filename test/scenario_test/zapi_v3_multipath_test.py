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

import collections
collections.Callable = collections.abc.Callable

import nose

from lib.noseplugin import OptionParser, parser_option

from lib import base
from lib.base import BGP_FSM_ESTABLISHED, local
from lib.gobgp import GoBGPContainer


class GoBGPTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        g1 = GoBGPContainer(name='g1', asn=65000, router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level,
                            zebra=True, zapi_version=3, zebra_multipath_enabled=True)

        g2 = GoBGPContainer(name='g2', asn=65001, router_id='192.168.0.2',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level,
                            zebra=True, zapi_version=3, zebra_multipath_enabled=True)

        g3 = GoBGPContainer(name='g3', asn=65001, router_id='192.168.0.3',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level,
                            zebra=True, zapi_version=3, zebra_multipath_enabled=True)

        initial_wait_time = max(ctn.run() for ctn in [g1, g2, g3])

        time.sleep(initial_wait_time)

        g1.add_peer(g2, vpn=True, addpath=True)
        g2.add_peer(g1, vpn=True, addpath=True)
        g1.add_peer(g3, vpn=True, addpath=True)
        g3.add_peer(g1, vpn=True, addpath=True)

        cls.g1 = g1
        cls.g2 = g2
        cls.g3 = g3

    """
    # Multipath route
    10.0.0.0/24 proto zebra metric 20
        nexthop via 127.0.0.1  dev lo weight 1
        nexthop via 127.0.0.2  dev lo weight 1
    # Single nexthop route
    10.0.0.0/24 via 127.0.0.2 dev lo proto zebra metric 20
    """

    def parse_ip_route(self, ip_route_output):
        routes = {}
        current_mpath_dest = ""
        for line in ip_route_output:
            tokens = line.split()
            if len(tokens) == 0:
                continue
            if tokens[0] == "nexthop":
                # multipath nexthops
                routes[current_mpath_dest].add(tokens[2])
            elif tokens[1] == "via":
                # single nexthop route
                routes[tokens[0]] = set([tokens[2]])
                current_mpath_dest = ""
            elif tokens[1] == "proto":
                # multipath route line 1
                routes[tokens[0]] = set()
                current_mpath_dest = tokens[0]
        return routes

    def test_01_neighbors_established(self):
        self.g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g2)
        self.g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g3)

    def test_02_add_multipath_vrf_route(self):
        self.g1.local('ip netns add ns01')
        self.g1.local('ip netns add ns02')
        self.g2.local('ip netns add ns01')
        self.g2.local('ip netns add ns02')
        self.g3.local('ip netns add ns01')
        self.g3.local('ip netns add ns02')

        self.g1.local('ip netns exec ns01 ip li set up dev lo')
        self.g1.local('ip netns exec ns01 ip addr add 127.0.0.2/8 dev lo')
        self.g1.local('ip netns exec ns02 ip li set up dev lo')
        self.g1.local('ip netns exec ns02 ip addr add 127.0.0.2/8 dev lo')

        self.g2.local('ip netns exec ns01 ip li set up dev lo')
        self.g2.local('ip netns exec ns01 ip addr add 127.0.0.2/8 dev lo')
        self.g2.local('ip netns exec ns02 ip li set up dev lo')
        self.g2.local('ip netns exec ns02 ip addr add 127.0.0.2/8 dev lo')

        self.g3.local('ip netns exec ns01 ip li set up dev lo')
        self.g3.local('ip netns exec ns01 ip addr add 127.0.0.2/8 dev lo')
        self.g3.local('ip netns exec ns02 ip li set up dev lo')
        self.g3.local('ip netns exec ns02 ip addr add 127.0.0.2/8 dev lo')

        self.g1.local("vtysh -c 'enable' -c 'conf t' -c 'vrf 1 netns ns01'")
        self.g1.local("vtysh -c 'enable' -c 'conf t' -c 'vrf 2 netns ns02'")
        self.g2.local("vtysh -c 'enable' -c 'conf t' -c 'vrf 1 netns ns01'")
        self.g2.local("vtysh -c 'enable' -c 'conf t' -c 'vrf 2 netns ns02'")
        self.g3.local("vtysh -c 'enable' -c 'conf t' -c 'vrf 1 netns ns01'")
        self.g3.local("vtysh -c 'enable' -c 'conf t' -c 'vrf 2 netns ns02'")

        self.g1.local("gobgp vrf add vrf01 id 1 rd 1:1 rt both 1:1")
        self.g1.local("gobgp vrf add vrf02 id 2 rd 2:2 rt both 2:2")
        self.g2.local("gobgp vrf add vrf01 id 1 rd 1:1 rt both 1:1")
        self.g2.local("gobgp vrf add vrf02 id 2 rd 2:2 rt both 2:2")
        self.g3.local("gobgp vrf add vrf01 id 1 rd 1:1 rt both 1:1")
        self.g3.local("gobgp vrf add vrf02 id 2 rd 2:2 rt both 2:2")

        self.g2.local("gobgp vrf vrf01 rib add 10.0.0.0/24 nexthop 127.0.0.1")
        self.g2.local("gobgp vrf vrf02 rib add 20.0.0.0/24 nexthop 127.0.0.1")

        time.sleep(2)

        lines = self.g1.local("ip netns exec ns01 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 1)
        self.assertEqual(kernel_routes['10.0.0.0/24'], set(['127.0.0.1']))

        lines = self.g1.local("ip netns exec ns02 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 1)
        self.assertEqual(kernel_routes['20.0.0.0/24'], set(['127.0.0.1']))

        self.g3.local("gobgp vrf vrf01 rib add 10.0.0.0/24 nexthop 127.0.0.2")
        self.g3.local("gobgp vrf vrf02 rib add 20.0.0.0/24 nexthop 127.0.0.2")

        time.sleep(2)

        lines = self.g1.local("ip netns exec ns01 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 1)
        self.assertEqual(kernel_routes['10.0.0.0/24'], set(['127.0.0.1', '127.0.0.2']))

        lines = self.g1.local("ip netns exec ns02 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 1)
        self.assertEqual(kernel_routes['20.0.0.0/24'], set(['127.0.0.1', '127.0.0.2']))

    def test_03_remove_vrf_route_from_multipath(self):
        self.g3.local("gobgp vrf vrf01 rib del 10.0.0.0/24 nexthop 127.0.0.2")
        self.g3.local("gobgp vrf vrf02 rib del 20.0.0.0/24 nexthop 127.0.0.2")

        time.sleep(2)

        lines = self.g1.local("ip netns exec ns01 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 1)
        self.assertEqual(kernel_routes['10.0.0.0/24'], set(['127.0.0.1']))

        lines = self.g1.local("ip netns exec ns02 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 1)
        self.assertEqual(kernel_routes['20.0.0.0/24'], set(['127.0.0.1']))

        self.g2.local("gobgp vrf vrf01 rib del 10.0.0.0/24 nexthop 127.0.0.1")
        self.g2.local("gobgp vrf vrf02 rib del 20.0.0.0/24 nexthop 127.0.0.1")

        lines = self.g1.local("ip netns exec ns01 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 0)

        lines = self.g1.local("ip netns exec ns02 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 0)

    def test_04_multipath_with_vrf_import(self):
        self.g1.local("gobgp vrf del vrf01")
        self.g1.local("gobgp vrf add vrf01 id 1 rd 1:1 rt import 1:1 2:2 3:3 export 1:1")

        self.g2.local("gobgp vrf vrf01 rib add 10.0.0.0/24 nexthop 127.0.0.1")
        self.g2.local("gobgp vrf vrf02 rib add 20.0.0.0/24 nexthop 127.0.0.1")

        time.sleep(2)

        lines = self.g1.local("ip netns exec ns01 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 2)
        self.assertEqual(kernel_routes['10.0.0.0/24'], set(['127.0.0.1']))
        self.assertEqual(kernel_routes['20.0.0.0/24'], set(['127.0.0.1']))

        lines = self.g1.local("ip netns exec ns02 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 1)
        self.assertEqual(kernel_routes['20.0.0.0/24'], set(['127.0.0.1']))

        self.g3.local("gobgp vrf vrf01 rib add 10.0.0.0/24 nexthop 127.0.0.2")
        self.g3.local("gobgp vrf vrf02 rib add 20.0.0.0/24 nexthop 127.0.0.2")

        time.sleep(2)

        lines = self.g1.local("ip netns exec ns01 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 2)
        self.assertEqual(kernel_routes['10.0.0.0/24'], set(['127.0.0.1', '127.0.0.2']))
        self.assertEqual(kernel_routes['20.0.0.0/24'], set(['127.0.0.1', '127.0.0.2']))

        lines = self.g1.local("ip netns exec ns02 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 1)
        self.assertEqual(kernel_routes['20.0.0.0/24'], set(['127.0.0.1', '127.0.0.2']))

    def test_05_cleanup_multipath_vrf_import(self):
        self.g3.local("gobgp vrf vrf01 rib del 10.0.0.0/24 nexthop 127.0.0.2")
        self.g3.local("gobgp vrf vrf02 rib del 20.0.0.0/24 nexthop 127.0.0.2")

        time.sleep(2)

        lines = self.g1.local("ip netns exec ns01 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 2)
        self.assertEqual(kernel_routes['10.0.0.0/24'], set(['127.0.0.1']))
        self.assertEqual(kernel_routes['20.0.0.0/24'], set(['127.0.0.1']))

        lines = self.g1.local("ip netns exec ns02 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 1)
        self.assertEqual(kernel_routes['20.0.0.0/24'], set(['127.0.0.1']))

        self.g2.local("gobgp vrf vrf01 rib del 10.0.0.0/24 nexthop 127.0.0.1")
        self.g2.local("gobgp vrf vrf02 rib del 20.0.0.0/24 nexthop 127.0.0.1")

        lines = self.g1.local("ip netns exec ns01 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 0)

        lines = self.g1.local("ip netns exec ns02 ip r", capture=True).split('\n')
        kernel_routes = self.parse_ip_route(lines)
        self.assertEqual(len(kernel_routes), 0)


if __name__ == '__main__':
    output = local("which docker 2>&1 > /dev/null ; echo $?", capture=True)
    if int(output) != 0:
        print("docker not found")
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
