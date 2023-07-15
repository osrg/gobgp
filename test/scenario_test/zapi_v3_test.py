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
                            zebra=True, zapi_version=3)

        g2 = GoBGPContainer(name='g2', asn=65001, router_id='192.168.0.2',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level,
                            zebra=True, zapi_version=3)

        initial_wait_time = max(ctn.run() for ctn in [g1, g2])

        time.sleep(initial_wait_time)

        g1.add_peer(g2, vpn=True)
        g2.add_peer(g1, vpn=True)

        cls.g1 = g1
        cls.g2 = g2

    def test_01_neighbor_established(self):
        self.g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g2)

    def test_02_vrf_routes_add(self):
        self.g1.local('ip netns add ns01')
        self.g1.local('ip netns add ns02')
        self.g2.local('ip netns add ns01')
        self.g2.local('ip netns add ns02')

        self.g1.local('ip netns exec ns01 ip li set up dev lo')
        self.g1.local('ip netns exec ns02 ip li set up dev lo')
        self.g2.local('ip netns exec ns01 ip li set up dev lo')
        self.g2.local('ip netns exec ns02 ip li set up dev lo')

        self.g1.local("vtysh -c 'enable' -c 'conf t' -c 'vrf 1 netns ns01'")
        self.g1.local("vtysh -c 'enable' -c 'conf t' -c 'vrf 2 netns ns02'")
        self.g2.local("vtysh -c 'enable' -c 'conf t' -c 'vrf 1 netns ns01'")
        self.g2.local("vtysh -c 'enable' -c 'conf t' -c 'vrf 2 netns ns02'")

        self.g1.local("gobgp vrf add vrf01 id 1 rd 1:1 rt both 1:1")
        self.g1.local("gobgp vrf add vrf02 id 2 rd 2:2 rt both 2:2")
        self.g2.local("gobgp vrf add vrf01 id 1 rd 1:1 rt both 1:1")
        self.g2.local("gobgp vrf add vrf02 id 2 rd 2:2 rt both 2:2")

        self.g1.local("gobgp vrf vrf01 rib add 10.0.0.0/24 nexthop 127.0.0.1")
        self.g1.local("gobgp vrf vrf02 rib add 20.0.0.0/24 nexthop 127.0.0.1")

        time.sleep(2)

        lines = self.g2.local("ip netns exec ns01 ip r", capture=True).split('\n')
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].split(' ')[0], '10.0.0.0/24')

        lines = self.g2.local("ip netns exec ns02 ip r", capture=True).split('\n')
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].split(' ')[0], '20.0.0.0/24')

    def test_03_vrf_routes_del(self):
        self.g1.local("gobgp vrf vrf01 rib del 10.0.0.0/24 nexthop 127.0.0.1")
        self.g1.local("gobgp vrf vrf02 rib del 20.0.0.0/24 nexthop 127.0.0.1")

        time.sleep(2)
        lines = self.g2.local("ip netns exec ns01 ip r", capture=True).split('\n')
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], "")

        lines = self.g2.local("ip netns exec ns02 ip r", capture=True).split('\n')
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], "")

    def test_04_vrf_import_routes(self):
        self.g1.local("gobgp vrf del vrf01")
        # Import vrf2 routes into vrf1
        self.g1.local("gobgp vrf add vrf01 id 1 rd 1:1 rt import 1:1 2:2 export 1:1")

        self.g1.local("gobgp vrf vrf01 rib add 10.0.0.0/24 nexthop 127.0.0.1")
        self.g1.local("gobgp vrf vrf02 rib add 20.0.0.0/24 nexthop 127.0.0.1")

        time.sleep(2)

        # g1 has the vrf2 route imported to vrf1 and updated on zebra
        lines = self.g1.local("ip netns exec ns01 ip r", capture=True).split('\n')
        self.assertEqual(len(lines), 2)
        route_destinations = set()
        route_destinations.add(lines[0].split(' ')[0])
        route_destinations.add(lines[1].split(' ')[0])
        self.assertEqual(len(route_destinations.intersection(set(["10.0.0.0/24", "20.0.0.0/24"]))), 2)

        # Ensure other vrf and other neighbors are not impacted
        lines = self.g1.local("ip netns exec ns02 ip r", capture=True).split('\n')
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].split(' ')[0], '20.0.0.0/24')

        lines = self.g2.local("ip netns exec ns01 ip r", capture=True).split('\n')
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].split(' ')[0], '10.0.0.0/24')

        lines = self.g2.local("ip netns exec ns02 ip r", capture=True).split('\n')
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].split(' ')[0], '20.0.0.0/24')

        # Routes imported from another vrf are cleaned up properly
        self.g1.local("gobgp vrf vrf02 rib del 20.0.0.0/24 nexthop 127.0.0.1")
        lines = self.g1.local("ip netns exec ns01 ip r", capture=True).split('\n')
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].split(' ')[0], '10.0.0.0/24')

        lines = self.g1.local("ip netns exec ns02 ip r", capture=True).split('\n')
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].split(' ')[0], '')


if __name__ == '__main__':
    output = local("which docker 2>&1 > /dev/null ; echo $?", capture=True)
    if int(output) != 0:
        print("docker not found")
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
