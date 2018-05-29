# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

from __future__ import absolute_import

import sys
import time
import unittest

import nose
from fabric.api import local
from lib import base
from lib.gobgp import GoBGPContainer
from lib.noseplugin import OptionParser, parser_option


class GoBGPTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        #               +------+
        #               |  rr  |
        #        +------| (RR) |------+
        #        |      +------+      |
        #      (iBGP)              (iBGP)
        #        |                    |
        # +-------------+      +-------------+
        # |     c1      |      |     c2      |
        # | (RR Client) |      | (RR Client) |
        # +-------------+      +-------------+
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        rr = GoBGPContainer(name='rr', asn=65000, router_id='192.168.0.100',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        c1 = GoBGPContainer(name='c1', asn=65000, router_id='192.168.0.101',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        c2 = GoBGPContainer(name='c2', asn=65000, router_id='192.168.0.102',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)

        ctns = {ctn.name: ctn for ctn in [rr, c1, c2]}

        initial_wait_time = max(ctn.run() for ctn in ctns.values())

        time.sleep(initial_wait_time)

        common_peer_kwargs = {
            'vpn': True,
            'graceful_restart': True,
            'llgr': True,
            'addpath': True
        }

        rr.add_peer(c1, is_rr_client=True, **common_peer_kwargs)
        rr.add_peer(c2, is_rr_client=True, **common_peer_kwargs)

        c1.add_peer(rr, **common_peer_kwargs)
        c2.add_peer(rr, **common_peer_kwargs)

        # shared vrf
        c1.local("gobgp vrf add vrf9 rd 900:900 rt both 900:900")
        c2.local("gobgp vrf add vrf9 rd 900:900 rt both 900:900")
        c1.local("gobgp vrf vrf9 rib add 10.0.0.0/24")
        c2.local("gobgp vrf vrf9 rib add 20.0.0.0/24")

        # isolated vrfs
        c1.local("gobgp vrf add vrf1 rd 100:100 rt both 100:100")
        c2.local("gobgp vrf add vrf2 rd 200:200 rt both 200:200")

        c1.local("gobgp vrf vrf1 rib add 10.0.0.0/24")
        c2.local("gobgp vrf vrf2 rib add 20.0.0.0/24")

        cls.rr_name = rr.ip_addrs[0][1].split('/')[0]

        cls.rr = rr
        cls.c1 = c1
        cls.c2 = c2
        cls.ctns = ctns

    def test_01_neighbors_established(self):
        self.rr.wait_for(expected_state=base.BGP_FSM_ESTABLISHED, peer=self.c1)
        self.rr.wait_for(expected_state=base.BGP_FSM_ESTABLISHED, peer=self.c2)
        self.assertEquals(1, len(self.c1.get_adj_rib_in(self.rr, rf='ipv4-l3vpn')))
        self.assertEquals(3, len(self.c1.get_adj_rib_in(self.rr, rf='rtc')))

        self.assertEquals(1, len(self.c2.get_adj_rib_in(self.rr, rf='ipv4-l3vpn')))
        self.assertEquals(3, len(self.c2.get_adj_rib_in(self.rr, rf='rtc')))

        self.assertEquals(2, len(self.rr.get_adj_rib_in(self.c1, rf='ipv4-l3vpn')))
        self.assertEquals(2, len(self.rr.get_adj_rib_in(self.c1, rf='rtc')))
        self.assertEquals(2, len(self.rr.get_adj_rib_in(self.c2, rf='ipv4-l3vpn')))
        self.assertEquals(2, len(self.rr.get_adj_rib_in(self.c2, rf='rtc')))

    def test_02_route_add_propagated_through_rr(self):
        self.c1.local("gobgp vrf vrf9 rib add 11.11.0.0/24")
        time.sleep(5)
        self.assertEquals(2, len(self.c2.get_adj_rib_in(self.rr, rf='ipv4-l3vpn')))

    def test_03_route_withdraw_propagated_through_rr(self):
        self.c1.local("gobgp vrf vrf9 rib del 11.11.0.0/24")
        time.sleep(5)
        self.assertEquals(1, len(self.c2.get_adj_rib_in(self.rr, rf='ipv4-l3vpn')))


if __name__ == '__main__':
    output = local("which docker 2>&1 > /dev/null ; echo $?", capture=True)
    if int(output) is not 0:
        print "docker not found"
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
