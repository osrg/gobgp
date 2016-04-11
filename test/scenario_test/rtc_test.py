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

import unittest
from fabric.api import local
from lib import base
from lib.gobgp import *
from lib.quagga import *
import sys
import os
import time
import nose
from noseplugin import OptionParser, parser_option
from itertools import combinations


class GoBGPTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        g1 = GoBGPContainer(name='g1', asn=65000, router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        g2 = GoBGPContainer(name='g2', asn=65000, router_id='192.168.0.2',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        ctns = [g1, g2]

        initial_wait_time = max(ctn.run() for ctn in ctns)

        time.sleep(initial_wait_time)

        g1.local("gobgp vrf add vrf1 rd 100:100 rt both 100:100")
        g1.local("gobgp vrf add vrf2 rd 200:200 rt both 200:200")
        g2.local("gobgp vrf add vrf1 rd 100:100 rt both 100:100")
        g2.local("gobgp vrf add vrf3 rd 300:300 rt both 300:300")

        g1.local("gobgp vrf vrf1 rib add 10.0.0.0/24")
        g1.local("gobgp vrf vrf2 rib add 10.0.0.0/24")
        g2.local("gobgp vrf vrf1 rib add 20.0.0.0/24")
        g2.local("gobgp vrf vrf3 rib add 20.0.0.0/24")

        for a, b in combinations(ctns, 2):
            a.add_peer(b, vpn=True, passwd='rtc', graceful_restart=True)
            b.add_peer(a, vpn=True, passwd='rtc', graceful_restart=True)

        cls.g1 = g1
        cls.g2 = g2

    # test each neighbor state is turned establish
    def test_01_neighbor_established(self):
        self.g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g2)

    def test_02_check_gobgp_adj_rib_out(self):
        time.sleep(10)
        self.assertTrue(len(self.g1.get_adj_rib_out(self.g2, rf='ipv4-l3vpn')) == 1)
        self.assertTrue(len(self.g2.get_adj_rib_out(self.g1, rf='ipv4-l3vpn')) == 1)

    def test_03_add_vrf(self):
        self.g1.local("gobgp vrf add vrf3 rd 300:300 rt both 300:300")
        time.sleep(10)
        self.assertTrue(len(self.g1.get_adj_rib_in(self.g2, rf='ipv4-l3vpn')) == 2)

    def test_04_del_vrf(self):
        self.g1.local("gobgp vrf del vrf1")
        time.sleep(10)
        self.assertTrue(len(self.g1.get_adj_rib_in(self.g2, rf='ipv4-l3vpn')) == 1)

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
