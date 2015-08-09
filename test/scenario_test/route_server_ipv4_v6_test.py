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
import sys
import os
import time
import nose
from noseplugin import OptionParser, parser_option


class GoBGPIPv6Test(unittest.TestCase):

    wait_per_retry = 5
    retry_limit = 15

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        g1 = GoBGPContainer(name='g1', asn=65002, router_id='192.168.0.2',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        q1 = QuaggaBGPContainer(name='q1', asn=65003, router_id='192.168.0.3')
        q2 = QuaggaBGPContainer(name='q2', asn=65004, router_id='192.168.0.4')
        q3 = QuaggaBGPContainer(name='q3', asn=65005, router_id='192.168.0.5')
        q4 = QuaggaBGPContainer(name='q4', asn=65006, router_id='192.168.0.6')

        ctns = [g1, q1, q2, q3, q4]
        v4 = [q1, q2]
        v6 = [q3, q4]

        for idx, q in enumerate(v4):
            route = '10.0.{0}.0/24'.format(idx+1)
            q.add_route(route)

        for idx, q in enumerate(v6):
            route = '2001:{0}::/96'.format(idx+1)
            q.add_route(route, rf='ipv6')

        initial_wait_time = max(ctn.run() for ctn in ctns)

        time.sleep(initial_wait_time)

        br01 = Bridge(name='br01', subnet='192.168.10.0/24')
        br01.addif(g1)
        for ctn in v4:
            br01.addif(ctn)
            g1.add_peer(ctn, is_rs_client=True)
            ctn.add_peer(g1)

        br02 = Bridge(name='br02', subnet='2001::/96')
        br02.addif(g1)
        for ctn in v6:
            br02.addif(ctn)
            g1.add_peer(ctn, is_rs_client=True)
            ctn.add_peer(g1)

        cls.gobgp = g1
        cls.quaggas = {'q1': q1, 'q2': q2, 'q3': q3, 'q4': q4}
        cls.bridges = {'br01': br01, 'br02': br02}
        cls.ipv4s = {'q1': q1, 'q2': q2}
        cls.ipv6s = {'q3': q3, 'q4': q4}

    def check_gobgp_local_rib(self, ctns, rf):
        for rs_client in ctns.itervalues():
            done = False
            for _ in range(self.retry_limit):
                if done:
                    break
                local_rib = self.gobgp.get_local_rib(rs_client, rf)
                local_rib = [p['prefix'] for p in local_rib]
                if len(local_rib) < len(ctns)-1:
                    time.sleep(self.wait_per_retry)
                    continue

                self.assertTrue(len(local_rib) == (len(ctns)-1))

                for c in ctns.itervalues():
                    if rs_client != c:
                        for r in c.routes:
                            self.assertTrue(r in local_rib)

                done = True
            if done:
                continue
            # should not reach here
            self.assertTrue(False)

    def check_rs_client_rib(self, ctns, rf):
        for rs_client in ctns.itervalues():
            done = False
            for _ in range(self.retry_limit):
                if done:
                    break
                global_rib = rs_client.get_global_rib(rf=rf)
                global_rib = [p['prefix'] for p in global_rib]
                if len(global_rib) < len(ctns):
                    time.sleep(self.wait_per_retry)
                    continue

                self.assertTrue(len(global_rib) == len(ctns))

                for c in ctns.itervalues():
                    for r in c.routes:
                        self.assertTrue(r in global_rib)

                done = True
            if done:
                continue
            # should not reach here
            self.assertTrue(False)

    # test each neighbor state is turned establish
    def test_01_neighbor_established(self):
        for q in self.quaggas.itervalues():
            self.gobgp.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=q)

    def test_02_check_ipv4_peer_rib(self):
        self.check_gobgp_local_rib(self.ipv4s, 'ipv4')
        self.check_rs_client_rib(self.ipv4s, 'ipv4')

    def test_03_check_ipv6_peer_rib(self):
        self.check_gobgp_local_rib(self.ipv6s, 'ipv6')
        self.check_rs_client_rib(self.ipv6s, 'ipv6')


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
