# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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

import nose

from lib.noseplugin import OptionParser, parser_option

from lib import base
from lib.base import (
    BGP_FSM_ESTABLISHED,
    assert_several_times,
    local,
)
from lib.gobgp import GoBGPContainer
from lib.quagga import QuaggaBGPContainer


class GoBGPTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        g1 = GoBGPContainer(name='g1', asn=65001, router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        q1 = QuaggaBGPContainer(name='q1', asn=65002, router_id='192.168.0.2')
        g2 = GoBGPContainer(name='g2', asn=65001, router_id='192.168.0.3',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        ctns = [g1, g2, q1]

        initial_wait_time = max(ctn.run() for ctn in ctns)

        time.sleep(initial_wait_time)

        g1.add_peer(q1)
        q1.add_peer(g1)

        q1.add_peer(g2)
        g2.add_peer(q1)

        g1.add_route('10.0.0.0/24')

        cls.g1 = g1
        cls.g2 = g2
        cls.q1 = q1
        cls.ctns = {n.name: n for n in ctns}

    # test each neighbor state is turned establish
    def test_01_neighbor_established(self):
        self.g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.q1)
        self.q1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g2)

    def test_02_check_reject_as_loop(self):
        def f():
            r = self.g2.get_neighbor(self.q1)
            self.assertTrue('afi_safis' in r)
            received = 0
            for afisafi in r['afi_safis']:
                self.assertTrue('state' in afisafi)
                s = afisafi.get('state')
                self.assertTrue('received' in s)
                received += s.get('received')
                # hacky. 'accepted' is zero so the key was deleted due to
                # omitempty tag in bgp_configs.go.
                self.assertFalse(s.get('accepted'), None)
            self.assertEqual(received, 1)

        assert_several_times(f)

    def test_03_update_peer(self):
        self.g2.update_peer(self.q1, allow_as_in=10)

        self.q1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g2)

    def test_04_check_accept_as_loop(self):
        def f():
            r = self.g2.get_neighbor(self.q1)
            self.assertTrue('afi_safis' in r)
            received = 0
            accepted = 0
            for afisafi in r['afi_safis']:
                self.assertTrue('state' in afisafi)
                s = afisafi.get('state')
                received += s.get('received')
                accepted += s.get('accepted')
            self.assertEqual(received, 1)
            self.assertEqual(accepted, 1)

        assert_several_times(f)

    def test_05_check_remove_private_as_peer_all(self):
        g3 = GoBGPContainer(name='g3', asn=100, router_id='192.168.0.4',
                            ctn_image_name=parser_option.gobgp_image,
                            log_level=parser_option.gobgp_log_level)
        g4 = GoBGPContainer(name='g4', asn=200, router_id='192.168.0.5',
                            ctn_image_name=parser_option.gobgp_image,
                            log_level=parser_option.gobgp_log_level)
        time.sleep(max(ctn.run() for ctn in [g3, g4]))

        self.ctns['g3'] = g3
        self.ctns['g4'] = g4

        self.g2.add_peer(g3)
        g3.add_peer(self.g2)

        g3.add_peer(g4, remove_private_as='all')
        g4.add_peer(g3)

        self.g2.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=g3)
        g3.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=g4)

        def f():
            rib = g4.get_global_rib()
            self.assertEqual(len(rib), 1)
            self.assertEqual(len(rib[0]['paths']), 1)
            self.assertEqual(rib[0]['paths'][0]['aspath'], [100])

        assert_several_times(f)

    def test_06_check_remove_private_as_peer_replace(self):
        g3 = self.ctns['g3']
        g4 = self.ctns['g4']
        g3.update_peer(g4, remove_private_as='replace')

        g3.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=g4)

        def f():
            rib = g4.get_global_rib()
            self.assertEqual(rib[0]['paths'][0]['aspath'], [100, 100, 100, 100])

        assert_several_times(f)

    def test_07_check_replace_peer_as(self):
        g5 = GoBGPContainer(name='g5', asn=100, router_id='192.168.0.6',
                            ctn_image_name=parser_option.gobgp_image,
                            log_level=parser_option.gobgp_log_level)
        time.sleep(g5.run())

        g4 = self.ctns['g4']
        g4.add_peer(g5, replace_peer_as=True)
        g5.add_peer(g4)

        g4.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=g5)

        def f():
            rib = g5.get_global_rib()
            self.assertEqual(rib[0]['paths'][0]['aspath'], [200, 200, 200, 200, 200])

        assert_several_times(f)


if __name__ == '__main__':
    output = local("which docker 2>&1 > /dev/null ; echo $?", capture=True)
    if int(output) is not 0:
        print("docker not found")
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
