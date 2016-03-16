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
from lib.exabgp import *
import sys
import os
import time
import nose
from noseplugin import OptionParser, parser_option
from itertools import chain


def community_exists(path, com):
    a, b = com.split(':')
    com = (int(a) << 16) + int(b)
    for a in path['attrs']:
        if a['type'] == BGP_ATTR_TYPE_COMMUNITIES and com in a['communities']:
            return True
    return False


class GoBGPTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        g1 = GoBGPContainer(name='g1', asn=65000, router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        q1 = ExaBGPContainer(name='q1', asn=65001, router_id='192.168.0.2')
        q2 = ExaBGPContainer(name='q2', asn=65002, router_id='192.168.0.3')
        q3 = ExaBGPContainer(name='q3', asn=65003, router_id='192.168.0.4')

        qs = [q1, q2, q3]
        ctns = [g1, q1, q2, q3]

        # advertise a route from q1, q2, q3
        for idx, q in enumerate(qs):
            route = '10.0.{0}.0/24'.format(idx+1)
            q.add_route(route)

        initial_wait_time = max(ctn.run() for ctn in ctns)

        time.sleep(initial_wait_time)

        g1.local('gobgp global policy export add default reject')

        for q in qs:
            g1.add_peer(q)
            q.add_peer(g1)

        cls.gobgp = g1
        cls.quaggas = {'q1': q1, 'q2': q2, 'q3': q3}

    # test each neighbor state is turned establish
    def test_01_neighbor_established(self):
        for q in self.quaggas.itervalues():
            self.gobgp.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=q)

    def test_02_check_adj_rib_out(self):
        for q in self.quaggas.itervalues():
            self.assertTrue(len(self.gobgp.get_adj_rib_out(q)) == 0)

    def test_03_add_peer(self):
        q = ExaBGPContainer(name='q4', asn=65004, router_id='192.168.0.5')
        q.add_route('10.10.0.0/24')
        time.sleep(q.run())
        self.gobgp.add_peer(q)
        q.add_peer(self.gobgp)
        self.gobgp.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=q)
        self.quaggas['q4'] = q
        for q in self.quaggas.itervalues():
            self.assertTrue(len(self.gobgp.get_adj_rib_out(q)) == 0)

    def test_04_disable_peer(self):
        q3 = self.quaggas['q3']
        self.gobgp.disable_peer(q3)
        self.gobgp.wait_for(expected_state=BGP_FSM_IDLE, peer=q3)

        for q in self.quaggas.itervalues():
            if q.name == 'q3':
                continue
            self.assertTrue(len(self.gobgp.get_adj_rib_out(q)) == 0)

    def test_05_enable_peer(self):
        q3 = self.quaggas['q3']
        self.gobgp.enable_peer(q3)
        self.gobgp.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=q3)

        for q in self.quaggas.itervalues():
            self.assertTrue(len(self.gobgp.get_adj_rib_out(q)) == 0)

    def test_06_disable_peer2(self):
        q3 = self.quaggas['q3']
        # advertise a route which was also advertised by q1
        # this route will be best for g1 because q3's router-id is larger
        # than q1
        q3.add_route('10.0.1.0/24')
        time.sleep(3)
        # then disable q3
        self.gobgp.disable_peer(q3)
        self.gobgp.wait_for(expected_state=BGP_FSM_IDLE, peer=q3)

        for q in self.quaggas.itervalues():
            if q.name == 'q3':
                continue
            self.assertTrue(len(self.gobgp.get_adj_rib_out(q)) == 0)

    def test_07_adv_to_one_peer(self):
        self.gobgp.local('gobgp policy neighbor add ns0 {0}'.format(self.gobgp.peers[self.quaggas['q1']]['neigh_addr'].split('/')[0]))
        self.gobgp.local('gobgp policy statement add st0')
        self.gobgp.local('gobgp policy statement st0 add condition neighbor ns0')
        self.gobgp.local('gobgp policy statement st0 add action accept')
        self.gobgp.local('gobgp policy add p0 st0')
        self.gobgp.local('gobgp global policy export add p0 default reject')
        for q in self.quaggas.itervalues():
            self.gobgp.softreset(q, type='out')

    def test_08_check_adj_rib_out(self):
        for q in self.quaggas.itervalues():
            if q.name == 'q3':
                continue
            paths = self.gobgp.get_adj_rib_out(q)
            if q == self.quaggas['q1']:
                self.assertTrue(len(paths) == 2)
            else:
                self.assertTrue(len(paths) == 0)

    def test_09_change_global_policy(self):
        self.gobgp.local('gobgp policy statement st0 add action community add 65100:10')
        self.gobgp.local('gobgp global policy export set p0 default accept')
        for q in self.quaggas.itervalues():
            self.gobgp.softreset(q, type='out')

    def test_10_check_adj_rib_out(self):
        for q in self.quaggas.itervalues():
            if q.name == 'q3':
                continue
            paths = self.gobgp.get_adj_rib_out(q)
            if q != self.quaggas['q3']:
                self.assertTrue(len(paths) == 2)
            for path in paths:
                if q == self.quaggas['q1']:
                    self.assertTrue(community_exists(path, '65100:10'))
                else:
                    self.assertFalse(community_exists(path, '65100:10'))


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
