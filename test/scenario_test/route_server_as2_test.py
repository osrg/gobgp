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


class GoBGPTestBase(unittest.TestCase):

    wait_per_retry = 5
    retry_limit = 10

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        g1 = GoBGPContainer(name='g1', asn=65000, router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)

        rs_clients = [ExaBGPContainer(name='q{0}'.format(i+1), asn=65001+i,
                      router_id='192.168.0.{0}'.format(i+2))
                      for i in range(4)]
        ctns = [g1] + rs_clients
        q1 = rs_clients[0]
        q2 = rs_clients[1]
        q3 = rs_clients[2]
        q4 = rs_clients[3]

        # advertise a route from route-server-clients
        for idx, rs_client in enumerate(rs_clients):
            route = '10.0.{0}.0/24'.format(idx+1)
            rs_client.add_route(route)
            if idx < 2:
                route = '10.0.10.0/24'
            rs_client.add_route(route)

        initial_wait_time = max(ctn.run() for ctn in ctns)

        time.sleep(initial_wait_time)

        for i, rs_client in enumerate(rs_clients):
            g1.add_peer(rs_client, is_rs_client=True)
            as2 = False
            if i > 1:
                as2 = True
            rs_client.add_peer(g1, as2=as2)

        cls.gobgp = g1
        cls.quaggas = { x.name: x for x in rs_clients }


    # test each neighbor state is turned establish
    def test_01_neighbor_established(self):
        for q in self.quaggas.itervalues():
            self.gobgp.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=q)

    def test_02_check_gobgp_local_rib(self):
        for rs_client in self.quaggas.itervalues():
            done = False
            for _ in range(self.retry_limit):
                if done:
                    break

                state = self.gobgp.get_neighbor_state(rs_client)
                self.assertEqual(state, BGP_FSM_ESTABLISHED)
                local_rib = self.gobgp.get_local_rib(rs_client)
                local_rib = [p['prefix'] for p in local_rib]
                if len(local_rib) < len(self.quaggas)-1:
                    time.sleep(self.wait_per_retry)
                    continue

                self.assertTrue(len(local_rib) == 4)
                done = True

            if done:
                continue
            # should not reach here
            self.assertTrue(False)

    def test_03_stop_q2_and_check_neighbor_status(self):
        q2 = self.quaggas['q2']
        q2.remove()
        self.gobgp.wait_for(expected_state=BGP_FSM_IDLE, peer=q2)


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
