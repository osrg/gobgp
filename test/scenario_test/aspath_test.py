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

from __future__ import absolute_import

import sys
import time
import unittest

from fabric.api import local
import nose

from lib.noseplugin import OptionParser, parser_option

from lib import base
from lib.base import BGP_FSM_ESTABLISHED
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
        time.sleep(1)
        self.assertTrue(len(self.g2.get_global_rib()) == 0)

    def test_03_update_peer(self):
        self.g2.update_peer(self.q1, allow_as_in=10)

        self.q1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g2)

    def test_04_check_accept_as_loop(self):
        time.sleep(1)
        self.assertTrue(len(self.g2.get_global_rib()) == 1)


if __name__ == '__main__':
    output = local("which docker 2>&1 > /dev/null ; echo $?", capture=True)
    if int(output) is not 0:
        print "docker not found"
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
