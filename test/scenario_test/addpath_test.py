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
from lib.base import BGP_FSM_ESTABLISHED
from lib.gobgp import *
from lib.exabgp import *
import sys
import os
import time
import nose
from lib.noseplugin import OptionParser, parser_option
from itertools import combinations


class GoBGPTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        g1 = GoBGPContainer(name='g1', asn=65000, router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        e1 = ExaBGPContainer(name='e1', asn=65000, router_id='192.168.0.2')

        ctns = [g1, e1]

        e1.add_route(route='192.168.100.0/24', identifier=10, aspath=[100, 200, 300])
        e1.add_route(route='192.168.100.0/24', identifier=20, aspath=[100, 200])
        e1.add_route(route='192.168.100.0/24', identifier=30, aspath=[100])

        initial_wait_time = max(ctn.run() for ctn in ctns)

        time.sleep(initial_wait_time)

        g1.add_peer(e1, addpath=True)
        e1.add_peer(g1, addpath=True)
        cls.g1 = g1
        cls.e1 = e1

    # test each neighbor state is turned establish
    def test_01_neighbor_established(self):
        self.g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.e1)

    # test three routes are installed to the rib due to add-path feature
    def test_02_check_g1_global_rib(self):
        rib = self.g1.get_global_rib()
        self.assertTrue(len(rib) == 1)
        self.assertTrue(len(rib[0]['paths']) == 3)

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
