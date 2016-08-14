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
from itertools import chain
import Queue


class GoBGPTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        g1 = GoBGPContainer(name='g1', asn=65000, router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        q1 = QuaggaBGPContainer(name='q1', asn=65001, router_id='192.168.0.2')
        q2 = QuaggaBGPContainer(name='q2', asn=65002, router_id='192.168.0.3')
        q3 = QuaggaBGPContainer(name='q3', asn=65003, router_id='192.168.0.4')

        qs = [q1, q2, q3]
        ctns = [g1, q1, q2, q3]

        # advertise a route from q1, q2, q3
        for idx, q in enumerate(qs):
            route = '10.0.{0}.0/24'.format(idx+1)
            q.add_route(route)

        initial_wait_time = max(ctn.run() for ctn in ctns)

        time.sleep(initial_wait_time)

        for q in qs:
            g1.add_peer(q, reload_config=False, passwd='passwd')
            q.add_peer(g1, passwd='passwd', passive=True)

        g1.create_config()
        g1.reload_config()

        cls.gobgp = g1
        cls.quaggas = {'q1': q1, 'q2': q2, 'q3': q3}

    def test_01_monitor_initial_adv(self):
        qu = Queue.Queue()
        self.gobgp.monitor_global_rib(qu)
        for q in self.quaggas.itervalues():
            self.gobgp.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=q)
            print '{0} get established'.format(q.name)

        cnt = 0

        while True:
            info = qu.get(timeout=120)
            cnt += 1
            print 'monitor got {0}, cnt = {1}'.format(info, cnt)
            if cnt == len(self.quaggas):
                break

    def test_02_stop_q1(self):
        qu = Queue.Queue()
        self.gobgp.monitor_global_rib(qu)
        self.quaggas['q1'].stop()

        while True:
            info = qu.get(timeout=120)
            print 'monitor got {0}'.format(info)
            self.assertTrue(info['isWithdraw'])
            break


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
