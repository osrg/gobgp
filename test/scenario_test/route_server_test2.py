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
from lib.exabgp import ExaBGPContainer


class GoBGPTestBase(unittest.TestCase):

    wait_per_retry = 5
    retry_limit = 15

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        g1 = GoBGPContainer(name='g1', asn=65000, router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        g2 = GoBGPContainer(name='g2', asn=65001, router_id='192.168.0.2',
                            ctn_image_name=gobgp_ctn_image_name)
        e1 = ExaBGPContainer(name='e1', asn=65002, router_id='192.168.0.3')

        ctns = [g1, g2, e1]
        cls.clients = {cli.name: cli for cli in (g2, e1)}

        initial_wait_time = max(ctn.run() for ctn in ctns)
        time.sleep(initial_wait_time)

        for cli in list(cls.clients.values()):
            # Omit "passwd" to avoid a issue on ExaBGP version 4.0.5:
            # https://github.com/Exa-Networks/exabgp/issues/766
            g1.add_peer(cli, is_rs_client=True, passive=True, prefix_limit=10)
            cli.add_peer(g1)

        # advertise a route from route-server-clients
        g2.add_route('10.0.0.0/24')
        e1.add_route('10.0.1.0/24')

        cls.gobgp = g1

    # test each neighbor state is turned establish
    def test_01_neighbor_established(self):
        for cli in list(self.clients.values()):
            self.gobgp.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=cli)

    def test_02_add_neighbor(self):
        e2 = ExaBGPContainer(name='e2', asn=65001, router_id='192.168.0.4')
        time.sleep(e2.run())
        self.gobgp.add_peer(e2, is_rs_client=True)
        e2.add_peer(self.gobgp)

        self.gobgp.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=e2)
        self.clients[e2.name] = e2

    def test_03_check_neighbor_rib(self):
        rib = self.gobgp.get_local_rib(self.clients['e2'])
        self.assertEqual(len(rib), 1)
        self.assertEqual(len(rib[0]['paths']), 1)
        path = rib[0]['paths'][0]
        self.assertTrue(65001 not in path['aspath'])

    def test_04_withdraw_path(self):
        self.clients['g2'].local('gobgp global rib del 10.0.0.0/24')
        time.sleep(1)
        afisafis = self.gobgp.get_neighbor(self.clients['g2'])['afi_safis']
        advertised = 0
        for afisafi in afisafis:
            s = afisafi.get('state')
            advertised += s.get('advertised')
            self.assertEqual(s.get('accepted'), None)  # means info['accepted'] == 0
            self.assertEqual(s.get('received'), None)  # means info['received'] == 0

        self.assertEqual(advertised, 1)


if __name__ == '__main__':
    output = local("which docker 2>&1 > /dev/null ; echo $?", capture=True)
    if int(output) != 0:
        print("docker not found")
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
