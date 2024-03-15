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
import json
import time
import unittest

import collections
collections.Callable = collections.abc.Callable

import nose

from lib import base
from lib.base import (
    BGP_FSM_ESTABLISHED,
    assert_several_times,
    local,
)
from lib.gobgp import GoBGPContainer
from lib.exabgp import ExaBGPContainer
from lib.noseplugin import OptionParser, parser_option


class GoBGPTestBase(unittest.TestCase):
    SEND_MAX = 5
    INSTALLED_PATHS = SEND_MAX + 1

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
        g3 = GoBGPContainer(name='g3', asn=65000, router_id='192.168.0.3',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        e1 = ExaBGPContainer(name='e1', asn=65000, router_id='192.168.0.4')

        ctns = [g1, g2, g3, e1]
        initial_wait_time = max(ctn.run() for ctn in ctns)

        time.sleep(initial_wait_time)

        g1.add_peer(e1, addpath=16)
        e1.add_peer(g1, addpath=16)

        g1.add_peer(g2, is_rr_client=True)
        g2.add_peer(g1)

        g1.add_peer(g3, addpath=cls.SEND_MAX, is_rr_client=True)
        g3.add_peer(g1, addpath=cls.SEND_MAX)

        cls.g1 = g1
        cls.g2 = g2
        cls.g3 = g3
        cls.e1 = e1

    # test each neighbor state is turned establish
    def test_00_neighbor_established(self):
        self.g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g2)
        self.g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g3)
        self.g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.e1)

    # prepare routes with path_id (no error check)
    def test_01_prepare_add_paths_routes(self):
        aspath = []
        for i in range(self.INSTALLED_PATHS):
            aspath.append((i + 1) * 100)
            self.e1.add_route(
                route="192.168.100.0/24",
                identifier=(i + 1) * 10,
                aspath=aspath,
            )

    # test three routes are installed to the rib due to add-path feature
    def test_02_check_g1_global_rib(self):
        def f():
            rib = self.g1.get_global_rib()
            self.assertEqual(len(rib), 1)
            self.assertEqual(len(rib[0]["paths"]), self.INSTALLED_PATHS)

        assert_several_times(f)

    # test only the best path is advertised to g2
    def test_03_check_g2_global_rib(self):
        def f():
            rib = self.g2.get_global_rib()
            self.assertEqual(len(rib), 1)
            self.assertEqual(len(rib[0]['paths']), 1)
            self.assertEqual(len(rib[0]["paths"][0]["aspath"]), 1)

        assert_several_times(f)

    # test three routes are advertised to g3
    def test_04_check_g3_global_rib(self):
        def f():
            rib = self.g3.get_global_rib()
            self.assertEqual(len(rib), 1)
            self.assertEqual(len(rib[0]["paths"]), self.SEND_MAX)

        assert_several_times(f)

    def test_05_check_g1_adj_out(self):
        adj_out = self.g1.get_adj_rib_out(self.g2, add_path_enabled=True)
        self.assertEqual(len(adj_out), 1)
        self.assertEqual(len(adj_out[0]["paths"]), 1)

        adj_out = self.g1.get_adj_rib_out(self.g3, add_path_enabled=True)
        self.assertEqual(len(adj_out), 1)
        self.assertEqual(len(adj_out[0]["paths"]), self.INSTALLED_PATHS)
        # expect the last path to be filtered
        self.assertTrue(adj_out[0]["paths"][-1].get("send-max-filtered", False))

    # withdraw a route with path_id (no error check)
    def test_06_withdraw_route_with_path_id(self):
        self.e1.del_route(route="192.168.100.0/24", identifier=10)

    # test the withdrawn route is removed from the rib
    def test_07_check_g1_global_rib(self):
        def f():
            rib = self.g1.get_global_rib()
            self.assertEqual(len(rib), 1)
            self.assertEqual(len(rib[0]["paths"]), self.INSTALLED_PATHS - 1)
            # we deleted the highest priority path
            for path in rib[0]['paths']:
                self.assertTrue(2 <= len(path["aspath"]) <= self.INSTALLED_PATHS)

        assert_several_times(f)

    # test the best path is replaced due to the removal from g1 rib
    def test_08_check_g2_global_rib(self):
        def f():
            rib = self.g2.get_global_rib()
            self.assertEqual(len(rib), 1)
            self.assertEqual(len(rib[0]['paths']), 1)
            self.assertEqual(len(rib[0]["paths"][0]["aspath"]), 2)

        assert_several_times(f)

    # test the withdrawn route is removed from the rib of g3
    # and the filtered route is advertised to g3
    def test_09_check_g3_global_rib(self):
        def f():
            rib = self.g3.get_global_rib()
            self.assertEqual(len(rib), 1)
            self.assertEqual(len(rib[0]["paths"]), self.SEND_MAX)
            for path in rib[0]['paths']:
                self.assertTrue(2 <= len(path["aspath"]) <= self.INSTALLED_PATHS)

        assert_several_times(f)

    # install a route with path_id via GoBGP CLI (no error check)
    def test_10_install_add_paths_route_via_cli(self):
        # identifier is duplicated with the identifier of the route from e1
        self.g1.add_route(route='192.168.100.0/24', identifier=10, local_pref=500)

    # test the route from CLI is installed to the rib
    def test_11_check_g1_global_rib(self):
        def f():
            rib = self.g1.get_global_rib()
            self.assertEqual(len(rib), 1)
            self.assertEqual(len(rib[0]["paths"]), self.INSTALLED_PATHS)
            for path in rib[0]['paths']:
                if not path["aspath"]:
                    self.assertEqual(path['local-pref'], 500)
                else:
                    self.assertTrue(2 <= len(path["aspath"]) <= self.INSTALLED_PATHS)

        assert_several_times(f)

    def test_12_check_g1_adj_out(self):
        adj_out = self.g1.get_adj_rib_out(self.g2, add_path_enabled=True)
        self.assertEqual(len(adj_out), 1)
        self.assertEqual(len(adj_out[0]["paths"]), 1)

        adj_out = self.g1.get_adj_rib_out(self.g3, add_path_enabled=True)
        self.assertEqual(len(adj_out), 1)
        self.assertEqual(len(adj_out[0]["paths"]), self.INSTALLED_PATHS)
        print(json.dumps(adj_out, indent=2))
        # the new best path shouldn't be advertised as it is added after
        # the limit is reached
        self.assertEqual(adj_out[0]["paths"][0]["local-pref"], 500)
        self.assertTrue(adj_out[0]["paths"][0].get("send-max-filtered", False))

    # test the best path is replaced due to the CLI route from g1 rib
    def test_13_check_g2_global_rib(self):
        def f():
            rib = self.g2.get_global_rib()
            self.assertEqual(len(rib), 1)
            self.assertEqual(len(rib[0]['paths']), 1)
            self.assertEqual(len(rib[0]["paths"][0]["aspath"]), 0)
            self.assertEqual(rib[0]["paths"][0]["local-pref"], 500)

        assert_several_times(f)

    # test the route from CLI is advertised from g1
    def test_14_check_g3_global_rib(self):
        def f():
            rib = self.g3.get_global_rib()
            self.assertEqual(len(rib), 1)
            print(json.dumps(rib, indent=2))
            self.assertEqual(len(rib[0]["paths"]), self.SEND_MAX)
            for path in rib[0]['paths']:
                self.assertTrue(2 <= len(path["aspath"]) <= self.INSTALLED_PATHS)

        assert_several_times(f)

    # remove non-existing route with path_id via GoBGP CLI (no error check)
    def test_15_remove_non_existing_add_paths_route_via_cli(self):
        # specify locally non-existing identifier which has the same value
        # with the identifier of the route from e1
        self.g1.del_route(route='192.168.100.0/24', identifier=20)

    # test none of route is removed by non-existing path_id via CLI
    def test_16_check_g1_global_rib(self):
        def f():
            rib = self.g1.get_global_rib()
            self.assertEqual(len(rib), 1)
            self.assertEqual(len(rib[0]["paths"]), self.INSTALLED_PATHS)
            for path in rib[0]['paths']:
                if not path["aspath"]:
                    self.assertEqual(path['local-pref'], 500)
                else:
                    self.assertTrue(2 <= len(path["aspath"]) <= self.INSTALLED_PATHS)

        assert_several_times(f)

    # remove route with path_id via GoBGP CLI (no error check)
    def test_17_remove_add_paths_route_via_cli(self):
        self.g1.del_route(route='192.168.100.0/24', identifier=10)

    def test_18_check_g1_adj_out(self):
        adj_out = self.g1.get_adj_rib_out(self.g2, add_path_enabled=True)
        self.assertEqual(len(adj_out), 1)
        self.assertEqual(len(adj_out[0]["paths"]), 1)

        adj_out = self.g1.get_adj_rib_out(self.g3, add_path_enabled=True)
        self.assertEqual(len(adj_out), 1)
        self.assertEqual(len(adj_out[0]["paths"]), self.INSTALLED_PATHS - 1)

    # test the route is removed from the rib via CLI
    def test_19_check_g1_global_rib(self):
        def f():
            rib = self.g1.get_global_rib()
            self.assertEqual(len(rib), 1)
            self.assertEqual(len(rib[0]["paths"]), self.INSTALLED_PATHS - 1)
            for path in rib[0]['paths']:
                if not path["aspath"]:
                    self.assertTrue(2 <= len(path["aspath"]) <= self.INSTALLED_PATHS)

        assert_several_times(f)

    # test the best path is replaced the removal from g1 rib
    def test_20_check_g2_global_rib(self):
        def f():
            rib = self.g2.get_global_rib()
            self.assertEqual(len(rib), 1)
            self.assertEqual(len(rib[0]['paths']), 1)
            self.assertEqual(len(rib[0]["paths"][0]["aspath"]), 2)

        assert_several_times(f)

    # test the removed route from CLI is withdrawn by g1
    def test_21_check_g3_global_rib(self):
        def f():
            rib = self.g3.get_global_rib()
            self.assertEqual(len(rib), 1)
            self.assertEqual(len(rib[0]["paths"]), self.SEND_MAX)
            for path in rib[0]['paths']:
                if not path["aspath"]:
                    self.assertTrue(2 <= len(path["aspath"]) <= self.INSTALLED_PATHS)

        assert_several_times(f)


if __name__ == '__main__':
    output = local("which docker 2>&1 > /dev/null ; echo $?", capture=True)
    if int(output) != 0:
        print("docker not found")
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
