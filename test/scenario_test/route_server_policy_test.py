# Copyright (C) 2014,2015 Nippon Telegraph and Telephone Corporation.
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
import requests
import json
import toml
import os
import time
import sys
import nose
import quagga_access as qaccess
from peer_info import Peer
from peer_info import Destination
from peer_info import Path
from ciscoconfparse import CiscoConfParse
import docker_control as fab
from noseplugin import OptionParser
from noseplugin import parser_option
import scenario_test_util as util


class GoBGPTest(unittest.TestCase):

    gobgp_ip = "10.0.255.1"
    gobgp_port = "8080"
    rest_url_neighbor = "http://" + gobgp_ip + ":" + gobgp_port + "/v1/bgp/neighbor/"
    base_dir = "/tmp/gobgp/"
    gobgp_config_file = "/tmp/gobgp/gobgpd.conf"
    gobgp_config = None
    quagga_num = 3
    initial_wait_time = 10
    wait_per_retry = 5

    def __init__(self, *args, **kwargs):
        super(GoBGPTest, self).__init__(*args, **kwargs)

    def setUp(self):
        self.quagga_configs = []

    def initialize(self, policy_pattern=None):
        use_local = parser_option.use_local
        go_path = parser_option.go_path
        log_debug = parser_option.gobgp_log_debug
        fab.init_policy_test_env_executor(self.quagga_num, use_local, go_path, log_debug, policy=policy_pattern)
        print "please wait " + str(self.initial_wait_time) + " second"
        time.sleep(self.initial_wait_time)

        self.assertTrue(self.check_load_config())

    def check_established(self, addresses):
        for address in addresses:
            result = self.retry_until(address, target_state="BGP_FSM_ESTABLISHED",retry=10)
            self.assertEqual(result, True)


    """
      import-policy test
                                ---------------------------------------
      peer2 ->(192.168.2.0/24)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                |                                     |
                                | ->x peer3-rib                       |
                                ---------------------------------------
    """
    def test_01_import_policy_initial(self):

        # initialize test environment
        # policy_pattern:p1 attaches a policy to reject route 192.168.0.0/16 (16...24)
        # coming from peer2(10.0.0.2) to peer3(10.0.0.3)'s import-policy.
        self.initialize(policy_pattern="p1")
        self.check_established(util.get_neighbor_address(self.gobgp_config))

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        peer3 = "10.0.0.3"
        base_url = self.rest_url_neighbor
        w = self.wait_per_retry

        path = util.get_paths_in_localrib(base_url, peer1, "192.168.2.0", retry=3, interval=w)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = util.get_routing_table(peer1,"192.168.2.0", retry=3, interval=w)
        print qpath
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = util.get_adj_rib_in(base_url, peer2, "192.168.2.0/24", retry=3, interval=w)
        # print path
        self.assertIsNotNone(path)

        path = util.get_paths_in_localrib(base_url, peer3, "192.168.2.0",retry=0, interval=w)
        # print path
        self.assertIsNone(path)

        # check show ip bgp on peer1(quagga3)
        qpath = util.get_routing_table(peer3,"192.168.2.0", retry=3, interval=w)
        # print qpath
        self.assertIsNone(qpath)


    """
      export-policy test
                                ---------------------------------------
      peer2 ->(192.168.2.0/24)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                |                                     |
                                | ->  peer3-rib ->x peer3-adj-rib-out |
                                ---------------------------------------
    """
    def test_02_export_policy_initial(self):

        # initialize test environment
        # policy_pattern:p1 attaches a policy to reject route 192.168.0.0/16 (16...24)
        # coming from peer2(10.0.0.2) to peer3(10.0.0.3)'s export-policy.
        self.initialize(policy_pattern="p2")
        self.check_established(util.get_neighbor_address(self.gobgp_config))

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        peer3 = "10.0.0.3"
        base_url = self.rest_url_neighbor
        w = self.wait_per_retry

        paths = util.get_paths_in_localrib(base_url, peer1, "192.168.2.0", retry=3, interval=w)
        # print paths
        self.assertIsNotNone(paths)

        # check show ip bgp on peer1(quagga1)
        qpath = util.get_routing_table(peer1, "192.168.2.0", retry=3, interval=w)
        # print qpath
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = util.get_adj_rib_in(base_url, peer2, "192.168.2.0/24", retry=1, interval=w)
        # print path
        self.assertIsNotNone(path)

        path = util.get_paths_in_localrib(base_url, peer3, "192.168.2.0")
        # print path
        self.assertIsNotNone(path)

        path = util.get_adj_rib_out(base_url, peer3, "192.168.2.0", retry=1, interval=w)
        # print path
        self.assertIsNone(path)

        # check show ip bgp on peer1(quagga3)
        qpath = util.get_routing_table(peer3,"192.168.2.0", retry=3, interval=w)
        # print qpath
        self.assertIsNone(qpath)


    """
      import-policy test
      r1:192.168.2.0
      r2:192.168.20.0
      r3:192.168.200.0
                           -------------------------------------------------
                           |peer1                                          |
      peer2 ->(r1,r2,r3)-> | ->(r1,r2,r3)-> rib ->(r1,r2,r3)-> adj-rib-out | ->(r1,r2,r3)-> peer1
                           |                                               |
                           |peer3                                          |
                           | ->(r1)->       rib ->(r1)->       adj-rib-out | ->(r1)-> peer3
                           -------------------------------------------------
                   |
           update gobgp.conf
                   |
                   V
                           -------------------------------------------------
                           |peer1                                          |
      peer2 ->(r1,r2,r3)-> | ->(r1,r2,r3)-> rib ->(r1,r2,r3)-> adj-rib-out | ->(r1,r2,r3)-> peer1
                           |                                               |
                           |peer3                                          |
                           | ->(r1,r3)->    rib ->(r1,r3)->    adj-rib-out | ->(r1,r3)-> peer3
                           -------------------------------------------------
    """
    def test_03_import_policy_update(self):
        # initialize test environment
        # policy_pattern:p3 attaches a policy to reject route
        # 192.168.2.0/24, 192.168.20.0/24, 192.168.200.0/24
        # coming from peer2(10.0.0.2) to peer3(10.0.0.3)'s import-policy.
        self.initialize(policy_pattern="p3")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        peer3 = "10.0.0.3"
        base_url = self.rest_url_neighbor
        w = self.wait_per_retry

        # add other network
        tn = qaccess.login(peer2)
        print "add network 192.168.20.0/24"
        qaccess.add_network(tn, 65002, "192.168.20.0/24")
        print "add network 192.168.200.0/24"
        qaccess.add_network(tn, 65002, "192.168.200.0/24")
        qaccess.logout(tn)

        self.check_established(util.get_neighbor_address(self.gobgp_config))

        time.sleep(self.initial_wait_time)

        def path_exists_in_localrib(peer, prefix,r=10):
            paths = util.get_paths_in_localrib(base_url, peer, prefix, retry=r, interval=w)
            return paths is not None

        def path_exists_in_routing_table(peer, prefix,r=10):
            qpath = util.get_routing_table(peer, prefix, retry=r, interval=w)
            return qpath is not None

        def path_exists_in_adj_rib_in(peer, prefix,r=10):
            path = util.get_adj_rib_in(base_url, peer, prefix, retry=r, interval=w)
            return path is not None


        self.assertTrue(path_exists_in_localrib(peer1,"192.168.2.0"))
        self.assertTrue(path_exists_in_localrib(peer1,"192.168.20.0"))
        self.assertTrue(path_exists_in_localrib(peer1,"192.168.200.0"))

        self.assertTrue(path_exists_in_localrib(peer3,"192.168.2.0"))
        self.assertFalse(path_exists_in_localrib(peer3,"192.168.20.0",r=3))
        self.assertFalse(path_exists_in_localrib(peer3,"192.168.200.0",r=0))

        # check show ip bgp on peer1(quagga1)
        self.assertTrue(path_exists_in_routing_table(peer1, "192.168.2.0"))
        self.assertTrue(path_exists_in_routing_table(peer1, "192.168.20.0"))
        self.assertTrue(path_exists_in_routing_table(peer1, "192.168.200.0"))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, "192.168.2.0"))
        self.assertFalse(path_exists_in_routing_table(peer3, "192.168.20.0",r=3))
        self.assertFalse(path_exists_in_routing_table(peer3, "192.168.200.0",r=0))

        # check adj-rib-out in peer2
        self.assertTrue(path_exists_in_adj_rib_in(peer2, "192.168.2.0/24"))
        self.assertTrue(path_exists_in_adj_rib_in(peer2, "192.168.20.0/24"))
        self.assertTrue(path_exists_in_adj_rib_in(peer2, "192.168.200.0/24"))

        # update policy
        print "update_policy_config"
        fab.update_policy_config(parser_option.go_path, policy_pattern="p3")
        time.sleep(self.initial_wait_time)

        # soft reset
        print "soft_reset"
        self.soft_reset(peer2, "ipv4")

        # check local-rib
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.2.0"))
        self.assertFalse(path_exists_in_localrib(peer3,"192.168.20.0",r=3))
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.200.0"))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, "192.168.2.0"))
        self.assertFalse(path_exists_in_routing_table(peer3, "192.168.20.0",r=0))
        self.assertTrue(path_exists_in_routing_table(peer3, "192.168.200.0"))


    """
      export-policy test
      r1:192.168.2.0
      r2:192.168.20.0
      r3:192.168.200.0
                           -------------------------------------------------
                           |peer1                                          |
      peer2 ->(r1,r2,r3)-> | ->(r1,r2,r3)-> rib ->(r1,r2,r3)-> adj-rib-out | ->(r1,r2,r3)-> peer1
                           |                                               |
                           |peer3                                          |
                           | ->(r1,r2,r3)-> rib ->(r1)->       adj-rib-out | ->(r1)-> peer3
                           -------------------------------------------------
                   |
           update gobgp.conf
                   |
                   V
                           -------------------------------------------------
                           |peer1                                          |
      peer2 ->(r1,r2,r3)-> | ->(r1,r2,r3)-> rib ->(r1,r2,r3)-> adj-rib-out | ->(r1,r2,r3)-> peer1
                           |                                               |
                           |peer3                                          |
                           | ->(r1,r2,r3)-> rib ->(r1,r3)->    adj-rib-out | ->(r1,r3)-> peer3
                           -------------------------------------------------
    """
    @nose.tools.nottest
    def test_04_export_policy_update(self):
        # initialize test environment
        # policy_pattern:p4 attaches a policy to reject route
        # 192.168.2.0/24, 192.168.20.0/24, 192.168.200.0/24
        # coming from peer2(10.0.0.2) to peer3(10.0.0.3)'s export-policy.
        self.initialize(policy_pattern="p4")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        peer3 = "10.0.0.3"
        base_url = self.rest_url_neighbor
        w = self.wait_per_retry

        # add other network
        tn = qaccess.login(peer2)
        print "add network 192.168.20.0/24"
        qaccess.add_network(tn, 65002, "192.168.20.0/24")
        print "add network 192.168.200.0/24"
        qaccess.add_network(tn, 65002, "192.168.200.0/24")
        qaccess.logout(tn)

        self.check_established(self.get_neighbor_address(self.gobgp_config))

        time.sleep(self.initial_wait_time)


        def path_exists_in_localrib(peer, prefix,r=10):
            paths = util.get_paths_in_localrib(base_url, peer, prefix, retry=r, interval=w)
            return paths is not None

        def path_exists_in_routing_table(peer, prefix,r=10):
            qpath = util.get_routing_table(peer, prefix, retry=r, interval=w)
            return qpath is not None

        def path_exists_in_adj_rib_in(peer, prefix,r=10):
            path = util.get_adj_rib_in(base_url, peer, prefix, retry=r, interval=w)
            return path is not None

        def path_exists_in_adj_rib_out(peer, prefix,r=10):
            path = util.get_adj_rib_out(base_url, peer, prefix, retry=r, interval=w)
            return path is not None


        self.assertTrue(path_exists_in_localrib(peer1,"192.168.2.0"))
        self.assertTrue(path_exists_in_localrib(peer1,"192.168.20.0"))
        self.assertTrue(path_exists_in_localrib(peer1,"192.168.200.0"))

        # check peer3 local-rib
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.2.0"))
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.20.0"))
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.200.0"))

        # check peer3 rib-out
        self.assertTrue(path_exists_in_adj_rib_out(peer3,"192.168.2.0/24"))
        self.assertFalse(path_exists_in_adj_rib_out(peer3,"192.168.20.0/24",r=3))
        self.assertFalse(path_exists_in_adj_rib_out(peer3,"192.168.200.0/24",r=3))

        # check show ip bgp on peer1(quagga1)
        self.assertTrue(path_exists_in_routing_table(peer1, "192.168.2.0"))
        self.assertTrue(path_exists_in_routing_table(peer1, "192.168.20.0"))
        self.assertTrue(path_exists_in_routing_table(peer1, "192.168.200.0"))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, "192.168.2.0"))
        self.assertFalse(path_exists_in_routing_table(peer3, "192.168.20.0",r=3))
        self.assertFalse(path_exists_in_routing_table(peer3, "192.168.200.0",r=0))

        # check adj-rib-out in peer2
        peer2 = "10.0.0.2"
        self.assertTrue(path_exists_in_adj_rib_in(peer2, "192.168.2.0/24"))
        self.assertTrue(path_exists_in_adj_rib_in(peer2, "192.168.20.0/24"))
        self.assertTrue(path_exists_in_adj_rib_in(peer2, "192.168.200.0/24"))

        # update policy
        print "update_policy_config"
        fab.update_policy_config(parser_option.go_path, policy_pattern="p4")
        time.sleep(self.initial_wait_time)

        # soft reset
        print "soft_reset"
        self.soft_reset(peer2, "ipv4")

        # check local-rib
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.2.0"))
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.20.0"))
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.200.0"))

        # check local-adj-out-rib
        self.assertTrue(path_exists_in_adj_rib_out(peer3, "192.168.2.0/24"))
        self.assertFalse(path_exists_in_adj_rib_out(peer3, "192.168.20.0/24",r=3))
        self.assertTrue(path_exists_in_adj_rib_out(peer3, "192.168.200.0/24"))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, "192.168.2.0"))
        self.assertFalse(path_exists_in_routing_table(peer3, "192.168.20.0",r=3))
        self.assertTrue(path_exists_in_routing_table(peer3, "192.168.200.0"))


    def retry_until(self, neighbor_address, target_state="BGP_FSM_ESTABLISHED", retry=3):
        retry_count = 0

        while True:

            current_state = util.get_neighbor_state(self.rest_url_neighbor, neighbor_address)
            if current_state == target_state:
                print "state changed to %s : %s" % (current_state, neighbor_address)
                return True
            else:
                retry_count += 1
                if retry_count > retry:
                    break
                else:
                    print "current state is %s" % current_state
                    print "please wait more (" + str(self.wait_per_retry) + " second)"
                    time.sleep(self.wait_per_retry)

        print "exceeded retry count : %s" % neighbor_address
        return False


    def soft_reset(self, neighbor_address, route_family, type="in"):
        url = self.rest_url_neighbor + neighbor_address + "/softreset"+type+"/" + route_family
        r = requests.post(url)
        if r.status_code == requests.codes.ok:
            print "Succeed"
        else:
            print "Failed"


    def check_load_config(self):
        self.gobgp_config = util.load_gobgp_config(self.gobgp_config_file)
        self.quagga_configs = util.load_quagga_config(self.base_dir)
        if self.gobgp_config is None:
            print "Failed to read the gobgp configuration file"
            return False
        if len(self.quagga_configs) == 0:
            print "Failed to read the quagga configuration file"
            return False
        return True


if __name__ == '__main__':
    if fab.test_user_check() is False:
        print "you are not root."
        sys.exit(1)
    if fab.docker_pkg_check() is False:
        print "not install docker package."
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()], defaultTest=sys.argv[0])
