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
import os
import time
import sys
import nose
import quagga_access as qaccess
import docker_control as fab
from noseplugin import OptionParser
from noseplugin import parser_option
from gobgp_test import GoBGPTestBase
from constant import *


class GoBGPTest(GoBGPTestBase):

    quagga_num = 3

    def __init__(self, *args, **kwargs):
        super(GoBGPTest, self).__init__(*args, **kwargs)

    def initialize(self, policy_pattern=None):
        use_local = parser_option.use_local
        go_path = parser_option.go_path
        log_debug = parser_option.gobgp_log_debug
        fab.init_policy_test_env_executor(self.quagga_num, use_local, go_path, log_debug, policy=policy_pattern)
        print "please wait " + str(self.initial_wait_time) + " second"
        time.sleep(self.initial_wait_time)

        self.assertTrue(self.check_load_config())

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
        addresses = self.get_neighbor_address(self.gobgp_config) 
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        peer3 = "10.0.0.3"

        path = self.get_paths_in_localrib(peer1, "192.168.2.0/24", retry=3)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_routing_table(peer1,"192.168.2.0/24", retry=3)
        print qpath
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_adj_rib_in(peer2, "192.168.2.0/24", retry=3)
        # print path
        self.assertIsNotNone(path)

        path = self.get_paths_in_localrib(peer3, "192.168.2.0/24",retry=0)
        # print path
        self.assertIsNone(path)

        # check show ip bgp on peer1(quagga3)
        qpath = self.get_routing_table(peer3,"192.168.2.0/24", retry=3)
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
        addresses = self.get_neighbor_address(self.gobgp_config) 
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        peer3 = "10.0.0.3"

        paths = self.get_paths_in_localrib(peer1, "192.168.2.0/24", retry=3)
        # print paths
        self.assertIsNotNone(paths)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_routing_table(peer1, "192.168.2.0/24", retry=3)
        # print qpath
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_adj_rib_in(peer2, "192.168.2.0/24", retry=1)
        # print path
        self.assertIsNotNone(path)

        path = self.get_paths_in_localrib(peer3, "192.168.2.0/24")
        # print path
        self.assertIsNotNone(path)

        path = self.get_adj_rib_out(peer3, "192.168.2.0/24", retry=1)
        # print path
        self.assertIsNone(path)

        # check show ip bgp on peer1(quagga3)
        qpath = self.get_routing_table(peer3,"192.168.2.0/24", retry=3)
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

        # add other network
        tn = qaccess.login(peer2)
        print "add network 192.168.20.0/24"
        qaccess.add_network(tn, 65002, "192.168.20.0/24")
        print "add network 192.168.200.0/24"
        qaccess.add_network(tn, 65002, "192.168.200.0/24")
        qaccess.logout(tn)

        addresses = self.get_neighbor_address(self.gobgp_config) 
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        time.sleep(self.initial_wait_time)

        def path_exists_in_localrib(peer, prefix,r=10):
            paths = self.get_paths_in_localrib(peer, prefix, retry=r)
            return paths is not None

        def path_exists_in_routing_table(peer, prefix,r=10):
            qpath = self.get_routing_table(peer, prefix, retry=r)
            return qpath is not None

        def path_exists_in_adj_rib_in(peer, prefix,r=10):
            path = self.get_adj_rib_in(peer, prefix, retry=r)
            return path is not None


        self.assertTrue(path_exists_in_localrib(peer1,"192.168.2.0/24"))
        self.assertTrue(path_exists_in_localrib(peer1,"192.168.20.0/24"))
        self.assertTrue(path_exists_in_localrib(peer1,"192.168.200.0/24"))

        self.assertTrue(path_exists_in_localrib(peer3,"192.168.2.0/24"))
        self.assertFalse(path_exists_in_localrib(peer3,"192.168.20.0/24",r=3))
        self.assertFalse(path_exists_in_localrib(peer3,"192.168.200.0/24",r=0))

        # check show ip bgp on peer1(quagga1)
        self.assertTrue(path_exists_in_routing_table(peer1, "192.168.2.0/24"))
        self.assertTrue(path_exists_in_routing_table(peer1, "192.168.20.0/24"))
        self.assertTrue(path_exists_in_routing_table(peer1, "192.168.200.0/24"))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, "192.168.2.0/24"))
        self.assertFalse(path_exists_in_routing_table(peer3, "192.168.20.0/24",r=3))
        self.assertFalse(path_exists_in_routing_table(peer3, "192.168.200.0/24",r=0))

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
        self.soft_reset(peer2, IPv4)

        # check local-rib
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.2.0/24"))
        self.assertFalse(path_exists_in_localrib(peer3,"192.168.20.0/24",r=3))
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.200.0/24"))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, "192.168.2.0/24"))
        self.assertFalse(path_exists_in_routing_table(peer3, "192.168.20.0/24",r=0))
        self.assertTrue(path_exists_in_routing_table(peer3, "192.168.200.0/24"))


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

        # add other network
        tn = qaccess.login(peer2)
        print "add network 192.168.20.0/24"
        qaccess.add_network(tn, 65002, "192.168.20.0/24")
        print "add network 192.168.200.0/24"
        qaccess.add_network(tn, 65002, "192.168.200.0/24")
        qaccess.logout(tn)

        addresses = self.get_neighbor_address(self.gobgp_config) 
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        time.sleep(self.initial_wait_time)

        def path_exists_in_localrib(peer, prefix,r=10):
            paths = self.get_paths_in_localrib(peer, prefix, retry=r)
            return paths is not None

        def path_exists_in_routing_table(peer, prefix,r=10):
            qpath = self.get_routing_table(peer, prefix, retry=r)
            return qpath is not None

        def path_exists_in_adj_rib_in(peer, prefix,r=10):
            path = self.get_adj_rib_in(peer, prefix, retry=r)
            return path is not None

        def path_exists_in_adj_rib_out(peer, prefix,r=10):
            path = self.get_adj_rib_out(peer, prefix, retry=r)
            return path is not None


        self.assertTrue(path_exists_in_localrib(peer1,"192.168.2.0/24"))
        self.assertTrue(path_exists_in_localrib(peer1,"192.168.20.0/24"))
        self.assertTrue(path_exists_in_localrib(peer1,"192.168.200.0/24"))

        # check peer3 local-rib
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.2.0/24"))
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.20.0/24"))
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.200.0/24"))

        # check peer3 rib-out
        self.assertTrue(path_exists_in_adj_rib_out(peer3,"192.168.2.0/24"))
        self.assertFalse(path_exists_in_adj_rib_out(peer3,"192.168.20.0/24",r=3))
        self.assertFalse(path_exists_in_adj_rib_out(peer3,"192.168.200.0/24",r=3))

        # check show ip bgp on peer1(quagga1)
        self.assertTrue(path_exists_in_routing_table(peer1, "192.168.2.0/24"))
        self.assertTrue(path_exists_in_routing_table(peer1, "192.168.20.0/24"))
        self.assertTrue(path_exists_in_routing_table(peer1, "192.168.200.0/24"))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, "192.168.2.0/24"))
        self.assertFalse(path_exists_in_routing_table(peer3, "192.168.20.0/24",r=3))
        self.assertFalse(path_exists_in_routing_table(peer3, "192.168.200.0/24",r=0))

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
        self.soft_reset(peer2, IPv4)

        # check local-rib
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.2.0/24"))
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.20.0/24"))
        self.assertTrue(path_exists_in_localrib(peer3,"192.168.200.0/24"))

        # check local-adj-out-rib
        self.assertTrue(path_exists_in_adj_rib_out(peer3, "192.168.2.0/24"))
        self.assertFalse(path_exists_in_adj_rib_out(peer3, "192.168.20.0/24",r=3))
        self.assertTrue(path_exists_in_adj_rib_out(peer3, "192.168.200.0/24"))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, "192.168.2.0/24"))
        self.assertFalse(path_exists_in_routing_table(peer3, "192.168.20.0/24",r=3))
        self.assertTrue(path_exists_in_routing_table(peer3, "192.168.200.0/24"))


if __name__ == '__main__':
    if fab.test_user_check() is False:
        print "you are not root."
        sys.exit(1)
    if fab.docker_pkg_check() is False:
        print "not install docker package."
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()], defaultTest=sys.argv[0])
