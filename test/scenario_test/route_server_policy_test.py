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

import time
import sys
import nose
import quagga_access as qaccess
import docker_control as fab
import StringIO
from noseplugin import OptionParser
from noseplugin import parser_option
from gobgp_test import GoBGPTestBase
from constant import *
from fabric.api import local


def print_elapsed_time(f):
    def wrapped(*args, **kwargs):
        start = time.time()
        f(*args, **kwargs)
        elapsed_time = time.time() - start
        print "%s: elapsed_time:%d sec" % (f.__name__, elapsed_time)

    return wrapped

class GoBGPTest(GoBGPTestBase):

    quagga_num = 3
    retry_count_common = 2
    initial_wait_time = 5

    def __init__(self, *args, **kwargs):
        super(GoBGPTest, self).__init__(*args, **kwargs)


    def setUp(self):
        self.quagga_configs = []
        self.use_ipv6_gobgp = False
        self.use_exa_bgp = False
        self.retry_count_common = 2
        self.initial_wait_time = 1
        self.wait_per_retry = 3

        if fab.docker_container_check() or fab.bridge_setting_check():
            print "gobgp test environment already exists. clean up..."
            fab.docker_containers_destroy(False, False)


    @classmethod
    @print_elapsed_time
    def setUpClass(cls):
        print 'prepare gobgp'
        cls.go_path = parser_option.go_path
        cls.use_local = parser_option.use_local
        cls.log_debug = parser_option.gobgp_log_debug
        fab.prepare_gobgp(cls.log_debug, cls.use_local)
        fab.build_config_tools(cls.go_path)

    @print_elapsed_time
    def initialize(self):
        fab.init_policy_test_env_executor(self.quagga_num,
                                          use_ipv6=self.use_ipv6_gobgp,
                                          use_exabgp=self.use_exa_bgp)
        print "please wait " + str(self.initial_wait_time) + " second"
        time.sleep(self.initial_wait_time)
        self.assertTrue(self.check_load_config())

    @print_elapsed_time
    def setup_config(self, peer, policy_name, target):
        fab.make_config(self.quagga_num, self.go_path, BRIDGE_0, use_compiled=True)
        fab.update_policy_config(self.go_path, peer, policy_name, target)

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


        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        peer3 = "10.0.0.3"
        prefix1 = "192.168.2.0/24"
        w = self.wait_per_retry

        self.setup_config(peer3, "test_01_import_policy_initial", "import")
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config) 
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")


        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check adj-rib-in in peer2
        path = self.get_adj_rib_in(peer2, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        path = self.get_paths_in_localrib(peer3, prefix1,retry=0)
        self.assertIsNone(path)

        # check show ip bgp on peer1(quagga3)
        qpath = self.get_route(peer3, prefix1, retry=self.retry_count_common, interval=w)
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
        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        peer3 = "10.0.0.3"
        prefix1 = "192.168.2.0/24"
        w = self.wait_per_retry

        self.setup_config(peer3, "test_02_export_policy_initial", "export")
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config) 
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        paths = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(paths)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_adj_rib_in(peer2, prefix1, retry=1)
        self.assertIsNotNone(path)

        path = self.get_paths_in_localrib(peer3, prefix1)
        self.assertIsNotNone(path)

        path = self.get_adj_rib_out(peer3, prefix1, retry=1)
        # print path
        self.assertIsNone(path)

        # check show ip bgp on peer1(quagga3)
        qpath = self.get_route(peer3, prefix1, retry=self.retry_count_common, interval=w)
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

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        peer3 = "10.0.0.3"
        r1 = "192.168.2.0/24"
        r2 = "192.168.20.0/24"
        r3 = "192.168.200.0/24"
        w = self.wait_per_retry

        self.setup_config(peer3, "test_03_import_policy_update", "import")
        self.initialize()

        # add other network
        tn = qaccess.login(peer2)
        print "add network 192.168.20.0/24"
        qaccess.add_network(tn, 65002, r2)
        print "add network 192.168.200.0/24"
        qaccess.add_network(tn, 65002, r3)
        qaccess.logout(tn)

        addresses = self.get_neighbor_address(self.gobgp_config) 
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        time.sleep(self.initial_wait_time)

        def path_exists_in_localrib(peer, prefix,r=10):
            paths = self.get_paths_in_localrib(peer, prefix, retry=r, interval=w)
            return paths is not None

        def path_exists_in_routing_table(peer, prefix,r=10):
            qpath = self.get_route(peer, prefix, retry=r, interval=w)
            return qpath is not None

        def path_exists_in_adj_rib_in(peer, prefix,r=10):
            path = self.get_adj_rib_in(peer, prefix, retry=r, interval=w)
            return path is not None


        self.assertTrue(path_exists_in_localrib(peer1,r1))
        self.assertTrue(path_exists_in_localrib(peer1,r2))
        self.assertTrue(path_exists_in_localrib(peer1,r3))

        self.assertTrue(path_exists_in_localrib(peer3,r1))
        self.assertFalse(path_exists_in_localrib(peer3,r2, r=1))
        self.assertFalse(path_exists_in_localrib(peer3,r3, r=0))

        # check show ip bgp on peer1(quagga1)
        self.assertTrue(path_exists_in_routing_table(peer1, r1))
        self.assertTrue(path_exists_in_routing_table(peer1, r2))
        self.assertTrue(path_exists_in_routing_table(peer1, r3))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, r1))
        self.assertFalse(path_exists_in_routing_table(peer3, r2, r=1))
        self.assertFalse(path_exists_in_routing_table(peer3, r3, r=0))

        # check adj-rib-out in peer2
        self.assertTrue(path_exists_in_adj_rib_in(peer2, r1))
        self.assertTrue(path_exists_in_adj_rib_in(peer2, r2))
        self.assertTrue(path_exists_in_adj_rib_in(peer2, r3))

        # update policy
        print "update_policy_config"
        fab.update_policy_config(self.go_path, peer3, "test_03_import_policy_update_softreset", "import", isReplace=True)
        fab.reload_config()
        time.sleep(self.initial_wait_time)

        # soft reset
        print "soft_reset"
        self.soft_reset(peer2, IPv4)

        # check local-rib
        self.assertTrue(path_exists_in_localrib(peer3,r1))
        self.assertFalse(path_exists_in_localrib(peer3,r2,r=1))
        self.assertTrue(path_exists_in_localrib(peer3,r3))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, r1))
        self.assertFalse(path_exists_in_routing_table(peer3, r2, r=1))
        self.assertTrue(path_exists_in_routing_table(peer3, r3))


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
        self.initialize(policy_pattern="test_04_export_policy_update")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        peer3 = "10.0.0.3"
        r1 = "192.168.2.0/24"
        r2 = "192.168.20.0/24"
        r3 = "192.168.200.0/24"
        w = self.wait_per_retry

        # add other network
        tn = qaccess.login(peer2)
        print "add network 192.168.20.0/24"
        qaccess.add_network(tn, 65002, r2)
        print "add network 192.168.200.0/24"
        qaccess.add_network(tn, 65002, r3)
        qaccess.logout(tn)

        addresses = self.get_neighbor_address(self.gobgp_config) 
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        time.sleep(self.initial_wait_time)

        def path_exists_in_localrib(peer, prefix,r=10):
            paths = self.get_paths_in_localrib(peer, prefix, retry=r)
            return paths is not None

        def path_exists_in_routing_table(peer, prefix,r=10):
            qpath = self.get_route(peer, prefix, retry=r, interval=w)
            return qpath is not None

        def path_exists_in_adj_rib_in(peer, prefix,r=10):
            path = self.get_adj_rib_in(peer, prefix, retry=r, interval=w)
            return path is not None

        def path_exists_in_adj_rib_out(peer, prefix,r=10):
            path = self.get_adj_rib_out(peer, prefix, retry=r, interval=w)
            return path is not None


        self.assertTrue(path_exists_in_localrib(peer1,r1))
        self.assertTrue(path_exists_in_localrib(peer1,r2))
        self.assertTrue(path_exists_in_localrib(peer1,r3))

        # check peer3 local-rib
        self.assertTrue(path_exists_in_localrib(peer3,r1))
        self.assertTrue(path_exists_in_localrib(peer3,r2))
        self.assertTrue(path_exists_in_localrib(peer3,r3))

        # check peer3 rib-out
        self.assertTrue(path_exists_in_adj_rib_out(peer3,r1))
        self.assertFalse(path_exists_in_adj_rib_out(peer3,r2,r=1))
        self.assertFalse(path_exists_in_adj_rib_out(peer3,r3,r=1))

        # check show ip bgp on peer1(quagga1)
        self.assertTrue(path_exists_in_routing_table(peer1, r1))
        self.assertTrue(path_exists_in_routing_table(peer1, r2))
        self.assertTrue(path_exists_in_routing_table(peer1, r3))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, r1))
        self.assertFalse(path_exists_in_routing_table(peer3, r2,r=1))
        self.assertFalse(path_exists_in_routing_table(peer3, r3,r=1))

        # check adj-rib-out in peer2
        peer2 = "10.0.0.2"
        self.assertTrue(path_exists_in_adj_rib_in(peer2, r1))
        self.assertTrue(path_exists_in_adj_rib_in(peer2, r2))
        self.assertTrue(path_exists_in_adj_rib_in(peer2, r3))

        # update policy
        print "update_policy_config"
        fab.update_policy_config(parser_option.go_path, policy_pattern="test_04_export_policy_update")
        time.sleep(self.initial_wait_time)

        # soft reset
        print "soft_reset"
        self.soft_reset(peer2, IPv4)

        # check local-rib
        self.assertTrue(path_exists_in_localrib(peer3,r1))
        self.assertTrue(path_exists_in_localrib(peer3,r2))
        self.assertTrue(path_exists_in_localrib(peer3,r3))

        # check local-adj-out-rib
        self.assertTrue(path_exists_in_adj_rib_out(peer3, r1))
        self.assertFalse(path_exists_in_adj_rib_out(peer3, r2, r=1))
        self.assertTrue(path_exists_in_adj_rib_out(peer3, r3))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, r1))
        self.assertFalse(path_exists_in_routing_table(peer3, r2, r=1))
        self.assertTrue(path_exists_in_routing_table(peer3, r3))

    """
       import-policy test
       r1=2001:0:10:2::/64
                         --------------------------------------------------
       peer2 ->(r1)->    | ->(r1)->  peer1-rib ->(r1)-> peer1-adj-rib-out | ->(r1)-> peer1
                         |                                                |
                         | ->x       peer3-rib                            |
                         --------------------------------------------------
    """
    def test_05_import_policy_initial_ipv6(self):

        # initialize test environment
        # policy_pattern:p5 attaches a policy to reject route 2001:0:10:2:: (64...128)
        # coming from peer2(2001::192:168:0:2) to peer3(2001::192:168:0:3)'s
        # import-policy.
        self.use_ipv6_gobgp = True
        self.initialize(policy_pattern="test_05_import_policy_initial_ipv6")

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "2001::192:168:0:1"
        peer2 = "2001::192:168:0:2"
        peer3 = "2001::192:168:0:3"
        r1 = "2001:0:10:2::/64"
        w = self.wait_per_retry

        path = self.get_paths_in_localrib(peer1, r1, retry=self.retry_count_common, af=IPv6, interval=w)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1, r1, retry=self.retry_count_common, af=IPv6)
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_adj_rib_in(peer2, r1, retry=self.retry_count_common, af=IPv6)
        self.assertIsNotNone(path)

        path = self.get_paths_in_localrib(peer3, r1, retry=0, af=IPv6)
        self.assertIsNone(path)

        # check show ip bgp on peer1(quagga3)
        qpath = self.get_route(peer3, r1, retry=1, interval=w, af=IPv6)
        self.assertIsNone(qpath)


    """
      export-policy test
      r1=2001:0:10:2::/64
                        --------------------------------------------------
      peer2 ->(r1)->    | ->(r1)->  peer1-rib ->(r1)-> peer1-adj-rib-out | ->(r1)-> peer1
                        |                                                |
                        | ->(r1)->  peer3-rib ->x peer3-adj-rib-out      |
                        --------------------------------------------------
    """
    def test_06_export_policy_initial_ipv6(self):

        # initialize test environment
        # policy_pattern:p6 attaches a policy to reject route 2001:0:10:2:: (64...128)
        # coming from peer2(2001::192:168:0:2) to peer3(2001::192:168:0:3)'s export-policy.
        self.use_ipv6_gobgp = True
        self.initialize(policy_pattern="test_06_export_policy_initial_ipv6")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "2001::192:168:0:1"
        peer2 = "2001::192:168:0:2"
        peer3 = "2001::192:168:0:3"
        r1 = "2001:0:10:2::/64"
        w = self.wait_per_retry

        paths = self.get_paths_in_localrib(peer1, r1, retry=self.retry_count_common, interval=w, af=IPv6)
        self.assertIsNotNone(paths)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1, r1, retry=self.retry_count_common, interval=w, af=IPv6)
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_adj_rib_in(peer2, r1, retry=1, interval=w, af=IPv6)
        self.assertIsNotNone(path)

        path = self.get_paths_in_localrib(peer3, r1, af=IPv6, interval=w)
        self.assertIsNotNone(path)

        path = self.get_adj_rib_out(peer3, r1, retry=1, interval=w, af=IPv6)
        self.assertIsNone(path)

        # check show ip bgp on peer1(quagga3)
        qpath = self.get_route(peer3, r1, retry=1, interval=w, af=IPv6)
        self.assertIsNone(qpath)


    """
      import-policy test
      r1=2001:0:10:2::/64
      r2=2001:0:10:20::/64
      r3=2001:0:10:200::/64
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
    def test_07_import_policy_update(self):
        # initialize test environment
        # policy_pattern:p7 attaches a policy to reject route
        # 2001:0:10:2::/64, 2001:0:10:20::/64, 2001:0:10:200::/64
        # coming from peer2(2001::192:168:0:2) to peer3(2001::192:168:0:3)'s
        # import-policy.
        self.use_ipv6_gobgp = True
        self.initialize(policy_pattern="test_07_import_policy_update")

        peer1 = "2001::192:168:0:1"
        peer2 = "2001::192:168:0:2"
        peer3 = "2001::192:168:0:3"
        r1 = "2001:0:10:2::/64"
        r2 = "2001:0:10:20::/64"
        r3 = "2001:0:10:200::/64"

        w = self.wait_per_retry

        # add other network
        tn = qaccess.login(peer2)
        print "add network 2001:0:10:20::/64"
        qaccess.add_network(tn, 65002, r2, use_ipv6=True)
        print "add network 2001:0:10:200::/64"
        qaccess.add_network(tn, 65002, r3, use_ipv6=True)
        qaccess.logout(tn)

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        time.sleep(self.initial_wait_time)

        def path_exists_in_localrib(peer, prefix, r=10):
            paths = self.get_paths_in_localrib(peer, prefix,
                                               retry=r, interval=w, af=IPv6)
            return paths is not None

        def path_exists_in_routing_table(peer, prefix, r=10):
            qpath = self.get_route(peer, prefix, retry=r, interval=w, af=IPv6)
            return qpath is not None

        def path_exists_in_adj_rib_in(peer, prefix, r=10):
            path = self.get_adj_rib_in(peer, prefix,
                                       retry=r, interval=w, af=IPv6)
            return path is not None

        self.assertTrue(path_exists_in_localrib(peer1, r1))
        self.assertTrue(path_exists_in_localrib(peer1, r2))
        self.assertTrue(path_exists_in_localrib(peer1, r3))

        self.assertTrue(path_exists_in_localrib(peer3, r1))
        self.assertFalse(path_exists_in_localrib(peer3, r2, r=1))
        self.assertFalse(path_exists_in_localrib(peer3, r3, r=1))

        # check show ip bgp on peer1(quagga1)
        self.assertTrue(path_exists_in_routing_table(peer1, r1))
        self.assertTrue(path_exists_in_routing_table(peer1, r2))
        self.assertTrue(path_exists_in_routing_table(peer1, r3))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, r1))
        self.assertFalse(path_exists_in_routing_table(peer3, r2, r=1))
        self.assertFalse(path_exists_in_routing_table(peer3, r3, r=1))

        # check adj-rib-out in peer2
        self.assertTrue(path_exists_in_adj_rib_in(peer2, r1))
        self.assertTrue(path_exists_in_adj_rib_in(peer2, r2))
        self.assertTrue(path_exists_in_adj_rib_in(peer2, r3))

        # update policy
        print "update_policy_config"
        fab.update_policy_config(parser_option.go_path, policy_pattern="test_07_import_policy_update")
        time.sleep(self.initial_wait_time)

        # soft reset
        print "soft_reset"
        self.soft_reset(peer2, IPv6)

        # check local-rib
        self.assertTrue(path_exists_in_localrib(peer3, r1))
        self.assertFalse(path_exists_in_localrib(peer3, r2, r=1))
        self.assertTrue(path_exists_in_localrib(peer3, r3))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, r1))
        self.assertFalse(path_exists_in_routing_table(peer3, r2, r=1))
        self.assertTrue(path_exists_in_routing_table(peer3, r3))

    """
      export-policy test
      r1=2001:0:10:2::/64
      r2=2001:0:10:20::/64
      r3=2001:0:10:200::/64
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
    def test_08_export_policy_update(self):
        # initialize test environment
        # policy_pattern:p8 attaches a policy to reject route
        # 2001:0:10:2::/64, 2001:0:10:20::/64, 2001:0:10:200::/64
        # coming from peer2(2001::192:168:0:2) to peer3(2001::192:168:0:3)'s
        # export-policy.
        self.use_ipv6_gobgp = True
        self.initialize(policy_pattern="test_08_export_policy_update")

        peer1 = "2001::192:168:0:1"
        peer2 = "2001::192:168:0:2"
        peer3 = "2001::192:168:0:3"
        r1 = "2001:0:10:2::/64"
        r2 = "2001:0:10:20::/64"
        r3 = "2001:0:10:200::/64"
        w = self.wait_per_retry

        # add other network
        tn = qaccess.login(peer2)
        print "add network 2001:0:10:20::/64"
        qaccess.add_network(tn, 65002, r2, use_ipv6=True)
        print "add network 2001:0:10:200::/64"
        qaccess.add_network(tn, 65002, r3, use_ipv6=True)
        qaccess.logout(tn)

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        time.sleep(self.initial_wait_time)

        def path_exists_in_localrib(peer, prefix, r=10):
            paths = self.get_paths_in_localrib(peer, prefix,
                                               retry=r, interval=w, af=IPv6)
            return paths is not None

        def path_exists_in_routing_table(peer, prefix, r=10):
            qpath = self.get_route(peer, prefix, retry=r, interval=w, af=IPv6)
            return qpath is not None

        def path_exists_in_adj_rib_in(peer, prefix, r=10):
            path = self.get_adj_rib_in(peer, prefix,
                                       retry=r, interval=w, af=IPv6)
            return path is not None

        def path_exists_in_adj_rib_out(peer, prefix, r=10):
            path = self.get_adj_rib_out(peer, prefix,
                                        retry=r, interval=w, af=IPv6)
            return path is not None

        self.assertTrue(path_exists_in_localrib(peer1, r1))
        self.assertTrue(path_exists_in_localrib(peer1, r2))
        self.assertTrue(path_exists_in_localrib(peer1, r3))

        # check peer3 local-rib
        self.assertTrue(path_exists_in_localrib(peer3, r1))
        self.assertTrue(path_exists_in_localrib(peer3, r2))
        self.assertTrue(path_exists_in_localrib(peer3, r3))

        # check peer3 rib-out
        self.assertTrue(path_exists_in_adj_rib_out(peer3, r1))
        self.assertFalse(path_exists_in_adj_rib_out(peer3, r2, r=1))
        self.assertFalse(path_exists_in_adj_rib_out(peer3, r3, r=1))

        # check show ip bgp on peer1(quagga1)
        self.assertTrue(path_exists_in_routing_table(peer1, r1))
        self.assertTrue(path_exists_in_routing_table(peer1, r2))
        self.assertTrue(path_exists_in_routing_table(peer1, r3))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, r1))
        self.assertFalse(path_exists_in_routing_table(peer3, r2, r=1))
        self.assertFalse(path_exists_in_routing_table(peer3, r3, r=1))

        # check adj-rib-out in peer2
        self.assertTrue(path_exists_in_adj_rib_in(peer2, r1))
        self.assertTrue(path_exists_in_adj_rib_in(peer2, r2))
        self.assertTrue(path_exists_in_adj_rib_in(peer2, r3))

        # update policy
        print "update_policy_config"
        fab.update_policy_config(parser_option.go_path, policy_pattern="p8")
        time.sleep(self.initial_wait_time)

        # soft reset
        print "soft_reset"
        self.soft_reset(peer2, "ipv6")

        # check local-rib
        self.assertTrue(path_exists_in_localrib(peer3, r1))
        self.assertTrue(path_exists_in_localrib(peer3, r2))
        self.assertTrue(path_exists_in_localrib(peer3, r3))

        # check local-adj-out-rib
        self.assertTrue(path_exists_in_adj_rib_out(peer3, r1))
        self.assertFalse(path_exists_in_adj_rib_out(peer3, r2, r=1))
        # Currently this test fails because of export_policy handling
        self.assertTrue(path_exists_in_adj_rib_out(peer3, r3))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, r1))
        self.assertFalse(path_exists_in_routing_table(peer3, r2, r=1))
        self.assertTrue(path_exists_in_routing_table(peer3, r3))


    """
      import-policy test
                                   ---------------------------------------
      exabgp ->(aspath_length=10)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                   |                                     |
                                   | ->x peer2-rib                       |
                                   ---------------------------------------

    """
    def test_09_aspath_length_condition_import(self):

        # initialize test environment
        # policy_pattern:p9 attaches a policy to reject a path whose aspath length is greater than or equal 10
        # to peer2(10.0.0.2)'s import-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path)


        #make_config_append(100, go_path, BRIDGE_0, peer_opts="--none-peer")

        self.quagga_num = 2
        self.use_exa_bgp = True

        self.initialize(policy_pattern="test_09_aspath_length_condition_import")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        print qpath
        self.assertIsNotNone(qpath)

        # check local-rib in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=0)
        self.assertIsNone(path)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=1, interval=w)
        self.assertIsNone(qpath)


    """
      import-policy test
                                     ---------------------------------------
      exabgp ->(aspath=[65100,...])->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                     |                                     |
                                     | ->x peer2-rib                       |
                                     ---------------------------------------

    """
    def test_10_aspath_from_condition_import(self):

        # initialize test environment
        # policy_pattern:AspFrom attaches a policy to reject a path that is from 65100
        # to peer2(10.0.0.2)'s import-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path)

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_10_aspath_from_condition_import")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check local-rib in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=0)
        self.assertIsNone(path)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=1, interval=w)
        self.assertIsNone(qpath)


    """
      import-policy test
                                        ---------------------------------------
      exabgp ->(aspath=[...65098,...])->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                        |                                     |
                                        | ->x peer2-rib                       |
                                        ---------------------------------------

    """
    def test_11_aspath_any_condition_import(self):

        # initialize test environment
        # policy_pattern:AspFrom attaches a policy to reject a path that contains 65098 in its aspath attr
        # to peer2(10.0.0.2)'s import-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path)

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_11_aspath_any_condition_import")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check local-rib in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=0)
        self.assertIsNone(path)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=1, interval=w)
        self.assertIsNone(qpath)

    """
      import-policy test
                                     ---------------------------------------
      exabgp ->(aspath=[...,65090])->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                     |                                     |
                                     | ->x peer2-rib                       |
                                     ---------------------------------------

    """
    def test_12_aspath_origin_condition_import(self):

        # initialize test environment
        # policy_pattern:AspFrom attaches a policy for rejecting a path that has 65090 at last in its aspath attr
        # to peer2(10.0.0.2)'s import-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path)

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_12_aspath_origin_condition_import")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check local-rib in peer2
        path = self.get_paths_in_localrib(peer2, prefix1,retry=0)
        self.assertIsNone(path)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=1, interval=w)
        self.assertIsNone(qpath)


    """
      import-policy test
                                    ---------------------------------------
      exabgp -> (aspath=[65100]) -> | ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                    |                                     |
                                    | ->x peer2-rib                       |
                                    ---------------------------------------

    """
    def test_13_aspath_only_condition_import(self):

        # initialize test environment
        # policy_pattern:AspFrom attaches a policy for rejecting a path that has only 65100 in its aspath attr
        # to peer2(10.0.0.2)'s import-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asn = '65100'
        generate_exabgp_config(prefix1, aspath=asn)

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_13_aspath_only_condition_import")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check local-rib in peer2
        path = self.get_paths_in_localrib(peer2, prefix1,retry=0)
        self.assertIsNone(path)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, prefix1, retry=1, interval=w)
        self.assertIsNone(qpath)


    """
      import-policy test
                                     ---------------------------------------
      exabgp ->(aspath=[...,65090])->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                     |                                     |
                                     | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                     ---------------------------------------
      This case check if policy passes the path to peer2 because of condition mismatch.
    """
    def test_14_aspath_only_condition_import(self):

        # initialize test environment
        # policy_pattern:AspFrom attaches a policy for rejecting a path that has 65090 at last in its aspath attr
        # to peer2(10.0.0.2)'s import-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path)

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_14_aspath_only_condition_import")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_paths_in_localrib(peer2, prefix1,retry=0)
        self.assertIsNotNone(path)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)


    """
      import-policy test
                                     ---------------------------------------
      exabgp ->(community=65100:10)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                     |                                     |
                                     | ->x peer2-rib                       |
                                     ---------------------------------------
    """
    def test_15_community_condition_import(self):

        # initialize test environment
        # policy_pattern:AspFrom attaches a policy for rejecting a path that has 65100:10 in its community attr
        # to peer2(10.0.0.2)'s import-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path, community=community)

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_15_community_condition_import")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check local-rib in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=1, interval=w)
        self.assertIsNone(path)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, prefix1, retry=1, interval=w)
        self.assertIsNone(qpath)


    """
      import-policy test
                                     ---------------------------------------
      exabgp ->(community=65100:10)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                     |                                     |
                                     | ->x peer2-rib                       |
                                     ---------------------------------------
    """
    def test_16_community_condition_regexp_import(self):

        # initialize test environment
        # policy_pattern:AspFrom attaches a policy for rejecting a path that has 65100:10 in its community attr
        # to peer2(10.0.0.2)'s import-policy.
        # this policy uses a regexp as the community condition.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path, community=community)

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_16_community_condition_regexp_import")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        print qpath
        self.assertIsNotNone(qpath)

        # check local-rib in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=1, interval=w)
        self.assertIsNone(path)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, prefix1, retry=1, interval=w)
        self.assertIsNone(qpath)

    """
      import-policy test
                                     ---------------------------------------
      exabgp ->(community=65100:10)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                     |                                     |
                                     | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                     |     apply action                    |
                                     ---------------------------------------
    """
    def test_17_community_add_action_import(self):

        # initialize test environment
        # policy_pattern:AspFrom attaches a policy for addition community 65100:10 to its community attr
        # to peer2(10.0.0.2)'s import-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path, community=community)

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_17_community_add_action_import")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_paths_in_localrib(peer2, prefix1,retry=0)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'communites' in x ]
        self.assertTrue((65100 << 16 | 20) in attrs[0]['communites'])

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertTrue(self.check_community(peer2, prefix1.split('/')[0], '65100:20'))


    """
      import-policy test
                                     ---------------------------------------
      exabgp ->(community=65100:10)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                     |                                     |
                                     | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                     |     apply action                    |
                                     ---------------------------------------
    """
    def test_18_community_replace_action_import(self):

        # initialize test environment
        # policy_pattern:AspFrom attaches a policy to replace community 65100:10 in its community attr
        # to peer2(10.0.0.2)'s import-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path, community=community)

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_18_community_replace_action_import")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_paths_in_localrib(peer2, prefix1,retry=0)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'communites' in x ]
        self.assertTrue((65100 << 16 | 20) in attrs[0]['communites'])
        self.assertTrue((65100 << 16 | 30) in attrs[0]['communites'])

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertTrue(self.check_community(peer2, prefix1.split('/')[0], '65100:20'))
        self.assertTrue(self.check_community(peer2, prefix1.split('/')[0], '65100:30'))
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:10', retry=0))

    """
      import-policy test
                                     ---------------------------------------
      exabgp ->(community=65100:10)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
               (community=65100:20)  |                                     |
               (community=65100:30)  | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                     |     apply action                    |
                                     ---------------------------------------
    """
    def test_19_community_remove_action_import(self):

        # initialize test environment
        # policy_pattern:AspFrom attaches a policy to remove community 65100:20 65100:30 in its community attr
        # to peer2(10.0.0.2)'s import-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = ' 65100:10 65100:20 65100:30 '
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path, community=community)

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_19_community_remove_action_import")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_paths_in_localrib(peer2, prefix1,retry=0)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'communites' in x ]
        self.assertTrue((65100 << 16 | 20) not in attrs[0]['communites'])
        self.assertTrue((65100 << 16 | 30) not in attrs[0]['communites'])

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertTrue(self.check_community(peer2, prefix1.split('/')[0], '65100:10', retry=1))
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:20', retry=0))
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:30', retry=0))



    """
      import-policy test
                                     ---------------------------------------
      exabgp ->(community=65100:10)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
               (community=65100:20)  |                                     |
               (community=65100:30)  | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                     |     apply action                    |
                                     ---------------------------------------
    """
    def test_20_community_null_action_import(self):

        # initialize test environment
        # policy_pattern:AspFrom attaches a policy to remove its community attr
        # to peer2(10.0.0.2)'s import-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = ' 65100:10 65100:20 65100:30 '
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path, community=community)

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_20_community_null_action_import")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_paths_in_localrib(peer2, prefix1,retry=0)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'communites' in x ]
        self.assertFalse('communites' in attrs)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:20', retry=0))
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:30', retry=0))
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:10', retry=0))

    """
      import-policy test
                                     ---------------------------------------
      exabgp ->(community=65100:10)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                     |                                     |
                                     | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                     |                   apply action      |
                                     ---------------------------------------
    """
    def test_21_community_add_action_export(self):

        # initialize test environment
        # policy_pattern:CommunityAddEXP attaches a policy to add community 65100:20 into its community attr
        # to peer2(10.0.0.2)'s export-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path, community=community)

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_21_community_add_action_export")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_paths_in_localrib(peer2, prefix1,retry=0)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'communites' in x ]
        self.assertFalse((65100 << 16 | 20) in attrs[0]['communites'])
        # check out-rib
        path = self.get_adj_rib_out(peer2, prefix1, retry=0)
        attrs = [x for x in path['attrs'] if 'communites' in x ]
        self.assertTrue((65100 << 16 | 20) in attrs[0]['communites'])

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertTrue(self.check_community(peer2, prefix1.split('/')[0], '65100:20'))


    """
      import-policy test
                                     ---------------------------------------
      exabgp ->(community=65100:10)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                     |                                     |
                                     | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                     |                   apply action      |
                                     ---------------------------------------
    """
    def test_22_community_replace_action_export(self):

        # initialize test environment
        # policy_pattern:CommunityReplaceEXP attaches a policy to replace its community
        # with 65100:20 and 65100:30 in its community attr to peer2(10.0.0.2)'s export-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path, community=community)

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_22_community_replace_action_export")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=0)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'communites' in x ]
        self.assertFalse((65100 << 16 | 20) in attrs[0]['communites'])
        self.assertFalse((65100 << 16 | 30) in attrs[0]['communites'])
        # check out-rib
        path = self.get_adj_rib_out(peer2, prefix1, retry=1)
        attrs = [x for x in path['attrs'] if 'communites' in x ]
        self.assertTrue((65100 << 16 | 20) in attrs[0]['communites'])
        self.assertTrue((65100 << 16 | 30) in attrs[0]['communites'])


        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertTrue(self.check_community(peer2, prefix1.split('/')[0], '65100:20'))
        self.assertTrue(self.check_community(peer2, prefix1.split('/')[0], '65100:30'))
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:10', retry=0))

    """
      import-policy test
                                     ---------------------------------------
      exabgp ->(community=65100:10)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
               (community=65100:20)  |                                     |
               (community=65100:30)  | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                     |                   apply action      |
                                     ---------------------------------------
    """
    def test_23_community_remove_action_export(self):

        # initialize test environment
        # policy_pattern:CommunityRemoveEXP attaches a policy to remove 65100:20 and 65100:30
        # in its community attr to peer2(10.0.0.2)'s import-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = ' 65100:10 65100:20 65100:30 '
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path, community=community)

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_23_community_remove_action_export")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=1)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'communites' in x ]
        self.assertTrue((65100 << 16 | 20) in attrs[0]['communites'])
        self.assertTrue((65100 << 16 | 30) in attrs[0]['communites'])
        # check out-rib
        path = self.get_adj_rib_out(peer2, prefix1, retry=1)
        attrs = [x for x in path['attrs'] if 'communites' in x ]
        self.assertFalse((65100 << 16 | 20) in attrs[0]['communites'])
        self.assertFalse((65100 << 16 | 30) in attrs[0]['communites'])


        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertTrue(self.check_community(peer2, prefix1.split('/')[0], '65100:10', retry=0))
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:20', retry=0))
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:30', retry=0))



    """
      import-policy test
                                     ---------------------------------------
      exabgp ->(community=65100:10)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
               (community=65100:20)  |                                     |
               (community=65100:30)  | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                     |                   apply action      |
                                     ---------------------------------------
    """
    def test_24_community_null_action_export(self):

        # initialize test environment
        # policy_pattern:CommunityNullEXP attaches a policy to remove its community attr
        # to peer2(10.0.0.2)'s export-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = ' 65100:10 65100:20 65100:30 '
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path, community=community)

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_24_community_null_action_export")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_paths_in_localrib(peer2, prefix1,  retry=0)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'communites' in x ]
        self.assertTrue((65100 << 16 | 10) in attrs[0]['communites'])
        self.assertTrue((65100 << 16 | 20) in attrs[0]['communites'])
        self.assertTrue((65100 << 16 | 30) in attrs[0]['communites'])
        # check out-rib
        path = self.get_adj_rib_out(peer2, prefix1, retry=1)
        attrs = [x for x in path['attrs'] if 'communites' in x ]
        self.assertFalse('communites' in attrs)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:20', retry=0))
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:30', retry=0))
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:10', retry=0))


    """
      distribute-policy test
                                            ---------------------
      exabgp ->r1(community=65100:10) ->  x | ->  peer1-rib ->  | -> r2 --> peer1
               r2(192.168.2.0/24)     ->  o |                   |
                                            | ->  peer2-rib ->  | -> r2 --> peer2
                                            |                   |
                                            ---------------------
    """
    def test_25_distribute_reject(self):

        # initialize test environment
        # policy_pattern:CommunityNullEXP attaches a policy to remove its community attr
        # to peer2(10.0.0.2)'s export-policy.

        # generate exabgp configuration file
        r1 = "192.168.100.0/24"
        r2 = "192.168.2.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = ' 65100:10 65100:20 65100:30 '
        as_path =  reduce(lambda a,b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(r1, aspath=as_path, community=community)
        e.add_route(r2, aspath=['65100'])
        e.write()




        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_25_distribute_reject")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_paths_in_localrib(peer2, prefix1,  retry=0)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'communites' in x ]
        self.assertTrue((65100 << 16 | 10) in attrs[0]['communites'])
        self.assertTrue((65100 << 16 | 20) in attrs[0]['communites'])
        self.assertTrue((65100 << 16 | 30) in attrs[0]['communites'])
        # check out-rib
        path = self.get_adj_rib_out(peer2, prefix1, retry=1)
        attrs = [x for x in path['attrs'] if 'communites' in x ]
        self.assertFalse('communites' in attrs)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:20', retry=0))
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:30', retry=0))
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:10', retry=0))



    """
      distribute-policy test
                                     ---------------------------------------
      exabgp ->(community=65100:10)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
               (community=65100:20)  |                                     |
               (community=65100:30)  | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                     |                   apply action      |
                                     ---------------------------------------
    """
    def test_26_distribute_modify_community(self):

        # initialize test environment
        # policy_pattern:CommunityNullEXP attaches a policy to remove its community attr
        # to peer2(10.0.0.2)'s export-policy.

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = ' 65100:10 65100:20 65100:30 '
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        generate_exabgp_config(prefix1, aspath=as_path, community=community)


        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        self.initialize(policy_pattern="test_24_community_null_action_export")
        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check adj-rib-out in peer2
        path = self.get_paths_in_localrib(peer2, prefix1,  retry=0)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'communites' in x ]
        self.assertTrue((65100 << 16 | 10) in attrs[0]['communites'])
        self.assertTrue((65100 << 16 | 20) in attrs[0]['communites'])
        self.assertTrue((65100 << 16 | 30) in attrs[0]['communites'])
        # check out-rib
        path = self.get_adj_rib_out(peer2, prefix1, retry=1)
        attrs = [x for x in path['attrs'] if 'communites' in x ]
        self.assertFalse('communites' in attrs)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:20', retry=0))
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:30', retry=0))
        self.assertFalse(self.check_community(peer2, prefix1.split('/')[0], '65100:10', retry=0))



def generate_exabgp_config(pref, aspath='', community=''):
    value = {'prefix': pref,
             'aspath': aspath,
             'community': community}

    pwd = local("pwd", capture=True)
    conf_dir = pwd + "/exabgp_test_conf"
    f = open(conf_dir+ "/" + EXABGP_COMMON_CONF, 'w')
    f.write(EXABGP_COMMON_TEMPLATE % value)
    f.close()


EXABGP_COMMON_TEMPLATE = '''
neighbor 10.0.255.1 {
  router-id 192.168.0.7;
  local-address 10.0.0.100;
  local-as 65100;
  peer-as 65000;
  hold-time 90;
  md5 "hoge100";
  graceful-restart;

  family {
    inet unicast;
  }
  static {
    # static routes
    route %(prefix)s next-hop 10.0.0.100 as-path [%(aspath)s] community [%(community)s];
  }
}
'''

class ExabgpConfig(object):

    basic_conf_begin = '''
neighbor 10.0.255.1 {
  router-id 192.168.0.7;
  local-address 10.0.0.100;
  local-as 65100;
  peer-as 65000;
  hold-time 90;
  md5 "hoge100";
  graceful-restart;

  family {
    inet unicast;
  }
  static {
    # static routes
'''

    basic_conf_end = '''
  }
}
'''

    def __init__(self, config_name):
        self.o = StringIO.StringIO()
        self.config_name = config_name
        print self.basic_conf_begin >> self.o

    def add_route(self, prefix, aspath='', community=''):
        value = {'prefix': prefix,
                 'aspath': aspath,
                 'community': community}
        r = "route %(prefix)s next-hop 10.0.0.100 as-path [%(aspath)s] community [%(community)s];" % value
        print r >> self.o

    def write(self):
        print self.basic_conf_end >> self.o
        pwd = local("pwd", capture=True)
        conf_dir = pwd + "/exabgp_test_conf"

        with open(conf_dir + "/" + self.config_name, 'w') as f:
            f.write(self.o.getvalue())


if __name__ == '__main__':
    if fab.test_user_check() is False:
        print "you are not root."
        sys.exit(1)
    if fab.docker_pkg_check() is False:
        print "not install docker package."
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()], defaultTest=sys.argv[0])
