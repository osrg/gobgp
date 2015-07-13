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


    @print_elapsed_time
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
        cls.log_debug = True if parser_option.gobgp_log_level == 'debug' else False
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
    def setup_config(self, peer, policy_name, target, add_exabgp=False, defaultReject=False):
        ipver = IPv4 if not self.use_ipv6_gobgp else IPv6
        fab.make_config(self.quagga_num, self.go_path, BRIDGE_0, use_compiled=True, ipver=ipver)

        if add_exabgp:
            self.setup_exabgp()

        fab.update_policy_config(self.go_path, peer, policy_name, target, defaultReject=defaultReject)

    @print_elapsed_time
    def setup_exabgp(self):
        self.use_exa_bgp = True
        ipver = IPv4 if not self.use_ipv6_gobgp else IPv6
        fab.make_config_append(100, self.go_path, BRIDGE_0, peer_opts="--none-peer", use_compiled=True, ipver=ipver)


    """
      import-policy test
                                ---------------------------------------
      peer2 ->(192.168.2.0/24)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                |                                     |
                                | ->x peer3-rib                       |
                                ---------------------------------------
    """
    def test_01_import_policy_initial(self):

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        peer3 = "10.0.0.3"
        prefix1 = "192.168.2.0/24"
        w = self.wait_per_retry

        # policy:test_02_export_policy_initial which rejects paths
        # that are 192.168.0.0/16 (16...24) and coming from peer2(10.0.0.2)
        # is attached to peer3(10.0.0.3)'s import-policy.
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

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        peer3 = "10.0.0.3"
        prefix1 = "192.168.2.0/24"
        w = self.wait_per_retry

        # policy:test_02_export_policy_initial which rejects paths
        # that are 192.168.0.0/16 (16...24) and coming from peer2(10.0.0.2)
        # is attached to peer3(10.0.0.3)'s export-policy.
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

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        peer3 = "10.0.0.3"
        r1 = "192.168.2.0/24"
        r2 = "192.168.20.0/24"
        r3 = "192.168.200.0/24"
        w = self.wait_per_retry

        # policy:test_03_import_policy_update which rejects paths
        # that are 192.168.2.0/24, 192.168.20.0/24, 192.168.200.0/24
        # and coming from peer2(10.0.0.2)
        # is attached to peer3(10.0.0.3)'s import-policy.
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
        self.set_policy(peer3, "import", "test_03_import_policy_update_softreset")
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

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        peer3 = "10.0.0.3"
        r1 = "192.168.2.0/24"
        r2 = "192.168.20.0/24"
        r3 = "192.168.200.0/24"
        w = self.wait_per_retry

        # policy:test_04_export_policy_update which rejects paths
        # that are 192.168.2.0/24, 192.168.20.0/24, 192.168.200.0/24
        # and coming from peer2(10.0.0.2)
        # is attached to peer3(10.0.0.3)'s export-policy.
        self.setup_config(peer3, "test_04_export_policy_update", "export")
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
        self.set_policy(peer3, "export", "test_04_export_policy_update_softreset")
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

        peer1 = "2001::192:168:0:1"
        peer2 = "2001::192:168:0:2"
        peer3 = "2001::192:168:0:3"
        r1 = "2001:0:10:2::/64"
        w = self.wait_per_retry

        self.use_ipv6_gobgp = True

        # policy:test_06_export_policy_initial_ipv6 which rejects paths
        # that are 2001:0:10:2:: (64...128) and coming from peer2(2001::192:168:0:2)
        # is attached to peer3(2001::192:168:0:3)'s import-policy.
        self.setup_config(peer3, "test_05_import_policy_initial_ipv6", "import")
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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

        peer1 = "2001::192:168:0:1"
        peer2 = "2001::192:168:0:2"
        peer3 = "2001::192:168:0:3"
        r1 = "2001:0:10:2::/64"
        w = self.wait_per_retry

        self.use_ipv6_gobgp = True

        # policy:test_06_export_policy_initial_ipv6 which rejects paths
        # that are 2001:0:10:2:: (64...128) and coming from peer2(2001::192:168:0:2)
        # is attached to peer3(2001::192:168:0:3)'s export-policy.
        self.setup_config(peer3, "test_06_export_policy_initial_ipv6", "export")
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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

        peer1 = "2001::192:168:0:1"
        peer2 = "2001::192:168:0:2"
        peer3 = "2001::192:168:0:3"
        r1 = "2001:0:10:2::/64"
        r2 = "2001:0:10:20::/64"
        r3 = "2001:0:10:200::/64"
        w = self.wait_per_retry

        self.use_ipv6_gobgp = True

        # policy:test_07_import_policy_update which rejects paths
        # that are 2001:0:10:2::/64, 2001:0:10:20::/64, 2001:0:10:200::/64
        # and coming from peer2(2001::192:168:0:2)
        # is attached to peer3(2001::192:168:0:3)'s import-policy.
        self.setup_config(peer3, "test_07_import_policy_update", "import")
        self.initialize()

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
        self.set_policy(peer3, "import", "test_07_import_policy_update_softreset")
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

        peer1 = "2001::192:168:0:1"
        peer2 = "2001::192:168:0:2"
        peer3 = "2001::192:168:0:3"
        r1 = "2001:0:10:2::/64"
        r2 = "2001:0:10:20::/64"
        r3 = "2001:0:10:200::/64"
        w = self.wait_per_retry

        self.use_ipv6_gobgp = True

        # policy:test_08_export_policy_update which rejects paths
        # that are 2001:0:10:2::/64, 2001:0:10:20::/64, 2001:0:10:200::/64
        # and coming from peer2(2001::192:168:0:2)
        # is attached to peer3(2001::192:168:0:3)'s export-policy.
        self.setup_config(peer3, "test_08_export_policy_update", "export")
        self.initialize()

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
        self.set_policy(peer3, "export", "test_08_export_policy_update_softreset")
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

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        as_path =  reduce(lambda a,b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path)
        e.write()

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        self.quagga_num = 2

        # policy:test_09_aspath_length_condition_import which rejects paths
        # whose aspath length is greater than or equal 10
        # is attached to peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_09_aspath_length_condition_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        as_path =  reduce(lambda a,b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_10_aspath_from_condition_import which rejects paths
        # that come from AS65100 is attached to peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_10_aspath_from_condition_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        as_path =  reduce(lambda a,b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_11_aspath_any_condition_import which rejects paths
        # that contain 65098 in its aspath attr
        # is attached to peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_11_aspath_any_condition_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_12_aspath_origin_condition_import which rejects paths
        # that have 65090 at last in its aspath attr
        # is attached to peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_12_aspath_origin_condition_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asn = '65100'

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=asn)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_13_aspath_only_condition_import which rejects paths
        # that have only 65100 in its aspath attr
        # is attached to peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_13_aspath_only_condition_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        as_path =  reduce(lambda a,b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_16_community_condition_regexp_import which rejects paths
        # that have 65090 at last in its aspath attr
        # is attached to peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_14_aspath_only_condition_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_15_community_condition_import which rejects paths
        # that have 65100:10 in its community attr
        # is attached to peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_15_community_condition_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_16_community_condition_regexp_import which rejects paths
        # that have 65100:10 in its community attr
        # is attached to peer2(10.0.0.2)'s import-policy.
        # This policy uses a regexp as the community condition.
        self.setup_config(peer2, "test_16_community_condition_regexp_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_17_community_add_action_import which adds community 65100:10
        # is attached to peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_17_community_add_action_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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
        self.assertTrue(self.check_community(peer2, prefix1.split('/')[0], '65100:20', retry=0))


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

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_18_community_replace_action_import which replace with
        # community 65100:10 is attached to peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_18_community_replace_action_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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
        self.assertTrue(self.check_community(peer2, prefix1.split('/')[0], '65100:20', retry=0))
        self.assertTrue(self.check_community(peer2, prefix1.split('/')[0], '65100:30', retry=0))
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

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = ' 65100:10 65100:20 65100:30 '
        as_path =  reduce(lambda a,b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_19_community_remove_action_import which removes
        # community 65100:20 65100:30 is attached to peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_19_community_remove_action_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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
        self.assertTrue(self.check_community(peer2, prefix1.split('/')[0], '65100:10', retry=0))
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

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = ' 65100:10 65100:20 65100:30 '
        as_path =  reduce(lambda a,b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_20_community_null_action_import which removes all community
        # is attached to peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_20_community_null_action_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_21_community_add_action_export which adds community 65100:20
        # is attached to peer2(10.0.0.2)'s export-policy.
        self.setup_config(peer2, "test_21_community_add_action_export", "export", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_22_community_replace_action_export which replaces
        # communities with 65100:20 and 65100:30 is attached to
        # peer2(10.0.0.2)'s export-policy.
        self.setup_config(peer2, "test_22_community_replace_action_export", "export", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = ' 65100:10 65100:20 65100:30 '
        as_path =  reduce(lambda a,b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_23_community_remove_action_export which removes
        # community 65100:20 and 65100:30 is attached to
        # peer2(10.0.0.2)'s export-policy.
        self.setup_config(peer2, "test_23_community_remove_action_export", "export", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = ' 65100:10 65100:20 65100:30 '
        as_path =  reduce(lambda a,b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_24_community_null_action_export which removes its community attr
        # is attached to peer2(10.0.0.2)'s export-policy.
        self.setup_config(peer2, "test_24_community_null_action_export", "export", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

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
      import-policy test
                          ---------------------------------------
      exabgp ->(med=300)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                          |                                     |
                          | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                          |     apply action                    |
                          ---------------------------------------
    """
    def test_25_med_replace_action_import(self):

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        med = "300"
        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community, med=med)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_25_med_replace_action_import which replace 100 in its med attr
        # is attached to  peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_25_med_replace_action_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check local-rib in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=0)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'metric' in x]
        self.assertTrue(100 == attrs[0]['metric'])

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertTrue(self.check_med(peer2, prefix1.split('/'), 100, retry=0))

    """
      import-policy test
                          ---------------------------------------
      exabgp ->(med=300)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                          |                                     |
                          | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                          |     apply action                    |
                          ---------------------------------------
    """
    def test_26_med_add_action_import(self):

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        med = "300"
        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community, med=med)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_26_med_add_action_import which add 100 in its med attr
        # is attached to  peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_26_med_add_action_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check local-rib in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=0)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'metric' in x]
        self.assertTrue(400 == attrs[0]['metric'])

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertTrue(self.check_med(peer2, prefix1.split('/'), 400, retry=0))

    """
      import-policy test
                          ---------------------------------------
      exabgp ->(med=300)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                          |                                     |
                          | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                          |     apply action                    |
                          ---------------------------------------
    """
    def test_27_med_subtract_action_import(self):

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        med = "300"
        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community, med=med)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_27_med_subtract_action_import which subtract 100 in its med attr
        # is attached to  peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_27_med_subtract_action_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check local-rib in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=0)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'metric' in x]
        self.assertTrue(200 == attrs[0]['metric'])

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertTrue(self.check_med(peer2, prefix1.split('/'), 200, retry=0))

    """
      export-policy test
                          ---------------------------------------
      exabgp ->(med=300)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                          |                                     |
                          | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                          |                   apply action      |
                          ---------------------------------------
    """
    def test_28_med_replace_action_export(self):

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        med = "300"
        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community, med=med)
        e.write()


        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_28_med_replace_action_export which replace 100 in its med attr
        # is attached to  peer2(10.0.0.2)'s export-policy.
        self.setup_config(peer2, "test_28_med_replace_action_export", "export", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check local-rib in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=1)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'metric' in x]
        self.assertFalse(100 == attrs[0]['metric'])
        # check adj-rib-out
        path = self.get_adj_rib_out(peer2, prefix1, retry=1)
        attrs = [x for x in path['attrs'] if 'metric' in x]
        self.assertTrue(100 == attrs[0]['metric'])


        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertTrue(self.check_med(peer2, prefix1.split('/'), 100, retry=0))

    """
      export-policy test
                          ---------------------------------------
      exabgp ->(med=300)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                          |                                     |
                          | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                          |                   apply action      |
                          ---------------------------------------
    """
    def test_29_med_add_action_export(self):

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        med = "300"
        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community, med=med)
        e.write()


        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_29_med_add_action_export which add 100 in its med attr
        # is attached to  peer2(10.0.0.2)'s export-policy.
        self.setup_config(peer2, "test_29_med_add_action_export", "export", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

       # check local-rib in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=1)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'metric' in x]
        self.assertFalse(400 == attrs[0]['metric'])
        # check adj-rib-out
        path = self.get_adj_rib_out(peer2, prefix1, retry=1)
        attrs = [x for x in path['attrs'] if 'metric' in x]
        self.assertTrue(400 == attrs[0]['metric'])


        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertTrue(self.check_med(peer2, prefix1.split('/'), 400, retry=0))

    """
      export-policy test
                          ---------------------------------------
      exabgp ->(med=300)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                          |                                     |
                          | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                          |                   apply action      |
                          ---------------------------------------
    """
    def test_30_med_subtract_action_export(self):

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = '65100:10'
        as_path =  reduce(lambda a,b: a + " " + b, asns)
        med = "300"
        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, community=community, med=med)
        e.write()


        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_30_med_subtract_action_export which subtract 100 in its med attr
        # is attached to  peer2(10.0.0.2)'s export-policy.
        self.setup_config(peer2, "test_30_med_subtract_action_export", "export", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

       # check local-rib in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=1)
        self.assertIsNotNone(path)
        attrs = [x for x in path[0]['attrs'] if 'metric' in x]
        self.assertFalse(200 == attrs[0]['metric'])
        # check adj-rib-out
        path = self.get_adj_rib_out(peer2, prefix1, retry=1)
        attrs = [x for x in path['attrs'] if 'metric' in x]
        self.assertTrue(200 == attrs[0]['metric'])

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)
        self.assertTrue(self.check_med(peer2, prefix1.split('/'), 200, retry=0))

    """
      distribute-policy test
                                            ---------------------
      exabgp ->r1(community=65100:10) ->  x | ->  peer1-rib ->  | -> r2 --> peer1
               r2(192.168.10.0/24)    ->  o |                   |
                                            | ->  peer2-rib ->  | -> r2 --> peer2
                                            ---------------------
    """
    def test_31_distribute_reject(self):

        # generate exabgp configuration file
        r1 = "192.168.100.0/24"
        r2 = "192.168.10.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = ' 65100:10 65100:20 65100:30 '
        as_path = reduce(lambda a, b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(r1, aspath=as_path, community=community)
        e.add_route(r2, aspath='65100')
        e.write()

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        exabgp = "10.0.0.100"
        w = self.wait_per_retry

        # policy:test_31_distribute_reject which rejects routes that have community=65100:10
        # is attached to exabgp(10.0.0.100)'s distribute policy.
        self.setup_config(exabgp, "test_31_distribute_reject", "distribute", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        path = self.get_paths_in_localrib(peer1, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNone(qpath)

        path = self.get_paths_in_localrib(peer2, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNone(path)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNone(qpath)

        path = self.get_paths_in_localrib(peer1, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(qpath)

        path = self.get_paths_in_localrib(peer2, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer2, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(qpath)



    """
      distribute-policy test
                                            ---------------------
      exabgp ->r1(community=65100:10) ->  x | ->  peer1-rib ->  | -> r2 --> peer1
               r2(192.168.10.0/24)    ->  o |                   |
                                            | ->  peer2-rib ->  | -> r2 --> peer2
                                            ---------------------
    """
    def test_32_distribute_accept(self):
        # generate exabgp configuration file
        r1 = "192.168.100.0/24"
        r2 = "192.168.10.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = ' 65100:10 65100:20 65100:30 '
        as_path = reduce(lambda a, b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(r1, aspath=as_path, community=community)
        e.add_route(r2, aspath='65100')
        e.write()

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        exabgp = "10.0.0.100"
        w = self.wait_per_retry

        # policy:test_32_distribute_accept which accepts 192.168.10.0/24
        # is attached to exabgp(10.0.0.100)'s distribute policy.
        self.setup_config(exabgp, "test_32_distribute_accept", "distribute", add_exabgp=True, defaultReject=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")


        path = self.get_paths_in_localrib(peer1, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNone(qpath)

        path = self.get_paths_in_localrib(peer2, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNone(path)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNone(qpath)

        path = self.get_paths_in_localrib(peer1, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(qpath)

        path = self.get_paths_in_localrib(peer2, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer2, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(qpath)


    """
      distribute-policy test
                                            ---------------------
      exabgp ->r1(community=65100:10) ->  o | ->  peer1-rib ->  | -> r1(community=65100:10, 65100:20), r2 --> peer1
               r2(192.168.10.0/24)    ->  o |                   |
                                            | ->  peer2-rib ->  | -> r1(community=65100:10, 65100:20), r2 --> peer2
                                            ---------------------
    """
    def test_33_distribute_set_community_action(self):

        # generate exabgp configuration file
        r1 = "192.168.100.0/24"
        r2 = "192.168.10.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = ' 65100:10 '
        as_path = reduce(lambda a, b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(r1, aspath=as_path, community=community)
        e.add_route(r2, aspath='65100')
        e.write()

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        exabgp = "10.0.0.100"
        w = self.wait_per_retry

        # policy:test_33_distribute_set_community_action which set community
        # attr is attached to exabgp(10.0.0.100)'s distribute policy.
        self.setup_config(exabgp, "test_33_distribute_set_community_action", "distribute", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        path = self.get_paths_in_localrib(peer1, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(qpath)

        path = self.get_paths_in_localrib(peer2, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(path)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(qpath)

        path = self.get_paths_in_localrib(peer1, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(qpath)

        path = self.get_paths_in_localrib(peer2, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer2, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(qpath)

        # check show ip bgp on peer2(quagga2)
        self.assertTrue(self.check_community(peer1, r1.split('/')[0], '65100:10', retry=0))
        self.assertTrue(self.check_community(peer1, r1.split('/')[0], '65100:20', retry=0))
        self.assertTrue(self.check_community(peer2, r1.split('/')[0], '65100:10', retry=0))
        self.assertTrue(self.check_community(peer2, r1.split('/')[0], '65100:20', retry=0))


    """
      distribute-policy test
                                         ---------------------
      exabgp ->r1(med=300)         ->  o | ->  peer1-rib ->  | -> r1(med=400), r2 --> peer1
               r2(192.168.10.0/24) ->  o |                   |
                                         | ->  peer2-rib ->  | -> r1(med=400), r2 --> peer2
                                         ---------------------
    """
    def test_34_distribute_set_med_action(self):

        # generate exabgp configuration file
        r1 = "192.168.100.0/24"
        r2 = "192.168.10.0/24"
        asns = ['65100'] + [ str(asn) for asn in range(65099, 65090, -1) ]
        community = ' 65100:10 '
        as_path = reduce(lambda a, b: a + " " + b, asns)
        med = "300"
        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(r1, aspath=as_path, community=community, med=med)
        e.add_route(r2, aspath='65100')
        e.write()

        self.quagga_num = 2
        self.use_exa_bgp = True
        self.use_ipv6_gobgp = False

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        exabgp = "10.0.0.100"
        w = self.wait_per_retry

        # policy:test_34_distribute_set_med_action which subtract 100 in its med attr
        # is attached to  peer2(10.0.0.2)'s distribute-policy.
        self.setup_config(exabgp, "test_34_distribute_set_med_action", "distribute", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")


        path = self.get_paths_in_localrib(peer1, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(qpath)

        path = self.get_paths_in_localrib(peer2, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(path)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, r1, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(qpath)

        path = self.get_paths_in_localrib(peer1, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(qpath)

        path = self.get_paths_in_localrib(peer2, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer2, r2, retry=self.retry_count_common, interval=w)
        self.assertIsNotNone(qpath)

        # check show ip bgp on peer2(quagga2)
        self.assertTrue(self.check_med(peer1, r1.split('/'), 400, retry=0))
        self.assertTrue(self.check_med(peer2, r1.split('/'), 400, retry=0))



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
        update distribute policy
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
    def test_35_distribute_policy_update(self):
        # initialize test environment


        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        peer3 = "10.0.0.3"
        r1 = "192.168.2.0/24"
        r2 = "192.168.20.0/24"
        r3 = "192.168.200.0/24"
        w = self.wait_per_retry

        # policy:test_28_distribute_policy_update which rejects routes
        # 192.168.20.0/24, 192.168.200.0/24 from peer2 is attached to peer2.
        # After policy's update, 192.168.200.0/24 can go through.
        self.setup_config(peer2, "test_35_distribute_policy_update", "distribute")
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
        self.assertFalse(path_exists_in_localrib(peer1,r2, r=1))
        self.assertFalse(path_exists_in_localrib(peer1,r3, r=0))

        self.assertTrue(path_exists_in_localrib(peer3,r1))
        self.assertFalse(path_exists_in_localrib(peer3,r2, r=1))
        self.assertFalse(path_exists_in_localrib(peer3,r3, r=0))

        # check show ip bgp on peer1(quagga1)
        self.assertTrue(path_exists_in_routing_table(peer1, r1))
        self.assertFalse(path_exists_in_routing_table(peer1, r2, r=1))
        self.assertFalse(path_exists_in_routing_table(peer1, r3, r=0))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, r1))
        self.assertFalse(path_exists_in_routing_table(peer3, r2, r=1))
        self.assertFalse(path_exists_in_routing_table(peer3, r3, r=0))

        # check adj-rib-in in peer2
        self.assertTrue(path_exists_in_adj_rib_in(peer2, r1))
        self.assertTrue(path_exists_in_adj_rib_in(peer2, r2))
        self.assertTrue(path_exists_in_adj_rib_in(peer2, r3))

        # update policy
        print "update_policy_config"
        self.set_policy(peer2, "distribute", "test_35_distribute_policy_update_softreset")
        time.sleep(self.initial_wait_time)

        # soft reset
        print "soft_reset"
        self.soft_reset(peer2, IPv4)

        # check local-rib
        self.assertTrue(path_exists_in_localrib(peer1,r1))
        self.assertFalse(path_exists_in_localrib(peer1,r2, r=1))
        self.assertTrue(path_exists_in_localrib(peer1,r3))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer1, r1))
        self.assertFalse(path_exists_in_routing_table(peer1, r2, r=1))
        self.assertTrue(path_exists_in_routing_table(peer1, r3))

        # check local-rib
        self.assertTrue(path_exists_in_localrib(peer3,r1))
        self.assertFalse(path_exists_in_localrib(peer3,r2,r=1))
        self.assertTrue(path_exists_in_localrib(peer3,r3))

        # check show ip bgp on peer3(quagga3)
        self.assertTrue(path_exists_in_routing_table(peer3, r1))
        self.assertFalse(path_exists_in_routing_table(peer3, r2, r=1))
        self.assertTrue(path_exists_in_routing_table(peer3, r3))



    """
      import-policy test
                                             ---------------------------------------
      exabgp ->(aspath=[65100 65099 65000])->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                             |                                     |
                                             | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                             |     apply action                    |
                                             ---------------------------------------
    """
    def test_36_aspath_prepend_action_import(self):

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100', '65099', '65000']
        as_path = reduce(lambda a, b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"

        # policy:test_36_aspath_prepend_action_import which prepends asnumber 65005
        # 5 times is attached to peer2(10.0.0.2)'s export-policy.
        self.setup_config(peer2, "test_36_aspath_prepend_action_import", "import", add_exabgp=True)
        self.initialize()

        def get_asseq(target):
            attrs = [p for p in target[0]['attrs'] if p['type'] == 2]
            path_asns = [a['asns'] for a in attrs[0]['as_paths'] if a['segment_type'] == 2]
            return path_asns[0]

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check aspath
        asseq = get_asseq(path)
        expected = [int(n) for n in asns]
        self.assertListEqual(asseq, expected)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check as path
        path_asns = qpath['aspath']
        expected = asns
        self.assertListEqual(path_asns, expected)


        # check adj-rib-out in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=0)
        self.assertIsNotNone(path)

        # check aspath
        asseq = get_asseq(path)
        expected = [int(n) for n in ['65005'] * 5 + asns ]
        self.assertListEqual(asseq, expected)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        print(qpath)

        # check as path
        path_asns = qpath['aspath']
        expected = ['65005'] * 5 + asns
        self.assertListEqual(path_asns, expected)


    """
      export-policy test
                                             ---------------------------------------
      exabgp ->(aspath=[65100 65099 65000])->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                             |                                     |
                                             | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                             |                   apply action      |
                                             ---------------------------------------
    """
    def test_37_aspath_prepend_action_export(self):

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100', '65099', '65000']
        as_path = reduce(lambda a, b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"

        # policy:test_37_aspath_prepend_action_export which prepends asnumber 65005
        # 5 times is attached to peer2(10.0.0.2)'s export-policy.
        self.setup_config(peer2, "test_37_aspath_prepend_action_export", "export", add_exabgp=True)
        self.initialize()

        def get_asseq(target):
            attrs = [p for p in target[0]['attrs'] if p['type'] == 2]
            path_asns = [a['asns'] for a in attrs[0]['as_paths'] if a['segment_type'] == 2]
            return path_asns[0]

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check aspath
        asseq = get_asseq(path)
        expected = [int(n) for n in asns]
        self.assertListEqual(asseq, expected)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check as path
        path_asns = qpath['aspath']
        expected = asns
        self.assertListEqual(path_asns, expected)

        # check adj-rib-out in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=0)
        self.assertIsNotNone(path)

        # check aspath
        asseq = get_asseq(path)
        expected = [int(n) for n in asns]
        self.assertListEqual(asseq, expected)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check as path
        path_asns = qpath['aspath']
        expected = ['65005'] * 5 + asns
        self.assertListEqual(path_asns, expected)


    """
      import-policy test
                                             ---------------------------------------
      exabgp ->(aspath=[65100 65099 65000])->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                             |                                     |
                                             | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                             |     apply action                    |
                                             ---------------------------------------
    """
    def test_38_aspath_prepend_action_lastas_import(self):

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100', '65099', '65000']
        as_path = reduce(lambda a, b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"

        # policy:test_38_aspath_prepend_action_lastas_import which prepends
        # the leftmost asnumber 5 times is attached to peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_38_aspath_prepend_action_lastas_import", "import", add_exabgp=True)
        self.initialize()

        def get_asseq(target):
            attrs = [p for p in target[0]['attrs'] if p['type'] == 2]
            path_asns = [a['asns'] for a in attrs[0]['as_paths'] if a['segment_type'] == 2]
            return path_asns[0]

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check aspath
        asseq = get_asseq(path)
        expected = [int(n) for n in asns]
        self.assertListEqual(asseq, expected)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1,prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check as path
        path_asns = qpath['aspath']
        expected = asns
        self.assertListEqual(path_asns, expected)


        # check adj-rib-out in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=0)
        self.assertIsNotNone(path)

        # check aspath
        asseq = get_asseq(path)
        expected = [int(n) for n in ['65100'] * 5 + asns]
        self.assertListEqual(asseq, expected)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        print(qpath)

        # check as path
        path_asns = qpath['aspath']
        expected = ['65100'] * 5 + asns
        self.assertListEqual(path_asns, expected)



    """
      export-policy test
                                             ---------------------------------------
      exabgp ->(aspath=[65100 65099 65000])->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                             |                                     |
                                             | ->  peer2-rib ->  peer2-adj-rib-out | --> peer2
                                             |                   apply action      |
                                             ---------------------------------------
    """
    def test_39_aspath_prepend_action_lastas_export(self):

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100', '65099', '65000']
        as_path = reduce(lambda a, b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"

        # policy:test_39_aspath_prepend_action_lastas_export which prepends
        # the leftmost asnumber 5 times is attached to peer2(10.0.0.2)'s export-policy.
        self.setup_config(peer2, "test_39_aspath_prepend_action_lastas_export", "export", add_exabgp=True)
        self.initialize()

        def get_asseq(target):
            attrs = [p for p in target[0]['attrs'] if p['type'] == 2]
            path_asns = [a['asns'] for a in attrs[0]['as_paths'] if a['segment_type'] == 2]
            return path_asns[0]

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check aspath
        asseq = get_asseq(path)
        expected = [int(n) for n in asns]
        self.assertListEqual(asseq, expected)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check as path
        path_asns = qpath['aspath']
        expected = asns
        self.assertListEqual(path_asns, expected)

        # check adj-rib-out in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=0)
        self.assertIsNotNone(path)

        # check aspath
        asseq = get_asseq(path)
        expected = [int(n) for n in asns]
        self.assertListEqual(asseq, expected)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check as path
        path_asns = qpath['aspath']
        expected = ['65100'] * 5 + asns
        self.assertListEqual(path_asns, expected)


    """
      import-policy test
                                                      ---------------------------------------
      exabgp ->(extcommunity=origin:65001.65100:200)->| ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                                      |                                     |
                                                      | ->x peer2-rib                       |
                                                      ---------------------------------------
    """
    def test_40_ecommunity_origin_condition_import(self):

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [str(asn) for asn in range(65099, 65090, -1)]
        extcommunity = 'origin:4259970636:200'
        as_path = reduce(lambda a, b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, extcommunity=extcommunity)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_40_ecommunity_origin_condition_import which rejects paths
        # that have origin:4259970636:200 in its extended community attr
        # is attached to peer2(10.0.0.2)'s import-policy.
        self.setup_config(peer2, "test_40_ecommunity_origin_condition_import", "import", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        # check local-rib in peer1
        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check local-rib in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=1, interval=w)
        self.assertIsNone(path)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, prefix1, retry=1, interval=w)
        self.assertIsNone(qpath)

    """
      export-policy test
                                                 ---------------------------------------
      exabgp ->(extcommunity=origin:65010:320)-> | ->  peer1-rib ->  peer1-adj-rib-out | --> peer1
                                                 |                                     |
                                                 | ->  peer2-rib ->x peer2-adj-rib-out |
                                                 ---------------------------------------
    """
    def test_41_ecommunity_target_condition_export(self):

        # generate exabgp configuration file
        prefix1 = "192.168.100.0/24"
        asns = ['65100'] + [str(asn) for asn in range(65099, 65090, -1)]
        extcommunity = 'target:65010:320'
        as_path = reduce(lambda a, b: a + " " + b, asns)

        e = ExabgpConfig(EXABGP_COMMON_CONF)
        e.add_route(prefix1, aspath=as_path, extcommunity=extcommunity)
        e.write()

        self.quagga_num = 2

        peer1 = "10.0.0.1"
        peer2 = "10.0.0.2"
        w = self.wait_per_retry

        # policy:test_41_ecommunity_target_condition_export which rejects paths
        # that have target:65010:320 in its extended community attr
        # is attached to peer2(10.0.0.2)'s export-policy.
        self.setup_config(peer2, "test_41_ecommunity_target_condition_export", "export", add_exabgp=True)
        self.initialize()

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        # check local-rib in peer1
        path = self.get_paths_in_localrib(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(path)

        # check show ip bgp on peer1(quagga1)
        qpath = self.get_route(peer1, prefix1, retry=self.retry_count_common)
        self.assertIsNotNone(qpath)

        # check local-rib in peer2
        path = self.get_paths_in_localrib(peer2, prefix1, retry=1, interval=w)
        self.assertIsNotNone(path)

        # check local-rib in peer2
        path = self.get_adj_rib_out(peer2, prefix1, retry=1, interval=w)
        self.assertIsNone(path)

        # check show ip bgp on peer2(quagga2)
        qpath = self.get_route(peer2, prefix1, retry=1, interval=w)
        self.assertIsNone(qpath)


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
        print >> self.o, self.basic_conf_begin

    def add_route(self, prefix, aspath='', community='', med='0', extcommunity=''):
        value = {'prefix': prefix,
                 'aspath': aspath,
                 'community': community,
                 'med': med,
                 'extended-community': extcommunity}
        r = "route %(prefix)s next-hop 10.0.0.100 as-path [%(aspath)s] community [%(community)s] " \
            "med %(med)s extended-community [%(extended-community)s];" % value
        print >> self.o, r

    def write(self):
        print >> self.o, self.basic_conf_end
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
