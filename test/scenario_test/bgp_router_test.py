# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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
from gobgp_test import GoBGPTestBase
from gobgp_test import ADJ_RIB_OUT, GLOBAL_RIB
from gobgp_test import NEIGHBOR
from noseplugin import OptionParser
from noseplugin import parser_option

class GoBGPTest(GoBGPTestBase):
    quagga_num = 3
    append_quagga = 10
    remove_quagga = 10
    append_quagga_best = 20

    def __init__(self, *args, **kwargs):
        super(GoBGPTest, self).__init__(*args, **kwargs)

    # test each neighbor state is turned establish
    def test_01_neighbor_established(self):
        print "test_neighbor_established"

        use_local = parser_option.use_local
        go_path = parser_option.go_path
        log_debug = parser_option.gobgp_log_debug
        fab.init_test_env_executor(self.quagga_num, use_local, go_path, log_debug, is_route_server=False)

        print "please wait " + str(self.initial_wait_time) + " second"
        time.sleep(self.initial_wait_time)
        if self.check_load_config() is False:
            return

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        for address in addresses:
            # get neighbor state and remote ip from gobgp connections
            print "check of [ " + address + " ]"
            neighbor = self.ask_gobgp(NEIGHBOR, address)
            state = neighbor['info']['bgp_state']
            remote_ip = neighbor['conf']['remote_ip']
            self.assertEqual(address, remote_ip)
            self.assertEqual(state, "BGP_FSM_ESTABLISHED")

    # Test of advertised route gobgp from each quagga


    def test_02_received_route(self):
        print "test_received_route"
        if self.check_load_config() is False:
            return

        self.assert_global_rib()

    # Test of advertising route to each quagga form gobgp
    def test_03_advertising_route(self):
        print "test_advertising_route"
        if self.check_load_config() is False:
            return

        for address in self.get_neighbor_address(self.gobgp_config):
            print "check of [ " + address + " ]"
            rib = self.ask_gobgp(ADJ_RIB_OUT, address)
            print rib
            self.assert_quagga_rib(address)

    # check if quagga that is appended can establish connection with gobgp
    def test_04_established_with_appended_quagga(self):
        print "test_established_with_appended_quagga"
        if self.check_load_config() is False:
            return

        go_path = parser_option.go_path
        # append new quagga container
        fab.docker_container_quagga_append_executor(self.append_quagga, go_path, is_route_server=False)
        print "please wait " + str(self.initial_wait_time) + " second"
        time.sleep(self.initial_wait_time)
        append_quagga_address = "10.0.0." + str(self.append_quagga)
        self.retry_routine_for_state([append_quagga_address], "BGP_FSM_ESTABLISHED")

        # get neighbor state and remote ip of new quagga
        print "check of [" + append_quagga_address + " ]"
        neighbor = self.ask_gobgp(NEIGHBOR, append_quagga_address)
        state = neighbor['info']['bgp_state']
        remote_ip = neighbor['conf']['remote_ip']
        self.assertEqual(append_quagga_address, remote_ip)
        self.assertEqual(state, "BGP_FSM_ESTABLISHED")

    # Test of advertised route gobgp from each quagga when append quagga container
    def test_05_received_route_when_appended_quagga(self):
        print "test_received_route_by_appended_quagga"
        if self.check_load_config() is False:
            return

        self.assert_global_rib()

    # Test of advertising route to each quagga form gobgp when append quagga container
    def test_06_advertising_route_when_appended_quagga(self):
        print "test_advertising_route_to_appended_quagga"
        if self.check_load_config() is False:
            return

        for address in self.get_neighbor_address(self.gobgp_config):
            print "check of [ " + address + " ]"
            self.assert_quagga_rib(address)

    def test_07_active_when_quagga_removed(self):
        print "test_active_when_removed_quagga"
        if self.check_load_config() is False:
            return

        # remove quagga container
        fab.docker_container_quagga_removed_executor(self.remove_quagga)
        print "please wait " + str(self.initial_wait_time) + " second"
        time.sleep(self.initial_wait_time)
        removed_quagga_address = "10.0.0." + str(self.remove_quagga)
        self.retry_routine_for_state([removed_quagga_address], "BGP_FSM_ACTIVE")

        # get neighbor state and remote ip of removed quagga
        print "check of [" + removed_quagga_address + " ]"
        neighbor = self.ask_gobgp(NEIGHBOR, removed_quagga_address)
        state = neighbor['info']['bgp_state']
        remote_ip = neighbor['conf']['remote_ip']
        self.assertEqual(removed_quagga_address, remote_ip)
        self.assertEqual(state, "BGP_FSM_ACTIVE")

    def test_08_received_route_when_quagga_removed(self):
        print "test_received_route_when_removed_quagga"
        if self.check_load_config() is False:
            return

        retry_count = 0
        still_exists = False
        while retry_count < self.dest_check_limit:

            rib = self.ask_gobgp(GLOBAL_RIB)

            removed_prefix = "10.0.0.%d/24" % self.remove_quagga
            still_exists = False
            for dst in rib:
                for path in dst['paths']:
                    if path['nlri']['prefix'] == removed_prefix:
                        still_exists = True

            if not still_exists:
                print "compare OK"
                break
            else:
                retry_count += 1
                print "compare NG -> retry ( %d / %d )" % (retry_count, self.dest_check_limit)
                time.sleep(self.wait_per_retry)

        self.assertEqual(still_exists, False)

    def test_09_advertising_route_when_quagga_removed(self):
        print "test_advertising_route_when_removed_quagga"
        if self.check_load_config() is False:
            return

        remove_quagga_address = "10.0.0." + str(self.remove_quagga)
        removed_prefix = "10.0.0.%d/24" % self.remove_quagga
        for address in self.get_neighbor_address(self.gobgp_config):
            if remove_quagga_address == address:
                continue

            print "check of [ " + address + " ]"

            retry_count = 0
            cmp_result = False
            while retry_count < self.dest_check_limit:

                tn = qaccess.login(address)
                q_rib = qaccess.show_rib(tn)
                still_exists = False
                for q_path in q_rib:
                    if q_path['Network'] == removed_prefix:
                        still_exists = True
                #self.assertEqual(still_exists, False)

                cmp_result = self.compare_route_with_quagga_configs(address, q_rib, route_server=False)

                if cmp_result and not still_exists:
                    print "compare OK"
                    break
                else:
                    retry_count += 1
                    print "compare NG -> retry ( %d / %d )" % (retry_count, self.dest_check_limit)
                    time.sleep(self.wait_per_retry)

            self.assertEqual(still_exists, False)
            self.assertEqual(cmp_result, True)

    def test_10_bestpath_selection_of_received_route(self):
        print "test_bestpath_selection_of_received_route"
        if self.check_load_config() is False:
            return

        go_path = parser_option.go_path
        fab.docker_container_make_bestpath_env_executor(self.append_quagga_best, go_path, is_route_server=False)
        print "please wait " + str(self.initial_wait_time) + " second"
        time.sleep(self.initial_wait_time)

        print "add neighbor setting"
        tn = qaccess.login("11.0.0.20")
        qaccess.add_neighbor(tn, "65020", "11.0.0.2", "65002")
        qaccess.add_neighbor(tn, "65020", "12.0.0.3", "65003")

        tn = qaccess.login("11.0.0.2")
        tn = qaccess.add_metric(tn, "200", "192.168.20.0")
        qaccess.add_neighbor(tn, "65002", "11.0.0.20", "65020")
        qaccess.add_neighbor_metric(tn, "65002", "10.0.255.1", "200")

        tn = qaccess.login("10.0.0.3")
        tn = qaccess.add_metric(tn, "100", "192.168.20.0")
        qaccess.add_neighbor(tn, "65003", "12.0.0.20", "65020")
        qaccess.add_neighbor_metric(tn, "65003", "10.0.255.1", "100")

        print "please wait " + str(self.initial_wait_time) + " second"
        time.sleep(self.initial_wait_time)

        target_network = "192.168.20.0/24"
        ans_nexthop = "10.0.0.3"

        print "check whether target network %s 's nexthop is %s" % (target_network, ans_nexthop)
        self.retry_routine_for_bestpath("", target_network, ans_nexthop)

    def assert_quagga_rib(self, address):
        retry_count = 0
        cmp_result = False
        while retry_count < self.dest_check_limit:
            tn = qaccess.login(address)
            q_rib = qaccess.show_rib(tn)
            cmp_result = self.compare_route_with_quagga_configs(address, q_rib, route_server=False)

            if cmp_result:
                print "compare OK"
                break
            else:
                retry_count += 1
                print "compare NG -> retry ( %d / %d )" % (retry_count, self.dest_check_limit)
                time.sleep(self.wait_per_retry)
        self.assertTrue(cmp_result)

    def assert_global_rib(self):
        retry_count = 0
        cmp_result = False
        while retry_count < self.dest_check_limit:
            rib = self.ask_gobgp(GLOBAL_RIB)
            cmp_result = self.compare_global_rib_with_quagga_configs(rib)

            if cmp_result:
                print "compare OK"
                break
            else:
                retry_count += 1
                print "compare NG -> retry ( %d / %d )" % (retry_count, self.dest_check_limit)
                time.sleep(self.wait_per_retry)
        self.assertTrue(cmp_result)

if __name__ == '__main__':
    if fab.test_user_check() is False:
        print "you are not root."
        sys.exit(1)
    if fab.docker_pkg_check() is False:
        print "not install docker package."
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()], defaultTest=sys.argv[0])
