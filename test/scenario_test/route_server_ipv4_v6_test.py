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
from gobgp_test import ADJ_RIB_IN, ADJ_RIB_OUT, LOCAL_RIB, GLOBAL_RIB
from gobgp_test import NEIGHBOR
from noseplugin import OptionParser
from noseplugin import parser_option

class GoBGPIPv6Test(GoBGPTestBase):
    quagga_num = 2
    append_quagga = 10
    remove_quagga = 10
    append_quagga_best = 20

    def __init__(self, *args, **kwargs):
        super(GoBGPIPv6Test, self).__init__(*args, **kwargs)

    # test each neighbor state is turned establish
    def test_01_ipv4_ipv6_neighbor_established(self):
        print "test_ipv4_ipv6_neighbor_established"

        image = parser_option.gobgp_image
        go_path = parser_option.go_path
        log_debug = True if parser_option.gobgp_log_level == 'debug' else False
        fab.init_ipv6_test_env_executor(self.quagga_num, image, go_path, log_debug)
        print "please wait (" + str(self.initial_wait_time) + " second)"
        time.sleep(self.initial_wait_time)
        fab.docker_container_ipv6_quagga_append_executor([3, 4], go_path)
        print "please wait (" + str(self.initial_wait_time) + " second)"
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
            print "state" + state

    def test_02_ipv4_ipv6_received_route(self):
        print "test_ipv4_ipv6_received_route"
        if self.check_load_config() is False:
            return

        for address in self.get_neighbor_address(self.gobgp_config):
            print "check of [ " + address + " ]"
            af = fab.IPv6 if ":" in address else fab.IPv4

            def check_func():
                local_rib = self.ask_gobgp(LOCAL_RIB, address, af)

                for quagga_config in self.quagga_configs:
                    if quagga_config.peer_ip == address or quagga_config.ip_version != af:
                        for c_dest in quagga_config.destinations.itervalues():
                            # print "config : ", c_dest.prefix, "my ip or different ip version!!!"
                            exist_n = 0
                            for g_dest in local_rib:
                                if c_dest.prefix == g_dest['prefix']:
                                    exist_n += 1
                            if exist_n != 0:
                                return False
                    else:
                        for c_dest in quagga_config.destinations.itervalues():
                            exist_n = 0
                            for g_dest in local_rib:
                                if c_dest.prefix == g_dest['prefix']:
                                    exist_n += 1
                            if exist_n != 1:
                                return False
                return True

            retry_count = 0
            cmp_result = False
            while retry_count < self.dest_check_limit:

                cmp_result = check_func()

                if cmp_result:
                    print "compare OK"
                    break
                else:
                    retry_count += 1
                    print "compare NG -> retry ( %d / %d )" % (retry_count, self.dest_check_limit)
                    time.sleep(self.wait_per_retry)

            self.assertEqual(cmp_result, True)

    def test_03_advertising_route(self):
        print "test_advertising_route"
        if self.check_load_config() is False:
            return

        for address in self.get_neighbor_address(self.gobgp_config):
            print "check of [ " + address + " ]"
            af = fab.IPv6 if ":" in address else fab.IPv4

            def check_func():
                tn = qaccess.login(address)
                q_rib = qaccess.show_rib(tn, af)

                for quagga_config in self.quagga_configs:
                    if quagga_config.peer_ip == address or quagga_config.ip_version != af:
                        for c_dest in quagga_config.destinations.itervalues():
                            exist_n = 0
                            for c_path in c_dest.paths:
                                # print "conf : ", c_path.network, c_path.nexthop, "my ip  or different ip version!!!"
                                for q_path in q_rib:
                                    # print "quag : ", q_path['Network'], q_path['Next Hop']
                                    if "0.0.0.0" == q_path['Next Hop'] or "::" == q_path['Next Hop']:
                                        continue
                                    if c_path.network.split("/")[0] == q_path['Network']:
                                        exist_n += 1
                                if exist_n != 0:
                                    return False
                    else:
                        for c_dest in quagga_config.destinations.itervalues():
                            exist_n = 0
                            for c_path in c_dest.paths:
                                # print "conf : ", c_path.network, c_path.nexthop
                                for q_path in q_rib:
                                    # print "quag : ", q_path['Network'], q_path['Next Hop']
                                    if quagga_config.ip_version != fab.IPv6:
                                        c_path.network = c_path.network.split("/")[0]
                                    if c_path.network == q_path['Network'] and c_path.nexthop == q_path['Next Hop']:
                                        exist_n += 1
                                if exist_n != 1:
                                    return False
                return True

            retry_count = 0
            check_result = False
            while retry_count < self.dest_check_limit:

                check_result = check_func()

                if check_result:
                    print "compare OK"
                    break
                else:
                    retry_count += 1
                    print "compare NG -> retry ( %d / %d )" % (retry_count, self.dest_check_limit)
                    time.sleep(self.wait_per_retry)

            self.assertEqual(check_result, True)

if __name__ == '__main__':
    if fab.test_user_check() is False:
        print "you are not root."
        sys.exit(1)
    if fab.docker_pkg_check() is False:
        print "not install docker package."
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()], defaultTest=sys.argv[0])
