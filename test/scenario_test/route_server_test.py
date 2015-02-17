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


class GoBGPTest(unittest.TestCase):

    gobgp_ip = "10.0.255.1"
    gobgp_port = "8080"
    base_dir = "/tmp/gobgp/"
    gobgp_config_file = "/tmp/gobgp/gobgpd.conf"
    gobgp_config = None
    quagga_num = 3
    append_quagga = 10
    remove_quagga = 10
    append_quagga_best = 20
    initial_wait_time = 10
    wait_per_retry = 5
    retry_limit = (60 - initial_wait_time) / wait_per_retry

    def __init__(self, *args, **kwargs):
        super(GoBGPTest, self).__init__(*args, **kwargs)

    def setUp(self):
        self.quagga_configs = []

    # test each neighbor state is turned establish
    def test_01_neighbor_established(self):
        print "test_neighbor_established"

        use_local = parser_option.use_local
        go_path = parser_option.go_path
        fab.init_test_env_executor(self.quagga_num, use_local, go_path)

        print "please wait " + str(self.initial_wait_time) + " second"
        time.sleep(self.initial_wait_time)
        if self.check_load_config() is False:
            return

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_state(addresses, "BGP_FSM_ESTABLISHED")

        for address in addresses:
            # get neighbor state and remote ip from gobgp connections
            print "check of [ " + address + " ]"
            url = "http://" + self.gobgp_ip + ":" + self.gobgp_port + "/v1/bgp/neighbor/" + address
            r = requests.get(url)
            neighbor = json.loads(r.text)
            state = neighbor['info']['bgp_state']
            remote_ip = neighbor['conf']['remote_ip']
            self.assertEqual(address, remote_ip)
            self.assertEqual(state, "BGP_FSM_ESTABLISHED")

    # Test of advertised route gobgp from each quagga
    def test_02_received_route(self):
        print "test_received_route"
        if self.check_load_config() is False:
            return

        for address in self.get_neighbor_address(self.gobgp_config):
            print "check of [ " + address + " ]"
            # get local-rib per peer
            url = "http://" + self.gobgp_ip + ":" + self.gobgp_port + "/v1/bgp/neighbor/" + address + "/local-rib"
            r = requests.get(url)
            local_rib = json.loads(r.text)

            for quagga_config in self.quagga_configs:
                if quagga_config.peer_ip == address:
                    for c_dest in quagga_config.destinations.itervalues():
                        g_dests = local_rib['Destinations']
                        exist_n = 0
                        for g_dest in g_dests:
                            if c_dest.prefix == g_dest['Prefix']:
                                exist_n += 1
                        self.assertEqual(exist_n, 0)
                else:
                    for c_dest in quagga_config.destinations.itervalues():
                        g_dests = local_rib['Destinations']
                        exist_n = 0
                        for g_dest in g_dests:
                            if c_dest.prefix == g_dest['Prefix']:
                                exist_n += 1
                        self.assertEqual(exist_n, 1)

    # Test of advertising route to each quagga form gobgp
    def test_03_advertising_route(self):
        print "test_advertising_route"
        if self.check_load_config() is False:
            return

        for address in self.get_neighbor_address(self.gobgp_config):
            print "check of [ " + address + " ]"
            tn = qaccess.login(address)
            q_rib = qaccess.show_rib(tn)
            for quagga_config in self.quagga_configs:
                if quagga_config.peer_ip == address:
                    for c_dest in quagga_config.destinations.itervalues():
                        exist_n = 0
                        for c_path in c_dest.paths:
                            for q_path in q_rib:
                                if c_path.network.split("/")[0] == q_path['Network'] and "0.0.0.0" == q_path['Next Hop']:
                                    exist_n += 1
                            self.assertEqual(exist_n, 1)
                else:
                    for c_dest in quagga_config.destinations.itervalues():
                        exist_n = 0
                        for c_path in c_dest.paths:
                            for q_path in q_rib:
                                if c_path.network.split("/")[0] == q_path['Network'] and c_path.nexthop == q_path['Next Hop']:
                                    exist_n += 1
                            self.assertEqual(exist_n, 1)

    # check if quagga that is appended can establish connection with gobgp
    def test_04_established_with_appended_quagga(self):
        print "test_established_with_appended_quagga"
        if self.check_load_config() is False:
            return

        go_path = parser_option.go_path
        # append new quagga container
        fab.docker_container_quagga_append_executor(self.append_quagga, go_path)
        print "please wait " + str(self.initial_wait_time) + " second"
        time.sleep(self.initial_wait_time)
        append_quagga_address = "10.0.0." + str(self.append_quagga)
        self.retry_routine_for_state([append_quagga_address], "BGP_FSM_ESTABLISHED")

        # get neighbor state and remote ip of new quagga
        print "check of [" + append_quagga_address + " ]"
        url = "http://" + self.gobgp_ip + ":" + self.gobgp_port + "/v1/bgp/neighbor/" + append_quagga_address
        r = requests.get(url)
        neighbor = json.loads(r.text)
        state = neighbor['info']['bgp_state']
        remote_ip = neighbor['conf']['remote_ip']
        self.assertEqual(append_quagga_address, remote_ip)
        self.assertEqual(state, "BGP_FSM_ESTABLISHED")

    # Test of advertised route gobgp from each quagga when append quagga container
    def test_05_received_route_when_appended_quagga(self):
        print "test_received_route_by_appended_quagga"
        if self.check_load_config() is False:
            return

        for address in self.get_neighbor_address(self.gobgp_config):
            print "check of [ " + address + " ]"
            # get local-rib per peer
            url = "http://" + self.gobgp_ip + ":" + self.gobgp_port + "/v1/bgp/neighbor/" + address + "/local-rib"
            r = requests.get(url)
            local_rib = json.loads(r.text)

            for quagga_config in self.quagga_configs:
                if quagga_config.peer_ip == address:
                    for c_dest in quagga_config.destinations.itervalues():
                        # print "config : ", c_dest.prefix, "my ip !!!"
                        g_dests = local_rib['Destinations']
                        exist_n = 0
                        for g_dest in g_dests:
                            # print "gobgp : ", g_dest['Prefix']
                            if c_dest.prefix == g_dest['Prefix']:
                                exist_n += 1
                        self.assertEqual(exist_n, 0)
                else:
                    for c_dest in quagga_config.destinations.itervalues():
                        # print "config : ", c_dest.prefix,"
                        g_dests = local_rib['Destinations']
                        exist_n = 0
                        for g_dest in g_dests:
                            # print "gobgp : ", g_dest['Prefix']
                            if c_dest.prefix == g_dest['Prefix']:
                                exist_n += 1
                        self.assertEqual(exist_n, 1)

    # Test of advertising route to each quagga form gobgp when append quagga container
    def test_06_advertising_route_when_appended_quagga(self):
        print "test_advertising_route_to_appended_quagga"
        if self.check_load_config() is False:
            return

        for address in self.get_neighbor_address(self.gobgp_config):
            print "check of [ " + address + " ]"
            tn = qaccess.login(address)
            q_rib = qaccess.show_rib(tn)
            for quagga_config in self.quagga_configs:
                if quagga_config.peer_ip == address:
                    for c_dest in quagga_config.destinations.itervalues():
                        exist_n = 0
                        for c_path in c_dest.paths:
                            # print "conf : ", c_path.network, c_path.nexthop, "my ip !!!"
                            for q_path in q_rib:
                                # print "quag : ", q_path['Network'], q_path['Next Hop']
                                if c_path.network.split("/")[0] == q_path['Network'] and "0.0.0.0" == q_path['Next Hop']:
                                    exist_n += 1
                            self.assertEqual(exist_n, 1)
                else:
                    for c_dest in quagga_config.destinations.itervalues():
                        exist_n = 0
                        for c_path in c_dest.paths:
                            # print "conf : ", c_path.network, c_path.nexthop
                            for q_path in q_rib:
                                # print "quag : ", q_path['Network'], q_path['Next Hop']
                                if c_path.network.split("/")[0] == q_path['Network'] and c_path.nexthop == q_path['Next Hop']:
                                    exist_n += 1
                            self.assertEqual(exist_n, 1)

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
        url = "http://" + self.gobgp_ip + ":" + self.gobgp_port + "/v1/bgp/neighbor/" + removed_quagga_address
        r = requests.get(url)
        neighbor = json.loads(r.text)
        state = neighbor['info']['bgp_state']
        remote_ip = neighbor['conf']['remote_ip']
        self.assertEqual(removed_quagga_address, remote_ip)
        self.assertEqual(state, "BGP_FSM_ACTIVE")

    def test_08_received_route_when_quagga_removed(self):
        print "test_received_route_when_removed_quagga"
        if self.check_load_config() is False:
            return

        remove_quagga_address = "10.0.0." + str(self.remove_quagga)
        for address in self.get_neighbor_address(self.gobgp_config):
            if remove_quagga_address == address:
                continue

            print "check of [ " + address + " ]"
            # get local-rib per peer
            url = "http://" + self.gobgp_ip + ":" + self.gobgp_port + "/v1/bgp/neighbor/" + address + "/local-rib"
            r = requests.get(url)
            local_rib = json.loads(r.text)

            for quagga_config in self.quagga_configs:
                if quagga_config.peer_ip == address:
                    for c_dest in quagga_config.destinations.itervalues():
                        # print "config : ", c_dest.prefix, "my ip !!!"
                        g_dests = local_rib['Destinations']
                        exist_n = 0
                        for g_dest in g_dests:
                            # print "gobgp : ", g_dest['Prefix']
                            if c_dest.prefix == g_dest['Prefix']:
                                exist_n += 1
                        self.assertEqual(exist_n, 0)
                else:
                    for c_dest in quagga_config.destinations.itervalues():
                        # print "config : ", c_dest.prefix
                        g_dests = local_rib['Destinations']
                        exist_n = 0
                        for g_dest in g_dests:
                            # print "gobgp : ", g_dest['Prefix']
                            if c_dest.prefix == g_dest['Prefix']:
                                exist_n += 1
                        self.assertEqual(exist_n, 1)

    def test_09_advertising_route_when_quagga_removed(self):
        print "test_advertising_route_when_removed_quagga"
        if self.check_load_config() is False:
            return

        remove_quagga_address = "10.0.0." + str(self.remove_quagga)
        for address in self.get_neighbor_address(self.gobgp_config):
            if remove_quagga_address == address:
                continue

            print "check of [ " + address + " ]"
            tn = qaccess.login(address)
            q_rib = qaccess.show_rib(tn)
            for quagga_config in self.quagga_configs:
                if quagga_config.peer_ip == address:
                    for c_dest in quagga_config.destinations.itervalues():
                        exist_n = 0
                        for c_path in c_dest.paths:
                            # print "conf : ", c_path.network, c_path.nexthop, "my ip !!!"
                            for q_path in q_rib:
                                # print "quag : ", q_path['Network'], q_path['Next Hop']
                                if c_path.network.split("/")[0] == q_path['Network'] and "0.0.0.0" == q_path['Next Hop']:
                                    exist_n += 1
                            self.assertEqual(exist_n, 1)
                else:
                    for c_dest in quagga_config.destinations.itervalues():
                        exist_n = 0
                        for c_path in c_dest.paths:
                            # print "conf : ", c_path.network, c_path.nexthop
                            for q_path in q_rib:
                                # print "quag : ", q_path['Network'], q_path['Next Hop']
                                if c_path.network.split("/")[0] == q_path['Network'] and c_path.nexthop == q_path['Next Hop']:
                                    exist_n += 1
                            self.assertEqual(exist_n, 1)

    def test_10_bestpath_selection_of_received_route(self):
        print "test_bestpath_selection_of_received_route"
        if self.check_load_config() is False:
            return

        go_path = parser_option.go_path
        fab.docker_container_make_bestpath_env_executor(self.append_quagga_best, go_path)
        print "please wait " + str(self.initial_wait_time) + " second"
        time.sleep(self.initial_wait_time)

        print "add neighbor setting"
        tn = qaccess.login("11.0.0.20")
        qaccess.add_neighbor(tn, "65020", "11.0.0.2", "65002")
        qaccess.add_neighbor(tn, "65020", "12.0.0.3", "65003")

        tn = qaccess.login("10.0.0.2")
        tn = qaccess.add_metric(tn, "200", "192.168.20.0")
        qaccess.add_neighbor(tn, "65002", "11.0.0.20", "65020")
        qaccess.add_neighbor_metric(tn, "65002", "10.0.255.1", "200")

        tn = qaccess.login("10.0.0.3")
        tn = qaccess.add_metric(tn, "100", "192.168.20.0")
        qaccess.add_neighbor(tn, "65003", "12.0.0.20", "65020")
        qaccess.add_neighbor_metric(tn, "65003", "10.0.255.1", "100")

        print "please wait " + str(self.initial_wait_time) + " second"
        time.sleep(self.initial_wait_time)

        check_address = "10.0.0.1"
        target_network = "192.168.20.0"
        ans_nexthop = "10.0.0.3"

        print "check of [ " + check_address + " ]"
        self.retry_routine_for_bestpath(check_address, target_network, ans_nexthop)

    def retry_routine_for_state(self, addresses, allow_state):
        in_prepare_quagga = True
        retry_count = 0
        while in_prepare_quagga:
            if retry_count != 0:
                print "please wait more (" + str(self.wait_per_retry) + " second)"
                time.sleep(self.wait_per_retry)
            if retry_count >= self.retry_limit:
                print "retry limit"
                break
            retry_count += 1
            success_count = 0
            for address in addresses:
                # get neighbor state and remote ip from gobgp connections
                url = "http://" + self.gobgp_ip + ":" + self.gobgp_port + "/v1/bgp/neighbor/" + address
                try:
                    r = requests.get(url)
                    neighbor = json.loads(r.text)
                except Exception:
                    continue
                if neighbor is None:
                    continue
                state = neighbor['info']['bgp_state']
                remote_ip = neighbor['conf']['remote_ip']
                if address == remote_ip and state == allow_state:
                    success_count += 1
            if success_count == len(addresses):
                in_prepare_quagga = False
        time.sleep(self.wait_per_retry)

    # load configration from gobgp(gobgpd.conf)
    def retry_routine_for_bestpath(self, check_address, target_network, ans_nexthop):
        # get local-rib
        rep_nexthop = ""
        target_exist = False
        url = "http://" + self.gobgp_ip + ":" + self.gobgp_port + "/v1/bgp/neighbor/" + check_address + "/local-rib"
        r = requests.get(url)
        local_rib = json.loads(r.text)
        g_dests = local_rib['Destinations']
        for g_dest in g_dests:
            best_path_idx = g_dest['BestPathIdx']
            if target_network == g_dest['Prefix']:
                target_exist = True
                g_paths = g_dest['Paths']
                idx = 0
                if len(g_paths) < 2:
                    print "target path has not been bestpath selected yet."
                    print "please wait more (" + str(self.wait_per_retry) + " second)"
                    time.sleep(self.wait_per_retry)
                    self.retry_routine_for_bestpath(check_address, target_network, ans_nexthop)
                    return
                for g_path in g_paths:
                    print "best_path_Idx: " + str(best_path_idx) + "idx: " + str(idx)
                    print "pre: ", g_dest['Prefix'], "net: ", g_path['Network'], "next: ", g_path['Nexthop']
                    if str(best_path_idx) == str(idx):
                        rep_nexthop = g_path['Nexthop']
                    idx += 1
        if target_exist is False:
            print "target path has not been receive yet."
            print "please wait more (" + str(self.wait_per_retry) + " second)"
            time.sleep(self.wait_per_retry)
            self.retry_routine_for_bestpath(check_address, target_network, ans_nexthop)
            return
        self.assertEqual(ans_nexthop, rep_nexthop)

    def load_gobgp_config(self):
        try:
            self.gobgp_config = toml.loads(open(self.gobgp_config_file).read())
        except IOError, (errno, strerror):
            print "I/O error(%s): %s" % (errno, strerror)

    # load configration from quagga(bgpd.conf)
    def load_quagga_config(self):
        dirs = []
        try:
            content = os.listdir(self.base_dir)
            for item in content:
                if "q" != item[0]:
                    continue
                if os.path.isdir(os.path.join(self.base_dir, item)):
                    dirs.append(item)
        except OSError, (errno, strerror):
            print "I/O error(%s): %s" % (errno, strerror)

        for dir in dirs:
            config_path = self.base_dir + dir + "/bgpd.conf"
            config = CiscoConfParse(config_path)

            peer_ip = config.find_objects(r"^!\smy\saddress")[0].text.split(" ")[3]
            peer_ip_version = config.find_objects(r"^!\smy\sip_version")[0].text.split(" ")[3]
            peer_id = config.find_objects(r"^bgp\srouter-id")[0].text.split(" ")[2]
            peer_as = config.find_objects(r"^router\sbgp")[0].text.split(" ")[2]
            quagga_config = Peer(peer_ip, peer_id, peer_as, peer_ip_version)

            networks = config.find_objects(r"^network")
            if len(networks) == 0:
                continue
            for network in networks:
                elems = network.text.split(" ")
                prefix = elems[1].split("/")[0]
                network = elems[1]
                nexthop = peer_ip
                path = Path(network, nexthop)
                dest = Destination(prefix)
                dest.paths.append(path)
                quagga_config.destinations[prefix] = dest
                # print "prefix: " + prefix
                # print "network: " + network
                # print "nexthop: " + nexthop

            neighbors = config.find_objects(r"^neighbor\s.*\sremote-as")
            if len(neighbors) == 0:
                continue
            for neighbor in neighbors:
                elems = neighbor.text.split(" ")
                neighbor = Peer(elems[1], None,  elems[3], None)
                quagga_config.neighbors.append(neighbor)
            self.quagga_configs.append(quagga_config)

    # get address of each neighbor from gobpg configration
    def get_neighbor_address(self, config):
        address = []
        neighbors_config = config['NeighborList']
        for neighbor_config in neighbors_config:
            neighbor_ip = neighbor_config['NeighborAddress']
            address.append(neighbor_ip)
        return address

    def check_load_config(self):
        self.load_gobgp_config()
        self.load_quagga_config()
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
