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


class GoBGPIPv6Test(unittest.TestCase):

    gobgp_ip = "10.0.255.1"
    gobgp_port = "8080"
    base_dir = "/tmp/gobgp/"
    gobgp_config_file = "/tmp/gobgp/gobgpd.conf"
    gobgp_config = None
    quagga_num = 2
    append_quagga = 10
    remove_quagga = 10
    append_quagga_best = 20
    initial_wait_time = 10
    wait_per_retry = 5
    retry_limit = (60 - initial_wait_time) / wait_per_retry

    def __init__(self, *args, **kwargs):
        super(GoBGPIPv6Test, self).__init__(*args, **kwargs)

    def setUp(self):
        self.quagga_configs = []

    # test each neighbor state is turned establish
    def test_01_ipv4_ipv6_neighbor_established(self):
        print "test_ipv4_ipv6_neighbor_established"

        use_local = parser_option.use_local
        go_path = parser_option.go_path
        log_debug = parser_option.gobgp_log_debug
        fab.init_ipv6_test_env_executor(self.quagga_num, use_local, go_path, log_debug)
        print "please wait (" + str(self.initial_wait_time) + " second)"
        time.sleep(self.initial_wait_time)
        fab.docker_container_ipv6_quagga_append_executor([3, 4], go_path)
        print "please wait (" + str(self.initial_wait_time) + " second)"
        time.sleep(self.initial_wait_time)
        if self.check_load_config() is False:
            return

        addresses = self.get_neighbor_address(self.gobgp_config)
        self.retry_routine_for_stete(addresses)

        for address in addresses:
            # get neighbor state and remote ip from gobgp connections
            print "check of [ " + address[0] + " : " + address[1] + " ]"
            url = "http://" + self.gobgp_ip + ":" + self.gobgp_port + "/v1/bgp/neighbor/" + address[0]
            r = requests.get(url)
            neighbor = json.loads(r.text)
            state = neighbor['info']['bgp_state']
            remote_ip = neighbor['conf']['remote_ip']
            self.assertEqual(address[0], remote_ip)
            self.assertEqual(state, "BGP_FSM_ESTABLISHED")
            print "state" + state

    def test_02_ipv4_ipv6_received_route(self):
        print "test_ipv4_ipv6_received_route"
        if self.check_load_config() is False:
            return

        for address in self.get_neighbor_address(self.gobgp_config):
            print "check of [ " + address[0] + " : " + address[1] + " ]"
            # get local-rib per peer
            url = "http://" + self.gobgp_ip + ":" + self.gobgp_port + "/v1/bgp/neighbor/" + address[0] + "/local-rib"
            r = requests.get(url)
            local_rib = json.loads(r.text)

            for quagga_config in self.quagga_configs:
                # print quagga_config.peer_ip + " : " + address[0] + " | " + quagga_config.ip_version + " : " + address[1]
                if quagga_config.peer_ip == address[0] or quagga_config.ip_version != address[1]:
                    for c_dest in quagga_config.destinations.itervalues():
                        # print "config : ", c_dest.prefix, "my ip or different ip version!!!"
                        g_dests = local_rib['Destinations']
                        exist_n = 0
                        for g_dest in g_dests:
                            # print "gobgp : ", g_dest['Prefix']
                            if c_dest.prefix == g_dest['Prefix']:
                                exist_n += 1
                        self.assertEqual(exist_n, 0)
                else:
                    for c_dest in quagga_config.destinations.itervalues():
                        # print "config : ", c_dest.prefix"
                        g_dests = local_rib['Destinations']
                        exist_n = 0
                        for g_dest in g_dests:
                            # print "gobgp : ", g_dest['Prefix']
                            if c_dest.prefix == g_dest['Prefix']:
                                exist_n += 1
                        self.assertEqual(exist_n, 1)

    def test_03_advertising_route(self):
        print "test_advertising_route"
        if self.check_load_config() is False:
            return

        for address in self.get_neighbor_address(self.gobgp_config):
            print "check of [ " + address[0] + " : " + address[1] + " ]"
            tn = qaccess.login(address[0])
            if address[1] == "IPv6":
                q_rib = qaccess.show_ipv6_rib(tn)
            else:
                q_rib = qaccess.show_rib(tn)
            for quagga_config in self.quagga_configs:
                if quagga_config.peer_ip == address[0] or quagga_config.ip_version != address[1]:
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
                            self.assertEqual(exist_n, 0)

                else:
                    for c_dest in quagga_config.destinations.itervalues():
                        exist_n = 0
                        for c_path in c_dest.paths:
                            # print "conf : ", c_path.network, c_path.nexthop
                            for q_path in q_rib:
                                # print "quag : ", q_path['Network'], q_path['Next Hop']
                                if quagga_config.ip_version != "IPv6":
                                    c_path.network = c_path.network.split("/")[0]
                                if c_path.network == q_path['Network'] and c_path.nexthop == q_path['Next Hop']:
                                    exist_n += 1
                            self.assertEqual(exist_n, 1)

    def retry_routine_for_stete(self, addresses):
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
                url = "http://" + self.gobgp_ip + ":" + self.gobgp_port + "/v1/bgp/neighbor/" + address[0]
                try:
                    r = requests.get(url)
                    neighbor = json.loads(r.text)
                except Exception:
                    continue
                if neighbor is None:
                    continue
                state = neighbor['info']['bgp_state']
                remote_ip = neighbor['conf']['remote_ip']
                if address[0] == remote_ip and state == "BGP_FSM_ESTABLISHED":
                    success_count += 1
            if success_count == len(addresses):
                in_prepare_quagga = False
        time.sleep(self.wait_per_retry)

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
            address_version = "IPv4"
            if ":" in neighbor_ip:
                address_version = "IPv6"
            neighbor_ip_info = [neighbor_ip, address_version]
            address.append(neighbor_ip_info)
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
