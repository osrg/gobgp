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
from ciscoconfparse import CiscoConfParse
from peer_info import Peer
from peer_info import Destination
from peer_info import Path
from constant import *

class GoBGPTestBase(unittest.TestCase):

    gobgp_ip = GOBGP_IP
    gobgp_port = "8080"
    base_dir = CONFIG_DIRR
    gobgp_config_file = CONFIG_DIRR + "gobgpd.conf"
    gobgp_config = None
    initial_wait_time = 10
    wait_per_retry = 5
    retry_limit = (60 - initial_wait_time) / wait_per_retry

    def __init__(self, *args, **kwargs):
        super(GoBGPTestBase, self).__init__(*args, **kwargs)

    def setUp(self):
        self.quagga_configs = []

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
                try:
                    neighbor = self.ask_gobgp(NEIGHBOR, address)
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

    def retry_routine_for_bestpath(self, check_address, target_network, ans_nexthop):
        # get rib
        if check_address == "":
            rib = self.ask_gobgp(GLOBAL_RIB)
        else:
            rib = self.ask_gobgp(LOCAL_RIB, check_address)

        target_exist = False
        g_dests = rib['Destinations']
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

    def ask_gobgp(self, what, who="", af="ipv4"):
        url = "http://" + self.gobgp_ip + ":" + self.gobgp_port + "/v1/bgp/"
        if what == GLOBAL_RIB:
            url += "/".join([what, af])
        elif what == NEIGHBOR:
            url += "/".join([NEIGHBOR, who])
        else:
            url += "/".join([NEIGHBOR, who, what, af])
        r = requests.get(url)
        result = json.loads(r.text)
        return result
