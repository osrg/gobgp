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
from fabric.api import local
import json
import toml
import os
import time
from ciscoconfparse import CiscoConfParse
from peer_info import Peer
from peer_info import Destination
from peer_info import Path
from constant import *
import quagga_access as qaccess

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

    def get_neighbor_state(self, neighbor_address):
        print "check neighbor state for %s" % (neighbor_address)
        state = None
        try:
            neighbor = self.ask_gobgp(NEIGHBOR, neighbor_address)
            state = neighbor['info']['bgp_state']
            remote_ip = neighbor['conf']['remote_ip']
            assert remote_ip == neighbor_address
            return state
        except Exception as e:
            print e
        return state

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
                state = self.get_neighbor_state(address)
                if state == allow_state:
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
        for g_dest in rib:
            best_path_idx = g_dest['best_path_idx'] if 'best_path_idx' in g_dest else 0
            if target_network == g_dest['prefix']:
                target_exist = True
                g_paths = g_dest['paths']
                idx = 0
                if len(g_paths) < 2:
                    print "target path has not been bestpath selected yet."
                    print "please wait more (" + str(self.wait_per_retry) + " second)"
                    time.sleep(self.wait_per_retry)
                    self.retry_routine_for_bestpath(check_address, target_network, ans_nexthop)
                    return
                for g_path in g_paths:
                    print "best_path_Idx: " + str(best_path_idx) + ", idx: " + str(idx)
                    print g_dest
                    print "pre: ", g_dest['prefix'], "net: ", g_path['nlri']['prefix'], "next: ", g_path['nexthop']
                    if str(best_path_idx) == str(idx):
                        rep_nexthop = g_path['nexthop']
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
                network = elems[1]
                nexthop = peer_ip
                path = Path(network, nexthop)
                dest = Destination(network)
                dest.paths.append(path)
                quagga_config.destinations[network] = dest
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
        cmd = "%s/%s -j -u %s -p %s show " % (CONFIG_DIR, CLI_CMD, self.gobgp_ip, self.gobgp_port)
        if what == GLOBAL_RIB:
            cmd += " ".join([what, af])
        elif what == NEIGHBOR:
            cmd += " ".join([NEIGHBOR, who])
        else:
            cmd += " ".join([NEIGHBOR, who, what, af])
        j = local(cmd, capture=True)
        result = json.loads(j)
        return result

    def soft_reset(self, neighbor_address, route_family, type="in"):
        cmd = "%s/%s -j -u %s -p %s softreset%s " % (CONFIG_DIR, CLI_CMD, self.gobgp_ip, self.gobgp_port, type)
        cmd += "neighbor %s %s" % (neighbor_address, route_family)
        local(cmd)

    def get_paths_in_localrib(self, neighbor_address, target_prefix, retry=3, interval=5):
        retry_count = 0
        while True:
            local_rib = self.ask_gobgp(LOCAL_RIB, neighbor_address)
            g_dest = [dest for dest in local_rib if dest['prefix'] == target_prefix]
            if len(g_dest) > 0:
                assert len(g_dest) == 1
                d = g_dest[0]
                return d['paths']
            else:
                retry_count += 1
                if retry_count > retry:
                    break
                else:
                    print "destination is none : %s" % neighbor_address
                    print "please wait more (" + str(interval) + " second)"
                    time.sleep(interval)

        print "destination is none"
        return None

    def get_adj_rib_in(self, neighbor_address, target_prefix, retry=3, interval=-1):
        if interval < 0:
            interval = self.wait_per_retry
        return self.get_adj_rib(neighbor_address, target_prefix, retry, interval, type=ADJ_RIB_IN)


    def get_adj_rib_out(self, neighbor_address, target_prefix, retry=3, interval=-1):
        if interval < 0:
            interval = self.wait_per_retry
        return self.get_adj_rib(neighbor_address, target_prefix, retry, interval, type=ADJ_RIB_OUT)


    def get_adj_rib(self, neighbor_address, target_prefix, retry, interval, type=ADJ_RIB_IN):
        retry_count = 0
        while True:
            rib = self.ask_gobgp(type, neighbor_address)
            paths = [p for p in rib if p['nlri']['prefix'] == target_prefix]

            if len(paths) > 0:
                assert len(paths) == 1
                return paths[0]
            else:
                retry_count += 1
                if retry_count > retry:
                    break
                else:
                    print "adj_rib_%s is none" % type
                    print "wait (" + str(interval) + " seconds)"
                    time.sleep(interval)

        print "adj_rib_%s is none" % type
        return None


    # get route information on quagga
    def get_routing_table(self, neighbor_address, target_prefix, retry=3, interval=-1):
        if interval < 0:
            interval = self.wait_per_retry
        print "check route %s on quagga : %s" % (target_prefix, neighbor_address)
        retry_count = 0

        # quagga cli doesn't show prefix's netmask
        quagga_prefix = target_prefix.split('/')[0]
        while True:
            tn = qaccess.login(neighbor_address)
            q_rib = qaccess.show_rib(tn)
            qaccess.logout(tn)
            for q_path in q_rib:
                if quagga_prefix == q_path['Network']:
                    return q_path

            retry_count += 1
            if retry_count > retry:
                break
            else:
                print "target_prefix %s is none" % target_prefix
                print "wait (" + str(interval) + " seconds)"
                time.sleep(interval)

        print "route : %s is none" % target_prefix
        return None
