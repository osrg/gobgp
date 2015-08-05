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
    gobgp_ipv6 = GOBGP_ADDRESS_0[IPv6]
    base_dir = CONFIG_DIRR
    gobgp_config_file = CONFIG_DIRR + "gobgpd.conf"
    gobgp_config = None
    initial_wait_time = 10
    wait_per_retry = 5
    retry_limit = (60 - initial_wait_time) / wait_per_retry
    dest_check_limit = 3

    def __init__(self, *args, **kwargs):
        super(GoBGPTestBase, self).__init__(*args, **kwargs)

    def setUp(self):
        self.quagga_configs = []
        self.use_ipv6_gobgp = False

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

    def extract_bgp_section(self):
        with open(self.gobgp_config_file) as f:
            dst = ''
            for line in f:
                if 'DefinedSets' in line:
                    break
                dst += line

            return dst.encode('utf8')

    def load_gobgp_config(self):
        try:
            t = self.extract_bgp_section()
            self.gobgp_config = toml.loads(t)
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
        neighbors_config = config['Neighbors']['NeighborList']
        for neighbor_config in neighbors_config:
            neighbor_ip = neighbor_config['NeighborConfig']['NeighborAddress']
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
        af = "-a %s" % af
        cmd = "%s -j " % CLI_CMD
        if what == GLOBAL_RIB:
            cmd += " ".join([what, af])
        elif what == NEIGHBOR:
            cmd += " ".join([NEIGHBOR, who])
        else:
            cmd += " ".join([NEIGHBOR, who, what, af])
        j = local(cmd, capture=True)
        result = json.loads(j)
        return result

    def soft_reset(self, neighbor_address, af, type="in"):
        cmd = "%s -j " % CLI_CMD
        cmd += "neighbor %s " % neighbor_address
        cmd += "softreset%s -a %s" % (type, af)
        local(cmd)

    def set_policy(self, peer, target, policy_name, default_accept=True):
        default_policy = "ACCEPT" if default_accept else "REJECT"
        cmd = "%s " % CLI_CMD
        cmd += NEIGHBOR + " %s " % peer
        cmd += POLICY + " add %s %s %s" % (target, policy_name, default_policy)
        local(cmd)

    def get_paths_in_localrib(self, neighbor_address, target_prefix, af="ipv4", retry=3, interval=5):
        retry_count = 0
        while True:
            local_rib = self.ask_gobgp(LOCAL_RIB, neighbor_address, af)
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

    def get_adj_rib_in(self, neighbor_address, target_prefix, retry=3, interval=-1, af=IPv4):
        if interval < 0:
            interval = self.wait_per_retry
        return self.get_adj_rib(neighbor_address, target_prefix, af, retry, interval, type=ADJ_RIB_IN)


    def get_adj_rib_out(self, neighbor_address, target_prefix, retry=3, interval=-1, af=IPv4):
        if interval < 0:
            interval = self.wait_per_retry
        return self.get_adj_rib(neighbor_address, target_prefix, af, retry, interval, type=ADJ_RIB_OUT)


    def get_adj_rib(self, neighbor_address, target_prefix, af, retry, interval, type=ADJ_RIB_IN):
        retry_count = 0
        while True:
            rib = self.ask_gobgp(type, neighbor_address, af)
            paths = [p for p in rib if p['prefix'] == target_prefix]

            if len(paths) > 0:
                assert len(paths) == 1
                assert len(paths[0]['paths']) == 1
                return paths[0]['paths'][0]
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

    # quagga login check
    def try_login_quagga(self, peer, retry=3, interval=1):
        print "try login to quagga : %s" % peer
        if interval < 0:
            interval = self.wait_per_retry
        retry_count = 0
        while True:
            try:
                tn = qaccess.login(peer)
                return tn
            except:
                retry_count += 1
                if retry_count > retry:
                    break
                print "failed to login to %s" % peer
                print "wait (" + str(interval) + " seconds)"
                time.sleep(interval)
        return None


    # get route information on quagga
    def get_route(self, neighbor_address, target_prefix, retry=3, interval=-1, af=IPv4):
        if interval < 0:
            interval = self.wait_per_retry
        print "check route %s on quagga : %s" % (target_prefix, neighbor_address)
        retry_count = 0

        while True:
            tn = qaccess.login(neighbor_address)
            q_rib = qaccess.lookup_prefix(tn, target_prefix, af)
            qaccess.logout(tn)
            for q_path in q_rib:
                if target_prefix == q_path['Network']:
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


    # get route information on quagga
    def check_community(self, neighbor_address, target_addr, community, retry=3, interval=-1, af=IPv4):
        if interval < 0:
            interval = self.wait_per_retry
        print "check route %s on quagga : %s" % (target_addr, neighbor_address)
        retry_count = 0

        while True:
            tn = qaccess.login(neighbor_address)
            result = qaccess.check_community(tn, target_addr, community, af)
            qaccess.logout(tn)

            if result:
                return True
            else:
                print "target path %s with community %s is none" % (target_addr, community)

            retry_count += 1
            if retry_count > retry:
                break
            else:
                print "wait (" + str(interval) + " seconds)"
                time.sleep(interval)

        return False


    # get route information on quagga
    def check_med(self, neighbor_address, target_addr, med, retry=3, interval=-1, af=IPv4):
        if interval < 0:
            interval = self.wait_per_retry
        print "check route %s on quagga : %s" % (target_addr, neighbor_address)
        retry_count = 0

        while True:
            tn = qaccess.login(neighbor_address)
            result = qaccess.check_med(tn, target_addr, med, af)
            qaccess.logout(tn)

            if result:
                return True
            else:
                print "target path %s with med %s is none" % (target_addr, med)

            retry_count += 1
            if retry_count > retry:
                break
            else:
                print "wait (" + str(interval) + " seconds)"
                time.sleep(interval)

        return False

    def compare_rib_with_quagga_configs(self, rib_owner_addr, local_rib):

        for quagga_config in self.quagga_configs:
            if quagga_config.peer_ip == rib_owner_addr:
                # check local_rib doesn't contain own destinations.
                for destination in quagga_config.destinations.itervalues():
                    for rib_destination in local_rib:
                        if destination.prefix == rib_destination['prefix']:
                            return False

            else:
                # check local_rib contains destinations that other quaggas
                # advertised.
                for destination in quagga_config.destinations.itervalues():
                    found = False
                    for rib_destination in local_rib:
                        if destination.prefix == rib_destination['prefix']:
                            found = True
                            break

                    if not found:
                        return False

        return True

    def compare_route_with_quagga_configs(self, address, quagga_rib, route_server=True):
        for quagga_config in self.quagga_configs:
            for destination in quagga_config.destinations.itervalues():
                for path in destination.paths:
                    network = path.network.split("/")[0]

                    if quagga_config.peer_ip == address:
                        nexthop = "0.0.0.0"
                    else:
                        if route_server:
                            nexthop = path.nexthop
                        else:
                            nexthop = self.gobgp_ip

                    found = False
                    for quagga_path in quagga_rib:
                        if network == quagga_path['Network'] and nexthop == quagga_path['Next Hop']:
                            found = True
                            break
                    if not found:
                        return False

        return True

    def compare_global_rib_with_quagga_configs(self, rib):
        for quagga_config in self.quagga_configs:
            peer_ip = quagga_config.peer_ip
            for d in quagga_config.destinations.itervalues():
                for p in d.paths:
                    print "check of %s's route %s existence in gobgp global rib" % (
                    peer_ip, p.network)
                    exist = False
                    for dst in rib:
                        for path in dst['paths']:
                            if path['nlri']['prefix'] == p.network:
                                exist = True
                                if exist:
                                    is_nexthop_same = path['nexthop'] == p.nexthop
                                    if not is_nexthop_same:
                                        return False
                    if not exist:
                        return False
        return True
