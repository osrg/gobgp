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
import quagga_access as qaccess
from ciscoconfparse import CiscoConfParse
import docker_control as fab


class GoBGPTest(unittest.TestCase):

    gobgp_ip = "10.0.255.1"
    gobgp_port = "8080"
    base_dir = "/usr/local/gobgp/"
    gobgp_config_file = "/usr/local/gobgp/gobgpd.conf"
    gobgp_config = None
    quagga_num = 3
    appending_quagga = 10
    deleting_quagga = 10
    appending_quagga_best = 20
    fab.init_test_env_executor(quagga_num)

    def __init__(self, *args, **kwargs):
        super(GoBGPTest, self).__init__(*args, **kwargs)

    def setUp(self):
        self.quagga_configs = []
        self.load_gobgp_config()
        self.load_quagga_config()

    # test each neighbor state is turned establish
    def test_01_neighbor_established(self):
        print "test_neighbor_established"
        if self.check_load_config() is False:
            return
        addresses = self.get_neighbor_address(self.gobgp_config)

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
                        # print "config : ", c_dest.prefix"
                        g_dests = local_rib['Destinations']
                        exist_n = 0
                        for g_dest in g_dests:
                            # print "gobgp : ", g_dest['Prefix']
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

    # check if quagga that is appended can establish connection with gobgp
    def test_04_established_with_appended_quagga(self):
        print "test_established_with_appended_quagga"

        # append new quagga container
        fab.docker_container_append(self.appending_quagga)
        append_quagga_address = "10.0.0." + str(self.appending_quagga)

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

        # remove quagga container
        fab.docker_container_removed(self.deleting_quagga)
        removed_quagga_address = "10.0.0." + str(self.deleting_quagga)

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

        deleting_quagga_address = "10.0.0." + str(self.deleting_quagga)
        for address in self.get_neighbor_address(self.gobgp_config):
            if deleting_quagga_address == address:
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
                        # print "config : ", c_dest.prefix,"
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

        deleting_quagga_address = "10.0.0." + str(self.deleting_quagga)
        for address in self.get_neighbor_address(self.gobgp_config):
            if deleting_quagga_address == address:
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

    def test_10_bestpath_selection_by_received_route(self):
        pass

    # load configration from gobgp(gobgpd.conf)
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
                if os.path.isdir(os.path.join(self.base_dir, item)):
                    dirs.append(item)
        except OSError, (errno, strerror):
            print "I/O error(%s): %s" % (errno, strerror)

        for dir in dirs:
            config_path = self.base_dir + dir + "/bgpd.conf"
            config = CiscoConfParse(config_path)
            peer_ip = "10.0.0." + str(dir).replace("q", "")
            peer_id = config.find_objects(r"^bgp\srouter-id")[0].text
            peer_as = config.find_objects(r"^router\sbgp")[0].text
            quagga_config = Peer(peer_ip, peer_id, peer_as)

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
                neighbor = Peer(elems[1], None,  elems[3])
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
        if self.gobgp_config is None:
            print "Failed to read the gobgp configuration file"
            return False
        if len(self.quagga_configs) == 0:
            print "Failed to read the quagga configuration file"
            return False
        return True


class Peer:
    def __init__(self, peer_ip, peer_id, peer_as):
        self.peer_ip = peer_ip
        self.peer_id = peer_id
        self.peer_as = peer_as
        self.neighbors = []
        self.destinations = {}


class Destination:
    def __init__(self, prefix):
        self.prefix = prefix
        self.paths = []


class Path:
    def __init__(self, network, nexthop):
        self.network = network
        self.nexthop = nexthop
        self.origin = None
        self.as_path = []
        self.metric = None


