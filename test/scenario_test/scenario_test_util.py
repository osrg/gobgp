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

import os
import time
import json
import requests
import quagga_access as qaccess
import toml
from peer_info import Peer
from peer_info import Destination
from peer_info import Path
from ciscoconfparse import CiscoConfParse
from constant import *


# get address of each neighbor from gobpg configration
def get_neighbor_address(config):
    address = []
    neighbors_config = config['NeighborList']
    for neighbor_config in neighbors_config:
        neighbor_ip = neighbor_config['NeighborAddress']
        address.append(neighbor_ip)
    return address


# get route information on quagga
def get_route(neighbor_address, target_prefix, retry=3, interval=5, rf=IPv4):
    print "check route %s on quagga : %s" % (target_prefix, neighbor_address)
    retry_count = 0
    while True:

        tn = qaccess.login(neighbor_address)
        q_rib = qaccess.lookup_prefix(tn, target_prefix, rf)
        qaccess.logout(tn)
        for q_path in q_rib:
            if target_prefix == q_path['Network']:
                return q_path

        retry_count += 1
        print "route %s doesn't exist in %s's routing table" % (target_prefix, neighbor_address)
        if retry_count > retry:
            break
        else:
            print "wait (" + str(interval) + " seconds)"
            time.sleep(interval)

    return None


def get_adj_rib_in(url, neighbor_address, target_prefix, retry=3, interval=5, rf=IPv4):
    return _get_adj_rib(url, neighbor_address, target_prefix, rf,
                       retry, interval, type="in")


def get_adj_rib_out(url, neighbor_address, target_prefix, retry=3, interval=5, rf=IPv4):
    return _get_adj_rib(url, neighbor_address, target_prefix, rf,
                       retry, interval, type="out")


def _get_adj_rib(base_url, neighbor_address, target_prefix, rf, retry, interval, type="in"):
    url = base_url + neighbor_address + "/adj-rib-" +type +"/" + rf

    retry_count = 0
    while True:

        r = requests.get(url)
        in_rib = json.loads(r.text)
        paths = [p for p in in_rib if p['Network'] == target_prefix]

        if len(paths) > 0:
            assert len(paths) == 1
            return paths[0]
        else:
            retry_count += 1
            print "%s doesn't exist in %s's adj_rib_%s" % (target_prefix, neighbor_address, type)
            if retry_count > retry:
                break
            else:

                print "wait (" + str(interval) + " seconds)"
                time.sleep(interval)

    return None


def get_neighbor_state(base_url, neighbor_address):
    print "check neighbor state for %s" % (neighbor_address)
    state = None
    url = base_url + neighbor_address
    try:
        r = requests.get(url)
        neighbor = json.loads(r.text)

        state = neighbor['info']['bgp_state']
        remote_ip = neighbor['conf']['remote_ip']
        assert remote_ip == neighbor_address
        return state
    except Exception as e:
        print e
    return state


def get_paths_in_localrib(base_url, neighbor_address, target_prefix, retry=3, interval=5, rf=IPv4):
    url = base_url + neighbor_address + "/local-rib" + "/" + rf

    retry_count = 0
    while True:
        r = requests.get(url)
        local_rib = json.loads(r.text)
        g_dests = local_rib['Destinations']
        g_dest = [dest for dest in g_dests if dest['Prefix'] == target_prefix]
        if len(g_dest) > 0:
            assert len(g_dest) == 1
            d = g_dest[0]
            return d['Paths']
        else:
            retry_count += 1
            print "destination %s doesn't exist in %s's local-rib" % (target_prefix, neighbor_address)
            if retry_count > retry:
                break
            else:
                print "please wait more (" + str(interval) + " second)"
                time.sleep(interval)

    return None


def load_gobgp_config(gobgp_config_file):

    config = None
    try:
        config = toml.loads(open(gobgp_config_file).read())
    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)

    return config


# load configration from quagga(bgpd.conf)
def load_quagga_config(base_dir):
    configs = []
    dirs = []
    try:
        content = os.listdir(base_dir)
        for item in content:
            if "q" != item[0]:
                continue
            if os.path.isdir(os.path.join(base_dir, item)):
                dirs.append(item)
    except OSError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)

    for dir in dirs:
        config_path = base_dir + dir + "/bgpd.conf"
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
        configs.append(quagga_config)

    return configs