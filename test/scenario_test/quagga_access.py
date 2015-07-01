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

import sys
import telnetlib
from constant import *

PASSWORD = "zebra"
CONN_PASSWORD = "hogehoge"
QLPORT = 2605


def login(host):
    tn = telnetlib.Telnet(host, QLPORT)
    tn.read_until("Password: ")
    tn.write(PASSWORD + "\n")
    tn.write("enable\n")
    tn.read_until("bgpd#")
    return tn


def logout(tn):
    tn.write("exit\n")
    tn.read_all()


def add_neighbor(tn, as_number, neighbor_address, remote_as):
    tn.write("configure terminal\n")
    tn.write("router bgp "+str(as_number)+"\n")
    tn.write("neighbor " + neighbor_address + " remote-as " + remote_as + "\n")
    tn.write("neighbor " + neighbor_address + " password " + CONN_PASSWORD + "\n")
    tn.write("exit\n")
    tn.write("exit\n")
    tn.read_until("bgpd#")


def add_neighbor_metric(tn, as_number, neighbor_address, metric):
    tn.write("configure terminal\n")
    tn.write("router bgp "+str(as_number)+"\n")
    tn.write("neighbor " + neighbor_address + " route-map MED" + metric + " out\n")
    tn.write("exit\n")
    tn.write("exit\n")
    tn.read_until("bgpd#")


def add_network(tn, as_number, network, use_ipv6=False):
    tn.write("configure terminal\n")
    tn.write("router bgp "+str(as_number)+"\n")
    if use_ipv6:
        tn.write("address-family ipv6\n")
        tn.write("network "+ network + " \n")
        tn.write("exit\n")
    else:
        tn.write("network "+ network + " \n")

    tn.write("exit\n")
    tn.write("exit\n")
    tn.read_until("bgpd#")


def add_metric(tn, metric, network):
    tn.write("configure terminal\n")
    tn.write("access-list 1 permit " + network + " 0.0.0.255\n")
    tn.write("route-map MED" + metric + " permit 10\n")
    tn.write("match ip address 1\n")
    tn.write("set metric " + metric + "\n")
    tn.write("route-map MED" + metric + " permit 10\n")
    tn.write("set metric\n")
    tn.read_until("bgpd(config-route-map)#")
    tn.write("exit\n")
    tn.write("exit\n")
    return tn


def show_config(tn):
    tn.write("show run\n")
    print tn.read_until("bgpd#")
    tn.write("exit\n")
    print tn.read_all()


def show_rib(tn, af=IPv4):
    if af == IPv4:
        tn.write("show ip bgp\n")
    elif af == IPv6:
        tn.write("show bgp ipv6\n")
    else:
        print "invalid af: ", af
        return
    tn.read_until("   Network          Next Hop            Metric LocPrf Weight Path")
    rib = tn.read_until("bgpd#")
    return rib_parser(rib)


def clear_ip_bgp(tn):
    tn.write("clear ip bgp *\n")
    tn.read_until("bgpd#")


def rib_parser(rib):
    lines = rib.split("\n")
    paths = []
    for line in lines:
        path = {}
        if line[0] == "*":
            elems = line.split()
            path['Network'] = elems[1]
            path['Next Hop'] = elems[2]
        if len(path) > 0:
            paths.append(path)
    return paths


def lookup_prefix(tn, prefix, af):
    if af == IPv4:
        tn.write("show ip bgp " + prefix + "\n")
    elif af == IPv6:
        tn.write("show bgp ipv6 " + prefix + "\n")
    else:
        print "invalid af: ", af
        return

    info = tn.read_until("bgpd#")
    paths = []
    for line in info.split("\n"):
        path = {}
        if "from" in line:
            nexthop = line.split()[0]
            path['Network'] = prefix
            path['Next Hop'] = nexthop
            paths.append(path)

    return paths


def check_community(tn, addr, community, af=IPv4):
    if af == IPv4:
        tn.write("show ip bgp community " + community + "\n")
    elif af == IPv6:
        tn.write("show bgp ipv6 community " + community + "\n")
    else:
        print "invalid af: ", af
        return
    result = tn.read_until("bgpd#")
    for line in result.split("\n"):
        if addr in line:
            return True

    return False


def check_med(tn, addr, med, af=IPv4):
    if af == IPv4:
        tn.write("show ip bgp " + addr[0] + "\n")
    elif af == IPv6:
        tn.write("show bgp ipv6 " + addr[0] + "\n")
    else:
        print "invalid af: ", af
        return
    result = tn.read_until("bgpd#")
    for line in result.split("\n"):
        if "metric" in line:
            if str(med) in line.split()[3]:
                return True

    return False
