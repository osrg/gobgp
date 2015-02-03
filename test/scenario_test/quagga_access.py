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

PASSWORD = "zebra"
CONN_PASSWORD = "hogehoge"
QLPORT = 2605


def login(host):
    tn = telnetlib.Telnet(host, QLPORT)
    tn.read_until("Password: ")
    tn.write(PASSWORD + "\n")
    tn.write("enable\n")
    return tn


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


def add_network(tn, as_number, network):
    tn.write("configure terminal\n")
    tn.write("router bgp "+str(as_number)+"\n")
    tn.write("network "+ network + " \n")
    tn.write("exit\n")
    tn.write("exit\n")
    print tn.read_until("bgpd#")


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


def show_rib(tn):
    tn.write("show ip bgp\n")
    tn.read_until("   Network          Next Hop            Metric LocPrf Weight Path")
    rib = tn.read_until("bgpd#")
    return rib_parser(rib)


def show_ipv6_rib(tn):
    tn.write("show bgp ipv6\n")
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

