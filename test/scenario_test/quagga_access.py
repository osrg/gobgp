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
QLPORT = 2605

def login(host):
    tn = telnetlib.Telnet(host, QLPORT)
    tn.read_until("Password: ")
    tn.write(PASSWORD + "\n")

    tn.write("enable\n")
    #print tn.read_all()
    return tn

def add_network(tn, as_number, network):
    tn.write("configure terminal\n")
    tn.write("router bgp "+str(as_number)+"\n")
    tn.write("network "+ network + " \n")
    tn.write("exit\n")
    tn.write("exit\n")
    print tn.read_until("bgpd#")

def show_config(tn):
    tn.write("show run\n")
    print tn.read_until("bgpd#")
    tn.write("exit\n")
    print tn.read_all()

def show_rib(tn):
    tn.write("show ip bgp\n")
    tn.read_until("   Network          Next Hop            Metric LocPrf Weight Path")
    rib = tn.read_until("bgpd#")
    # print header
    return rib_parser(rib)

def rib_parser(rib):
    lines = rib.split("\n")
    paths = []
    for line in lines:
        path = {}
        if line[0] == "*":
            elems = line.split()
            path['Network'] = elems[1]
            path['Next Hop'] = elems[2]
            # path['Metric'] = elems[3]
            # path['LocPrf'] = elems[4]
            # path['Weight'] = elems[5]
            # path['Path'] = elems[6]
        if len(path) > 0:
            paths.append(path)
    return paths

