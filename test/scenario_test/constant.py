# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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


IPv4 = 'ipv4'
IPv6 = 'ipv6'
GOBGP_IP = "10.0.255.1"
GOBGP_CONTAINER_NAME = "gobgp"
GOBGP_ADDRESS_0 = {IPv4: GOBGP_IP,
                   IPv6: "2001::0:192:168:255:1"}
GOBGP_ADDRESS_1 = {IPv4: "11.0.255.1",
                   IPv6: "2001::1:192:168:255:1"}
GOBGP_ADDRESS_2 = {IPv4: "12.0.255.1",
                   IPv6: "2001::2:192:168:255:1"}
GOBGP_CONFIG_FILE = "gobgpd.conf"
CONFIG_DIR = "/tmp/gobgp"
CONFIG_DIRR = "/tmp/gobgp/"
SHARE_VOLUME = "/root/share_volume"
CLI_CMD = "docker exec gobgp /go/bin/gobgp"
EXABGP_CONTAINER_NAME = "exabgp"
EXABGP_ADDRESS = "10.0.0.100/16"
EXABGP_CONFDIR = SHARE_VOLUME + "/exabgp_test_conf"
EXABGP_LOG_FILE = "exabgpd.log"
EXABGP_COMMON_CONF = "exabgp-gobgp-common.conf"
STARTUP_FILE_NAME = "gobgp_startup.sh"
STARTUP_FILE = SHARE_VOLUME + "/" + STARTUP_FILE_NAME
INSTALL_FILE_NAME = "gobgp_install.sh"
INSTALL_FILE = SHARE_VOLUME + "/" + INSTALL_FILE_NAME

IP_VERSION = IPv4
IF_CONFIG_OPTION = {IPv4: "inet", IPv6: "inet6"}
BRIDGE_0 = {"BRIDGE_NAME": "br0",
            IPv4: "10.0.255.2",
            IPv6: "2001::0:192:168:255:2"}
BRIDGE_1 = {"BRIDGE_NAME": "br1",
            IPv4: "11.0.255.2",
            IPv6: "2001::1:192:168:255:2"}
BRIDGE_2 = {"BRIDGE_NAME": "br2",
            IPv4: "12.0.255.2",
            IPv6: "2001::2:192:168:255:2"}
BRIDGES = [BRIDGE_0, BRIDGE_1, BRIDGE_2]

BASE_NET = {BRIDGE_0["BRIDGE_NAME"]: {IPv4: "10.0.0.", IPv6: "2001::0:192:168:0:"},
            BRIDGE_1["BRIDGE_NAME"]: {IPv4: "11.0.0.", IPv6: "2001::1:192:168:0:"},
            BRIDGE_2["BRIDGE_NAME"]: {IPv4: "12.0.0.", IPv6: "2001::2:192:168:0:"}}

BASE_MASK = {IPv4: "/16", IPv6: "/64"}

A_PART_OF_CURRENT_DIR = "/test/scenario_test"


ADJ_RIB_IN = "adj-in"
ADJ_RIB_OUT = "adj-out"
LOCAL_RIB = "local"
GLOBAL_RIB = "global rib"
NEIGHBOR = "neighbor"
POLICY = "policy"
