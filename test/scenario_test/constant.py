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
EXABGP_CONTAINER_NAME = "exabgp"
EXABGP_ADDRESS = "10.0.0.100/16"
EXABGP_CONFDIR = SHARE_VOLUME + "/exabgp_test_conf"
EXABGP_LOG_FILE = "exabgpd.log"
STARTUP_FILE_NAME = "gobgp_startup.sh"
STARTUP_FILE = SHARE_VOLUME + "/" + STARTUP_FILE_NAME

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

ADJ_RIB_IN = "adj-rib-in"
ADJ_RIB_OUT = "adj-rib-out"
LOCAL_RIB = "local-rib"
GLOBAL_RIB = "global/rib"
NEIGHBOR = "neighbor"
