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

import os
import time
import re
import sys
import nose
import collections
import docker_control as fab
import requests
import json
import toml
from noseplugin import OptionParser
from noseplugin import parser_option


sleep_time = 20
gobgp_ip = "10.0.255.1"
gobgp_port = "8080"
gobgp_config_file = "/usr/local/gobgp/gobgpd.conf"


def check_pattern():
    """
    if want to add test pattern, please write config name and notification message in this function.
    this tests is execute defined order.
    sample:
    pattern["<File to be used in test>"] = "<at that time the message>"
    """
    pattern = collections.OrderedDict()
    pattern["malformed1-exabgp-gobgp-v4-MP_REACH_NLRI.conf"] = "UPDATE message error / Attribute Flags Error / 0x600E0411223344"
    pattern["malformed1-exabgp-gobgp-v4-MP_UNREACH_NLRI.conf"] = "UPDATE message error / Attribute Flags Error / 0x600F0411223344"
    pattern["malformed1-exabgp-gobgp-v4-AS_PATH.conf"] = "UPDATE message error / Attribute Flags Error / 0x60020411223344"
    pattern["malformed1-exabgp-gobgp-v4-AS4_PATH.conf"] = "UPDATE message error / Attribute Flags Error / 0x60110411223344"
    pattern["malformed1-exabgp-gobgp-v4-NEXTHOP_INVALID.conf"] = "UPDATE message error / Attribute Flags Error / 0x600E08010110FFFFFF0000"
    pattern["malformed1-exabgp-gobgp-v4-ROUTE_FAMILY_INVALID.conf"] = "UPDATE message error / Attribute Flags Error / 0x600E150002011020010DB800000000000000000000000100"

    return pattern


def test_malformed_packet():
    pwd = os.getcwd()
    pattern = check_pattern()
    if fab.test_user_check() is False:
        print "you are not root"
        sys.exit(1)

    if fab.docker_pkg_check() is False:
        print "not install docker package."
        sys.exit(1)

    if len(pattern) <= 0:
        print "read test pattern is faild."
        print "pattern element is " + str(len(pattern))
        sys.exit(1)

    use_local = parser_option.use_local

    for pkey in pattern:
        conf_file = pwd + "/exabgp_test_conf/" + pkey
        if os.path.isfile(conf_file) is True:
            fab.init_malformed_test_env_executor(pkey, use_local)
            print "please wait"
            time.sleep(sleep_time)
            yield check_func, pkey, pattern[pkey]

        else:
            print "config file not exists."
            print conf_file
            sys.exit(1)


def check_func(exabgp_conf, result):
    # get neighbor addresses from gobgpd.conf
    addresses = get_neighbor_address()
    # check whether the service of gobgp is normally
    url = "http://" + gobgp_ip + ":" + gobgp_port + "/v1/bgp/neighbors"
    r = requests.get(url)
    neighbors = json.loads(r.text)

    assert len(neighbors) == len(addresses)

    for neighbor in neighbors:
        state = neighbor['info']['bgp_state']
        remote_ip = neighbor['conf']['remote_ip']
        e_transitions = neighbor['info']['fsm_established_transitions']
        if remote_ip == "10.0.0.1":
            print "check of [ " + remote_ip + " ]"
            assert state == "BGP_FSM_ESTABLISHED"
            assert e_transitions == 1
        else:
            print "check of [ " + remote_ip + " ]"
            assert remote_ip == "10.0.0.100"

    # get notification message from exabgp log
    err_msg = fab.get_notification_from_exabgp_log()
    notification = None
    parse_msg = re.search(r'error.*', err_msg)
    if parse_msg is not None:
        notification_src = parse_msg.group(0)[5:]
        notification = notification_src[1:-1]

    print "notification message : "
    print " >>> " + str(notification)

    # check notification messege
    assert notification == result


# get address of each neighbor from gobpg configration
def get_neighbor_address():
    address = []
    try:
        gobgp_config = toml.loads(open(gobgp_config_file).read())
        neighbors_config = gobgp_config['NeighborList']
        for neighbor_config in neighbors_config:
            neighbor_ip = neighbor_config['NeighborAddress']
            address.append(neighbor_ip)

    except IOError, (errno, strerror):
        print "I/O error(%s): %s" % (errno, strerror)

    return address

if __name__ == '__main__':
    if fab.test_user_check() is False:
        print "you are not root."
        sys.exit(1)
    if fab.docker_pkg_check() is False:
        print "not install docker package."
        sys.exit(1)
    nose.main(argv=sys.argv, addplugins=[OptionParser()], defaultTest=sys.argv[0])