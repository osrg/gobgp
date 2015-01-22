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
import collections
import docker_control as fab

sleep_time = 20


def check_pattern():
    """
    if want to add test pattern, please write config name and notification message in this function.
    this tests is execute defined order.
    sample:
    pattern["<File to be used in test>"] = "<at that time the message>"
    """
    pattern = collections.OrderedDict()
    pattern["malformed1-exabgp-gobgp-v4-MP_REACH_NLRI.conf"] = "UPDATE message error / Attribute Flags Error / 0x600F0411223344"
    pattern["malformed1-exabgp-gobgp-v4-AS_PATH.conf"] = "UPDATE message error / Malformed AS_PATH"
    pattern["malformed1-exabgp-gobgp-v4-AS4_PATH.conf"] = "UPDATE message error / Malformed AS_PATH"

    return pattern


def test_malformed_packet():
    pwd = os.getcwd()
    pattern = check_pattern()
    if len(pattern) <= 0:
        print "read test patten is faild."
        print "csv element is " + str(len(pattern))
        sys.exit(1)

    for pkey in pattern:
        conf_file = pwd + "/exabgp_test_conf/" + pkey
        if os.path.isfile(conf_file) is True:
            fab.init_malformed_test_env_executor(pkey)
            print "please wait"
            time.sleep(sleep_time)
            yield check_em, pkey, pattern[pkey]

        else:
            print "config file not exists."
            print conf_file
            sys.exit(1)


def check_em(exabgp_conf, result):
    err_msg = fab.get_notification_from_exabgp_log()
    parse_msg = re.search(r'error.*', err_msg).group(0)
    notification_src = parse_msg[5:]

    print "notification message : "
    print " >>> " + notification_src
    notification = notification_src[1:-1]

    assert notification == result