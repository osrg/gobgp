# Copyright (C) 2022 Yuya Kusakabe <yuya.kusakabe@gmail.com>
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


from itertools import combinations
import sys
import time
import unittest
import logging
log = logging.getLogger(__name__)

import collections
collections.Callable = collections.abc.Callable

import nose

from lib.noseplugin import OptionParser, parser_option

from lib import base
from lib.base import (
    BGP_FSM_ESTABLISHED,
    BGP_ATTR_TYPE_EXTENDED_COMMUNITIES,
    local,
)
from lib.gobgp import GoBGPContainer


class GoBGPTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        g1 = GoBGPContainer(name='g1', asn=65000, router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        g2 = GoBGPContainer(name='g2', asn=65000, router_id='192.168.0.2',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        ctns = [g1, g2]

        initial_wait_time = max(ctn.run() for ctn in ctns)

        time.sleep(initial_wait_time)

        for a, b in combinations(ctns, 2):
             a.add_peer(b, mup=True, passwd='mup')
             b.add_peer(a, mup=True, passwd='mup')

        cls.g1 = g1
        cls.g2 = g2


    # test each neighbor state is turned establish
    def test_01_neighbor_established(self):
        self.g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g2)


    def test_02_add_del_mup_route(self):
        tests = [
                ('mup_isd_route_ipv4', 'ipv4-mup', 'isd 10.0.0.0/24 rd 100:100 prefix 2001:db8:1:1::/64 locator-node-length 24 function-length 16 behavior ENDM_GTP4E rt 10:10 nexthop 2001::2', '2001::2'),
                ('mup_dsd_route_ipv4', 'ipv4-mup', 'dsd 10.0.0.1 rd 100:100 prefix 2001:db8:2:2::/64 locator-node-length 24 function-length 16 behavior END_DT4 rt 10:10 mup 10:10 nexthop 2001::2', '2001::2'),
                ('mup_t1st_route_ipv4', 'ipv4-mup', 't1st 192.168.0.1/32 rd 100:100 rt 10:10 teid 12345 qfi 9 endpoint 10.0.0.1 nexthop 10.0.0.2', '10.0.0.2'),
                ('mup_t1st_route_ipv4_hex_teid', 'ipv4-mup', 't1st 192.168.0.1/32 rd 100:100 rt 10:10 teid 0x00003039 qfi 9 endpoint 10.0.0.1 nexthop 10.0.0.2', '10.0.0.2'),
                ('mup_t1st_route_ipv4_ip_teid', 'ipv4-mup', 't1st 192.168.0.1/32 rd 100:100 rt 10:10 teid 0.0.0.100 qfi 9 endpoint 10.0.0.1 nexthop 10.0.0.2', '10.0.0.2'),
                ('mup_t2st_route_ipv4', 'ipv4-mup', 't2st 10.0.0.1 rd 100:100 rt 10:10 endpoint-address-length 64 teid 12345 mup 10:10 nexthop 10.0.0.2', '10.0.0.2'),
                ('mup_t2st_route_ipv4_hex_teid', 'ipv4-mup', 't2st 10.0.0.1 rd 100:100 rt 10:10 endpoint-address-length 48 teid 0xbeef mup 10:10 nexthop 10.0.0.2', '10.0.0.2'),
                ('mup_t2st_route_ipv4_ip_teid', 'ipv4-mup', 't2st 10.0.0.1 rd 100:100 rt 10:10 endpoint-address-length 64 teid 0.0.0.100 mup 10:10 nexthop 10.0.0.2', '10.0.0.2'),
                ('mup_isd_route_ipv6', 'ipv6-mup', 'isd 2001::/64 rd 100:100 prefix 2001:db8:1:1::/64 locator-node-length 24 function-length 16 behavior ENDM_GTP6E rt 10:10 nexthop 2001::2', '2001::2'),
                ('mup_dsd_route_ipv6', 'ipv6-mup', 'dsd 2001::1 rd 100:100 prefix 2001:db8:2:2::/64 locator-node-length 24 function-length 16 behavior END_DT6 rt 10:10 mup 10:10 nexthop 2001::2', '2001::2'),
                ('mup_t1st_route_ipv6', 'ipv6-mup', 't1st 2001:db8:1:1::1/128 rd 100:100 rt 10:10 teid 12345 qfi 9 endpoint 2001::1 nexthop 10.0.0.2', '10.0.0.2'),
                ('mup_t1st_route_ipv6_hex_teid', 'ipv6-mup', 't1st 2001:db8:1:1::1/128 rd 100:100 rt 10:10 teid 0x00003039 qfi 9 endpoint 2001::1 nexthop 10.0.0.2', '10.0.0.2'),
                ('mup_t1st_route_ipv6_ip_teid', 'ipv6-mup', 't1st 2001:db8:1:1::1/128 rd 100:100 rt 10:10 teid 0.0.0.100 qfi 9 endpoint 2001::1 nexthop 10.0.0.2', '10.0.0.2'),
                ('mup_t2st_route_ipv6', 'ipv6-mup', 't2st 2001::1 rd 100:100 rt 10:10 endpoint-address-length 160 teid 12345 mup 10:10 nexthop 10.0.0.2', '10.0.0.2'),
                ('mup_t2st_route_ipv6_hex_teid', 'ipv6-mup', 't2st 2001::1 rd 100:100 rt 10:10 endpoint-address-length 144 teid 0xbeef mup 10:10 nexthop 10.0.0.2', '10.0.0.2'),
                ('mup_t2st_route_ipv6_ip_teid', 'ipv6-mup', 't2st 2001::1 rd 100:100 rt 10:10 endpoint-address-length 160 teid 0.0.0.100 mup 10:10 nexthop 10.0.0.2', '10.0.0.2'),
                ]
        for msg, rf, route, nh in tests:
            with self.subTest(msg):
                self.g1.local('gobgp global rib add '
                              '-a {} {}'.format(rf, route))
                grib = self.g1.get_global_rib(rf=rf)
                log.debug('grib: {}'.format(grib))
                self.assertEqual(len(grib), 1)
                dst = grib[0]
                self.assertEqual(len(dst['paths']), 1)
                path = dst['paths'][0]
                self.assertEqual(path['nexthop'], nh)

                interval = 1
                timeout = int(30 / interval)
                done = False
                for _ in range(timeout):
                    if done:
                        break
                    grib = self.g2.get_global_rib(rf=rf)

                    if len(grib) < 1:
                        time.sleep(interval)
                        continue

                    self.assertEqual(len(grib), 1)
                    dst = grib[0]
                    self.assertEqual(len(dst['paths']), 1)
                    path = dst['paths'][0]
                    n_addrs = [i[1].split('/')[0] for i in self.g1.ip_addrs]
                    self.assertEqual(path['nexthop'], nh)
                    done = True

                self.g1.local('gobgp global rib del '
                              '-a {} {}'.format(rf, route))

                done = False
                for _ in range(timeout):
                    if done:
                        break
                    grib = self.g2.get_global_rib(rf=rf)

                    if len(grib) > 0:
                        time.sleep(interval)
                        continue
                    done = True


if __name__ == '__main__':
    output = local("which docker 2>&1 > /dev/null ; echo $?", capture=True)
    if int(output) != 0:
        print("docker not found")
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
