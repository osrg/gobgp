# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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
import time
import unittest

import collections
collections.Callable = collections.abc.Callable

import nose

from lib.noseplugin import OptionParser, parser_option

from lib import base
from lib.base import (
    assert_several_times,
    Bridge,
    BGP_FSM_ESTABLISHED,
    local,
)
from lib.gobgp import GoBGPContainer


class ZebraNHTTest(unittest.TestCase):
    """
    Test case for Next-Hop Tracking (NHT) with Zebra integration.

    Verifies that GoBGP correctly reacts to NEXTHOP_UPDATE messages from
    zebra by marking paths as reachable or unreachable, and propagates
    the resulting advertise/withdraw to BGP peers.

    OSPF is intentionally not used: nexthop reachability is driven by
    adding or removing a static route in r2's zebra, which is
    deterministic and keeps the test free of IGP convergence timing.

    Note: Quagga static routes always carry metric=0, so MED values are
    not validated here; MED handling is covered by unit tests.
    """

    # R1: GoBGP
    # R2: GoBGP + Zebra (static routes)
    #
    # +----+      +----+
    # | R1 |------| R2 |
    # +----+      +----+

    NEXTHOP = '10.3.1.1'
    PREFIX = '10.3.1.0/24'

    def _set_static_nexthop(self):
        # Point the static route at the r1-r2 bridge so zebra treats
        # the nexthop as reachable.
        self.r2.local(
            "vtysh -c 'configure terminal'"
            " -c 'ip route %s/32 192.168.12.1'"
            % self.NEXTHOP)

    def _remove_static_nexthop(self):
        self.r2.local(
            "vtysh -c 'configure terminal'"
            " -c 'no ip route %s/32 192.168.12.1'"
            % self.NEXTHOP)

    def _assert_best(self, rt, prefix):
        # Path is present and best ("*>").
        self.assertEqual(rt.local(
            "gobgp global rib -a ipv4 %s"
            " | grep '^\\*>' > /dev/null"
            " && echo OK || echo NG" % prefix,
            capture=True), 'OK')

    def _assert_not_best(self, rt, prefix):
        # Path is present but not best ("* ", not "*>").
        self.assertEqual(rt.local(
            "gobgp global rib -a ipv4 %s"
            " | grep '^\\* ' > /dev/null"
            " && echo OK || echo NG" % prefix,
            capture=True), 'OK')

    def _assert_no_prefix(self, rt, prefix):
        # Prefix is not in the table at all.
        self.assertEqual(rt.local(
            "gobgp global rib -a ipv4 %s"
            " | grep 'Network not in table' > /dev/null"
            " && echo OK || echo NG" % prefix,
            capture=True), 'OK')

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix
        cls.r1 = GoBGPContainer(
            name='r1', asn=65000, router_id='192.168.0.1',
            ctn_image_name=gobgp_ctn_image_name,
            log_level=parser_option.gobgp_log_level,
            zebra=False)

        cls.r2 = GoBGPContainer(
            name='r2', asn=65000, router_id='192.168.0.2',
            ctn_image_name=gobgp_ctn_image_name,
            log_level=parser_option.gobgp_log_level,
            zebra=True,
            zapi_version=3)

        wait_time = max(ctn.run() for ctn in [cls.r1, cls.r2])
        time.sleep(wait_time)

        cls.br_r1_r2 = Bridge(name='br_r1_r2', subnet='192.168.12.0/24')
        for ctn in (cls.r1, cls.r2):
            cls.br_r1_r2.addif(ctn)

    def test_01_BGP_neighbor_established(self):
        # Test to start BGP connection up between r1-r2.

        self.r1.add_peer(self.r2, bridge=self.br_r1_r2.name)
        self.r2.add_peer(self.r1, bridge=self.br_r1_r2.name)

        self.r1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.r2)

    def test_02_reachable_nexthop(self):
        # With the nexthop reachable via a static route, adding a BGP
        # path with that nexthop must result in the path being best on
        # r2 and reaching r1.
        self._set_static_nexthop()

        self.r2.local(
            'gobgp global rib add -a ipv4 %s nexthop %s'
            % (self.PREFIX, self.NEXTHOP))

        assert_several_times(
            f=lambda: self._assert_best(self.r2, self.PREFIX), t=60)
        assert_several_times(
            f=lambda: self._assert_best(self.r1, self.PREFIX), t=60)

    def test_03_nexthop_unreachable(self):
        # Remove the static route: nexthop becomes unreachable.
        # The existing path must transition from best to not-best on r2
        # and be withdrawn from r1. This exercises the
        # valid -> invalid transition path in GetChanges.
        self._remove_static_nexthop()

        assert_several_times(
            f=lambda: self._assert_not_best(self.r2, self.PREFIX), t=60)
        assert_several_times(
            f=lambda: self._assert_no_prefix(self.r1, self.PREFIX), t=60)

    def test_04_nexthop_restore(self):
        # Re-add the static route. The existing path must become best
        # again on r2 and be re-advertised to r1. This exercises the
        # invalid -> valid revalidation path.
        self._set_static_nexthop()

        assert_several_times(
            f=lambda: self._assert_best(self.r2, self.PREFIX), t=60)
        assert_several_times(
            f=lambda: self._assert_best(self.r1, self.PREFIX), t=60)

    def test_05_add_path_while_unreachable(self):
        # Make the nexthop unreachable again, then add a brand-new
        # path. The new path must be tracked as not-best on r2 and
        # must never be advertised to r1. This exercises the separate
        # code path where nexthop cache is applied to a newly added
        # path before propagation.
        self._remove_static_nexthop()

        prefix = '10.3.2.0/24'
        self.r2.local(
            'gobgp global rib add -a ipv4 %s nexthop %s'
            % (prefix, self.NEXTHOP))

        assert_several_times(
            f=lambda: self._assert_not_best(self.r2, prefix), t=60)
        assert_several_times(
            f=lambda: self._assert_no_prefix(self.r1, prefix), t=60)

    def test_06_restore_revalidates_new_path(self):
        # Re-add the static route. The new path added while unreachable
        # must now become best and be advertised to r1, confirming the
        # newly-added-invalid path can be revalidated.
        self._set_static_nexthop()

        assert_several_times(
            f=lambda: self._assert_best(self.r2, '10.3.2.0/24'), t=60)
        assert_several_times(
            f=lambda: self._assert_best(self.r1, '10.3.2.0/24'), t=60)


if __name__ == '__main__':
    output = local("which docker 2>&1 > /dev/null ; echo $?", capture=True)
    if int(output) != 0:
        print("docker not found")
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
