# Copyright (C) 2026 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import collections
import ipaddress
import json
import sys
import time
import unittest

collections.Callable = collections.abc.Callable


from lib import base
from lib import utils
from lib.base import (
    BGP_FSM_ESTABLISHED,
    BGPContainer,
    assert_several_times,
    local,
    Bridge,
)
from lib.gobgp import GoBGPContainer
from lib.noseplugin import parser_option


TCP_MD5_PASSWORD = 'password'
DYNAMIC_NEIGHBOR_PREFIX = '172.17.0.0/16'
NETSHOOT_IMAGE = 'nicolaka/netshoot:v0.15'
VRF_BIND_INTERFACE = 'vrf-md5'


def _netshoot(ctn, cmd):
    return local('docker run --rm --privileged=true --net container:{0} '
                 '{1} {2}'.format(ctn.docker_name(), NETSHOOT_IMAGE, cmd),
                 capture=True)


def _expected_md5keys(ctn, peer):
    info = ctn.peers[peer]
    if info['interface'] != '':
        addr = ctn.get_neighbor(peer)['state']['neighbor_address']
    else:
        addr = info['neigh_addr'].split('/')[0]
    addr = addr.split('%')[0]
    prefixlen = 128 if ':' in addr else 32
    return 'md5keys:{0}/{1}={2}'.format(
        addr,
        prefixlen,
        TCP_MD5_PASSWORD,
    )


def _assert_md5keys(test, ctn, peer):
    expected = _expected_md5keys(ctn, peer)
    _assert_md5keys_entry(test, ctn, expected)


def _assert_md5keys_entry(test, ctn, expected, established=True,
                          listen=True):
    def f():
        if established:
            test.assertIn(expected, _netshoot(ctn, 'ss -tni'))
        if listen:
            test.assertIn(expected, _netshoot(ctn, 'ss -tlni'))

    assert_several_times(f, t=10, s=1)


def _wait_dynamic_established(ctn, peer_addr):
    def f():
        peer = json.loads(ctn.local('gobgp -j neighbor {0}'.format(peer_addr),
                                    capture=True))
        if peer['state']['session_state'] != 6:
            raise AssertionError

    assert_several_times(f, t=120, s=1)


def _setup_vrf_device(ctn, table_id):
    subnet = ipaddress.ip_network(ctn.ip_addrs[0][1], strict=False)

    # The osrg/quagga-based test image has an old iproute2 that cannot create
    # VRF devices. Run netshoot in the same network namespace and use its
    # iproute2 instead.
    _netshoot(ctn, 'ip link add {0} type vrf table {1}'.format(
        VRF_BIND_INTERFACE,
        table_id,
    ))
    _netshoot(ctn, 'ip link set dev {0} up'.format(VRF_BIND_INTERFACE))
    _netshoot(ctn, 'ip link set dev eth0 master {0}'.format(
        VRF_BIND_INTERFACE,
    ))
    _netshoot(ctn, 'ip route replace table {0} {1} dev eth0'.format(
        table_id,
        subnet,
    ))


class GoBGPTCPMD5Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        g1 = GoBGPContainer(name='md5-g1', asn=65000,
                            router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        g2 = GoBGPContainer(name='md5-g2', asn=65001,
                            router_id='192.168.0.2',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)

        ctns = [g1, g2]

        initial_wait_time = max(ctn.run() for ctn in ctns)
        time.sleep(initial_wait_time)

        g1.add_peer(g2, passwd=TCP_MD5_PASSWORD)
        g2.add_peer(g1, passwd=TCP_MD5_PASSWORD, passive=True)

        cls.g1 = g1
        cls.g2 = g2

    def test_01_neighbor_established(self):
        self.g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g2)
        self.g2.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g1)


class GoBGPTCPMD5UnnumberedTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        g1 = GoBGPContainer(name='g1', asn=65000,
                            router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        g2 = GoBGPContainer(name='g2', asn=65001,
                            router_id='192.168.0.2',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)

        ctns = [g1, g2]

        initial_wait_time = max(ctn.run() for ctn in ctns)
        time.sleep(initial_wait_time)

        br = Bridge(name='unnumbered', subnet='fd00:179:5::/64')
        [br.addif(ctn) for ctn in [g1, g2]]

        utils.probe_link_local_address(g1, g2, 'eth1', 'eth1')

        g1.add_peer(g2, interface='eth1', passwd=TCP_MD5_PASSWORD)
        g2.add_peer(g1, interface='eth1', passwd=TCP_MD5_PASSWORD,
                    passive=True)

        cls.g1 = g1
        cls.g2 = g2

    def test_01_neighbor_established(self):
        self.g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g2)
        self.g2.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g1)

    def test_02_md5keys_are_set(self):
        _assert_md5keys(self, self.g1, self.g2)
        _assert_md5keys(self, self.g2, self.g1)


class GoBGPTCPMD5DynamicNeighborTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        g1 = GoBGPContainer(name='g1', asn=65000,
                            router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level,
                            bgp_config={
                                'peer-groups': [
                                    {
                                        'config': {
                                            'peer-group-name': 'PG1',
                                            'peer-as': 65001,
                                            'auth-password': TCP_MD5_PASSWORD,
                                        },
                                    },
                                ],
                                'dynamic-neighbors': [
                                    {
                                        'config': {
                                            'prefix': DYNAMIC_NEIGHBOR_PREFIX,
                                            'peer-group': 'PG1',
                                        },
                                    },
                                ],
                            })
        g2 = GoBGPContainer(name='g2', asn=65001,
                            router_id='192.168.0.2',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)

        ctns = [g1, g2]

        initial_wait_time = max(ctn.run() for ctn in ctns)
        time.sleep(initial_wait_time)

        g2.add_peer(g1, passwd=TCP_MD5_PASSWORD)

        cls.g1 = g1
        cls.g2 = g2
        cls.g2_addr = g2.ip_addrs[0][1].split('/')[0]

    def test_01_neighbor_established(self):
        self.g2.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g1)
        _wait_dynamic_established(self.g1, self.g2_addr)

    def test_02_md5keys_are_set(self):
        self.g2.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g1)
        _wait_dynamic_established(self.g1, self.g2_addr)
        expected = 'md5keys:{0}={1}'.format(
            DYNAMIC_NEIGHBOR_PREFIX,
            TCP_MD5_PASSWORD,
        )
        _assert_md5keys_entry(self, self.g1, expected, established=False)
        expected = 'md5keys:{0}/32={1}'.format(
            self.g2_addr,
            TCP_MD5_PASSWORD,
        )
        _assert_md5keys_entry(self, self.g1, expected, listen=False)
        _assert_md5keys(self, self.g2, self.g1)


class GoBGPTCPMD5BindInterfaceVRFTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        g1 = GoBGPContainer(name='vrf-g1', asn=65000,
                            router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level,
                            bgp_config={
                                'global': {
                                    'config': {
                                        'bind-to-device': VRF_BIND_INTERFACE,
                                    },
                                },
                            })
        g2 = GoBGPContainer(name='vrf-g2', asn=65001,
                            router_id='192.168.0.2',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level,
                            bgp_config={
                                'global': {
                                    'config': {
                                        'bind-to-device': VRF_BIND_INTERFACE,
                                    },
                                },
                            })

        ctns = [g1, g2]

        initial_wait_time = max(BGPContainer.run(ctn) for ctn in ctns)
        time.sleep(initial_wait_time)

        _setup_vrf_device(g1, 1010)
        _setup_vrf_device(g2, 2020)

        g1.start_gobgp()
        g2.start_gobgp()

        g1.add_peer(g2, passwd=TCP_MD5_PASSWORD, passive=True,
                    bind_interface=VRF_BIND_INTERFACE)
        g2.add_peer(g1, passwd=TCP_MD5_PASSWORD,
                    bind_interface=VRF_BIND_INTERFACE)

        cls.g1 = g1
        cls.g2 = g2

    def test_01_neighbor_established(self):
        self.g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g2)
        self.g2.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g1)

    def test_02_md5keys_are_set(self):
        # ss exposes MD5 keys through INET_DIAG_MD5SIG, but that data does not
        # include key ifindex. So we just check that the keys are set without
        # error and we don't check the ifindex part of the key.
        _assert_md5keys(self, self.g1, self.g2)
        _assert_md5keys(self, self.g2, self.g1)


