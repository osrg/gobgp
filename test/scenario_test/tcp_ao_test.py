# Copyright (C) 2026 The GoBGP Authors.
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


import base64
import collections
import ipaddress
import sys
import time
import unittest

collections.Callable = collections.abc.Callable


from lib import base
from lib import utils
from lib.base import (
    BGP_FSM_ESTABLISHED,
    BGPContainer,
    Bridge,
    assert_several_times,
    local,
)
from lib.gobgp import GoBGPContainer
from lib.noseplugin import parser_option


NETSHOOT_IMAGE = 'nicolaka/netshoot:v0.15'
VRF_BIND_INTERFACE = 'vrf-ao'

# Frequent keepalives make post-rotation traffic checks quick, while short
# retry and idle timers keep the forced reconnect within the test timeout.
TCP_AO_TIMERS = {
    'connect-retry': 1,
    'hold-time': 9,
    'keepalive-interval': 1,
    'idle-hold-time-after-reset': 1,
}

KeyProfile = collections.namedtuple(
    'KeyProfile', 'algorithm g1_send_id g2_send_id secret')

KEY_PROFILES = [
    KeyProfile('hmac-sha-1-96', 10, 20, b'tcp-ao-scenario-initial'),
    KeyProfile('aes-128-cmac-96', 11, 21, b'tcp-ao-scenario-rotation2'),
    KeyProfile('hmac-sha-256-96', 12, 22, b'tcp-ao-scenario-rotation3'),
    KeyProfile('hmac-sha-256-128', 13, 23, b'tcp-ao-scenario-rotation4'),
]
INITIAL_PROFILE = KEY_PROFILES[0]


def _netshoot(ctn, cmd):
    return local('docker run --rm --privileged=true --net container:{0} '
                 '{1} {2}'.format(ctn.docker_name(), NETSHOOT_IMAGE, cmd),
                 capture=True)


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


def _key(send_id, receive_id, algorithm, secret):
    return {
        'config': {
            'key-id': send_id,
            'receive-id': receive_id,
            'crypto-algorithm': algorithm,
            'secret-key': base64.b64encode(secret).decode('ascii'),
        },
    }


def _key_pair(profile):
    return (_key(profile.g1_send_id, profile.g2_send_id,
                 profile.algorithm, profile.secret),
            _key(profile.g2_send_id, profile.g1_send_id,
                 profile.algorithm, profile.secret))


def _initial_keys():
    g1_key, g2_key = _key_pair(INITIAL_PROFILE)
    return [g1_key], [g2_key]


def _keychain(name, keys):
    return {'config': {'name': name}, 'keys': keys}


def _tcp_ao_config(name, preferred_send_id):
    return {
        'keychain': name,
        'send-id': preferred_send_id,
    }


def _assert_keepalives_advance(test, endpoints):
    counts = [endpoint.received_keepalives() for endpoint in endpoints]

    def f():
        for endpoint, count in zip(endpoints, counts):
            test.assertGreater(endpoint.received_keepalives(), count)

    assert_several_times(f, t=10, s=1)


def _rotate_keys(test, g1, g2, *, dialer, profile, delete_old_keys):
    """Install, activate, and reconnect with one new key profile."""
    previous_g1_id = g1.latest_key_id
    previous_g2_id = g2.latest_key_id
    flops_before = (g1.flop_count(), g2.flop_count())
    new_g1_key, new_g2_key = _key_pair(profile)
    g1.keys.append(new_g1_key)
    g2.keys.append(new_g2_key)

    # Install the new keys on both peers before either sends with them.
    g1.reload_config(previous_g1_id)
    g2.reload_config(previous_g2_id)
    g1.assert_selected(test, previous_g1_id)
    g2.assert_selected(test, previous_g2_id)

    # Switch both send IDs and check that the live session stays up.
    g1.reload_config(g1.latest_key_id)
    g2.reload_config(g2.latest_key_id)
    g1.assert_selected(test, g1.latest_key_id)
    g2.assert_selected(test, g2.latest_key_id)
    _assert_keepalives_advance(test, (g1, g2))
    g1.wait_established()
    g2.wait_established()
    test.assertEqual(flops_before, (g1.flop_count(), g2.flop_count()))

    # Reconnect to exercise the active dial and passive accept paths with the
    # new preferred key.
    dialer.container.stop_gobgp()
    dialer.container.start_gobgp()
    g1.wait_established()
    g2.wait_established()
    g1.assert_selected(test, g1.latest_key_id)
    g2.assert_selected(test, g2.latest_key_id)

    # Delete old keys
    if delete_old_keys:
        flops_before = (g1.flop_count(), g2.flop_count())
        del g1.keys[:-1]
        del g2.keys[:-1]
        g1.reload_config(g1.latest_key_id)
        g2.reload_config(g2.latest_key_id)
        g1.assert_selected(test, g1.latest_key_id)
        g2.assert_selected(test, g2.latest_key_id)
        _assert_keepalives_advance(test, (g1, g2))
        test.assertEqual(flops_before, (g1.flop_count(), g2.flop_count()))


def _test_key_rotation(test, g1, g2, *, dialer,
                       delete_old_keys=True):
    g1.wait_established()
    g2.wait_established()
    g1.assert_selected(test, g1.latest_key_id)
    g2.assert_selected(test, g2.latest_key_id)

    for profile in KEY_PROFILES[1:]:
        _rotate_keys(test, g1, g2, dialer=dialer, profile=profile,
                     delete_old_keys=delete_old_keys)


class _TCPAOEndpoint:
    """One peer's container, neighbor, and mutable TCP-AO keychain."""

    def __init__(self, container, neighbor, keychain, keys):
        self.container = container
        self.neighbor = neighbor
        self.keychain = keychain
        self.keys = keys

    @property
    def latest_key_id(self):
        return self.keys[-1]['config']['key-id']

    @property
    def key_ids(self):
        return [key['config']['key-id'] for key in self.keys]

    def wait_established(self):
        self.container.wait_for(expected_state=BGP_FSM_ESTABLISHED,
                                peer=self.neighbor)

    def flop_count(self):
        return self.container.get_neighbor(self.neighbor)['state'].get(
            'flops', 0)

    def received_keepalives(self):
        state = self.container.get_neighbor(self.neighbor)['state']
        return state['messages']['received'].get('keepalive', 0)

    def reload_config(self, send_id):
        self.container.bgp_config['keychains'] = [
            _keychain(self.keychain, self.keys)]
        self.container.peers[self.neighbor]['tcp_ao']['send-id'] = send_id
        self.container.create_config()
        self.container.reload_config()

    def assert_selected(self, test, send_id):
        def f():
            state = self.container.get_neighbor(self.neighbor)[
                'state']['tcp_ao_state']
            keys = {key['send_id']: key for key in state['keys']}
            test.assertEqual(set(self.key_ids), set(keys))
            test.assertTrue(keys[send_id].get('current', False))
            test.assertTrue(keys[send_id].get('receive_next', False))

        assert_several_times(f, t=10, s=1)


class GoBGPTCPAOTest(unittest.TestCase):

    def setUp(self):
        base.TEST_PREFIX = parser_option.test_prefix

    def tearDown(self):
        if not getattr(parser_option, 'skip_docker_cleanup', False):
            base.cleanup_docker_leftovers()

    def test_01_peering_and_key_rotation(self):
        """Establish TCP-AO peering and rotate keys across algorithms."""
        g1_keys, g2_keys = _initial_keys()
        g1 = GoBGPContainer(
            name='ao-g1', asn=65000, router_id='192.168.0.1',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={'keychains': [
                _keychain('g1-chain', g1_keys),
            ]})
        g2 = GoBGPContainer(
            name='ao-g2', asn=65001, router_id='192.168.0.2',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={'keychains': [
                _keychain('g2-chain', g2_keys),
            ]})

        time.sleep(max(g1.run(), g2.run()))
        g1.add_peer(
            g2,
            tcp_ao=_tcp_ao_config(
                'g1-chain', INITIAL_PROFILE.g1_send_id),
            timers=TCP_AO_TIMERS)
        g2.add_peer(
            g1, passive=True,
            tcp_ao=_tcp_ao_config(
                'g2-chain', INITIAL_PROFILE.g2_send_id),
            timers=TCP_AO_TIMERS)

        g1_endpoint = _TCPAOEndpoint(container=g1, neighbor=g2,
                                     keychain='g1-chain', keys=g1_keys)
        g2_endpoint = _TCPAOEndpoint(container=g2, neighbor=g1,
                                     keychain='g2-chain', keys=g2_keys)
        _test_key_rotation(self, g1_endpoint, g2_endpoint, dialer=g1_endpoint)

    def test_02_peer_with_wrong_secret_does_not_establish(self):
        """Verify peers with mismatched TCP-AO secrets stay down."""
        g1_keys, g2_keys = _initial_keys()
        g2_keys[0]['config']['secret-key'] = base64.b64encode(
            b'tcp-ao-scenario-wrong-secret').decode('ascii')

        g1 = GoBGPContainer(
            name='ao-wrong-g1', asn=65000, router_id='192.168.0.1',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={'keychains': [_keychain('g1-chain', g1_keys)]})
        g2 = GoBGPContainer(
            name='ao-wrong-g2', asn=65001, router_id='192.168.0.2',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={'keychains': [_keychain('g2-chain', g2_keys)]})

        time.sleep(max(g1.run(), g2.run()))
        g1.add_peer(
            g2, tcp_ao=_tcp_ao_config(
                'g1-chain', INITIAL_PROFILE.g1_send_id),
            timers=TCP_AO_TIMERS)
        g2.add_peer(
            g1, passive=True, tcp_ao=_tcp_ao_config(
                'g2-chain', INITIAL_PROFILE.g2_send_id),
            timers=TCP_AO_TIMERS)

        # Sample across several connect retries; a single state check could
        # pass before an incorrectly authenticated session comes up.
        for _ in range(10):
            self.assertNotEqual(g1.get_neighbor_state(g2), BGP_FSM_ESTABLISHED)
            self.assertNotEqual(g2.get_neighbor_state(g1), BGP_FSM_ESTABLISHED)
            time.sleep(1)

    def test_03_unnumbered_peering(self):
        """Establish TCP-AO peering through IPv6 link-local addresses."""
        g1_keys, g2_keys = _initial_keys()
        g1 = GoBGPContainer(
            name='ao-unnumbered-g1', asn=65000, router_id='192.168.0.1',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={'keychains': [_keychain('g1-chain', g1_keys)]})
        g2 = GoBGPContainer(
            name='ao-unnumbered-g2', asn=65001, router_id='192.168.0.2',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={'keychains': [_keychain('g2-chain', g2_keys)]})

        time.sleep(max(g1.run(), g2.run()))
        bridge = Bridge(name='ao-unnumbered', subnet='fd00:179:6::/64')
        bridge.addif(g1)
        bridge.addif(g2)
        utils.probe_link_local_address(g1, g2, 'eth1', 'eth1')

        g1.add_peer(
            g2, interface='eth1',
            tcp_ao=_tcp_ao_config(
                'g1-chain', INITIAL_PROFILE.g1_send_id),
            timers=TCP_AO_TIMERS)
        g2.add_peer(
            g1, interface='eth1', passive=True,
            tcp_ao=_tcp_ao_config(
                'g2-chain', INITIAL_PROFILE.g2_send_id),
            timers=TCP_AO_TIMERS)

        g1_endpoint = _TCPAOEndpoint(container=g1, neighbor=g2,
                                     keychain='g1-chain', keys=g1_keys)
        g2_endpoint = _TCPAOEndpoint(container=g2, neighbor=g1,
                                     keychain='g2-chain', keys=g2_keys)
        g1_endpoint.wait_established()
        g2_endpoint.wait_established()
        g1_endpoint.assert_selected(self, INITIAL_PROFILE.g1_send_id)
        g2_endpoint.assert_selected(self, INITIAL_PROFILE.g2_send_id)

    def test_04_linux_vrf_device_peering_and_key_rotation(self):
        """Rotate AO keys on peers bound to Linux VRF devices."""
        g1_keys, g2_keys = _initial_keys()
        g1 = GoBGPContainer(
            name='ao-bind-vrf-g1', asn=65000, router_id='192.168.0.1',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={
                'global': {'config': {
                    'bind-to-device': VRF_BIND_INTERFACE,
                }},
                'keychains': [_keychain('g1-vrf-chain', g1_keys)],
            })
        g2 = GoBGPContainer(
            name='ao-bind-vrf-g2', asn=65001, router_id='192.168.0.2',
            ctn_image_name=parser_option.gobgp_image,
            log_level=parser_option.gobgp_log_level,
            bgp_config={
                'global': {'config': {
                    'bind-to-device': VRF_BIND_INTERFACE,
                }},
                'keychains': [_keychain('g2-vrf-chain', g2_keys)],
            })

        time.sleep(max(BGPContainer.run(ctn) for ctn in [g1, g2]))
        _setup_vrf_device(g1, 1010)
        _setup_vrf_device(g2, 2020)
        g1.start_gobgp()
        g2.start_gobgp()
        g1.add_peer(
            g2, passive=True, bind_interface=VRF_BIND_INTERFACE,
            tcp_ao=_tcp_ao_config('g1-vrf-chain',
                                  INITIAL_PROFILE.g1_send_id),
            timers=TCP_AO_TIMERS)
        g2.add_peer(
            g1, bind_interface=VRF_BIND_INTERFACE,
            tcp_ao=_tcp_ao_config('g2-vrf-chain',
                                  INITIAL_PROFILE.g2_send_id),
            timers=TCP_AO_TIMERS)

        g1_endpoint = _TCPAOEndpoint(container=g1, neighbor=g2,
                                     keychain='g1-vrf-chain', keys=g1_keys)
        g2_endpoint = _TCPAOEndpoint(container=g2, neighbor=g1,
                                     keychain='g2-vrf-chain', keys=g2_keys)

        # Keep delete_old_keys=False until the CI kernel includes the fix for
        # VRF-scoped TCP-AO key deletion:
        # https://github.com/torvalds/linux/commit/94ad9e114a1c7b16ea418c1456ac3835e038ab3f
        _test_key_rotation(self, g1_endpoint, g2_endpoint, dialer=g2_endpoint,
                           delete_old_keys=False)


if __name__ == '__main__':
    sys.exit(unittest.main())
