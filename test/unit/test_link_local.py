"""Link-local probing regressions; no Docker daemon required."""
import subprocess
from unittest.mock import Mock, call

import pytest

from lib import base, utils


def peers():
    a, b = Mock(), Mock()
    a.local.return_value = '2: eth1 inet6 fe80::a/64 scope link'
    b.local.return_value = '3: eth2 inet6 fe80::b/64 scope link'
    return a, b


def test_scoped_ping_does_not_require_reachable_neighbor_cache():
    a, b = peers()
    utils.probe_link_local_address(a, b, 'eth1', 'eth2')
    a.local.assert_any_call('ping6 -c 1 -W 1 fe80::b%eth1', timeout=5)
    b.local.assert_any_call('ping6 -c 1 -W 1 fe80::a%eth2', timeout=5)
    assert a.local.call_count == b.local.call_count == 2


@pytest.mark.parametrize('peer_index', [0, 1])
@pytest.mark.parametrize('error', [subprocess.CalledProcessError(1, 'ping6'),
                                   subprocess.TimeoutExpired('ping6', 5)])
def test_transient_ping_failure_retries_both_directions(monkeypatch, peer_index, error):
    a, b = peers()
    failed = (a, b)[peer_index]
    failed.local.side_effect = [failed.local.return_value, error, '']
    sleep = Mock()
    monkeypatch.setattr(base.time, 'sleep', sleep)
    utils.probe_link_local_address(a, b, 'eth1', 'eth2')
    sleep.assert_called_once()
    assert failed.local.call_count == 3


@pytest.mark.parametrize('error', [subprocess.CalledProcessError(1, 'ip'),
                                   subprocess.TimeoutExpired('ip', 5)])
def test_diagnostics_preserve_original_timeout(monkeypatch, error):
    a, b = peers()
    for peer in (a, b):
        peer.local.side_effect = [peer.local.return_value, error, error]
    original = RuntimeError('reachability timeout')
    monkeypatch.setattr(utils, 'wait_for', Mock(side_effect=original))
    with pytest.raises(RuntimeError) as raised:
        utils.probe_link_local_address(a, b, 'eth1', 'eth2')
    assert raised.value is original
    for peer, ifname in ((a, 'eth1'), (b, 'eth2')):
        assert peer.local.call_args_list[1:] == [
            call('ip -6 -o addr show dev ' + ifname, capture=True, timeout=5),
            call('ip -6 n show dev ' + ifname, capture=True, timeout=5),
        ]
