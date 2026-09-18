"""Docker cleanup and pytest lifecycle regressions; no daemon required."""
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock, call

import pytest

from lib import base

SCENARIO_DIR = Path(__file__).resolve().parents[1] / 'scenario_test'


@pytest.mark.parametrize('options', [[], ['--collect-only'], ['--skip-docker-cleanup'],
                                    ['--test-index', '-1'], ['-x']])
def test_pytest_lifecycle(tmp_path, options):
    events = tmp_path / 'events'
    plugin = (SCENARIO_DIR / 'conftest.py').read_text()
    plugin += '''
from pathlib import Path
EVENTS = Path(%r)
def record(event):
    with EVENTS.open('a') as output:
        output.write(event + '\\n')
base.cleanup_docker_leftovers = lambda: record('cleanup')
''' % str(events)
    (tmp_path / 'conftest.py').write_text(plugin)
    (tmp_path / 'test_lifecycle.py').write_text('''
import unittest
from conftest import record
class TestTopology(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        record('setup')
    def test_1(self):
        record('first')
        FAIL
    def test_2(self):
        record('second')
    @classmethod
    def tearDownClass(cls):
        record('teardown')
'''.replace('FAIL', 'self.fail("expected")' if '-x' in options else 'pass'))
    env = os.environ.copy()
    env['PYTHONPATH'] = str(SCENARIO_DIR.parent)
    env.pop('GOBGP_SKIP_DOCKER_CLEANUP', None)
    result = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-s', str(tmp_path), *options],
                            env=env, capture_output=True, text=True)
    assert result.returncode == (1 if '-x' in options else 0), result.stdout + result.stderr
    actual = events.read_text().splitlines() if events.exists() else []
    if '--collect-only' in options:
        assert actual == []
    elif '--skip-docker-cleanup' in options or '--test-index' in options:
        assert actual == ['setup', 'first', 'second', 'teardown']
    else:
        methods = ['first'] if '-x' in options else ['first', 'second']
        assert actual == ['cleanup', 'setup', *methods, 'teardown', 'cleanup', 'cleanup']


def test_cleanup_filters_by_label_and_removes_containers_first(monkeypatch):
    local = Mock(side_effect=['c1 c2', '', 'n1', ''])
    monkeypatch.setattr(base, 'local', local)
    base.cleanup_docker_leftovers()
    assert local.call_args_list == [
        call('docker ps -aq -f label=gobgp-test', capture=True),
        call('docker rm -f c1 c2', capture=True),
        call('docker network ls -q -f label=gobgp-test', capture=True),
        call('docker network rm n1', capture=True),
    ]


def test_cleanup_without_leftovers_does_not_remove_anything(monkeypatch):
    local = Mock(return_value='')
    monkeypatch.setattr(base, 'local', local)
    base.cleanup_docker_leftovers()
    assert local.call_count == 2
    assert all(' rm ' not in invocation.args[0] for invocation in local.call_args_list)
