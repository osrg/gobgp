import math
import os

import pytest
from lib import base
from lib.noseplugin import parser_option


def _parse_timeout_scale(value):
    try:
        scale = float(value)
    except (TypeError, ValueError):
        raise pytest.UsageError('--timeout-scale must be a number')

    if not math.isfinite(scale) or scale < 1.0:
        raise pytest.UsageError('--timeout-scale must be a finite number greater than or equal to 1.0')
    return scale


def pytest_addoption(parser):
    parser.addoption('--test-prefix', default='')
    parser.addoption('--gobgp-image', default='osrg/gobgp')
    parser.addoption('--exabgp-path', default='')
    parser.addoption('--go-path', default='')
    parser.addoption('--gobgp-log-level', default='info')
    parser.addoption('--test-index', type=int, default=0)
    parser.addoption('--config-format', default='yaml')
    parser.addoption(
        '--skip-docker-cleanup',
        action='store_true',
        default=os.environ.get('GOBGP_SKIP_DOCKER_CLEANUP') == '1',
        help='skip automatic cleanup of scenario-test Docker resources',
    )
    parser.addoption(
        '--timeout-scale',
        default=os.environ.get('GOBGP_TEST_TIMEOUT_SCALE', '1.0'),
        help='multiply default scenario-test wait timeouts by this factor',
    )


def pytest_configure(config):
    parser_option.test_prefix = config.getoption('--test-prefix')
    parser_option.gobgp_image = config.getoption('--gobgp-image')
    parser_option.exabgp_path = config.getoption('--exabgp-path')
    parser_option.go_path = config.getoption('--go-path')
    parser_option.gobgp_log_level = config.getoption('--gobgp-log-level')
    parser_option.test_index = config.getoption('--test-index')
    parser_option.config_format = config.getoption('--config-format')
    parser_option.skip_docker_cleanup = config.getoption('--skip-docker-cleanup')
    parser_option.timeout_scale = _parse_timeout_scale(config.getoption('--timeout-scale'))


def _manage_docker_state(config):
    if config.option.collectonly:
        return False
    if getattr(parser_option, 'skip_docker_cleanup', False):
        return False
    # Some tests use --test-index -1 only to print the scenario count. That
    # path must stay side-effect free, otherwise simple discovery would require
    # a working Docker daemon.
    if getattr(parser_option, 'test_index', 0) < 0:
        return False
    return True


def pytest_sessionstart(session):
    if not _manage_docker_state(session.config):
        return
    base.cleanup_docker_leftovers()


def _shares_test_lifecycle(item, nextitem):
    # Several scenario files are unittest.TestCase classes with setUpClass
    # owning live containers for multiple test methods. Cleaning after every
    # pytest item would delete that shared topology before the next method.
    if nextitem is None:
        return False
    item_cls = getattr(item, 'cls', None)
    if item_cls is None:
        return False
    return getattr(nextitem, 'cls', None) is item_cls


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_teardown(item, nextitem):
    # Wait for fixture finalizers and tearDownClass before removing their containers.
    yield
    if not _manage_docker_state(item.config):
        return
    # Function-style tests are cleaned after each item; unittest classes are
    # cleaned after the last method that shares the same setUpClass lifecycle.
    if not _shares_test_lifecycle(item, nextitem):
        base.cleanup_docker_leftovers()


def pytest_sessionfinish(session, exitstatus):
    if not _manage_docker_state(session.config):
        return
    base.cleanup_docker_leftovers()
