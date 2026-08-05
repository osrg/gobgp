import math
import os

import pytest
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
    parser_option.timeout_scale = _parse_timeout_scale(config.getoption('--timeout-scale'))
