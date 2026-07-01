import pytest
from lib.noseplugin import parser_option


def pytest_addoption(parser):
    parser.addoption('--test-prefix', default='')
    parser.addoption('--gobgp-image', default='osrg/gobgp')
    parser.addoption('--exabgp-path', default='')
    parser.addoption('--go-path', default='')
    parser.addoption('--gobgp-log-level', default='info')
    parser.addoption('--test-index', type=int, default=0)
    parser.addoption('--config-format', default='yaml')


def pytest_configure(config):
    parser_option.test_prefix = config.getoption('--test-prefix')
    parser_option.gobgp_image = config.getoption('--gobgp-image')
    parser_option.exabgp_path = config.getoption('--exabgp-path')
    parser_option.go_path = config.getoption('--go-path')
    parser_option.gobgp_log_level = config.getoption('--gobgp-log-level')
    parser_option.test_index = config.getoption('--test-index')
    parser_option.config_format = config.getoption('--config-format')
