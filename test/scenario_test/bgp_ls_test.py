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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# BGP-LS scenario test. Two GoBGP speakers exchange the link-state address
# family; routes are injected on g1 with the CLI and must appear on g2 with
# their BGP-LS attribute intact, then disappear when withdrawn.

import time
import unittest
from lib.noseplugin import parser_option

from lib import base
from lib.base import (
    BGP_FSM_ESTABLISHED,
    wait_for,
)
from lib.gobgp import GoBGPContainer

BGP_ATTR_TYPE_LS = 29

RF_LS = 'ls'

HEADEND = ('local-asn 65000 local-bgp-router-id 192.168.0.1 '
           'local-router-id 10.0.0.1')

# SR Policy Candidate Path NLRIs (RFC 9857). Each entry is the CLI route
# argument, the substring that identifies it in the RIB and the checks on the
# sr_policy part of the received BGP-LS attribute.
SR_POLICY_ROUTES = [
    {
        'name': 'sr-mpls candidate path',
        'route': 'srpolicy identifier 0 {} endpoint 10.0.0.2 color 100 '
                 'originator-asn 65000 originator-address 192.168.0.1 discriminator 1 '
                 'policy-name blue cp-name cp1 bsid 24001 priority 10 preference 200 '
                 'state-flags AEV segment-list 1:16002,24006 2:16003 '
                 'constraint-flags AS constraint-algorithm 128 constraint-srlg 10 20 '
                 'constraint-disjoint-group 7:NL:L constraint-metric 1:O 2:B:0:500'.format(HEADEND),
        'nlri': 'IPv4 ROUTER ID: 10.0.0.1} ENDPOINT: 10.0.0.2 COLOR: 100 ORIGIN: 3 ORIGINATOR: 65000/192.168.0.1 DISCRIMINATOR: 1',
        'sr_policy': {
            'policy_name': 'blue',
            'candidate_path_name': 'cp1',
            'constraints': {
                'flags': {'algorithm_only': True, 'strict': True, 'srv6': False},
                'algorithm': 128,
                'srlgs': [10, 20],
                'disjoint_group': {'group_id': 7, 'request': {'node': True, 'link': True, 'srlg': False},
                                   'status': {'link': True, 'node': False}},
                'metrics': [{'metric_type': 1, 'optimization': True, 'bound': 0},
                            {'metric_type': 2, 'optimization': False, 'bound': 500}],
            },
            'binding_sid': {'label': 24001, 'allocated': True},
            'state': {'priority': 10, 'preference': 200, 'active': True, 'evaluated': True, 'valid_sid_list': True},
            'segment_lists': [
                {'weight': 1, 'srv6': False, 'labels': [16002, 24006]},
                {'weight': 2, 'srv6': False, 'labels': [16003]},
            ],
        },
    },
    {
        'name': 'second candidate path of the same policy',
        'route': 'srpolicy identifier 0 {} endpoint 10.0.0.2 color 100 '
                 'originator-asn 65000 originator-address 192.168.0.1 discriminator 2 '
                 'cp-name cp2 preference 100 state-flags B segment-list 1:16004'.format(HEADEND),
        'nlri': 'IPv4 ROUTER ID: 10.0.0.1} ENDPOINT: 10.0.0.2 COLOR: 100 ORIGIN: 3 ORIGINATOR: 65000/192.168.0.1 DISCRIMINATOR: 2',
        'sr_policy': {
            'candidate_path_name': 'cp2',
            'state': {'priority': 0, 'preference': 100, 'backup': True},
            'segment_lists': [
                {'weight': 1, 'srv6': False, 'labels': [16004]},
            ],
        },
    },
    {
        'name': 'srv6 candidate path',
        'route': 'srpolicy identifier 0 local-igp-router-id 0000.0000.0001 local-asn 65000 '
                 'local-bgp-router-id 192.168.0.1 local-router-id 2001:db8::1 '
                 'endpoint 2001:db8::2 color 300 originator-asn 65000 originator-address 2001:db8::1 '
                 'discriminator 1 policy-name v6 srv6-bsid fc00:0:1::1 fc00:0:1::3 '
                 'specified-bsid fc00:0:1::2 :: '
                 'segment-list 1:fc00:0:2::1,fc00:0:3::1',
        'nlri': 'ENDPOINT: 2001:db8::2 COLOR: 300 ORIGIN: 3 ORIGINATOR: 65000/2001:db8::1 DISCRIMINATOR: 1',
        'sr_policy': {
            'policy_name': 'v6',
            'srv6_binding_sids': [
                {'sid': 'fc00:0:1::1', 'specified_sid': 'fc00:0:1::2', 'allocated': True},
                {'sid': 'fc00:0:1::3', 'specified_sid': '::', 'allocated': True},
            ],
            'segment_lists': [
                {'weight': 1, 'srv6': True, 'sids': ['fc00:0:2::1', 'fc00:0:3::1']},
            ],
        },
    },
    {
        'name': 'same candidate path on another headend',
        'route': 'srpolicy identifier 0 local-asn 65000 local-bgp-router-id 192.168.0.1 '
                 'local-router-id 10.0.0.3 endpoint 10.0.0.2 color 100 '
                 'originator-asn 65000 originator-address 192.168.0.1 discriminator 1 '
                 'segment-list 1:16005',
        'nlri': 'IPv4 ROUTER ID: 10.0.0.3} ENDPOINT: 10.0.0.2 COLOR: 100 ORIGIN: 3 ORIGINATOR: 65000/192.168.0.1 DISCRIMINATOR: 1',
        'sr_policy': {
            'segment_lists': [{'weight': 1, 'srv6': False, 'labels': [16005]}],
        },
    },
]


class GoBGPTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix

        g1 = GoBGPContainer(name='g1', asn=65000, router_id='192.168.0.1',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        g2 = GoBGPContainer(name='g2', asn=65001, router_id='192.168.0.2',
                            ctn_image_name=gobgp_ctn_image_name,
                            log_level=parser_option.gobgp_log_level)
        ctns = [g1, g2]

        initial_wait_time = max(ctn.run() for ctn in ctns)

        time.sleep(initial_wait_time)

        g1.add_peer(g2, ls=True)
        g2.add_peer(g1, ls=True)

        cls.g1 = g1
        cls.g2 = g2

    def _wait_for_rib(self, ctn, expected, timeout=30):
        def _has_expected_destinations():
            return len(ctn.get_global_rib(rf=RF_LS)) == expected

        wait_for(
            _has_expected_destinations,
            timeout=timeout,
            timeout_message=lambda: 'expected {} BGP-LS destinations on {}, got {}'.format(
                expected, ctn.name, ctn.get_global_rib(rf=RF_LS)),
        )
        return ctn.get_global_rib(rf=RF_LS)

    def _find_dst(self, rib, nlri):
        dsts = [d for d in rib if nlri in d['prefix']]
        self.assertEqual(len(dsts), 1, 'destination {} not found in {}'.format(nlri, rib))
        return dsts[0]

    def _ls_attr(self, path):
        attrs = [a for a in path['attrs'] if a['type'] == BGP_ATTR_TYPE_LS]
        self.assertEqual(len(attrs), 1, 'BGP-LS attribute missing in {}'.format(path))
        return attrs[0]

    def _check_sr_policy(self, sr_policy, expected):
        for key in ('policy_name', 'candidate_path_name'):
            if key in expected:
                self.assertEqual(sr_policy[key], expected[key])

        if 'binding_sid' in expected:
            bsid = sr_policy['binding_sid']
            self.assertEqual(bsid['label'], expected['binding_sid']['label'])
            self.assertEqual(bsid['flags']['allocated'], expected['binding_sid']['allocated'])
            self.assertFalse(bsid['flags']['srv6'])

        if 'srv6_binding_sids' in expected:
            bsids = sr_policy['srv6_binding_sids']
            self.assertEqual(len(bsids), len(expected['srv6_binding_sids']))
            for bsid, want in zip(bsids, expected['srv6_binding_sids']):
                self.assertEqual(bsid['sid'], want['sid'])
                self.assertEqual(bsid['specified_sid'], want['specified_sid'])
                self.assertEqual(bsid['flags']['allocated'], want['allocated'])

        if 'constraints' in expected:
            want = expected['constraints']
            constraints = sr_policy['constraints']
            for flag, value in want['flags'].items():
                self.assertEqual(constraints['flags'][flag], value)
            self.assertEqual(constraints['algorithm'], want['algorithm'])
            self.assertEqual(constraints['srlgs'], want['srlgs'])
            self.assertNotIn('affinity', constraints)
            group = constraints['disjoint_group']
            self.assertEqual(group['group_id'], want['disjoint_group']['group_id'])
            for flag, value in want['disjoint_group']['request'].items():
                self.assertEqual(group['request_flags'][flag], value)
            for flag, value in want['disjoint_group']['status'].items():
                self.assertEqual(group['status_flags'][flag], value)
            self.assertEqual(len(constraints['metrics']), len(want['metrics']))
            for metric, want_metric in zip(constraints['metrics'], want['metrics']):
                self.assertEqual(metric['metric_type'], want_metric['metric_type'])
                self.assertEqual(metric['flags']['optimization'], want_metric['optimization'])
                self.assertEqual(metric['bound'], want_metric['bound'])

        if 'state' in expected:
            state = sr_policy['state']
            self.assertEqual(state['priority'], expected['state']['priority'])
            self.assertEqual(state['preference'], expected['state']['preference'])
            for flag in ('active', 'evaluated', 'valid_sid_list', 'backup'):
                self.assertEqual(state['flags'][flag], expected['state'].get(flag, False), flag)

        lists = sr_policy['segment_lists']
        self.assertEqual(len(lists), len(expected['segment_lists']))
        for got, want in zip(lists, expected['segment_lists']):
            self.assertEqual(got['weight'], want['weight'])
            self.assertEqual(got['flags']['srv6'], want['srv6'])
            self.assertTrue(got['flags']['explicit'])
            self.assertTrue(got['flags']['computed'])
            # A clear V or R flag would advertise the injected path as
            # having failed verification or resolution (RFC 9857 5.7).
            self.assertTrue(got['flags']['verified'])
            self.assertTrue(got['flags']['resolved'])
            if 'labels' in want:
                self.assertEqual([s['label'] for s in got['segments']], want['labels'])
                self.assertTrue(all(s['segment_type'] == 1 for s in got['segments']))
            if 'sids' in want:
                self.assertEqual([s['sid'] for s in got['segments']], want['sids'])
                self.assertTrue(all(s['segment_type'] == 2 for s in got['segments']))
            self.assertTrue(all(s['flags']['sid_present'] for s in got['segments']))
            self.assertTrue(all(s['flags']['verified'] and s['flags']['resolved'] for s in got['segments']))

    # Both speakers must negotiate the link-state address family.
    def test_01_neighbor_established(self):
        self.g1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g2)
        self.g2.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.g1)

    # SR Policy Candidate Path NLRIs must reach the peer with the BGP-LS
    # attribute decoded, and distinct candidate paths must not collide.
    def test_02_sr_policy_candidate_paths_advertised(self):
        for entry in SR_POLICY_ROUTES:
            self.g1.local('gobgp global rib add -a {} {}'.format(RF_LS, entry['route']))

        self._wait_for_rib(self.g1, len(SR_POLICY_ROUTES))
        rib = self._wait_for_rib(self.g2, len(SR_POLICY_ROUTES))

        for entry in SR_POLICY_ROUTES:
            with self.subTest(entry['name']):
                dst = self._find_dst(rib, entry['nlri'])
                self.assertIn('SRPOLICY_CP', dst['prefix'])
                self.assertEqual(len(dst['paths']), 1)
                path = dst['paths'][0]
                self.assertEqual(path['nlri']['type'], 5)
                self.assertEqual(path['nexthop'], self.g1.ip_addrs[0][1].split('/')[0])
                self._check_sr_policy(self._ls_attr(path)['sr_policy'], entry['sr_policy'])

    # Withdrawing one candidate path must remove only that one.
    def test_03_sr_policy_candidate_path_withdrawn(self):
        first = SR_POLICY_ROUTES[0]
        self.g1.local('gobgp global rib del -a {} {}'.format(RF_LS, first['route']))

        rib = self._wait_for_rib(self.g2, len(SR_POLICY_ROUTES) - 1)
        self.assertEqual([d for d in rib if first['nlri'] in d['prefix']], [])
        for entry in SR_POLICY_ROUTES[1:]:
            self._find_dst(rib, entry['nlri'])

        for entry in SR_POLICY_ROUTES[1:]:
            self.g1.local('gobgp global rib del -a {} {}'.format(RF_LS, entry['route']))
        self._wait_for_rib(self.g2, 0)

    # The other BGP-LS NLRI types must still propagate over the same session.
    def test_04_other_ls_nlri_types_advertised(self):
        routes = [
            ('node', 'node protocol 2 identifier 7 local-asn 65000 local-bgp-ls-id 0 '
                     'local-igp-router-id 0000.0000.0001 node-name r1',
             'NODE { AS:65000 BGP-LS ID:0 0000.0000.0001 ISIS-L2:7'),
            ('prefixv6', 'prefixv6 protocol 2 identifier 7 local-asn 65000 local-bgp-ls-id 0 '
                         'local-igp-router-id 0000.0000.0001 ip-reachability-info fc00:b100:1::/64',
             'PREFIXv6 { LOCAL_NODE: 0000.0000.0001 PREFIX: [fc00:b100:1::/64]'),
        ]
        for name, route, nlri in routes:
            with self.subTest(name):
                self.g1.local('gobgp global rib add -a {} {}'.format(RF_LS, route))
                rib = self._wait_for_rib(self.g2, 1)
                self._find_dst(rib, nlri)
                self.g1.local('gobgp global rib del -a {} {}'.format(RF_LS, route))
                self._wait_for_rib(self.g2, 0)
