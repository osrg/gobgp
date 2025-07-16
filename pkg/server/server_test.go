// Copyright (C) 2016-2021 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

var logger = log.NewDefaultLogger()

func TestStop(t *testing.T) {
	assert := assert.New(t)
	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	assert.NoError(err)
	err = s.StopBgp(context.Background(), &api.StopBgpRequest{})
	assert.NoError(err)

	s = NewBgpServer()
	go s.Serve()
	err = s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	assert.NoError(err)
	p := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "2.2.2.2",
			PeerAsn:         1,
		},
		RouteServer: &api.RouteServer{
			RouteServerClient: true,
		},
	}
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p})
	assert.NoError(err)

	err = s.AddPeer(context.Background(), &api.AddPeerRequest{})
	assert.Error(err)
}

func TestModPolicyAssign(t *testing.T) {
	assert := assert.New(t)
	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	assert.NoError(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	err = s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: table.NewAPIPolicyFromTableStruct(&table.Policy{Name: "p1"})})
	assert.NoError(err)

	err = s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: table.NewAPIPolicyFromTableStruct(&table.Policy{Name: "p2"})})
	assert.NoError(err)

	err = s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: table.NewAPIPolicyFromTableStruct(&table.Policy{Name: "p3"})})
	assert.NoError(err)

	f := func(l []*oc.PolicyDefinition) *api.PolicyAssignment {
		pl := make([]*api.Policy, 0, len(l))
		for _, d := range l {
			pl = append(pl, table.ToPolicyApi(d))
		}
		return &api.PolicyAssignment{
			Policies: pl,
		}
	}

	r := f([]*oc.PolicyDefinition{{Name: "p1"}, {Name: "p2"}, {Name: "p3"}})
	r.Direction = api.PolicyDirection_POLICY_DIRECTION_IMPORT
	r.DefaultAction = api.RouteAction_ROUTE_ACTION_ACCEPT
	r.Name = table.GLOBAL_RIB_NAME
	err = s.AddPolicyAssignment(context.Background(), &api.AddPolicyAssignmentRequest{Assignment: r})
	assert.NoError(err)

	r.Direction = api.PolicyDirection_POLICY_DIRECTION_EXPORT
	err = s.AddPolicyAssignment(context.Background(), &api.AddPolicyAssignmentRequest{Assignment: r})
	assert.NoError(err)

	var ps []*api.PolicyAssignment
	err = s.ListPolicyAssignment(context.Background(), &api.ListPolicyAssignmentRequest{
		Name:      table.GLOBAL_RIB_NAME,
		Direction: api.PolicyDirection_POLICY_DIRECTION_IMPORT,
	}, func(p *api.PolicyAssignment) { ps = append(ps, p) })
	assert.NoError(err)
	assert.Equal(len(ps[0].Policies), 3)

	r = f([]*oc.PolicyDefinition{{Name: "p1"}})
	r.Direction = api.PolicyDirection_POLICY_DIRECTION_IMPORT
	r.DefaultAction = api.RouteAction_ROUTE_ACTION_ACCEPT
	r.Name = table.GLOBAL_RIB_NAME
	err = s.DeletePolicyAssignment(context.Background(), &api.DeletePolicyAssignmentRequest{Assignment: r})
	assert.NoError(err)

	ps = []*api.PolicyAssignment{}
	err = s.ListPolicyAssignment(context.Background(), &api.ListPolicyAssignmentRequest{
		Name:      table.GLOBAL_RIB_NAME,
		Direction: api.PolicyDirection_POLICY_DIRECTION_IMPORT,
	}, func(p *api.PolicyAssignment) { ps = append(ps, p) })
	assert.NoError(err)
	assert.Equal(len(ps[0].Policies), 2)

	ps = []*api.PolicyAssignment{}
	err = s.ListPolicyAssignment(context.Background(), &api.ListPolicyAssignmentRequest{
		Name: table.GLOBAL_RIB_NAME,
	}, func(p *api.PolicyAssignment) { ps = append(ps, p) })
	assert.NoError(err)
	assert.Equal(len(ps), 2)
}

func TestListPolicyAssignment(t *testing.T) {
	assert := assert.New(t)

	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	assert.NoError(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	for i := 1; i < 4; i++ {
		addr := "127.0.0." + strconv.Itoa(i)
		p := &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: addr,
				PeerAsn:         uint32(i + 1),
			},
			RouteServer: &api.RouteServer{
				RouteServerClient: true,
			},
		}
		err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p})
		assert.NoError(err)

		err = s.AddPolicy(context.Background(),
			&api.AddPolicyRequest{Policy: table.NewAPIPolicyFromTableStruct(&table.Policy{Name: fmt.Sprintf("p%d", i)})})
		assert.NoError(err)

		pa := &api.PolicyAssignment{
			Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
			DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
			Name:          addr,
			Policies:      []*api.Policy{{Name: fmt.Sprintf("p%d", i)}},
		}
		err = s.AddPolicyAssignment(context.Background(), &api.AddPolicyAssignmentRequest{Assignment: pa})
		assert.NoError(err)
	}

	ps := []*api.PolicyAssignment{}
	err = s.ListPolicyAssignment(context.Background(), &api.ListPolicyAssignmentRequest{
		Name: table.GLOBAL_RIB_NAME,
	}, func(p *api.PolicyAssignment) { ps = append(ps, p) })
	assert.NoError(err)
	assert.Equal(2, len(ps))

	ps = []*api.PolicyAssignment{}
	err = s.ListPolicyAssignment(context.Background(), &api.ListPolicyAssignmentRequest{}, func(p *api.PolicyAssignment) { ps = append(ps, p) })
	assert.NoError(err)
	assert.Equal(8, len(ps))

	ps = []*api.PolicyAssignment{}
	err = s.ListPolicyAssignment(context.Background(), &api.ListPolicyAssignmentRequest{
		Direction: api.PolicyDirection_POLICY_DIRECTION_EXPORT,
	}, func(p *api.PolicyAssignment) { ps = append(ps, p) })
	assert.NoError(err)
	assert.Equal(4, len(ps))
}

//nolint:errcheck // WatchEvent won't return an error here
func waitState(s *BgpServer, state api.PeerState_SessionState, expectedFamilies ...bgp.Family) *sync.WaitGroup {
	wg := &sync.WaitGroup{}
	watchCtxMsg, watchCancelMsg := context.WithCancel(context.Background())
	wg.Add(1)

	opts := make([]WatchOption, 0)
	opts = append(opts, WatchPeer())
	s.WatchEvent(watchCtxMsg,
		WatchEventMessageCallbacks{
			OnPeerUpdate: func(peer *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
				if peer == nil {
					return
				}
				apiPeerSessionState := func(peer apiutil.Peer) api.PeerState_SessionState {
					return api.PeerState_SessionState(int(peer.State.SessionState) + 1)
				}
				if peer.Type == apiutil.PEER_EVENT_STATE && apiPeerSessionState(peer.Peer) == state {
					for _, rf := range expectedFamilies {
						found := false
						for _, cap := range peer.Peer.State.RemoteCap {
							if cap.Code() == bgp.BGP_CAP_MULTIPROTOCOL && cap.(*bgp.CapMultiProtocol).CapValue == rf {
								found = true
								break
							}
						}
						if !found {
							return
						}
					}
					watchCancelMsg()
					wg.Done()
				}
			},
		}, opts...)

	return wg
}

func waitActive(s *BgpServer) *sync.WaitGroup {
	return waitState(s, api.PeerState_SESSION_STATE_ACTIVE)
}

func waitEstablished(s *BgpServer, rfs ...bgp.Family) *sync.WaitGroup {
	return waitState(s, api.PeerState_SESSION_STATE_ESTABLISHED, rfs...)
}

func TestListPathEnableFiltered(test *testing.T) {
	assert := assert.New(test)

	// Create servers and add peers
	server1 := NewBgpServer()
	go server1.Serve()
	err := server1.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.NoError(err)
	defer server1.StopBgp(context.Background(), &api.StopBgpRequest{})

	server2 := NewBgpServer()
	go server2.Serve()
	err = server2.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	assert.NoError(err)
	defer server2.StopBgp(context.Background(), &api.StopBgpRequest{})

	peer1 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         2,
		},
		Transport: &api.Transport{
			PassiveMode: true,
		},
	}
	err = server1.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer1})
	assert.NoError(err)

	peer2 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         1,
		},
		Transport: &api.Transport{
			RemotePort: 10179,
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				ConnectRetry:           1,
				IdleHoldTimeAfterReset: 1,
			},
		},
	}

	establishedWg := waitEstablished(server1)

	err = server2.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer2})
	assert.NoError(err)

	establishedWg.Wait()

	// Add IMPORT policy at server1 for rejecting 10.1.0.0/24
	d1 := &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
		Name:        "d1",
		Prefixes: []*api.Prefix{
			{
				IpPrefix:      "10.1.0.0/24",
				MaskLengthMax: 24,
				MaskLengthMin: 24,
			},
		},
	}
	s1 := &api.Statement{
		Name: "s1",
		Conditions: &api.Conditions{
			PrefixSet: &api.MatchSet{
				Name: "d1",
				Type: api.MatchSet_TYPE_ANY,
			},
		},
		Actions: &api.Actions{
			RouteAction: api.RouteAction_ROUTE_ACTION_REJECT,
		},
	}
	err = server1.AddDefinedSet(context.Background(), &api.AddDefinedSetRequest{DefinedSet: d1})
	assert.NoError(err)
	p1 := &api.Policy{
		Name:       "p1",
		Statements: []*api.Statement{s1},
	}
	err = server1.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: p1})
	assert.NoError(err)
	err = server1.AddPolicyAssignment(context.Background(), &api.AddPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          table.GLOBAL_RIB_NAME,
			Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
			Policies:      []*api.Policy{p1},
			DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
		},
	})
	assert.NoError(err)

	// Add EXPORT policy at server2 for accepting all routes and adding communities.
	commSet, _ := table.NewCommunitySet(oc.CommunitySet{
		CommunitySetName: "comset1",
		CommunityList:    []string{"100:100"},
	})
	err = server2.policy.AddDefinedSet(commSet, false)
	assert.NoError(err)

	statement := oc.Statement{
		Name: "stmt1",
		Actions: oc.Actions{
			BgpActions: oc.BgpActions{
				SetCommunity: oc.SetCommunity{
					SetCommunityMethod: oc.SetCommunityMethod{
						CommunitiesList: []string{"100:100"},
					},
					Options: string(oc.BGP_SET_COMMUNITY_OPTION_TYPE_ADD),
				},
			},
			RouteDisposition: oc.ROUTE_DISPOSITION_ACCEPT_ROUTE,
		},
	}
	policy := oc.PolicyDefinition{
		Name:       "policy1",
		Statements: []oc.Statement{statement},
	}
	p, err := table.NewPolicy(policy)
	if err != nil {
		test.Fatalf("cannot create new policy: %v", err)
	}
	err = server2.policy.AddPolicy(p, false)
	assert.NoError(err)
	policies := []*oc.PolicyDefinition{
		{
			Name: "policy1",
		},
	}
	err = server2.policy.AddPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT, policies, table.ROUTE_TYPE_REJECT)
	assert.NoError(err)

	// Add IMPORT policy at server1 for accepting all routes and replacing communities.
	statement = oc.Statement{
		Name: "stmt1",
		Actions: oc.Actions{
			BgpActions: oc.BgpActions{
				SetCommunity: oc.SetCommunity{
					SetCommunityMethod: oc.SetCommunityMethod{
						CommunitiesList: []string{"200:200"},
					},
					Options: string(oc.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE),
				},
			},
			RouteDisposition: oc.ROUTE_DISPOSITION_ACCEPT_ROUTE,
		},
	}
	policy = oc.PolicyDefinition{
		Name:       "policy1",
		Statements: []oc.Statement{statement},
	}
	p, err = table.NewPolicy(policy)
	if err != nil {
		test.Fatalf("cannot create new policy: %v", err)
	}
	err = server1.policy.AddPolicy(p, false)
	assert.NoError(err)
	policies = []*oc.PolicyDefinition{
		{
			Name: "policy1",
		},
	}
	err = server1.policy.AddPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_IMPORT, policies, table.ROUTE_TYPE_REJECT)
	assert.NoError(err)

	// Add paths
	family := &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_UNICAST,
	}
	bgpFamily := bgp.NewFamily(uint16(family.Afi), uint8(family.Safi))

	nlri1 := &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
		Prefix:    "10.1.0.0",
		PrefixLen: 24,
	}}}

	attrs := []*api.Attribute{
		{
			Attr: &api.Attribute_Origin{Origin: &api.OriginAttribute{
				Origin: 0,
			}},
		},
		{
			Attr: &api.Attribute_NextHop{NextHop: &api.NextHopAttribute{
				NextHop: "10.0.0.1",
			}},
		},
	}

	_, err = server2.AddPath(context.Background(), &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path: &api.Path{
			Family: family,
			Nlri:   nlri1,
			Pattrs: attrs,
		},
	})
	assert.NoError(err)

	nlri2 := &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
		Prefix:    "10.2.0.0",
		PrefixLen: 24,
	}}}
	_, err = server2.AddPath(context.Background(), &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path: &api.Path{
			Family: family,
			Nlri:   nlri2,
			Pattrs: attrs,
		},
	})
	assert.NoError(err)

	var wantEmptyCommunities []uint32
	wantCommunitiesAfterExportPolicies := []uint32{100<<16 | 100}
	wantCommunitiesAfterImportPolicies := []uint32{200<<16 | 200}

	getCommunities := func(path *apiutil.Path) []uint32 {
		for _, attr := range path.Attrs {
			switch attr.GetType() {
			case bgp.BGP_ATTR_TYPE_COMMUNITIES:
				m := attr.(*bgp.PathAttributeCommunities)
				return m.Value
			}
		}
		return nil
	}

	// Check ADJ_OUT routes before applying export policies.
	for count := 0; count < 2; {
		count = 0
		err = server2.ListPath(context.Background(), apiutil.ListPathRequest{
			TableType: api.TableType_TABLE_TYPE_ADJ_OUT,
			Family:    bgpFamily, Name: "127.0.0.1",
			// TODO(wenovus): This is confusing and we may want to change this.
			EnableFiltered: true,
		}, func(prefix bgp.AddrPrefixInterface, paths []*apiutil.Path) {
			count++
			for _, path := range paths {
				comms := getCommunities(path)
				if diff := cmp.Diff(wantEmptyCommunities, comms); diff != "" {
					test.Errorf("AdjRibOutPre communities for %v (-want, +got):\n%s", prefix, diff)
				} else {
					test.Logf("Got expected communities for %v: %v", prefix, comms)
				}
			}
		})
		assert.NoError(err)
	}

	// Check ADJ_OUT routes after applying export policies.
	for count := 0; count < 2; {
		count = 0
		err = server2.ListPath(context.Background(), apiutil.ListPathRequest{
			TableType: api.TableType_TABLE_TYPE_ADJ_OUT,
			Family:    bgpFamily, Name: "127.0.0.1",
			// TODO(wenovus): This is confusing and we may want to change this.
			EnableFiltered: false,
		}, func(prefix bgp.AddrPrefixInterface, paths []*apiutil.Path) {
			count++
			for _, path := range paths {
				if path.Filtered {
					continue
				}
				comms := getCommunities(path)
				if diff := cmp.Diff(wantCommunitiesAfterExportPolicies, comms); diff != "" {
					test.Errorf("AdjRibOutPost communities for %v (-want, +got):\n%s", prefix, diff)
				} else {
					test.Logf("Got expected communities for %v: %v", prefix, comms)
				}
			}
		})
		assert.NoError(err)
	}

	// Check ADJ_IN routes before applying import policies.
	for count := 0; count < 2; {
		count = 0
		err = server1.ListPath(context.Background(), apiutil.ListPathRequest{
			TableType:      api.TableType_TABLE_TYPE_ADJ_IN,
			Family:         bgpFamily,
			Name:           "127.0.0.1",
			EnableFiltered: false,
		}, func(prefix bgp.AddrPrefixInterface, paths []*apiutil.Path) {
			count++
			for _, path := range paths {
				comms := getCommunities(path)
				if diff := cmp.Diff(wantCommunitiesAfterExportPolicies, comms); diff != "" {
					test.Errorf("AdjRibInPre communities for %v (-want, +got):\n%s", prefix, diff)
				} else {
					test.Logf("Got expected communities for %v: %v", prefix, comms)
				}
			}
		})
		assert.NoError(err)
	}

	// Check ADJ_IN routes after applying import policies.
	for count := 0; count < 2; {
		count = 0
		err = server1.ListPath(context.Background(), apiutil.ListPathRequest{
			TableType:      api.TableType_TABLE_TYPE_ADJ_IN,
			Family:         bgpFamily,
			Name:           "127.0.0.1",
			EnableFiltered: true,
		}, func(prefix bgp.AddrPrefixInterface, paths []*apiutil.Path) {
			count++
			for _, path := range paths {
				if path.Filtered {
					continue
				}
				comms := getCommunities(path)
				if diff := cmp.Diff(wantCommunitiesAfterImportPolicies, comms); diff != "" {
					test.Errorf("AdjRibInPost communities for %v (-want, +got):\n%s", prefix, diff)
				} else {
					test.Logf("Got expected communities for %v: %v", prefix, comms)
				}
			}
		})
		assert.NoError(err)
	}

	// Check that 10.1.0.0/24 is filtered at the import side.
	count := 0
	err = server1.ListPath(context.Background(), apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: bgpFamily}, func(prefix bgp.AddrPrefixInterface, paths []*apiutil.Path) {
		count++
	})
	assert.NoError(err)
	assert.Equal(1, count)

	filtered := 0
	err = server1.ListPath(context.Background(), apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_ADJ_IN, Family: bgpFamily, Name: "127.0.0.1", EnableFiltered: true}, func(prefix bgp.AddrPrefixInterface, paths []*apiutil.Path) {
		if paths[0].Filtered {
			filtered++
		}
	})
	assert.NoError(err)
	assert.Equal(1, filtered)

	// Validate filtering at the export side.
	d2 := &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
		Name:        "d2",
		Prefixes: []*api.Prefix{
			{
				IpPrefix:      "10.3.0.0/24",
				MaskLengthMax: 24,
				MaskLengthMin: 24,
			},
		},
	}
	s2 := &api.Statement{
		Name: "s2",
		Conditions: &api.Conditions{
			PrefixSet: &api.MatchSet{
				Name: "d2",
				Type: api.MatchSet_TYPE_ANY,
			},
		},
		Actions: &api.Actions{
			RouteAction: api.RouteAction_ROUTE_ACTION_REJECT,
		},
	}
	err = server1.AddDefinedSet(context.Background(), &api.AddDefinedSetRequest{DefinedSet: d2})
	assert.NoError(err)
	p2 := &api.Policy{
		Name:       "p2",
		Statements: []*api.Statement{s2},
	}
	err = server1.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: p2})
	assert.NoError(err)
	err = server1.AddPolicyAssignment(context.Background(), &api.AddPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          table.GLOBAL_RIB_NAME,
			Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
			Policies:      []*api.Policy{p2},
			DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
		},
	})
	assert.NoError(err)

	nlri3 := &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
		Prefix:    "10.3.0.0",
		PrefixLen: 24,
	}}}
	_, err = server1.AddPath(context.Background(), &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path: &api.Path{
			Family: family,
			Nlri:   nlri3,
			Pattrs: attrs,
		},
	})
	assert.NoError(err)

	nlri4 := &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
		Prefix:    "10.4.0.0",
		PrefixLen: 24,
	}}}
	_, err = server1.AddPath(context.Background(), &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path: &api.Path{
			Family: family,
			Nlri:   nlri4,
			Pattrs: attrs,
		},
	})
	assert.NoError(err)

	count = 0
	err = server1.ListPath(context.Background(), apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: bgpFamily}, func(prefix bgp.AddrPrefixInterface, paths []*apiutil.Path) {
		count++
	})
	assert.NoError(err)
	assert.Equal(3, count)

	count = 0
	filtered = 0
	err = server1.ListPath(context.Background(), apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_ADJ_OUT, Family: bgpFamily, Name: "127.0.0.1", EnableFiltered: true}, func(prefix bgp.AddrPrefixInterface, paths []*apiutil.Path) {
		count++
		if paths[0].Filtered {
			filtered++
		}
	})
	assert.NoError(err)
	assert.Equal(2, count)
	assert.Equal(1, filtered)
}

func TestMonitor(test *testing.T) {
	assert := assert.New(test)
	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.NoError(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// Vrf1 111:111 and vrf2 import 111:111 and 222:222
	addVrf(test, s, "vrf1", "111:111", []string{"111:111"}, []string{"111:111"}, 1)
	addVrf(test, s, "vrf2", "222:222", []string{"111:111", "222:222"}, []string{"222:222"}, 2)

	p1 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         2,
		},
		Transport: &api.Transport{
			PassiveMode: true,
		},
	}
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p1})
	assert.NoError(err)

	t := NewBgpServer()
	go t.Serve()
	err = t.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	assert.NoError(err)
	defer t.StopBgp(context.Background(), &api.StopBgpRequest{})

	p2 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         1,
		},
		Transport: &api.Transport{
			RemotePort: 10179,
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				ConnectRetry:           1,
				IdleHoldTimeAfterReset: 1,
			},
		},
	}
	// go t.MonitorPeer(context.Background(), &api.MonitorPeerRequest{}, func(peer *api.Peer) {
	// 	if peer.State.SessionState == api.PeerState_ESTABLISHED {
	// 		close(ch)
	// 	}
	// })

	establishedWg := waitEstablished(s)

	err = t.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p2})
	assert.NoError(err)

	establishedWg.Wait()

	// Test WatchBestPath.
	w := s.watch(WatchBestPath(false))

	// Advertises a route.
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop("10.0.0.1"),
	}
	prefix := bgp.NewIPAddrPrefix(24, "10.0.0.0")
	path, _ := apiutil.NewPath(prefix, false, attrs, time.Now())
	if _, err := t.AddPath(context.Background(), &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      path,
	}); err != nil {
		test.Fatal(err)
	}

	ev := <-w.Event()
	b := ev.(*watchEventBestPath)
	assert.Equal(1, len(b.PathList))
	assert.Equal("10.0.0.0/24", b.PathList[0].GetNlri().String())
	assert.False(b.PathList[0].IsWithdraw)
	assert.Equal(1, len(b.Vrf))
	assert.True(b.Vrf[0])

	// Withdraws the previous route.
	// NOTE: Withdraw should not require any path attribute.
	if err := t.addPathList("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.0.0.0"), true, nil, time.Now(), false)}); err != nil {
		test.Error(err)
	}
	ev = <-w.Event()
	b = ev.(*watchEventBestPath)
	assert.Equal(1, len(b.PathList))
	assert.Equal("10.0.0.0/24", b.PathList[0].GetNlri().String())
	assert.True(b.PathList[0].IsWithdraw)
	assert.Equal(1, len(b.Vrf))
	assert.True(b.Vrf[0])

	// Stops the watcher still having an item.
	w.Stop()

	// Prepares an initial route to test WatchUpdate with "current" flag.
	if err := t.addPathList("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.1.0.0"), false, attrs, time.Now(), false)}); err != nil {
		test.Error(err)
	}
	for {
		// Waits for the initial route will be advertised.
		rib, _, err := s.getRib("", bgp.RF_IPv4_UC, nil)
		if err != nil {
			test.Error(err)
		}
		if len(rib.GetKnownPathList("", 0)) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Test WatchUpdate with "current" flag.
	w = s.watch(WatchUpdate(true, "", ""))

	// Test the initial route.
	ev = <-w.Event()
	u := ev.(*watchEventUpdate)
	assert.Equal(1, len(u.PathList))
	assert.Equal("10.1.0.0/24", u.PathList[0].GetNlri().String())
	assert.False(u.PathList[0].IsWithdraw)
	ev = <-w.Event()
	u = ev.(*watchEventUpdate)
	assert.Equal(len(u.PathList), 0) // End of RIB

	// Advertises an additional route.
	if err := t.addPathList("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.2.0.0"), false, attrs, time.Now(), false)}); err != nil {
		test.Error(err)
	}
	ev = <-w.Event()
	u = ev.(*watchEventUpdate)
	assert.Equal(1, len(u.PathList))
	assert.Equal("10.2.0.0/24", u.PathList[0].GetNlri().String())
	assert.False(u.PathList[0].IsWithdraw)

	// Withdraws the previous route.
	// NOTE: Withdraw should not require any path attribute.
	if err := t.addPathList("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.2.0.0"), true, nil, time.Now(), false)}); err != nil {
		test.Error(err)
	}
	ev = <-w.Event()
	u = ev.(*watchEventUpdate)
	assert.Equal(1, len(u.PathList))
	assert.Equal("10.2.0.0/24", u.PathList[0].GetNlri().String())
	assert.True(u.PathList[0].IsWithdraw)

	// Test bestpath events with vrf and rt import
	w.Stop()
	w = s.watch(WatchBestPath(false))
	attrs = []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop("10.0.0.1"),
	}

	if err := s.addPathList("vrf1", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.0.0.0"), false, attrs, time.Now(), false)}); err != nil {
		test.Error(err)
	}
	ev = <-w.Event()
	b = ev.(*watchEventBestPath)
	assert.Equal(1, len(b.PathList))
	assert.Equal("111:111:10.0.0.0/24", b.PathList[0].GetNlri().String())
	assert.False(b.PathList[0].IsWithdraw)
	assert.Equal(2, len(b.Vrf))
	assert.True(b.Vrf[1])
	assert.True(b.Vrf[2])

	// Withdraw the route
	if err := s.addPathList("vrf1", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.0.0.0"), true, attrs, time.Now(), false)}); err != nil {
		test.Error(err)
	}
	ev = <-w.Event()
	b = ev.(*watchEventBestPath)
	assert.Equal(1, len(b.PathList))
	assert.Equal("111:111:10.0.0.0/24", b.PathList[0].GetNlri().String())
	assert.True(b.PathList[0].IsWithdraw)
	assert.Equal(2, len(b.Vrf))
	assert.True(b.Vrf[1])
	assert.True(b.Vrf[2])

	w.Stop()
}

func TestNumGoroutineWithAddDeleteNeighbor(t *testing.T) {
	assert := assert.New(t)
	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	assert.NoError(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// wait a few seconds to avoid taking effect from other test cases.
	time.Sleep(time.Second * 5)

	num := runtime.NumGoroutine()

	p := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         2,
		},
		Transport: &api.Transport{
			PassiveMode: true,
		},
	}

	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p})
	assert.NoError(err)

	err = s.DeletePeer(context.Background(), &api.DeletePeerRequest{Address: "127.0.0.1"})
	assert.NoError(err)
	// wait goroutines to finish (e.g. internal goroutine for
	// InfiniteChannel)
	time.Sleep(time.Second * 5)
	for range 5 {
		if num == runtime.NumGoroutine() {
			return
		}
	}
	assert.Equal(num, runtime.NumGoroutine())
}

func newPeerandInfo(t *testing.T, myAs, as uint32, address string, rib *table.TableManager) (*peer, *table.PeerInfo) {
	nConf := &oc.Neighbor{Config: oc.NeighborConfig{PeerAs: as, NeighborAddress: address}}
	gConf := &oc.Global{Config: oc.GlobalConfig{As: myAs}}
	err := oc.SetDefaultNeighborConfigValues(nConf, nil, gConf)
	assert.NoError(t, err)
	policy := table.NewRoutingPolicy(logger)
	err = policy.Reset(&oc.RoutingPolicy{}, nil)
	assert.NoError(t, err)
	p := newPeer(
		&oc.Global{Config: oc.GlobalConfig{As: myAs}},
		nConf,
		rib,
		policy,
		logger)
	p.fsm.peerInfo.ID = net.ParseIP(address)
	for _, f := range rib.GetRFlist() {
		p.fsm.rfMap[f] = bgp.BGP_ADD_PATH_NONE
	}
	return p, &table.PeerInfo{AS: as, Address: net.ParseIP(address), ID: net.ParseIP(address)}
}

func process(rib *table.TableManager, l []*table.Path) (*table.Path, *table.Path) {
	dsts := make([]*table.Update, 0)
	for _, path := range l {
		dsts = append(dsts, rib.Update(path)...)
	}
	news, olds, _ := dstsToPaths(table.GLOBAL_RIB_NAME, 0, dsts)
	if len(news) != 1 {
		panic("can't handle multiple paths")
	}

	return news[0], olds[0]
}

func TestFilterpathWitheBGP(t *testing.T) {
	as := uint32(65000)
	p1As := uint32(65001)
	p2As := uint32(65002)
	rib := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	p1, pi1 := newPeerandInfo(t, as, p1As, "192.168.0.1", rib)
	p2, pi2 := newPeerandInfo(t, as, p2As, "192.168.0.2", rib)

	nlri := bgp.NewIPAddrPrefix(24, "10.10.10.0")
	pa1 := []bgp.PathAttributeInterface{bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{p1As})}), bgp.NewPathAttributeLocalPref(200)}
	pa2 := []bgp.PathAttributeInterface{bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{p2As})})}

	path1 := table.NewPath(pi1, nlri, false, pa1, time.Now(), false)
	path2 := table.NewPath(pi2, nlri, false, pa2, time.Now(), false)
	rib.Update(path2)
	d := rib.Update(path1)
	new, old, _ := d[0].GetChanges(table.GLOBAL_RIB_NAME, 0, false)
	assert.Equal(t, new, path1)
	filterpath(p1, new, old)
	filterpath(p2, new, old)

	new, old = process(rib, []*table.Path{path1.Clone(true)})
	assert.Equal(t, new, path2)
	// p1 and p2 advertized the same prefix and p1's was best. Then p1 withdraw it, so p2 must get withdawal.
	path := filterpath(p2, new, old)
	assert.NotNil(t, path)
	assert.True(t, path.IsWithdraw)

	// p1 should get the new best (from p2)
	assert.Equal(t, filterpath(p1, new, old), path2)

	new, old = process(rib, []*table.Path{path2.Clone(true)})
	assert.True(t, new.IsWithdraw)
	// p2 withdraw so p1 should get withdrawal.
	path = filterpath(p1, new, old)
	assert.True(t, path.IsWithdraw)

	// p2 withdraw so p2 should get nothing.
	path = filterpath(p2, new, old)
	assert.Nil(t, path)
}

func TestFilterpathWithiBGP(t *testing.T) {
	as := uint32(65000)

	rib := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	p1, pi1 := newPeerandInfo(t, as, as, "192.168.0.1", rib)
	// p2, pi2 := newPeerandInfo(as, as, "192.168.0.2", rib)
	p2, _ := newPeerandInfo(t, as, as, "192.168.0.2", rib)

	nlri := bgp.NewIPAddrPrefix(24, "10.10.10.0")
	pa1 := []bgp.PathAttributeInterface{bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{as})}), bgp.NewPathAttributeLocalPref(200)}
	// pa2 := []bgp.PathAttributeInterface{bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{as})})}

	path1 := table.NewPath(pi1, nlri, false, pa1, time.Now(), false)
	// path2 := table.NewPath(pi2, nlri, false, pa2, time.Now(), false)

	new, old := process(rib, []*table.Path{path1})
	assert.Equal(t, new, path1)
	path := filterpath(p1, new, old)
	assert.Nil(t, path)
	path = filterpath(p2, new, old)
	assert.Nil(t, path)

	new, old = process(rib, []*table.Path{path1.Clone(true)})
	path = filterpath(p1, new, old)
	assert.Nil(t, path)
	path = filterpath(p2, new, old)
	assert.Nil(t, path)
}

func TestFilterpathWithRejectPolicy(t *testing.T) {
	rib1 := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	_, pi1 := newPeerandInfo(t, 1, 2, "192.168.0.1", rib1)
	rib2 := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	p2, _ := newPeerandInfo(t, 1, 3, "192.168.0.2", rib2)

	comSet1 := oc.CommunitySet{
		CommunitySetName: "comset1",
		CommunityList:    []string{"100:100"},
	}
	s, _ := table.NewCommunitySet(comSet1)
	err := p2.policy.AddDefinedSet(s, false)
	assert.NoError(t, err)

	statement := oc.Statement{
		Name: "stmt1",
		Conditions: oc.Conditions{
			BgpConditions: oc.BgpConditions{
				MatchCommunitySet: oc.MatchCommunitySet{
					CommunitySet: "comset1",
				},
			},
		},
		Actions: oc.Actions{
			RouteDisposition: oc.ROUTE_DISPOSITION_REJECT_ROUTE,
		},
	}
	policy := oc.PolicyDefinition{
		Name:       "policy1",
		Statements: []oc.Statement{statement},
	}
	p, _ := table.NewPolicy(policy)
	err = p2.policy.AddPolicy(p, false)
	assert.NoError(t, err)

	policies := []*oc.PolicyDefinition{
		{
			Name: "policy1",
		},
	}
	err = p2.policy.AddPolicyAssignment(p2.TableID(), table.POLICY_DIRECTION_EXPORT, policies, table.ROUTE_TYPE_ACCEPT)
	assert.NoError(t, err)

	for _, addCommunity := range []bool{false, true, false, true} {
		nlri := bgp.NewIPAddrPrefix(24, "10.10.10.0")
		pa1 := []bgp.PathAttributeInterface{bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{1})}), bgp.NewPathAttributeLocalPref(200)}
		if addCommunity {
			pa1 = append(pa1, bgp.NewPathAttributeCommunities([]uint32{100<<16 | 100}))
		}
		path1 := table.NewPath(pi1, nlri, false, pa1, time.Now(), false)
		new, old := process(rib2, []*table.Path{path1})
		assert.Equal(t, new, path1)
		s := NewBgpServer()
		path2 := s.filterpath(p2, new, old)
		if addCommunity {
			assert.True(t, path2.IsWithdraw)
		} else {
			assert.False(t, path2.IsWithdraw)
		}
	}
}

func TestPeerGroup(test *testing.T) {
	assert := assert.New(test)
	s := NewBgpServer()
	s.logger.SetLevel(log.DebugLevel)
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.NoError(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	g := &oc.PeerGroup{
		Config: oc.PeerGroupConfig{
			PeerAs:        2,
			PeerGroupName: "g",
		},
	}
	err = s.addPeerGroup(g)
	assert.NoError(err)

	n := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: "127.0.0.1",
			PeerGroup:       "g",
		},
		Transport: oc.Transport{
			Config: oc.TransportConfig{
				PassiveMode: true,
			},
		},
	}
	configured := map[string]any{
		"config": map[string]any{
			"neigbor-address": "127.0.0.1",
			"peer-group":      "g",
		},
		"transport": map[string]any{
			"config": map[string]any{
				"passive-mode": true,
			},
		},
	}
	oc.RegisterConfiguredFields("127.0.0.1", configured)
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(n)})
	assert.NoError(err)

	t := NewBgpServer()
	go t.Serve()
	err = t.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	assert.NoError(err)
	defer t.StopBgp(context.Background(), &api.StopBgpRequest{})

	m := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: "127.0.0.1",
			PeerAs:          1,
		},
		Transport: oc.Transport{
			Config: oc.TransportConfig{
				RemotePort: 10179,
			},
		},
		Timers: oc.Timers{
			Config: oc.TimersConfig{
				ConnectRetry:           1,
				IdleHoldTimeAfterReset: 1,
			},
		},
	}

	establishedWg := waitEstablished(s)

	err = t.AddPeer(context.Background(), &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(m)})
	assert.NoError(err)

	establishedWg.Wait()
}

func TestDynamicNeighbor(t *testing.T) {
	assert := assert.New(t)
	s1 := NewBgpServer()
	s1.logger.SetLevel(log.DebugLevel)
	go s1.Serve()
	err := s1.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.NoError(err)
	defer s1.StopBgp(context.Background(), &api.StopBgpRequest{})

	g := &oc.PeerGroup{
		Config: oc.PeerGroupConfig{
			PeerAs:        2,
			PeerGroupName: "g",
		},
	}
	err = s1.addPeerGroup(g)
	assert.NoError(err)

	d := &api.AddDynamicNeighborRequest{
		DynamicNeighbor: &api.DynamicNeighbor{
			Prefix:    "127.0.0.0/24",
			PeerGroup: "g",
		},
	}
	err = s1.AddDynamicNeighbor(context.Background(), d)
	assert.NoError(err)

	s2 := NewBgpServer()
	go s2.Serve()
	err = s2.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	assert.NoError(err)
	defer s2.StopBgp(context.Background(), &api.StopBgpRequest{})

	m := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: "127.0.0.1",
			PeerAs:          1,
		},
		Transport: oc.Transport{
			Config: oc.TransportConfig{
				RemotePort: 10179,
			},
		},
		Timers: oc.Timers{
			Config: oc.TimersConfig{
				ConnectRetry:           1,
				IdleHoldTimeAfterReset: 1,
			},
		},
	}
	establisedWg := waitEstablished(s2)

	err = s2.AddPeer(context.Background(), &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(m)})
	assert.NoError(err)

	establisedWg.Wait()
}

func TestGracefulRestartTimerExpired(t *testing.T) {
	assert := assert.New(t)
	s1 := NewBgpServer()
	go s1.Serve()
	err := s1.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.NoError(err)
	defer s1.StopBgp(context.Background(), &api.StopBgpRequest{})

	p1 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         2,
		},
		Transport: &api.Transport{
			PassiveMode: true,
		},
		GracefulRestart: &api.GracefulRestart{
			Enabled:     true,
			RestartTime: minConnectRetryInterval,
		},
	}
	err = s1.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p1})
	assert.NoError(err)

	s2 := NewBgpServer()
	go s2.Serve()
	err = s2.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s2.StopBgp(context.Background(), &api.StopBgpRequest{})

	p2 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         1,
		},
		Transport: &api.Transport{
			RemotePort: 10179,
		},
		GracefulRestart: &api.GracefulRestart{
			Enabled:     true,
			RestartTime: 1,
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				ConnectRetry:           1,
				IdleHoldTimeAfterReset: 1,
			},
		},
	}

	establishedWg := waitEstablished(s2)

	err = s2.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p2})
	assert.NoError(err)

	establishedWg.Wait()

	// Force TCP session disconnected in order to cause Graceful Restart at s1
	// side.
	for _, n := range s2.neighborMap {
		n.fsm.conn.Close()
	}
	err = s2.StopBgp(context.Background(), &api.StopBgpRequest{})
	assert.NoError(err)

	time.Sleep(5 * time.Second)

	// Create dummy session which does NOT send BGP OPEN message in order to
	// cause Graceful Restart timer expired.
	var conn net.Conn

	conn, err = net.Dial("tcp", "127.0.0.1:10179")
	require.NoError(t, err)
	defer conn.Close()

	// this seems to take around 22 seconds... need to address this whole thing
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan struct{})
	// Waiting for Graceful Restart timer expired and moving on to IDLE state.
	for {
		// ignore error, we will hit the context deadline
		_ = s1.ListPeer(context.Background(), &api.ListPeerRequest{}, func(peer *api.Peer) {
			if peer.State.SessionState == api.PeerState_SESSION_STATE_IDLE {
				close(done)
			}
		})

		select {
		case <-done:
			return
		case <-ctx.Done():
			t.Fatalf("failed to enter IDLE state in the deadline")
			return
		}
	}
}

func TestTcpConnectionClosedAfterPeerDel(t *testing.T) {
	// With the current design, we can't intercept the transition.
	t.Skip("This test is temporarily disabled")

	assert := assert.New(t)
	s1 := NewBgpServer()
	go s1.Serve()
	err := s1.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.NoError(err)
	defer s1.StopBgp(context.Background(), &api.StopBgpRequest{})

	p1 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         2,
		},
		Transport: &api.Transport{
			PassiveMode: true,
		},
	}

	activeWg := waitActive(s1)

	err = s1.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p1})
	assert.NoError(err)

	activeWg.Wait()

	// We delete the peer incoming channel from the server list so that we can
	// intercept the transition from ACTIVE state to OPENSENT state.
	neighbor1 := s1.neighborMap[p1.Conf.NeighborAddress]
	incoming := neighbor1.fsm.h.msgCh
	err = s1.mgmtOperation(func() error {
		s1.delIncoming(incoming)
		return nil
	}, true)
	assert.NoError(err)

	s2 := NewBgpServer()
	go s2.Serve()
	err = s2.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s2.StopBgp(context.Background(), &api.StopBgpRequest{})

	p2 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         1,
		},
		Transport: &api.Transport{
			RemotePort: 10179,
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				ConnectRetry:           1,
				IdleHoldTimeAfterReset: 1,
			},
		},
	}

	err = s2.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p2})
	assert.NoError(err)

	// Wait for the s1 to receive the tcp connection from s2.
	ev := <-incoming.Out()
	msg := ev.(*fsmMsg)
	nextState := msg.MsgData.(bgp.FSMState)
	assert.Equal(nextState, bgp.BGP_FSM_OPENSENT)
	assert.NotEmpty(msg.fsm.conn)

	// Add the peer incoming channel back to the server
	err = s1.mgmtOperation(func() error {
		s1.addIncoming(incoming)
		return nil
	}, true)
	assert.NoError(err)

	// Delete the peer from s1.
	err = s1.DeletePeer(context.Background(), &api.DeletePeerRequest{Address: p1.Conf.NeighborAddress})
	assert.NoError(err)

	// Send the message OPENSENT transition message again to the server.
	incoming.In() <- msg

	// Wait for peer connection channel to be closed and check that the open
	// tcp connection has also been closed.
	<-neighbor1.fsm.connCh
	assert.Empty(neighbor1.fsm.conn)

	establishedWg := waitEstablished(s2)

	// Check that we can establish the peering when re-adding the peer.
	err = s1.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p1})
	assert.NoError(err)

	establishedWg.Wait()
}

func TestFamiliesForSoftreset(t *testing.T) {
	f := func(f bgp.Family) oc.AfiSafi {
		return oc.AfiSafi{
			State: oc.AfiSafiState{
				Family: f,
			},
		}
	}
	peer := &peer{
		fsm: &fsm{
			pConf: &oc.Neighbor{
				AfiSafis: []oc.AfiSafi{f(bgp.RF_RTC_UC), f(bgp.RF_IPv4_UC), f(bgp.RF_IPv6_UC)},
			},
		},
	}

	families := familiesForSoftreset(peer, bgp.RF_IPv4_UC)
	assert.Equal(t, len(families), 1)
	assert.Equal(t, families[0], bgp.RF_IPv4_UC)

	families = familiesForSoftreset(peer, bgp.RF_RTC_UC)
	assert.Equal(t, len(families), 1)
	assert.Equal(t, families[0], bgp.RF_RTC_UC)

	families = familiesForSoftreset(peer, bgp.Family(0))
	assert.Equal(t, len(families), 2)
	assert.NotContains(t, families, bgp.RF_RTC_UC)
}

func runNewServer(t *testing.T, as uint32, routerID string, listenPort int32) *BgpServer {
	s := NewBgpServer()
	go s.Serve()
	if err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        as,
			RouterId:   routerID,
			ListenPort: listenPort,
		},
	}); err != nil {
		t.Errorf("Failed to start server %s: %s", s.bgpConfig.Global.Config.RouterId, err)
	}
	return s
}

func peerServers(t *testing.T, ctx context.Context, servers []*BgpServer, families []oc.AfiSafiType) error {
	for i, server := range servers {
		for j, peer := range servers {
			if i == j {
				continue
			}

			neighborConfig := &oc.Neighbor{
				Config: oc.NeighborConfig{
					NeighborAddress: "127.0.0.1",
					PeerAs:          peer.bgpConfig.Global.Config.As,
				},
				AfiSafis: oc.AfiSafis{},
				Transport: oc.Transport{
					Config: oc.TransportConfig{
						RemotePort: uint16(peer.bgpConfig.Global.Config.Port),
					},
				},
				Timers: oc.Timers{
					Config: oc.TimersConfig{
						ConnectRetry:           1,
						IdleHoldTimeAfterReset: 1,
					},
				},
			}

			// first server to get neighbor config is passive to hopefully make handshake faster
			if j > i {
				neighborConfig.Transport.Config.PassiveMode = true
			}

			for _, family := range families {
				neighborConfig.AfiSafis = append(neighborConfig.AfiSafis, oc.AfiSafi{
					Config: oc.AfiSafiConfig{
						AfiSafiName: family,
						Enabled:     true,
					},
				})
			}

			if err := server.AddPeer(ctx, &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(neighborConfig)}); err != nil {
				t.Fatal(err)
			}
		}
	}

	return nil
}

func parseRDRT(rdStr string) (bgp.RouteDistinguisherInterface, bgp.ExtendedCommunityInterface, error) {
	rd, err := bgp.ParseRouteDistinguisher(rdStr)
	if err != nil {
		return nil, nil, err
	}

	rt, err := bgp.ParseExtendedCommunity(bgp.EC_SUBTYPE_ROUTE_TARGET, rdStr)
	if err != nil {
		return nil, nil, err
	}
	return rd, rt, nil
}

func addVrf(t *testing.T, s *BgpServer, vrfName, rdStr string, importRtsStr []string, exportRtsStr []string, id uint32) {
	rd, _, err := parseRDRT(rdStr)
	if err != nil {
		t.Fatal(err)
	}

	importRts := make([]bgp.ExtendedCommunityInterface, 0, len(importRtsStr))
	for _, importRtStr := range importRtsStr {
		_, rt, err := parseRDRT(importRtStr)
		if err != nil {
			t.Fatal(err)
		}
		importRts = append(importRts, rt)
	}

	exportRts := make([]bgp.ExtendedCommunityInterface, 0, len(exportRtsStr))
	for _, exportRtStr := range exportRtsStr {
		_, rt, err := parseRDRT(exportRtStr)
		if err != nil {
			t.Fatal(err)
		}
		exportRts = append(exportRts, rt)
	}
	irt, _ := apiutil.MarshalRTs(importRts)
	ert, _ := apiutil.MarshalRTs(exportRts)
	v, _ := apiutil.MarshalRD(rd)

	req := &api.AddVrfRequest{
		Vrf: &api.Vrf{
			Name:     vrfName,
			ImportRt: irt,
			ExportRt: ert,
			Rd:       v,
			Id:       id,
		},
	}
	if err = s.AddVrf(context.Background(), req); err != nil {
		t.Fatal(err)
	}
}

func TestDoNotReactToDuplicateRTCMemberships(t *testing.T) {
	ctx := context.Background()

	s1 := runNewServer(t, 1, "1.1.1.1", 10179)
	s1.logger.SetLevel(log.DebugLevel)
	s2 := runNewServer(t, 1, "2.2.2.2", 20179)
	s2.logger.SetLevel(log.DebugLevel)

	addVrf(t, s1, "vrf1", "111:111", []string{"111:111"}, []string{"111:111"}, 1)
	addVrf(t, s2, "vrf1", "111:111", []string{"111:111"}, []string{"111:111"}, 1)

	if err := peerServers(t, ctx, []*BgpServer{s1, s2}, []oc.AfiSafiType{oc.AFI_SAFI_TYPE_L3VPN_IPV4_UNICAST, oc.AFI_SAFI_TYPE_RTC}); err != nil {
		t.Fatal(err)
	}
	watcher := s1.watch(WatchUpdate(true, "", ""))

	// Add route to vrf1 on s2
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop("2.2.2.2"),
	}
	prefix := bgp.NewIPAddrPrefix(24, "10.30.2.0")
	path, _ := apiutil.NewPath(prefix, false, attrs, time.Now())

	if _, err := s2.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_VRF,
		VrfId:     "vrf1",
		Path:      path,
	}); err != nil {
		t.Fatal(err)
	}

	// s1 should receive this route from s2
	t1 := time.NewTimer(30 * time.Second)
	for found := false; !found; {
		select {
		case ev := <-watcher.Event():
			switch msg := ev.(type) {
			case *watchEventUpdate:
				for _, path := range msg.PathList {
					t.Logf("tester received path: %s", path.String())
					if vpnPath, ok := path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix); ok {
						if vpnPath.Prefix.Equal(prefix.Prefix) {
							t.Logf("tester found expected prefix: %s", vpnPath.Prefix)
							found = true
						} else {
							t.Logf("unknown prefix %s != %s", vpnPath.Prefix, prefix.Prefix)
						}
					}
				}
			}
		case <-t1.C:
			t.Fatalf("timeout while waiting for update path event")
		}
	}
	t1.Stop()

	// fabricate duplicated rtc message from s1
	// s2 should not send vpn route again
	_, rt, err := parseRDRT("111:111")
	if err != nil {
		t.Fatal(err)
	}
	rtcNLRI := bgp.NewRouteTargetMembershipNLRI(1, rt)
	rtcPath := table.NewPath(&table.PeerInfo{
		AS:      1,
		Address: net.ParseIP("127.0.0.1"),
		LocalID: net.ParseIP("2.2.2.2"),
		ID:      net.ParseIP("1.1.1.1"),
	}, rtcNLRI, false, []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop("1.1.1.1"),
	}, time.Now(), false)

	s1Peer := s2.neighborMap["127.0.0.1"]
	s2.propagateUpdate(s1Peer, []*table.Path{rtcPath})

	t2 := time.NewTimer(2 * time.Second)
	for done := false; !done; {
		select {
		case ev := <-watcher.Event():
			switch msg := ev.(type) {
			case *watchEventUpdate:
				for _, path := range msg.PathList {
					t.Logf("tester received path: %s", path.String())
					if vpnPath, ok := path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix); ok {
						t.Fatalf("vpn prefix %s was unexpectedly received", vpnPath.Prefix)
					}
				}
			}
		case <-t2.C:
			t.Logf("await update done")
			done = true
		}
	}

	err = s1.StopBgp(context.Background(), &api.StopBgpRequest{})
	assert.NoError(t, err)
	err = s2.StopBgp(context.Background(), &api.StopBgpRequest{})
	assert.NoError(t, err)
}

func TestDelVrfWithRTC(t *testing.T) {
	ctx := context.Background()

	s1 := runNewServer(t, 1, "1.1.1.1", 10179)
	defer s1.StopBgp(context.Background(), &api.StopBgpRequest{})
	s1.logger.SetLevel(log.DebugLevel)
	s2 := runNewServer(t, 1, "2.2.2.2", 20179)
	defer s2.StopBgp(context.Background(), &api.StopBgpRequest{})
	s2.logger.SetLevel(log.DebugLevel)

	addVrf(t, s1, "vrf1", "111:111", []string{"111:111"}, []string{}, 1)
	addVrf(t, s2, "vrf1", "111:111", []string{}, []string{"111:111"}, 1)

	if err := peerServers(t, ctx, []*BgpServer{s1, s2}, []oc.AfiSafiType{oc.AFI_SAFI_TYPE_L3VPN_IPV4_UNICAST, oc.AFI_SAFI_TYPE_RTC}); err != nil {
		t.Fatal(err)
	}
	watcher1 := s1.watch(WatchUpdate(true, "", ""))
	watcher2 := s2.watch(WatchUpdate(true, "", ""))

	// Add route to vrf1 on s2
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop("2.2.2.2"),
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
			bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 100, 100, true),
		}),
	}
	prefix := bgp.NewIPAddrPrefix(24, "10.30.2.0")
	path, _ := apiutil.NewPath(prefix, false, attrs, time.Now())

	if _, err := s2.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_VRF,
		VrfId:     "vrf1",
		Path:      path,
	}); err != nil {
		t.Fatal(err)
	}

	// s1 should receive this route from s2
	t1 := time.NewTimer(30 * time.Second)
	for found := false; !found; {
		select {
		case ev := <-watcher1.Event():
			switch msg := ev.(type) {
			case *watchEventUpdate:
				for _, path := range msg.PathList {
					t.Logf("tester received path: %s", path.String())
					if vpnPath, ok := path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix); ok {
						if vpnPath.Prefix.Equal(prefix.Prefix) {
							t.Logf("tester found expected prefix: %s", vpnPath.Prefix)
							found = true
						} else {
							t.Logf("unknown prefix %s != %s", vpnPath.Prefix, prefix.Prefix)
						}
					}
				}
			}
		case <-t1.C:
			t.Fatalf("timeout while waiting for update path event")
		}
	}
	t1.Stop()

	req := &api.DeleteVrfRequest{
		Name: "vrf1",
	}
	if err := s1.DeleteVrf(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	t2 := time.NewTimer(10 * time.Second)
	withdrawRTC := false
	withdrawVPN := false
	for !withdrawRTC || !withdrawVPN {
		select {
		case ev := <-watcher1.Event():
			switch msg := ev.(type) {
			case *watchEventUpdate:
				for _, path := range msg.PathList {
					t.Logf("tester received path: %s", path.String())
					if vpnPath, ok := path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix); ok {
						if vpnPath.Prefix.Equal(prefix.Prefix) && path.IsWithdraw {
							t.Logf("tester found expected withdrawn prefix: %s", vpnPath.Prefix)
							withdrawVPN = true
						} else {
							t.Logf("unknown prefix %s != %s", vpnPath.Prefix, prefix.Prefix)
						}
					}
				}
			}
		case ev := <-watcher2.Event():
			switch msg := ev.(type) {
			case *watchEventUpdate:
				for _, path := range msg.PathList {
					t.Logf("tester received path: %s", path.String())
					if rtm, ok := path.GetNlri().(*bgp.RouteTargetMembershipNLRI); ok {
						if path.IsWithdraw {
							t.Logf("rtm is withdrawn: %s", rtm.String())
							withdrawRTC = true
						}
					}
				}
			}
		case <-t2.C:
			t.Fatalf("timeout while waiting for withdrawn paths")
		}
	}
}

func TestSameRTCMessagesWithOneDifferrence(t *testing.T) {
	ctx := context.Background()

	s1 := runNewServer(t, 1, "1.1.1.1", 10179)
	defer s1.StopBgp(context.Background(), &api.StopBgpRequest{})
	s1.logger.SetLevel(log.DebugLevel)
	s2 := runNewServer(t, 1, "2.2.2.2", 20179)
	defer s2.StopBgp(context.Background(), &api.StopBgpRequest{})
	s2.logger.SetLevel(log.DebugLevel)

	if err := peerServers(t, ctx, []*BgpServer{s1, s2}, []oc.AfiSafiType{oc.AFI_SAFI_TYPE_L3VPN_IPV4_UNICAST, oc.AFI_SAFI_TYPE_RTC}); err != nil {
		t.Fatal(err)
	}
	watcher1 := s1.watch(WatchUpdate(true, "", ""))
	watcher2 := s2.watch(WatchUpdate(true, "", ""))

	rt := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 100, 100, true)

	// VPN Path:
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop("3.3.3.3"),
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{rt}),
	}
	rd, _ := bgp.ParseRouteDistinguisher("100:100")
	labels := bgp.NewMPLSLabelStack(100, 200)
	prefix := bgp.NewLabeledVPNIPAddrPrefix(24, "10.30.2.0", *labels, rd)
	path, _ := apiutil.NewPath(prefix, false, attrs, time.Now())

	if _, err := s2.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      path,
	}); err != nil {
		t.Fatal(err)
	}

	attrsNH0 := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop("0.0.0.0"),
	}
	pathRtc0, _ := apiutil.NewPath(bgp.NewRouteTargetMembershipNLRI(1, rt), false, attrsNH0, time.Now())
	if _, err := s1.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      pathRtc0,
	}); err != nil {
		t.Fatal(err)
	}

	// s1 should receive this route from s2
	t1 := time.NewTimer(30 * time.Second)
	for found := false; !found; {
		select {
		case ev := <-watcher1.Event():
			switch msg := ev.(type) {
			case *watchEventUpdate:
				for _, path := range msg.PathList {
					t.Logf("tester received path: %s", path.String())
					if vpnPath, ok := path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix); ok {
						if vpnPath.Prefix.Equal(prefix.Prefix) {
							t.Logf("tester found expected prefix: %s", vpnPath.Prefix)
							found = true
						} else {
							t.Logf("unknown prefix %s != %s", vpnPath.Prefix, prefix.Prefix)
						}
					}
				}
			}
		case <-t1.C:
			t.Fatalf("timeout while waiting for update path event")
		}
	}
	t1.Stop()

	// Extra ExtComm for small difference between RTC messages:
	rt200 := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 200, 200, true)
	attrsNH1 := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{rt200}),
		bgp.NewPathAttributeNextHop("0.0.0.0"),
	}
	pathRtc1, _ := apiutil.NewPath(bgp.NewRouteTargetMembershipNLRI(1, rt), false, attrsNH1, time.Now())
	if _, err := s1.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      pathRtc1,
	}); err != nil {
		t.Fatal(err)
	}

	// s1 should not receive withdrawn route from s2
	t1 = time.NewTimer(5 * time.Second)
	rtcNumber := 0
	for graceful := false; !graceful; {
		select {
		case ev := <-watcher1.Event():
			switch msg := ev.(type) {
			case *watchEventUpdate:
				for _, path := range msg.PathList {
					t.Logf("tester received path: %s", path.String())
					if vpnPath, ok := path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix); ok {
						if vpnPath.Prefix.Equal(prefix.Prefix) {
							if path.IsWithdraw {
								t.Fatalf("active path is withdrawn")
							} else {
								t.Logf("tester found expected prefix: %s", vpnPath.Prefix)
								graceful = true
							}
						} else {
							t.Logf("unknown prefix %s != %s", vpnPath.Prefix, prefix.Prefix)
						}
					}
				}
			}
		case ev := <-watcher2.Event():
			switch msg := ev.(type) {
			case *watchEventUpdate:
				for _, path := range msg.PathList {
					t.Logf("tester received path: %s", path.String())
					if rtm, ok := path.GetNlri().(*bgp.RouteTargetMembershipNLRI); ok {
						if path.IsWithdraw {
							t.Logf("rtm is withdrawn: %s", rtm.String())
						} else {
							rtcNumber++
							if rtcNumber > 1 {
								t.Logf("rtm added twice: %s", rtm.String())
							}
						}
					}
				}
			}
		case <-t1.C:
			t.Logf("no paths have been withdrawn")
			graceful = true
		}
	}
	t1.Stop()
}

func TestAddDeletePath(t *testing.T) {
	ctx := context.Background()
	s := runNewServer(t, 1, "1.1.1.1", 10179)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	nlri := &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
		Prefix:    "10.0.0.0",
		PrefixLen: 24,
	}}}

	nlri6 := &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
		Prefix:    "2001:DB8::",
		PrefixLen: 32,
	}}}

	nh1 := &api.Attribute{Attr: &api.Attribute_NextHop{NextHop: &api.NextHopAttribute{
		NextHop: "fd00::1",
	}}}

	nh2 := &api.Attribute{Attr: &api.Attribute_NextHop{NextHop: &api.NextHopAttribute{
		NextHop: "fd00::2",
	}}}

	nh3 := &api.Attribute{Attr: &api.Attribute_NextHop{NextHop: &api.NextHopAttribute{
		NextHop: "10.0.0.1",
	}}}

	nh4 := &api.Attribute{Attr: &api.Attribute_NextHop{NextHop: &api.NextHopAttribute{
		NextHop: "10.0.0.2",
	}}}

	a1 := &api.Attribute{Attr: &api.Attribute_Origin{Origin: &api.OriginAttribute{
		Origin: 0,
	}}}

	attrs := []*api.Attribute{a1, nh3}

	family := bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_UNICAST)
	family6 := bgp.NewFamily(bgp.AFI_IP6, bgp.SAFI_UNICAST)

	listRib := func(f bgp.Family) []*api.Destination {
		l := make([]*api.Destination, 0)
		err := s.ListPath(ctx, apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: f}, func(prefix bgp.AddrPrefixInterface, paths []*apiutil.Path) {
			d := api.Destination{
				Prefix: prefix.String(),
				Paths:  make([]*api.Path, len(paths)),
			}
			for i, path := range paths {
				d.Paths[i] = toPathApi(path, false, false, false)
			}
			l = append(l, &d)
		})
		assert.NoError(t, err)
		return l
	}

	numPaths := func(f bgp.Family) int {
		c := 0
		for _, d := range listRib(f) {
			c += len(d.Paths)
		}
		return c
	}

	var err error
	// DeletePath(AddPath()) without PeerInfo
	getPath := func() *api.Path {
		return &api.Path{
			Family: &api.Family{Afi: api.Family_Afi(family.Afi()), Safi: api.Family_Safi(family.Safi())},
			Nlri:   nlri,
			Pattrs: attrs,
		}
	}

	p1 := getPath()
	_, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      p1,
	})
	assert.NoError(t, err)
	assert.Equal(t, len(listRib(family)), 1)
	err = s.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      p1,
	})
	assert.NoError(t, err)
	assert.Equal(t, len(listRib(family)), 0)

	// DeletePath(ListPath()) without PeerInfo
	_, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      p1,
	})
	assert.NoError(t, err)
	l := listRib(family)
	assert.Equal(t, len(l), 1)
	err = s.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      l[0].Paths[0],
	})
	assert.NoError(t, err)
	assert.Equal(t, len(listRib(family)), 0)

	p2 := getPath()
	p2.SourceAsn = 1
	p2.SourceId = "1.1.1.1"

	// DeletePath(AddPath()) with PeerInfo
	_, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      p2,
	})
	assert.NoError(t, err)
	assert.Equal(t, len(listRib(family)), 1)
	err = s.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      p2,
	})
	assert.NoError(t, err)
	assert.Equal(t, len(listRib(family)), 0)

	// DeletePath(ListPath()) with PeerInfo
	_, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      p2,
	})
	assert.NoError(t, err)
	l = listRib(family)
	assert.Equal(t, len(l), 1)
	err = s.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      l[0].Paths[0],
	})
	assert.NoError(t, err)
	assert.Equal(t, len(listRib(family)), 0)

	// DeletePath(AddPath()) with different identifiers (ipv6)
	path1 := &api.Path{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_UNICAST,
		},
		Nlri:       nlri6,
		Pattrs:     []*api.Attribute{a1, nh1},
		Identifier: 1,
	}

	path2 := &api.Path{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_UNICAST,
		},
		Nlri:       nlri6,
		Pattrs:     []*api.Attribute{a1, nh2},
		Identifier: 2,
	}

	_, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      path1,
	})
	assert.NoError(t, err)
	assert.Equal(t, numPaths(family6), 1)

	_, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      path2,
	})
	assert.NoError(t, err)
	assert.Equal(t, numPaths(family6), 2)

	err = s.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      path1,
	})
	assert.NoError(t, err)
	assert.Equal(t, numPaths(family6), 1)

	err = s.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      path2,
	})
	assert.NoError(t, err)
	assert.Equal(t, numPaths(family6), 0)

	// DeletePath(AddPath()) with different identifiers (ipv4)
	path1 = &api.Path{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
		Nlri:       nlri,
		Pattrs:     []*api.Attribute{a1, nh3},
		Identifier: 1,
	}

	path2 = &api.Path{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
		Nlri:       nlri,
		Pattrs:     []*api.Attribute{a1, nh4},
		Identifier: 2,
	}

	_, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      path1,
	})
	assert.NoError(t, err)
	assert.Equal(t, numPaths(family), 1)

	_, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      path2,
	})
	assert.NoError(t, err)
	assert.Equal(t, numPaths(family), 2)

	err = s.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      path1,
	})
	assert.NoError(t, err)
	assert.Equal(t, numPaths(family), 1)

	err = s.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      path2,
	})
	assert.NoError(t, err)
	assert.Equal(t, numPaths(family), 0)

	// DeletePath(AddPath()) with different PeerInfo
	_, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      p2,
	})
	assert.NoError(t, err)
	assert.Equal(t, len(listRib(family)), 1)
	p3 := getPath()
	p3.SourceAsn = 2
	p3.SourceId = "1.1.1.2"
	err = s.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      p3,
	})
	assert.NoError(t, err)
	assert.Equal(t, len(listRib(family)), 1)

	// DeletePath(AddPath()) with uuid
	r, err := s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      p2,
	})
	assert.NoError(t, err)
	assert.Equal(t, len(listRib(family)), 1)
	err = s.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Uuid:      r.Uuid,
	})
	assert.NoError(t, err)
	assert.Equal(t, len(listRib(family)), 0)
	assert.Equal(t, len(s.uuidMap), 0)

	r, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      p2,
	})
	assert.NoError(t, err)
	assert.Equal(t, len(listRib(family)), 1)
	assert.Equal(t, len(s.uuidMap), 1)
	u := r.Uuid

	asPath := &api.Attribute{Attr: &api.Attribute_AsPath{AsPath: &api.AsPathAttribute{
		Segments: []*api.AsSegment{
			{
				Type:    1, // SET
				Numbers: []uint32{100, 200, 300},
			},
		},
	}}}

	p2.Pattrs = append(p2.Pattrs, asPath)
	r, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      p2,
	})
	assert.NoError(t, err)
	assert.Equal(t, len(listRib(family)), 1)
	assert.Equal(t, len(s.uuidMap), 1)
	assert.NotEqual(t, u, r.Uuid)
}

func TestDeleteNonExistingVrf(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", 10179)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	s.logger.SetLevel(log.DebugLevel)

	addVrf(t, s, "vrf1", "111:111", []string{"111:111"}, []string{"111:111"}, 1)
	req := &api.DeleteVrfRequest{Name: "Invalidvrf"}
	if err := s.DeleteVrf(context.Background(), req); err == nil {
		t.Fatal("Did not raise error for invalid vrf deletion.", err)
	}
}

func TestDeleteVrf(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", 10179)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	s.logger.SetLevel(log.DebugLevel)

	addVrf(t, s, "vrf1", "111:111", []string{"111:111"}, []string{"111:111"}, 1)
	req := &api.DeleteVrfRequest{Name: "vrf1"}
	if err := s.DeleteVrf(context.Background(), req); err != nil {
		t.Fatal("Vrf delete failed", err)
	}
}

func TestAddBogusPath(t *testing.T) {
	ctx := context.Background()
	s := runNewServer(t, 1, "1.1.1.1", 10179)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	nlri := &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{}}}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: &api.MpReachNLRIAttribute{}}}

	_, err := s.AddPath(ctx, &api.AddPathRequest{
		Path: &api.Path{
			Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
			Nlri:   nlri,
			Pattrs: []*api.Attribute{a},
		},
	})
	assert.NotNil(t, err)

	nlri = &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{}}}

	a = &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: &api.MpReachNLRIAttribute{
		Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST},
	}}}

	_, err = s.AddPath(ctx, &api.AddPathRequest{
		Path: &api.Path{
			Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
			Nlri:   nlri,
			Pattrs: []*api.Attribute{a},
		},
	})
	assert.NotNil(t, err)
}

// TestListPathWithIdentifiers confirms whether ListPath properly returns the
// identifier information for paths for the Global RIB and for VRF RIBs.
func TestListPathWithIdentifiers(t *testing.T) {
	ctx := context.Background()

	assert := assert.New(t)
	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	assert.NoError(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	family := bgp.NewFamily(bgp.AFI_IP, bgp.SAFI_UNICAST)
	nlri1 := &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
		Prefix:    "10.1.0.0",
		PrefixLen: 24,
	}}}

	attrs := []*api.Attribute{
		{
			Attr: &api.Attribute_Origin{Origin: &api.OriginAttribute{
				Origin: 0,
			}},
		},
		{
			Attr: &api.Attribute_NextHop{NextHop: &api.NextHopAttribute{
				NextHop: "10.0.0.1",
			}},
		},
	}
	paths := []*api.Path{
		{
			Family:     &api.Family{Afi: api.Family_Afi(family.Afi()), Safi: api.Family_Safi(family.Safi())},
			Nlri:       nlri1,
			Pattrs:     attrs,
			Identifier: 1,
		},
		{
			Family:     &api.Family{Afi: api.Family_Afi(family.Afi()), Safi: api.Family_Safi(family.Safi())},
			Nlri:       nlri1,
			Pattrs:     attrs,
			Identifier: 2,
		},
	}
	wantIDs := []uint32{1, 2}
	applyPathsTo := func(vrf string) {
		for _, path := range paths {
			_, err = s.AddPath(context.Background(), &api.AddPathRequest{
				TableType: api.TableType_TABLE_TYPE_GLOBAL,
				Path:      path,
				VrfId:     vrf,
			})
			assert.NoError(err)
		}
	}
	destinationsFrom := func(name string, tableType api.TableType) []*api.Destination {
		var destinations []*api.Destination
		err = s.ListPath(ctx, apiutil.ListPathRequest{
			Name:      name,
			TableType: tableType,
			Family:    family,
		}, func(prefix bgp.AddrPrefixInterface, paths []*apiutil.Path) {
			d := api.Destination{
				Prefix: prefix.String(),
				Paths:  make([]*api.Path, len(paths)),
			}
			for i, path := range paths {
				d.Paths[i] = toPathApi(path, false, false, false)
			}
			destinations = append(destinations, &d)
		})
		assert.NoError(err)
		return destinations
	}
	identifiersFrom := func(destinations []*api.Destination) []uint32 {
		var ids []uint32
		for _, d := range destinations {
			for _, p := range d.Paths {
				ids = append(ids, p.Identifier)
			}
		}
		slices.Sort(ids)
		return ids
	}

	t.Logf("For Global RIB")
	applyPathsTo("")
	gotDestinations := destinationsFrom("", api.TableType_TABLE_TYPE_GLOBAL)
	gotIDs := identifiersFrom(gotDestinations)
	if diff := cmp.Diff(gotIDs, wantIDs); diff != "" {
		t.Errorf("IDs differed for global RIB (-got, +want):\n%s", diff)
	}

	t.Logf("For VRF RIB")
	vrfName := "vrf"
	addVrf(t, s, vrfName, "0:0", []string{"0:0"}, []string{"0:0"}, 0)
	applyPathsTo(vrfName)
	gotDestinations = destinationsFrom(vrfName, api.TableType_TABLE_TYPE_VRF)
	gotIDs = identifiersFrom(gotDestinations)
	if diff := cmp.Diff(gotIDs, wantIDs); diff != "" {
		t.Errorf("IDs differed for VRF RIB (-got, +want):\n%s", diff)
	}
}

func TestWatchEvent(test *testing.T) {
	assert := assert.New(test)
	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.NoError(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	peer1 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         2,
		},
		Transport: &api.Transport{
			PassiveMode: true,
		},
	}
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer1})
	assert.NoError(err)

	d1 := &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
		Name:        "d1",
		Prefixes: []*api.Prefix{
			{
				IpPrefix:      "10.1.0.0/24",
				MaskLengthMax: 24,
				MaskLengthMin: 24,
			},
		},
	}
	s1 := &api.Statement{
		Name: "s1",
		Conditions: &api.Conditions{
			PrefixSet: &api.MatchSet{
				Name: "d1",
				Type: api.MatchSet_TYPE_ANY,
			},
		},
		Actions: &api.Actions{
			RouteAction: api.RouteAction_ROUTE_ACTION_REJECT,
		},
	}
	err = s.AddDefinedSet(context.Background(), &api.AddDefinedSetRequest{DefinedSet: d1})
	assert.NoError(err)
	p1 := &api.Policy{
		Name:       "p1",
		Statements: []*api.Statement{s1},
	}
	err = s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: p1})
	assert.NoError(err)
	err = s.AddPolicyAssignment(context.Background(), &api.AddPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          table.GLOBAL_RIB_NAME,
			Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
			Policies:      []*api.Policy{p1},
			DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
		},
	})
	assert.NoError(err)

	t := NewBgpServer()
	go t.Serve()
	err = t.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	assert.NoError(err)
	defer t.StopBgp(context.Background(), &api.StopBgpRequest{})

	family := &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_UNICAST,
	}

	nlri1 := &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
		Prefix:    "10.1.0.0",
		PrefixLen: 24,
	}}}

	attrs := []*api.Attribute{
		{
			Attr: &api.Attribute_Origin{Origin: &api.OriginAttribute{
				Origin: 0,
			}},
		},
		{
			Attr: &api.Attribute_NextHop{NextHop: &api.NextHopAttribute{
				NextHop: "10.0.0.1",
			}},
		},
	}

	_, err = t.AddPath(context.Background(), &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path: &api.Path{
			Family: family,
			Nlri:   nlri1,
			Pattrs: attrs,
		},
	})
	assert.NoError(err)

	nlri2 := &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
		Prefix:    "10.2.0.0",
		PrefixLen: 24,
	}}}
	_, err = t.AddPath(context.Background(), &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path: &api.Path{
			Family: family,
			Nlri:   nlri2,
			Pattrs: attrs,
		},
	})
	assert.NoError(err)

	peer2 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         1,
		},
		Transport: &api.Transport{
			RemotePort: 10179,
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				ConnectRetry:           1,
				IdleHoldTimeAfterReset: 1,
			},
		},
		AfiSafis: []*api.AfiSafi{
			{
				Config: &api.AfiSafiConfig{
					Family: &api.Family{
						Afi:  api.Family_AFI_IP,
						Safi: api.Family_SAFI_UNICAST,
					},
				},
			},
			{
				Config: &api.AfiSafiConfig{
					Family: &api.Family{
						Afi:  api.Family_AFI_IP6,
						Safi: api.Family_SAFI_UNICAST,
					},
				},
			},
		},
	}
	watchers := waitEstablished(s, bgp.RF_IPv4_UC, bgp.RF_IPv6_UC)

	err = t.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer2})
	assert.NoError(err)
	watchers.Wait()

	count := 0
	tableCh := make(chan struct{})
	f := func(paths []*apiutil.Path, _ time.Time) {
		count += len(paths)
		if len(paths) > 0 && count == 2 {
			close(tableCh)
		}
	}
	opts := make([]WatchOption, 0)
	opts = append(opts, WatchUpdate(true, "127.0.0.1", ""))
	err = s.WatchEvent(context.Background(), WatchEventMessageCallbacks{
		OnPathUpdate: f,
	}, opts...)
	assert.NoError(err)
	<-tableCh
	assert.Equal(2, count)
}

func TestAddDefinedSetReplace(t *testing.T) {
	assert := assert.New(t)
	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.NoError(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// set an initial policy
	n1 := &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR,
		Name:        "replaceme",
		List:        []string{"203.0.113.1/32"},
	}
	err = s.AddDefinedSet(context.Background(), &api.AddDefinedSetRequest{DefinedSet: n1})
	assert.NoError(err)

	// confirm the policy is what we set
	ns := make([]*api.DefinedSet, 0)
	fn := func(ds *api.DefinedSet) {
		ns = append(ns, ds)
	}
	err = s.ListDefinedSet(context.Background(), &api.ListDefinedSetRequest{
		DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR,
		Name:        "replaceme",
	}, fn)
	assert.NoError(err)
	assert.Equal(1, len(ns))
	assert.Equal("replaceme", ns[0].Name)
	assert.Equal([]string{"203.0.113.1/32"}, ns[0].List)

	// now replace the policy
	n2 := &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR,
		Name:        "replaceme",
		List:        []string{"203.0.113.2/32"},
	}
	err = s.AddDefinedSet(context.Background(), &api.AddDefinedSetRequest{DefinedSet: n2, Replace: true})
	assert.NoError(err)

	// confirm the policy was replaced
	ns = make([]*api.DefinedSet, 0)
	err = s.ListDefinedSet(context.Background(), &api.ListDefinedSetRequest{
		DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR,
		Name:        "replaceme",
	}, fn)
	assert.NoError(err)
	assert.Equal(1, len(ns))
	assert.Equal("replaceme", ns[0].Name)
	assert.Equal([]string{"203.0.113.2/32"}, ns[0].List)
}
