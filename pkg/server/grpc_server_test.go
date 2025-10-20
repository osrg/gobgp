package server

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func mustApi2apiutilPath(path *api.Path) *apiutil.Path {
	p, err := api2apiutilPath(path)
	if err != nil {
		panic(fmt.Sprintf("failed to convert api.Path to apiutil.Path: %v", err))
	}
	return p
}

func TestParseHost(t *testing.T) {
	tsts := []struct {
		name          string
		host          string
		expectNetwork string
		expectAddr    string
	}{
		{
			name:          "schemeless tcp host defaults to tcp",
			host:          "127.0.0.1:50051",
			expectNetwork: "tcp",
			expectAddr:    "127.0.0.1:50051",
		},
		{
			name:          "schemeless with only port defaults to tcp",
			host:          ":50051",
			expectNetwork: "tcp",
			expectAddr:    ":50051",
		},
		{
			name:          "unix socket",
			host:          "unix:///var/run/gobgp.socket",
			expectNetwork: "unix",
			expectAddr:    "/var/run/gobgp.socket",
		},
	}

	for _, tst := range tsts {
		t.Run(tst.name, func(t *testing.T) {
			gotNetwork, gotAddr := parseHost(tst.host)
			assert.Equal(t, tst.expectNetwork, gotNetwork)
			assert.Equal(t, tst.expectAddr, gotAddr)
		})
	}
}

func TestToPathApi(t *testing.T) {
	type args struct {
		path            *table.Path
		onlyBinary      bool
		nlriBinary      bool
		attributeBinary bool
	}
	n, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/8"))
	tests := []struct {
		name string
		args args
		want *api.Path
	}{
		{
			name: "ipv4 path",
			args: args{
				path: table.NewPath(bgp.RF_IPv4_UC, &table.PeerInfo{
					ID:           netip.MustParseAddr("10.10.10.10"),
					LocalID:      netip.MustParseAddr("10.11.11.11"),
					Address:      netip.MustParseAddr("10.12.12.12"),
					LocalAddress: netip.MustParseAddr("10.13.13.13"),
				},
					bgp.PathNLRI{NLRI: n},
					false,
					[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)},
					time.Time{},
					false),
			},
			want: &api.Path{
				Nlri:   nlri(n),
				Pattrs: attrs([]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}),
				Family: &api.Family{
					Afi:  api.Family_AFI_IP,
					Safi: api.Family_SAFI_UNICAST,
				},
				Validation: &api.Validation{},
				NeighborIp: "10.12.12.12",
				SourceId:   "10.10.10.10",
			},
		},
		{
			name: "eor ipv4 path",
			args: args{
				path: eor(bgp.RF_IPv4_UC),
			},
			want: &api.Path{
				Family: &api.Family{
					Afi:  api.Family_AFI_IP,
					Safi: api.Family_SAFI_UNICAST,
				},
				Pattrs:     []*api.Attribute{},
				Validation: &api.Validation{},
				NeighborIp: "10.12.12.12",
				SourceId:   "10.10.10.10",
			},
		},
		{
			name: "eor vpn path",
			args: args{
				path: eor(bgp.RF_IPv4_VPN),
			},
			want: &api.Path{
				Family: &api.Family{
					Afi:  api.Family_AFI_IP,
					Safi: api.Family_SAFI_MPLS_VPN,
				},
				Pattrs:     []*api.Attribute{},
				Validation: &api.Validation{},
				NeighborIp: "10.12.12.12",
				SourceId:   "10.10.10.10",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiPath := toPathApi(toPathApiUtil(tt.args.path), tt.args.onlyBinary, tt.args.nlriBinary, tt.args.attributeBinary)
			if tt.want.Nlri != nil {
				assert.Equal(t, tt.want.Nlri, apiPath.Nlri, "not equal nlri")
			}
			assert.Equal(t, tt.want.Pattrs, apiPath.Pattrs, "not equal attrs")
			assert.Equal(t, tt.want.Family, apiPath.Family, "not equal family")
			assert.Equal(t, tt.want.NeighborIp, apiPath.NeighborIp, "not equal neighbor")
		})
	}
}

func eor(f bgp.Family) *table.Path {
	p := table.NewEOR(f)
	p.SetSource(&table.PeerInfo{
		ID:           netip.MustParseAddr("10.10.10.10"),
		LocalID:      netip.MustParseAddr("10.11.11.11"),
		Address:      netip.MustParseAddr("10.12.12.12"),
		LocalAddress: netip.MustParseAddr("10.13.13.13"),
	})
	return p
}

func nlri(nlri bgp.NLRI) *api.NLRI {
	apiNlri, _ := apiutil.MarshalNLRI(nlri)
	return apiNlri
}

func attrs(attrs []bgp.PathAttributeInterface) []*api.Attribute {
	apiAttrs, _ := apiutil.MarshalPathAttributes(attrs)
	return apiAttrs
}

//nolint:errcheck // WatchEvent won't return an error here
func GRPCwaitState(t *testing.T, s api.GoBgpServiceClient, state api.PeerState_SessionState, expectedFamilies ...bgp.Family) *sync.WaitGroup {
	wg := &sync.WaitGroup{}
	watchCtx, watchCancel := context.WithCancel(context.Background())
	wg.Add(1)

	resp, err := s.WatchEvent(watchCtx, &api.WatchEventRequest{Peer: &api.WatchEventRequest_Peer{}})
	assert.NoError(t, err, "failed to start watch event")

	go func() {
		for {
			select {
			case <-watchCtx.Done():
				return
			default:
				r, err := resp.Recv()
				assert.NoError(t, err, "failed to receive watch event response")

				if peer := r.GetPeer(); peer != nil {
					if peer.Type == api.WatchEventResponse_PeerEvent_TYPE_STATE && peer.Peer.State.SessionState == state {
						remoteCaps, err := apiutil.UnmarshalCapabilities(peer.Peer.GetState().GetRemoteCap())
						if err != nil {
							t.Errorf("failed to unmarshal remote capabilities: %v", err)
						}
						for _, rf := range expectedFamilies {
							found := false
							for _, cap := range remoteCaps {
								if cap.Code() == bgp.BGP_CAP_MULTIPROTOCOL && cap.(*bgp.CapMultiProtocol).CapValue == rf {
									found = true
									break
								}
							}
							if !found {
								return
							}
						}
						watchCancel()
						wg.Done()
					}
				}
			}
		}
	}()
	return wg
}

func GRPCwaitActive(t *testing.T, s api.GoBgpServiceClient) *sync.WaitGroup {
	return GRPCwaitState(t, s, api.PeerState_SESSION_STATE_ACTIVE)
}

func GRPCwaitEstablished(t *testing.T, s api.GoBgpServiceClient, rfs ...bgp.Family) *sync.WaitGroup {
	return GRPCwaitState(t, s, api.PeerState_SESSION_STATE_ESTABLISHED, rfs...)
}

func TestGRPCWatchEvent(t *testing.T) {
	assert := assert.New(t)

	socketName, err := os.MkdirTemp("", "gobgp-grpc-test-*")
	assert.NoError(err)
	t.Cleanup(func() {
		_ = os.RemoveAll(socketName)
	})
	socketAddr := "unix://" + socketName + "/gobgp.sock"

	s := NewBgpServer(GrpcListenAddress(socketAddr))
	go s.Serve()
	defer s.Stop()

	err = s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.NoError(err)

	conn, err := grpc.NewClient(socketAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	assert.NoError(err)
	client := api.NewGoBgpServiceClient(conn)

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

	t2 := NewBgpServer()
	go t2.Serve()
	err = t2.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	assert.NoError(err)
	defer t2.StopBgp(context.Background(), &api.StopBgpRequest{})

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

	_, err = t2.AddPath(apiutil.AddPathRequest{
		Paths: []*apiutil.Path{
			mustApi2apiutilPath(&api.Path{
				Family: family,
				Nlri:   nlri1,
				Pattrs: attrs,
			}),
		},
	})

	assert.NoError(err)

	nlri2 := &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
		Prefix:    "10.2.0.0",
		PrefixLen: 24,
	}}}
	_, err = t2.AddPath(apiutil.AddPathRequest{
		Paths: []*apiutil.Path{
			mustApi2apiutilPath(&api.Path{
				Family: family,
				Nlri:   nlri2,
				Pattrs: attrs,
			}),
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

	t.Log("wait for peer1 to be established")
	establishedWg := GRPCwaitEstablished(t, client, bgp.RF_IPv4_UC, bgp.RF_IPv6_UC)
	t.Log("wait for peer1 to be established done")

	err = t2.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer2})
	assert.NoError(err)

	establishedWg.Wait()

	count := 0
	tableCh := make(chan any)
	watchCtx, watchCancel := context.WithCancel(context.Background())
	resp, err := client.WatchEvent(watchCtx, &api.WatchEventRequest{
		Table: &api.WatchEventRequest_Table{
			Filters: []*api.WatchEventRequest_Table_Filter{
				{
					Type:        api.WatchEventRequest_Table_Filter_TYPE_ADJIN,
					PeerAddress: "127.0.0.1",
					Init:        true,
				},
			},
		},
	})
	assert.NoError(err, "failed to start watch event")

	go func() {
		for {
			select {
			case <-watchCtx.Done():
				return
			default:
				r, err := resp.Recv()
				assert.NoError(err, "failed to receive watch event response")
				t := r.Event.(*api.WatchEventResponse_Table)
				count += len(t.Table.Paths)
				if count == 2 {
					watchCancel()
					close(tableCh)
				}
			}
		}
	}()
	assert.NoError(err)
	<-tableCh

	assert.Equal(2, count)
}

func TestToOcAttributeComparison(t *testing.T) {
	tests := []struct {
		in   api.Comparison
		want oc.AttributeComparison
	}{
		{api.Comparison_COMPARISON_EQ, oc.ATTRIBUTE_COMPARISON_EQ},
		{api.Comparison_COMPARISON_GE, oc.ATTRIBUTE_COMPARISON_GE},
		{api.Comparison_COMPARISON_LE, oc.ATTRIBUTE_COMPARISON_LE},
	}
	for _, tt := range tests {
		if got := toOcAttributeComparison(tt.in); got != tt.want {
			t.Fatalf("toOcAttributeComparison(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestNewAsPathLengthConditionFromApiStruct(t *testing.T) {
	tests := []struct {
		inType api.Comparison
		inVal  uint32
		wantOp string
	}{
		{api.Comparison_COMPARISON_EQ, 1, "="},
		{api.Comparison_COMPARISON_GE, 2, ">="},
		{api.Comparison_COMPARISON_LE, 3, "<="},
	}
	for _, tt := range tests {
		cond, err := newAsPathLengthConditionFromApiStruct(&api.AsPathLength{Type: tt.inType, Length: tt.inVal})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cond == nil {
			t.Fatalf("condition is nil")
		}
		got := cond.String()
		if got[:len(tt.wantOp)] != tt.wantOp {
			t.Fatalf("operator mismatch: got %q want prefix %q", got, tt.wantOp)
		}
	}
}

func TestNewCommunityCountConditionFromApiStruct(t *testing.T) {
	tests := []struct {
		inType api.Comparison
		inVal  uint32
		wantOp string
	}{
		{api.Comparison_COMPARISON_EQ, 10, "="},
		{api.Comparison_COMPARISON_GE, 20, ">="},
		{api.Comparison_COMPARISON_LE, 30, "<="},
	}
	for _, tt := range tests {
		cond, err := newCommunityCountConditionFromApiStruct(&api.CommunityCount{Type: tt.inType, Count: tt.inVal})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cond == nil {
			t.Fatalf("condition is nil")
		}
		got := cond.String()
		if got[:len(tt.wantOp)] != tt.wantOp {
			t.Fatalf("operator mismatch: got %q want prefix %q", got, tt.wantOp)
		}
	}
}
