package server

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
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

func TestNewPeerGroupFromAPIStructRejectsInvalidAllowOwnAsn(t *testing.T) {
	_, err := newPeerGroupFromAPIStruct(&api.PeerGroup{
		Conf: &api.PeerGroupConf{
			PeerGroupName: "pg",
			AllowOwnAsn:   256,
		},
	})
	assert.ErrorContains(t, err, "allow_own_asn is out of range")
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
	t.Log("t2 add peer done")

	establishedWg.Wait()
	t.Log("t2 peer established done")

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

func TestGRPCAddPathUpdatesUUIDMap(t *testing.T) {
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
			ListenPort: -1,
		},
	})
	assert.NoError(err)
	if err != nil {
		return
	}
	if !assert.Eventually(func() bool {
		_, statErr := os.Stat(socketName + "/gobgp.sock")
		return statErr == nil
	}, time.Second, 10*time.Millisecond) {
		return
	}

	conn, err := grpc.NewClient(socketAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	assert.NoError(err)
	if err != nil {
		return
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	client := api.NewGoBgpServiceClient(conn)

	prefix, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	assert.NoError(err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	assert.NoError(err)
	origin := bgp.NewPathAttributeOrigin(0)

	path := &api.Path{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
		Nlri:   nlri(prefix),
		Pattrs: attrs([]bgp.PathAttributeInterface{origin, nh}),
	}

	resp, err := client.AddPath(context.Background(), &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      path,
	})
	assert.NoError(err)
	if err != nil {
		return
	}

	id, err := uuid.FromBytes(resp.Uuid)
	assert.NoError(err)
	assert.Len(s.uuidMap, 1)
	for _, v := range s.uuidMap {
		assert.Equal(id, v)
	}
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

func TestNewConfigPrefixFromAPIStruct(t *testing.T) {
	c, err := newConfigPrefixFromAPIStruct(&api.Prefix{IpPrefix: "10.1.2.3/24", MaskLengthMin: 24, MaskLengthMax: 24})
	assert.NoError(t, err)
	assert.Equal(t, "10.1.2.3/24", c.IpPrefix.String())
	assert.Equal(t, "", c.RtcPrefix)
	assert.Equal(t, "24..24", c.MasklengthRange)

	// rtc-prefix is canonicalized (dotted AS -> asplain, /0 -> 0:0:0/0).
	c, err = newConfigPrefixFromAPIStruct(&api.Prefix{RtcPrefix: "100.1000:65000:100/80", MaskLengthMin: 80, MaskLengthMax: 80})
	assert.NoError(t, err)
	assert.Equal(t, "6554600:65000:100/80", c.RtcPrefix)
	assert.False(t, c.IpPrefix.IsValid())

	// A length-less rtc-prefix is accepted on input and canonicalized to /96.
	c, err = newConfigPrefixFromAPIStruct(&api.Prefix{RtcPrefix: "65000:65000:100", MaskLengthMin: 96, MaskLengthMax: 96})
	assert.NoError(t, err)
	assert.Equal(t, "65000:65000:100/96", c.RtcPrefix)

	// /0 wildcard (RTC default-route) keeps the caller's mask range.
	c, err = newConfigPrefixFromAPIStruct(&api.Prefix{RtcPrefix: "0:0:0/0", MaskLengthMin: 0, MaskLengthMax: 96})
	assert.NoError(t, err)
	assert.Equal(t, "0:0:0/0", c.RtcPrefix)
	assert.False(t, c.IpPrefix.IsValid())
	assert.Equal(t, "0..96", c.MasklengthRange)
	c, err = newConfigPrefixFromAPIStruct(&api.Prefix{RtcPrefix: "0:0/0", MaskLengthMin: 0, MaskLengthMax: 0})
	assert.NoError(t, err)
	assert.Equal(t, "0:0:0/0", c.RtcPrefix)

	_, err = newConfigPrefixFromAPIStruct(&api.Prefix{IpPrefix: "10.0.0.0/8", RtcPrefix: "65000:65000:100/96"})
	assert.NotNil(t, err)
	_, err = newConfigPrefixFromAPIStruct(&api.Prefix{})
	assert.NotNil(t, err)
	_, err = newConfigPrefixFromAPIStruct(&api.Prefix{RtcPrefix: "65000:65000"})
	assert.NotNil(t, err)
}

func TestNewPrefixFromApiStructRTC(t *testing.T) {
	p, err := newPrefixFromApiStruct(&api.Prefix{RtcPrefix: "65000:65000:100/96", MaskLengthMin: 96, MaskLengthMax: 96})
	assert.NoError(t, err)
	assert.Equal(t, bgp.RF_RTC_UC, p.AddressFamily)
	assert.Equal(t, uint8(96), p.MasklengthRangeMin)
	assert.Equal(t, uint8(96), p.MasklengthRangeMax)
	assert.Equal(t, "65000:65000:100/96", p.PrefixString())

	// /0 wildcard maps to ::/0 and matches any RTC NLRI.
	p, err = newPrefixFromApiStruct(&api.Prefix{RtcPrefix: "0:0:0/0", MaskLengthMin: 0, MaskLengthMax: 96})
	assert.NoError(t, err)
	assert.Equal(t, bgp.RF_RTC_UC, p.AddressFamily)
	assert.Equal(t, uint8(0), p.MasklengthRangeMin)
	assert.Equal(t, uint8(96), p.MasklengthRangeMax)
	assert.Equal(t, "::/0", p.Prefix.String())
	assert.Equal(t, "0:0:0/0", p.PrefixString())
	full, err := newPrefixFromApiStruct(&api.Prefix{RtcPrefix: "65000:65000:100/96", MaskLengthMin: 96, MaskLengthMax: 96})
	assert.NoError(t, err)
	assert.True(t, p.Prefix.Contains(full.Prefix.Addr()))
}

func TestGRPCWatchEventTypesAdjIn(t *testing.T) {
	assert := assert.New(t)

	socketName, err := os.MkdirTemp("", "gobgp-grpc-test-*")
	assert.NoError(err)
	t.Cleanup(func() {
		_ = os.RemoveAll(socketName)
	})
	socketAddr := "unix://" + socketName + "/gobgp.sock"

	// Start BGP Server 1
	s1 := NewBgpServer(GrpcListenAddress(socketAddr))
	go s1.Serve()
	defer s1.Stop()

	err = s1.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: 48000,
		},
	})
	assert.NoError(err)
	defer s1.StopBgp(context.Background(), &api.StopBgpRequest{})

	peer1 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         2,
		},
		Transport: &api.Transport{
			PassiveMode: true,
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
		},
	}
	err = s1.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer1})
	assert.NoError(err)

	s2 := NewBgpServer()
	go s2.Serve()
	defer s2.Stop()

	// Start BGP Server 2
	err = s2.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	assert.NoError(err)
	defer s2.StopBgp(context.Background(), &api.StopBgpRequest{})

	peer2 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         1,
		},
		Transport: &api.Transport{
			RemotePort: 48000,
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
		},
	}
	err = s2.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer2})
	assert.NoError(err)

	addPath := func(prefix string) uuid.UUID {
		family := &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		}
		nlri := &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
			Prefix:    prefix,
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
		req := apiutil.AddPathRequest{
			Paths: []*apiutil.Path{
				mustApi2apiutilPath(&api.Path{
					Family: family,
					Nlri:   nlri,
					Pattrs: attrs,
				}),
			},
		}

		resp, err := s2.AddPath(req)
		assert.NoError(err)

		return resp[0].UUID
	}

	conn, err := grpc.NewClient(
		socketAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	assert.NoError(err)
	defer conn.Close()

	client := api.NewGoBgpServiceClient(conn)

	establishedWg := GRPCwaitEstablished(t, client, bgp.RF_IPv4_UC)
	establishedWg.Wait()

	t.Run("adj_in", func(t *testing.T) {
		// Add paths that should be received during initial dump
		for _, prefix := range []string{"10.0.1.0", "10.0.2.0", "10.0.3.0", "10.0.4.0"} {
			addPath(prefix)
		}

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
			// Note the batch size
			BatchSize: 1,
		})
		assert.NoError(err, "failed to start watch event")

		count := 0
		lastEventType := api.WatchEventResponse_TableEvent_TYPE_UNSPECIFIED
		waitCh := make(chan any)

		go func() {
			for {
				select {
				case <-watchCtx.Done():
					return
				default:
					r, err := resp.Recv()
					assert.NoError(err)

					te := r.GetTable()
					assert.NotNil(te)

					currentEventType := te.GetType()
					if lastEventType == api.WatchEventResponse_TableEvent_TYPE_UNSPECIFIED {
						assert.Equal(currentEventType, api.WatchEventResponse_TableEvent_TYPE_ADJ_IN_INIT)
					} else if lastEventType == api.WatchEventResponse_TableEvent_TYPE_ADJ_IN_INIT {
						assert.Contains(
							[]api.WatchEventResponse_TableEvent_Type{
								api.WatchEventResponse_TableEvent_TYPE_ADJ_IN_INIT,
								api.WatchEventResponse_TableEvent_TYPE_ADJ_IN_INIT_END,
							},
							currentEventType,
						)
					} else if lastEventType == api.WatchEventResponse_TableEvent_TYPE_ADJ_IN_INIT_END {
						assert.Equal(currentEventType, api.WatchEventResponse_TableEvent_TYPE_ADJ_IN_EOR)
					} else if lastEventType == api.WatchEventResponse_TableEvent_TYPE_ADJ_IN_EOR {
						assert.Equal(currentEventType, api.WatchEventResponse_TableEvent_TYPE_ADJ_IN_UPDATE)
					} else if lastEventType == api.WatchEventResponse_TableEvent_TYPE_ADJ_IN_UPDATE {
						assert.Equal(currentEventType, api.WatchEventResponse_TableEvent_TYPE_ADJ_IN_UPDATE)
					} else {
						t.Errorf("unexpected table event type")
					}
					lastEventType = currentEventType

					count += len(te.GetPaths())
					if count == 4 {
						// When initial paths have been received, add another
						// one. This one is expected to have UPDATE event type.
						addPath("10.0.5.0")
					} else if count == 5 {
						watchCancel()
						waitCh <- nil
					}
				}
			}
		}()

		<-waitCh
		assert.Equal(5, count)

		err = s2.DeletePath(
			apiutil.DeletePathRequest{
				DeleteAll: true,
			},
		)
		assert.NoError(err)
	})

	t.Run("best", func(t *testing.T) {
		// Add paths that should be received during initial dump
		for _, prefix := range []string{"10.0.1.0", "10.0.2.0", "10.0.3.0", "10.0.4.0"} {
			addPath(prefix)
		}

		watchCtx, watchCancel := context.WithCancel(context.Background())
		resp, err := client.WatchEvent(watchCtx, &api.WatchEventRequest{
			Table: &api.WatchEventRequest_Table{
				Filters: []*api.WatchEventRequest_Table_Filter{
					{
						Type:        api.WatchEventRequest_Table_Filter_TYPE_BEST,
						PeerAddress: "127.0.0.1",
						Init:        true,
					},
				},
			},
			// Note the batch size
			BatchSize: 1,
		})
		assert.NoError(err)

		count := 0
		lastEventType := api.WatchEventResponse_TableEvent_TYPE_UNSPECIFIED
		waitCh := make(chan any)

		go func() {
			for {
				select {
				case <-watchCtx.Done():
					return
				default:
					r, err := resp.Recv()
					assert.NoError(err)

					te := r.GetTable()
					assert.NotNil(te)

					currentEventType := te.GetType()
					if lastEventType == api.WatchEventResponse_TableEvent_TYPE_UNSPECIFIED {
						assert.Equal(api.WatchEventResponse_TableEvent_TYPE_BEST_INIT, currentEventType)
					} else if lastEventType == api.WatchEventResponse_TableEvent_TYPE_BEST_INIT {
						assert.Contains(
							[]api.WatchEventResponse_TableEvent_Type{
								api.WatchEventResponse_TableEvent_TYPE_BEST_INIT,
								api.WatchEventResponse_TableEvent_TYPE_BEST_INIT_END,
							},
							currentEventType,
						)
					} else if lastEventType == api.WatchEventResponse_TableEvent_TYPE_BEST_INIT_END {
						assert.Equal(api.WatchEventResponse_TableEvent_TYPE_BEST_UPDATE, currentEventType)
					} else if lastEventType == api.WatchEventResponse_TableEvent_TYPE_BEST_UPDATE {
						assert.Equal(api.WatchEventResponse_TableEvent_TYPE_BEST_UPDATE, currentEventType)
					} else {
						t.Errorf("unexpected table event type")
					}
					lastEventType = currentEventType

					count += len(te.GetPaths())
					if count == 4 {
						// When initial paths have been received, add another
						// one. This one is expected to have UPDATE event type.
						addPath("10.0.5.0")
					} else if count == 5 {
						watchCancel()
						close(waitCh)
					}
				}
			}
		}()

		<-waitCh
		assert.Equal(5, count)

		err = s2.DeletePath(
			apiutil.DeletePathRequest{
				DeleteAll: true,
			},
		)
		assert.NoError(err)
	})
}
