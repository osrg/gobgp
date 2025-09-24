package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	peerTopoSrvCount = 2

	ptPolicyPrefixDefinedSet = "prefixes"
	ptPolicyPrefixAccepted   = "10.1.0.0"
	ptPolicyPrefixRejected   = "10.2.0.0"
	ptPolicyNameAccept       = "accept"
	ptPolicyNameReject       = "reject"
	ptPeerGroupSenders       = "senders"
	ptPeerGroupReceivers     = "receivers"
)

var (
	peerTopoHubPolicies = []*api.PolicyAssignment{
		{
			Name:          table.GLOBAL_RIB_NAME,
			Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
			DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
		},
		{
			Name:      table.GLOBAL_RIB_NAME,
			Direction: api.PolicyDirection_POLICY_DIRECTION_EXPORT,
			Policies: []*api.Policy{
				{
					Name: ptPolicyNameAccept,
					Statements: []*api.Statement{
						{
							Name: ptPolicyNameAccept + "-stmt0",
							Conditions: &api.Conditions{
								PrefixSet: &api.MatchSet{
									Type: api.MatchSet_TYPE_ANY,
									Name: ptPolicyPrefixDefinedSet,
								},
							},
							Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
						},
					},
				},
				{
					Name: ptPolicyNameReject,
					Statements: []*api.Statement{
						{
							Name:    ptPolicyNameReject + "-stmt0",
							Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_REJECT},
						},
					},
				},
			},
			DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT,
		},
	}

	peerTopoRt = bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65001, 100, true)
)

type peerTopoTest struct {
	routeReflector     bool
	routeServer        bool
	rsSecondaryRts     bool
	sharedPolicy       string
	sharedPolicyImport bool

	// 0 means RTC is disabled, any positive value - only that receiver should get path
	rtcReceiverIndex  int
	llgrReceiverIndex int

	expectedReceiverRoutes int
}

func (t peerTopoTest) name() string {
	parts := make([]string, 0, 4)
	addPart := func(cond bool, part string) {
		if cond {
			parts = append(parts, part)
		}
	}

	addPart(t.routeReflector, "route-reflector")
	addPart(t.routeServer, "route-server")
	addPart(t.rsSecondaryRts, "secondary-routes")
	addPart(t.rtcReceiverIndex > 0, "rtc")
	addPart(t.llgrReceiverIndex > 0, "llgr")
	addPart(t.sharedPolicy != "", t.sharedPolicy)
	addPart(t.sharedPolicyImport, "import")
	return strings.Join(parts, "-")
}

type peerTopo struct {
	hub       *BgpServer
	senders   []*BgpServer
	receivers []*BgpServer
}

func (tt peerTopoTest) makeTopo() (topo peerTopo, err error) {
	ctx := context.Background()

	asn := uint32(1)
	addr := net.IPv4(127, 0, 0, 100).To4()

	topo.hub = NewBgpServer()
	topo.hub.logger.SetLevel(log.DebugLevel)
	go topo.hub.Serve()

	if err := topo.hub.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:             asn,
			RouterId:        "1.1.1.1",
			ListenAddresses: []string{addr.String()},
			ListenPort:      10179,
		},
	}); err != nil {
		return topo, fmt.Errorf("error starting bgp on hub: %w", err)
	}

	if err := topo.hub.AddDefinedSet(ctx, &api.AddDefinedSetRequest{
		DefinedSet: &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
			Name:        ptPolicyPrefixDefinedSet,
			Prefixes: []*api.Prefix{
				{IpPrefix: ptPolicyPrefixAccepted + "/24", MaskLengthMin: 24, MaskLengthMax: 32},
			},
		},
	}); err != nil {
		return topo, fmt.Errorf("error adding defined set: %w", err)
	}
	for _, a := range peerTopoHubPolicies {
		for _, pol := range a.Policies {
			if err := topo.hub.AddPolicy(ctx, &api.AddPolicyRequest{
				Policy: pol,
			}); err != nil {
				return topo, fmt.Errorf("error adding policy: %w", err)
			}
		}

		if err := topo.hub.AddPolicyAssignment(ctx, &api.AddPolicyAssignmentRequest{
			Assignment: a,
		}); err != nil {
			return topo, fmt.Errorf("error adding policy assignment: %w", err)
		}
	}

	wg := waitStateMultiple(topo.hub, api.PeerState_SESSION_STATE_ESTABLISHED, 2*peerTopoSrvCount)
	for pgIndex, pg := range []struct {
		name    string
		servers *[]*BgpServer
	}{
		{ptPeerGroupSenders, &topo.senders},
		{ptPeerGroupReceivers, &topo.receivers},
	} {
		// Use iBGP (same ASN) in route-reflector tests, eBGP in route-server tests
		if tt.routeServer {
			asn++
		}

		pgConfig := tt.makePGConfig(pg.name, asn)
		if err := topo.hub.AddPeerGroup(ctx, &api.AddPeerGroupRequest{
			PeerGroup: oc.NewPeerGroupFromConfigStruct(pgConfig),
		}); err != nil {
			return topo, fmt.Errorf("error adding peer group: %w", err)
		}

		for srvIndex := range peerTopoSrvCount {
			addr[3]++

			srv := NewBgpServer()
			go srv.Serve()
			*pg.servers = append(*pg.servers, srv)

			var grCfg *api.GracefulRestart
			if tt.llgrReceiverIndex > 0 {
				grCfg = &api.GracefulRestart{
					Enabled:          true,
					RestartTime:      30,
					LonglivedEnabled: true,
				}
			}

			if err := srv.StartBgp(ctx, &api.StartBgpRequest{
				Global: &api.Global{
					Asn:             asn,
					RouterId:        fmt.Sprintf("1.2.%d.%d", pgIndex, srvIndex),
					ListenAddresses: []string{addr.String()},
					ListenPort:      -1,
					GracefulRestart: grCfg,
				},
			}); err != nil {
				return topo, fmt.Errorf("error starting peer bgp: %w", err)
			}

			srvNeigh := &oc.Neighbor{
				Config:    tt.makeNeighborConfig(srv, pg.name),
				Transport: tt.makeTransportConfig(topo.hub, srv, true),
			}
			if err := topo.hub.AddPeer(ctx, &api.AddPeerRequest{
				Peer: oc.NewPeerFromConfigStruct(srvNeigh),
			}); err != nil {
				return topo, fmt.Errorf("error adding hub peer: %w", err)
			}

			hubNeigh := &oc.Neighbor{
				Config:          tt.makeNeighborConfig(topo.hub, ""),
				GracefulRestart: pgConfig.GracefulRestart,
				Transport:       tt.makeTransportConfig(srv, topo.hub, false),
				AfiSafis:        tt.makeHubNeighAfiSafis(pg.name, srvIndex, pgConfig.AfiSafis),
			}
			if err := srv.AddPeer(ctx, &api.AddPeerRequest{
				Peer: oc.NewPeerFromConfigStruct(hubNeigh),
			}); err != nil {
				return topo, fmt.Errorf("error adding leaf peer: %w", err)
			}
		}
	}
	wg.Wait()

	return topo, nil
}

func (tt peerTopoTest) makeHubNeighAfiSafis(pgName string, srvIndex int, afiSafis []oc.AfiSafi) []oc.AfiSafi {
	if tt.llgrReceiverIndex == 0 || pgName != ptPeerGroupReceivers {
		return afiSafis
	}

	// For llgr-test - do not negotiate LLGR with one of receivers
	// and do not expect it to receive llgr route
	if srvIndex == tt.llgrReceiverIndex {
		return afiSafis
	}

	hubAfiSafis := slices.Clone(afiSafis)
	for i := range hubAfiSafis {
		hubAfiSafis[i].LongLivedGracefulRestart.Config.Enabled = false
	}
	return hubAfiSafis
}

func (tt peerTopoTest) getNeighborAddr(srv *BgpServer) netip.Addr {
	return srv.bgpConfig.Global.Config.LocalAddressList[0]
}

func (tt peerTopoTest) makeNeighborConfig(srv *BgpServer, pgName string) oc.NeighborConfig {
	return oc.NeighborConfig{
		NeighborAddress: tt.getNeighborAddr(srv),
		PeerAs:          srv.bgpConfig.Global.Config.As,
		PeerGroup:       pgName,
	}
}

func (tt peerTopoTest) makeTransportConfig(local, peer *BgpServer, passiveMode bool) oc.Transport {
	return oc.Transport{
		Config: oc.TransportConfig{
			LocalAddress: tt.getNeighborAddr(local),
			RemotePort:   uint16(peer.bgpConfig.Global.Config.Port),
			PassiveMode:  passiveMode,
		},
	}
}

func (tt peerTopoTest) makePGConfig(name string, asn uint32) *oc.PeerGroup {
	var (
		grCfg   oc.GracefulRestartConfig
		mpGrCfg oc.MpGracefulRestartConfig
		llgrCfg oc.LongLivedGracefulRestartConfig
	)
	if tt.llgrReceiverIndex > 0 {
		grCfg.Enabled = true
		grCfg.RestartTime = 30
		grCfg.LongLivedEnabled = true
		mpGrCfg.Enabled = true
		llgrCfg.Enabled = true
		llgrCfg.RestartTime = 300
	}

	pg := &oc.PeerGroup{
		Config: oc.PeerGroupConfig{
			PeerAs:        asn,
			PeerGroupName: name,
		},
		GracefulRestart: oc.GracefulRestart{Config: grCfg},
		AfiSafis: []oc.AfiSafi{
			{
				Config: oc.AfiSafiConfig{AfiSafiName: oc.AFI_SAFI_TYPE_IPV4_UNICAST, Enabled: true},

				MpGracefulRestart:        oc.MpGracefulRestart{Config: mpGrCfg},
				LongLivedGracefulRestart: oc.LongLivedGracefulRestart{Config: llgrCfg},
			},
		},
	}

	if tt.routeServer {
		pg.RouteServer = oc.RouteServer{
			Config: oc.RouteServerConfig{
				RouteServerClient: true,
				SecondaryRoute:    tt.rsSecondaryRts,
			},
		}
	} else if tt.routeReflector {
		pg.RouteReflector = oc.RouteReflector{
			Config: oc.RouteReflectorConfig{
				RouteReflectorClient: true,
			},
		}
	}

	if tt.sharedPolicy != "" {
		apCfg := oc.ApplyPolicyConfig{
			DefaultImportPolicy: oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE,
			ExportPolicyList:    []string{tt.sharedPolicy},
			DefaultExportPolicy: oc.DEFAULT_POLICY_TYPE_REJECT_ROUTE,
		}
		if tt.sharedPolicyImport {
			// Test filtering on import, not export. This doesn't help with
			// propagateUpdate performance, but makes configuring policies easier
			// too (and allow to avoid neighbor sets)
			apCfg.DefaultImportPolicy, apCfg.DefaultExportPolicy = apCfg.DefaultExportPolicy, apCfg.DefaultImportPolicy
			apCfg.ImportPolicyList, apCfg.ExportPolicyList = apCfg.ExportPolicyList, apCfg.ImportPolicyList
		}

		pg.ApplyPolicy = oc.ApplyPolicy{Config: apCfg}
		pg.Config.SharedPolicy = true
	} else if tt.routeServer {
		pg.ApplyPolicy = oc.ApplyPolicy{
			Config: oc.ApplyPolicyConfig{
				DefaultImportPolicy: oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE,
				ExportPolicyList:    []string{ptPolicyNameAccept},
				DefaultExportPolicy: oc.DEFAULT_POLICY_TYPE_REJECT_ROUTE,
			},
		}
	}

	if tt.rtcReceiverIndex > 0 && name == ptPeerGroupReceivers {
		pg.AfiSafis = append(pg.AfiSafis, oc.AfiSafi{
			Config: oc.AfiSafiConfig{AfiSafiName: oc.AFI_SAFI_TYPE_RTC, Enabled: true},
		})
	}

	return pg
}

func (topo peerTopo) dump() {
	dumpTableInfo := func(tableName string, rf bgp.Family, info *table.TableInfo, err error) {
		if err != nil {
			fmt.Printf("\t%s/%s: %s\n", tableName, rf, err.Error())
			return
		}

		if info.NumDestination > 0 {
			fmt.Printf("\t%s/%s: %d destinations, %d paths\n", tableName, rf, info.NumDestination, info.NumPath)
		}
	}

	dumpServer := func(srv *BgpServer) {
		_ = srv.mgmtOperation(func() error {
			for rf, tbl := range srv.globalRib.Tables {
				dumpTableInfo("global", rf, tbl.Info(), nil)
			}
			for rf, tbl := range srv.rsRib.Tables {
				dumpTableInfo("rs", rf, tbl.Info(), nil)
			}
			for neighAddr, neigh := range srv.neighborMap {
				for _, rf := range neigh.configuredRFlist() {
					info, err := neigh.adjRibIn.TableInfo(rf)
					dumpTableInfo(neighAddr+" adj-in", rf, info, err)
				}
			}

			return nil
		}, true)
	}

	fmt.Println("hub paths:")
	dumpServer(topo.hub)
	for i, srv := range topo.senders {
		fmt.Printf("sender#%d paths:\n", i)
		dumpServer(srv)
	}
	for i, srv := range topo.receivers {
		fmt.Printf("receiver#%d paths:\n", i)
		dumpServer(srv)
	}
}

func (topo peerTopo) stop() {
	topo.dump()
	if topo.hub != nil {
		topo.hub.Stop()
	}
	for _, srv := range topo.senders {
		srv.Stop()
	}
	for _, srv := range topo.receivers {
		srv.Stop()
	}
}

func (topo peerTopo) makeDefaultAtrs(llgrStale bool) []bgp.PathAttributeInterface {
	nh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	pattr := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nh,
	}

	if llgrStale {
		comm := bgp.NewPathAttributeCommunities([]uint32{uint32(bgp.COMMUNITY_LLGR_STALE)})
		pattr = append(pattr, comm)
	}

	return pattr
}

func (topo peerTopo) addPaths(family bgp.Family, llgrStale bool) error {
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(ptPolicyPrefixAccepted + "/24"))
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(ptPolicyPrefixRejected + "/24"))
	extComm := bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{peerTopoRt})

	for _, srv := range topo.senders {
		for _, nlri := range []bgp.NLRI{nlri1, nlri2} {
			if _, err := srv.AddPath(apiutil.AddPathRequest{
				Paths: []*apiutil.Path{
					{
						Family: family,
						Nlri:   nlri,
						Attrs:  append(topo.makeDefaultAtrs(llgrStale), extComm),
					},
				},
			}); err != nil {
				return err
			}
		}
	}

	return nil
}

func (topo peerTopo) addRTCPaths(rtcIndex int) error {
	srv := topo.receivers[rtcIndex]
	_, err := srv.AddPath(apiutil.AddPathRequest{
		Paths: []*apiutil.Path{
			{
				Family: bgp.RF_RTC_UC,
				Nlri:   bgp.NewRouteTargetMembershipNLRI(srv.bgpConfig.Global.Config.As, peerTopoRt),
				Attrs:  topo.makeDefaultAtrs(false),
			},
		},
	})
	return err
}

func (tt peerTopoTest) expectedPaths(srvIndex int) int {
	if tt.rtcReceiverIndex > 0 && tt.rtcReceiverIndex != srvIndex {
		return 0
	}
	if tt.llgrReceiverIndex > 0 && tt.llgrReceiverIndex != srvIndex {
		return 0
	}
	return tt.expectedReceiverRoutes
}

func countReachPaths(paths []*table.Path) (count int) {
	for _, p := range paths {
		if !p.IsEOR() && !p.IsWithdraw {
			count++
		}
	}
	return count
}

// Topology test spawns multiple servers and tests various aspects of passing route via
// route reflector or server using different types of policy application (global policy,
// per-peer policy for route server or per-peer-group policy using shared-export-policy
// option)
//
// This should've been full-fledged scenario test, but since they lack convenience of
// debugging, here we are.
//
// TODO: for secondary route test add additional filtering and checks that proper secondary
// route is received
func TestPeerStarTopology(t *testing.T) {
	for _, tt := range []peerTopoTest{
		{
			routeReflector:         true,
			expectedReceiverRoutes: 1,
		},
		{
			routeReflector:         true,
			rtcReceiverIndex:       1,
			expectedReceiverRoutes: 1,
		},
		{
			routeReflector:         true,
			llgrReceiverIndex:      1,
			expectedReceiverRoutes: 1,
		},
		{
			routeReflector:         true,
			sharedPolicy:           ptPolicyNameAccept,
			expectedReceiverRoutes: 1,
		},
		{
			routeReflector:         true,
			sharedPolicy:           ptPolicyNameAccept,
			sharedPolicyImport:     true,
			expectedReceiverRoutes: 1,
		},
		{
			routeReflector:         true,
			sharedPolicy:           ptPolicyNameReject,
			expectedReceiverRoutes: 0,
		},
		{
			routeReflector:         true,
			sharedPolicy:           ptPolicyNameAccept,
			rtcReceiverIndex:       1,
			expectedReceiverRoutes: 1,
		},
		{
			routeServer:            true,
			expectedReceiverRoutes: 1,
		},
		{
			routeServer:            true,
			rsSecondaryRts:         true,
			expectedReceiverRoutes: 1,
		},
		{
			routeServer:            true,
			sharedPolicy:           ptPolicyNameAccept,
			expectedReceiverRoutes: 1,
		},
		{
			routeServer:            true,
			sharedPolicy:           ptPolicyNameAccept,
			sharedPolicyImport:     true,
			expectedReceiverRoutes: 1,
		},
		{
			routeReflector:         true,
			sharedPolicy:           ptPolicyNameAccept,
			llgrReceiverIndex:      1,
			expectedReceiverRoutes: 1,
		},
		{
			routeServer:            true,
			rsSecondaryRts:         true,
			sharedPolicy:           ptPolicyNameAccept,
			expectedReceiverRoutes: 1,
		},
		{
			routeServer:            true,
			sharedPolicy:           ptPolicyNameReject,
			expectedReceiverRoutes: 0,
		},
	} {
		t.Run(tt.name(), func(t *testing.T) {
			topo, err := tt.makeTopo()
			require.NoError(t, err, "error while making topo")

			if tt.sharedPolicy != "" {
				assert.Len(t, topo.hub.receiverMap, 2)
			} else {
				assert.Len(t, topo.hub.receiverMap, 2*peerTopoSrvCount)
			}

			if tt.rtcReceiverIndex > 0 {
				err = topo.addRTCPaths(tt.rtcReceiverIndex)
				require.NoError(t, err, "error while adding rtc paths")
			}

			topo.hub.logger.Info("Start test", log.Fields{"test": tt.name()})
			err = topo.addPaths(bgp.RF_IPv4_UC, tt.llgrReceiverIndex > 0)
			require.NoError(t, err, "error while adding paths")

			assert.EventuallyWithT(t, func(collect *assert.CollectT) {
				for srvIndex, srv := range topo.receivers {
					var count int
					err := srv.ListPath(apiutil.ListPathRequest{
						TableType: api.TableType_TABLE_TYPE_GLOBAL,
						Family:    bgp.RF_IPv4_UC,
					}, func(prefix bgp.NLRI, paths []*apiutil.Path) {
						require.True(t, strings.HasPrefix(prefix.String(), ptPolicyPrefixAccepted),
							fmt.Sprintf("route prefix %q starts with %q", prefix.String(), ptPolicyPrefixAccepted))
						count += len(paths)
					})
					assert.NoError(t, err)
					assert.Equal(collect, tt.expectedPaths(srvIndex), count)
				}
			}, 10*time.Second, 100*time.Millisecond)

			// Check that our adj-out is correct too if peer reconnects, or
			// during initial state when we sync all peers at once
			err = topo.hub.mgmtOperation(func() error {
				checkReceiver := func(r receiver, expected int) {
					pathList, _ := topo.hub.getBestFromLocal(r, r.configuredRFlist())
					assert.Equal(t, expected, countReachPaths(pathList))
				}

				recvPg := topo.hub.peerGroupMap[ptPeerGroupReceivers]
				for srvIndex, srv := range topo.receivers {
					addr := tt.getNeighborAddr(srv).String()
					checkReceiver(recvPg.neighborMap[addr], tt.expectedPaths(srvIndex))
				}
				if tt.sharedPolicy != "" {
					// NOTE: getAdjOut() ignores LLGR/RTC for peer groups since LLGR/RTC is per-peer basis,
					// so while we sent correct set of routes (checked earlier), we expect total
					// number selected by policy here
					checkReceiver(recvPg, tt.expectedReceiverRoutes)
				}

				return nil
			}, false)
			require.NoError(t, err, "error while checking getBestFromLocalCount")

			topo.stop()

			for pgName, pg := range topo.hub.peerGroupMap {
				assert.Lenf(t, pg.neighborMap, 0,
					"expect that all neighbors are deleted in peer group %q", pgName)
			}
		})
	}
}

func TestPeerGroupSharedPolicyUpdate(t *testing.T) {
	const (
		numPeers = 3
		pgName   = "g"
	)

	assert := assert.New(t)
	expectReceivers := func(s *BgpServer, expected []string) {
		actual := make([]string, 0, len(expected))
		err := s.mgmtOperation(func() error {
			for k := range s.receiverMap {
				actual = append(actual, k)
			}
			return nil
		}, false)
		assert.NoError(err)
		assert.ElementsMatch(expected, actual)
	}

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

	pg := &oc.PeerGroup{
		Config: oc.PeerGroupConfig{
			PeerAs:        2,
			PeerGroupName: pgName,
		},
	}
	err = s.addPeerGroup(pg)
	assert.NoError(err)

	peerAddrs := make([]string, 0, numPeers)
	for i := range numPeers {
		n := &oc.Neighbor{
			Config: oc.NeighborConfig{
				NeighborAddress: netip.MustParseAddr(fmt.Sprintf("127.0.0.%d", 100+i)),
				PeerGroup:       pgName,
			},
			Transport: oc.Transport{
				Config: oc.TransportConfig{
					PassiveMode: true,
				},
			},
		}
		peerAddrs = append(peerAddrs, n.Config.NeighborAddress.String())

		err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(n)})
		assert.NoError(err)
	}
	expectReceivers(s, peerAddrs)

	// Enable shared policy: we should have only it as a receiver
	pg.Config.SharedPolicy = true
	_, err = s.updatePeerGroup(pg)
	assert.NoError(err)

	pgReceivers := []string{oc.NewPeerGroupPolicyAssignmentKeyFromName(pgName)}
	expectReceivers(s, pgReceivers)

	// Delete one peer in peer group, this should have no effect on server's receivers
	// (but should on neighborMap inside pg)
	err = s.DeletePeer(context.Background(), &api.DeletePeerRequest{
		Address: peerAddrs[0],
	})
	assert.NoError(err)
	peerAddrs = peerAddrs[1:]

	expectReceivers(s, pgReceivers)

	_ = s.mgmtOperation(func() error {
		assert.Len(s.peerGroupMap[pgName].neighborMap, len(peerAddrs))
		return nil
	}, false)

	// Disable shared policy - we should enable individual peers back
	pg.Config.SharedPolicy = false
	_, err = s.updatePeerGroup(pg)
	assert.NoError(err)

	expectReceivers(s, peerAddrs)

	// Delete rest of peers, no receivers should be left after it
	for _, addr := range peerAddrs {
		err = s.DeletePeer(context.Background(), &api.DeletePeerRequest{
			Address: addr,
		})
		assert.NoError(err)
	}
	expectReceivers(s, []string{})
}
