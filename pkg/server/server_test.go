// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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
	"net"
	"runtime"
	"testing"
	"time"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/internal/pkg/config"
	"github.com/osrg/gobgp/internal/pkg/table"
	"github.com/osrg/gobgp/pkg/packet/bgp"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModPolicyAssign(t *testing.T) {
	assert := assert.New(t)
	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			As:         1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	assert.Nil(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	err = s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: NewAPIPolicyFromTableStruct(&table.Policy{Name: "p1"})})
	assert.Nil(err)

	err = s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: NewAPIPolicyFromTableStruct(&table.Policy{Name: "p2"})})
	assert.Nil(err)

	err = s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: NewAPIPolicyFromTableStruct(&table.Policy{Name: "p3"})})
	assert.Nil(err)

	f := func(l []*config.PolicyDefinition) *api.PolicyAssignment {
		pl := make([]*api.Policy, 0, len(l))
		for _, d := range l {
			pl = append(pl, toPolicyApi(d))
		}
		return &api.PolicyAssignment{
			Policies: pl,
		}
	}

	r := f([]*config.PolicyDefinition{&config.PolicyDefinition{Name: "p1"}, &config.PolicyDefinition{Name: "p2"}, &config.PolicyDefinition{Name: "p3"}})
	r.Type = api.PolicyDirection_IMPORT
	r.Default = api.RouteAction_ACCEPT
	err = s.AddPolicyAssignment(context.Background(), &api.AddPolicyAssignmentRequest{Assignment: r})
	assert.Nil(err)

	ps, err := s.ListPolicyAssignment(context.Background(), &api.ListPolicyAssignmentRequest{Direction: api.PolicyDirection_IMPORT})
	assert.Nil(err)
	assert.Equal(len(ps[0].Policies), 3)

	r = f([]*config.PolicyDefinition{&config.PolicyDefinition{Name: "p1"}})
	r.Type = api.PolicyDirection_IMPORT
	r.Default = api.RouteAction_ACCEPT
	err = s.DeletePolicyAssignment(context.Background(), &api.DeletePolicyAssignmentRequest{Assignment: r})
	assert.Nil(err)

	ps, _ = s.ListPolicyAssignment(context.Background(), &api.ListPolicyAssignmentRequest{Direction: api.PolicyDirection_IMPORT})
	assert.Equal(len(ps[0].Policies), 2)
}

func TestMonitor(test *testing.T) {
	assert := assert.New(test)
	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			As:         1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.Nil(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	n := &config.Neighbor{
		Config: config.NeighborConfig{
			NeighborAddress: "127.0.0.1",
			PeerAs:          2,
		},
		Transport: config.Transport{
			Config: config.TransportConfig{
				PassiveMode: true,
			},
		},
	}
	err = s.addNeighbor(n)
	assert.Nil(err)

	t := NewBgpServer()
	go t.Serve()
	err = t.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			As:         2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	assert.Nil(err)
	defer t.StopBgp(context.Background(), &api.StopBgpRequest{})

	m := &config.Neighbor{
		Config: config.NeighborConfig{
			NeighborAddress: "127.0.0.1",
			PeerAs:          1,
		},
		Transport: config.Transport{
			Config: config.TransportConfig{
				RemotePort: 10179,
			},
		},
	}
	err = t.AddPeer(context.Background(), &api.AddPeerRequest{Peer: NewPeerFromConfigStruct(m)})
	assert.Nil(err)

	for {
		time.Sleep(time.Second)
		if t.getNeighbor("", false)[0].State.SessionState == config.SESSION_STATE_ESTABLISHED {
			break
		}
	}

	// Test WatchBestPath.
	w := s.Watch(WatchBestPath(false))

	// Advertises a route.
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop("10.0.0.1"),
	}
	if err := t.addPathList("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.0.0.0"), false, attrs, time.Now(), false)}); err != nil {
		log.Fatal(err)
	}
	ev := <-w.Event()
	b := ev.(*WatchEventBestPath)
	assert.Equal(1, len(b.PathList))
	assert.Equal("10.0.0.0/24", b.PathList[0].GetNlri().String())
	assert.False(b.PathList[0].IsWithdraw)

	// Withdraws the previous route.
	// NOTE: Withdow should not require any path attribute.
	if err := t.addPathList("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.0.0.0"), true, nil, time.Now(), false)}); err != nil {
		log.Fatal(err)
	}
	ev = <-w.Event()
	b = ev.(*WatchEventBestPath)
	assert.Equal(1, len(b.PathList))
	assert.Equal("10.0.0.0/24", b.PathList[0].GetNlri().String())
	assert.True(b.PathList[0].IsWithdraw)

	// Stops the watcher still having an item.
	w.Stop()

	// Prepares an initial route to test WatchUpdate with "current" flag.
	if err := t.addPathList("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.1.0.0"), false, attrs, time.Now(), false)}); err != nil {
		log.Fatal(err)
	}
	for {
		// Waits for the initial route will be advertised.
		rib, _, err := s.getRib("", bgp.RF_IPv4_UC, nil)
		if err != nil {
			log.Fatal(err)
		}
		if len(rib.GetKnownPathList("", 0)) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Test WatchUpdate with "current" flag.
	w = s.Watch(WatchUpdate(true))

	// Test the initial route.
	ev = <-w.Event()
	u := ev.(*WatchEventUpdate)
	assert.Equal(1, len(u.PathList))
	assert.Equal("10.1.0.0/24", u.PathList[0].GetNlri().String())
	assert.False(u.PathList[0].IsWithdraw)
	ev = <-w.Event()
	u = ev.(*WatchEventUpdate)
	assert.Equal(len(u.PathList), 0) // End of RIB

	// Advertises an additional route.
	if err := t.addPathList("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.2.0.0"), false, attrs, time.Now(), false)}); err != nil {
		log.Fatal(err)
	}
	ev = <-w.Event()
	u = ev.(*WatchEventUpdate)
	assert.Equal(1, len(u.PathList))
	assert.Equal("10.2.0.0/24", u.PathList[0].GetNlri().String())
	assert.False(u.PathList[0].IsWithdraw)

	// Withdraws the previous route.
	// NOTE: Withdow should not require any path attribute.
	if err := t.addPathList("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.2.0.0"), true, nil, time.Now(), false)}); err != nil {
		log.Fatal(err)
	}
	ev = <-w.Event()
	u = ev.(*WatchEventUpdate)
	assert.Equal(1, len(u.PathList))
	assert.Equal("10.2.0.0/24", u.PathList[0].GetNlri().String())
	assert.True(u.PathList[0].IsWithdraw)

	// Stops the watcher still having an item.
	w.Stop()
}

func TestNumGoroutineWithAddDeleteNeighbor(t *testing.T) {
	assert := assert.New(t)
	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			As:         1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	assert.Nil(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// wait a few seconds to avoid taking effect from other test cases.
	time.Sleep(time.Second * 5)

	num := runtime.NumGoroutine()

	p := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAs:          2,
		},
		Transport: &api.Transport{
			PassiveMode: true,
		},
	}

	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p})
	assert.Nil(err)

	err = s.DeletePeer(context.Background(), &api.DeletePeerRequest{Address: "127.0.0.1"})
	assert.Nil(err)
	// wait goroutines to finish (e.g. internal goroutine for
	// InfiniteChannel)
	time.Sleep(time.Second * 5)
	assert.Equal(num, runtime.NumGoroutine())
}

func newPeerandInfo(myAs, as uint32, address string, rib *table.TableManager) (*Peer, *table.PeerInfo) {
	nConf := &config.Neighbor{Config: config.NeighborConfig{PeerAs: as, NeighborAddress: address}}
	gConf := &config.Global{Config: config.GlobalConfig{As: myAs}}
	config.SetDefaultNeighborConfigValues(nConf, nil, gConf)
	policy := table.NewRoutingPolicy()
	policy.Reset(&config.RoutingPolicy{}, nil)
	p := NewPeer(
		&config.Global{Config: config.GlobalConfig{As: myAs}},
		nConf,
		rib,
		policy)
	for _, f := range rib.GetRFlist() {
		p.fsm.rfMap[f] = bgp.BGP_ADD_PATH_NONE
	}
	return p, &table.PeerInfo{AS: as, Address: net.ParseIP(address)}
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
	rib := table.NewTableManager([]bgp.RouteFamily{bgp.RF_IPv4_UC})
	p1, pi1 := newPeerandInfo(as, p1As, "192.168.0.1", rib)
	p2, pi2 := newPeerandInfo(as, p2As, "192.168.0.2", rib)

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

	rib := table.NewTableManager([]bgp.RouteFamily{bgp.RF_IPv4_UC})
	p1, pi1 := newPeerandInfo(as, as, "192.168.0.1", rib)
	//p2, pi2 := newPeerandInfo(as, as, "192.168.0.2", rib)
	p2, _ := newPeerandInfo(as, as, "192.168.0.2", rib)

	nlri := bgp.NewIPAddrPrefix(24, "10.10.10.0")
	pa1 := []bgp.PathAttributeInterface{bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{as})}), bgp.NewPathAttributeLocalPref(200)}
	//pa2 := []bgp.PathAttributeInterface{bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{as})})}

	path1 := table.NewPath(pi1, nlri, false, pa1, time.Now(), false)
	//path2 := table.NewPath(pi2, nlri, false, pa2, time.Now(), false)

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
	rib1 := table.NewTableManager([]bgp.RouteFamily{bgp.RF_IPv4_UC})
	_, pi1 := newPeerandInfo(1, 2, "192.168.0.1", rib1)
	rib2 := table.NewTableManager([]bgp.RouteFamily{bgp.RF_IPv4_UC})
	p2, _ := newPeerandInfo(1, 3, "192.168.0.2", rib2)

	comSet1 := config.CommunitySet{
		CommunitySetName: "comset1",
		CommunityList:    []string{"100:100"},
	}
	s, _ := table.NewCommunitySet(comSet1)
	p2.policy.AddDefinedSet(s)

	statement := config.Statement{
		Name: "stmt1",
		Conditions: config.Conditions{
			BgpConditions: config.BgpConditions{
				MatchCommunitySet: config.MatchCommunitySet{
					CommunitySet: "comset1",
				},
			},
		},
		Actions: config.Actions{
			RouteDisposition: config.ROUTE_DISPOSITION_REJECT_ROUTE,
		},
	}
	policy := config.PolicyDefinition{
		Name:       "policy1",
		Statements: []config.Statement{statement},
	}
	p, _ := table.NewPolicy(policy)
	p2.policy.AddPolicy(p, false)
	policies := []*config.PolicyDefinition{
		&config.PolicyDefinition{
			Name: "policy1",
		},
	}
	p2.policy.AddPolicyAssignment(p2.TableID(), table.POLICY_DIRECTION_EXPORT, policies, table.ROUTE_TYPE_ACCEPT)

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
	log.SetLevel(log.DebugLevel)
	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			As:         1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.Nil(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	g := &config.PeerGroup{
		Config: config.PeerGroupConfig{
			PeerAs:        2,
			PeerGroupName: "g",
		},
	}
	err = s.addPeerGroup(g)
	assert.Nil(err)

	n := &config.Neighbor{
		Config: config.NeighborConfig{
			NeighborAddress: "127.0.0.1",
			PeerGroup:       "g",
		},
		Transport: config.Transport{
			Config: config.TransportConfig{
				PassiveMode: true,
			},
		},
	}
	configured := map[string]interface{}{
		"config": map[string]interface{}{
			"neigbor-address": "127.0.0.1",
			"peer-group":      "g",
		},
		"transport": map[string]interface{}{
			"config": map[string]interface{}{
				"passive-mode": true,
			},
		},
	}
	config.RegisterConfiguredFields("127.0.0.1", configured)
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: NewPeerFromConfigStruct(n)})
	assert.Nil(err)

	t := NewBgpServer()
	go t.Serve()
	err = t.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			As:         2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	assert.Nil(err)
	defer t.StopBgp(context.Background(), &api.StopBgpRequest{})

	m := &config.Neighbor{
		Config: config.NeighborConfig{
			NeighborAddress: "127.0.0.1",
			PeerAs:          1,
		},
		Transport: config.Transport{
			Config: config.TransportConfig{
				RemotePort: 10179,
			},
		},
	}
	err = t.AddPeer(context.Background(), &api.AddPeerRequest{Peer: NewPeerFromConfigStruct(m)})
	assert.Nil(err)

	for {
		time.Sleep(time.Second)
		if t.getNeighbor("", false)[0].State.SessionState == config.SESSION_STATE_ESTABLISHED {
			break
		}
	}
}

func TestDynamicNeighbor(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)
	s1 := NewBgpServer()
	go s1.Serve()
	err := s1.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			As:         1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.Nil(err)
	defer s1.StopBgp(context.Background(), &api.StopBgpRequest{})

	g := &config.PeerGroup{
		Config: config.PeerGroupConfig{
			PeerAs:        2,
			PeerGroupName: "g",
		},
	}
	err = s1.addPeerGroup(g)
	assert.Nil(err)

	d := &api.AddDynamicNeighborRequest{
		DynamicNeighbor: &api.DynamicNeighbor{
			Prefix:    "127.0.0.0/24",
			PeerGroup: "g",
		},
	}
	err = s1.AddDynamicNeighbor(context.Background(), d)
	assert.Nil(err)

	s2 := NewBgpServer()
	go s2.Serve()
	err = s2.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			As:         2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	assert.Nil(err)
	defer s2.StopBgp(context.Background(), &api.StopBgpRequest{})

	m := &config.Neighbor{
		Config: config.NeighborConfig{
			NeighborAddress: "127.0.0.1",
			PeerAs:          1,
		},
		Transport: config.Transport{
			Config: config.TransportConfig{
				RemotePort: 10179,
			},
		},
	}
	err = s2.AddPeer(context.Background(), &api.AddPeerRequest{Peer: NewPeerFromConfigStruct(m)})

	assert.Nil(err)

	for {
		time.Sleep(time.Second)
		if s2.getNeighbor("", false)[0].State.SessionState == config.SESSION_STATE_ESTABLISHED {
			break
		}
	}
}

func TestGracefulRestartTimerExpired(t *testing.T) {
	assert := assert.New(t)
	s1 := NewBgpServer()
	go s1.Serve()
	err := s1.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			As:         1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.Nil(err)
	defer s1.StopBgp(context.Background(), &api.StopBgpRequest{})

	n := &config.Neighbor{
		Config: config.NeighborConfig{
			NeighborAddress: "127.0.0.1",
			PeerAs:          2,
		},
		Transport: config.Transport{
			Config: config.TransportConfig{
				PassiveMode: true,
			},
		},
		GracefulRestart: config.GracefulRestart{
			Config: config.GracefulRestartConfig{
				Enabled:     true,
				RestartTime: 1,
			},
		},
	}
	err = s1.addNeighbor(n)
	assert.Nil(err)

	s2 := NewBgpServer()
	go s2.Serve()
	err = s2.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			As:         2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s2.StopBgp(context.Background(), &api.StopBgpRequest{})

	m := &config.Neighbor{
		Config: config.NeighborConfig{
			NeighborAddress: "127.0.0.1",
			PeerAs:          1,
		},
		Transport: config.Transport{
			Config: config.TransportConfig{
				RemotePort: 10179,
			},
		},
		GracefulRestart: config.GracefulRestart{
			Config: config.GracefulRestartConfig{
				Enabled:     true,
				RestartTime: 1,
			},
		},
	}
	err = s2.addNeighbor(m)
	assert.Nil(err)

	// Waiting for BGP session established.
	for {
		time.Sleep(time.Second)
		if s2.getNeighbor("", false)[0].State.SessionState == config.SESSION_STATE_ESTABLISHED {
			break
		}
	}

	// Force TCP session disconnected in order to cause Graceful Restart at s1
	// side.
	for _, n := range s2.neighborMap {
		n.fsm.conn.Close()
	}
	s2.StopBgp(context.Background(), &api.StopBgpRequest{})

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

	// Waiting for Graceful Restart timer expired and moving on to IDLE state.
	for {
		if s1.getNeighbor("", false)[0].State.SessionState == config.SESSION_STATE_IDLE {
			break
		}

		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			t.Fatalf("failed to enter IDLE state in the deadline")
			return
		}
	}
}

func TestFamiliesForSoftreset(t *testing.T) {
	f := func(f bgp.RouteFamily) config.AfiSafi {
		return config.AfiSafi{
			State: config.AfiSafiState{
				Family: f,
			},
		}
	}
	peer := &Peer{
		fsm: &FSM{
			pConf: &config.Neighbor{
				AfiSafis: []config.AfiSafi{f(bgp.RF_RTC_UC), f(bgp.RF_IPv4_UC), f(bgp.RF_IPv6_UC)},
			},
		},
	}

	families := familiesForSoftreset(peer, bgp.RF_IPv4_UC)
	assert.Equal(t, len(families), 1)
	assert.Equal(t, families[0], bgp.RF_IPv4_UC)

	families = familiesForSoftreset(peer, bgp.RF_RTC_UC)
	assert.Equal(t, len(families), 1)
	assert.Equal(t, families[0], bgp.RF_RTC_UC)

	families = familiesForSoftreset(peer, bgp.RouteFamily(0))
	assert.Equal(t, len(families), 2)
	assert.NotContains(t, families, bgp.RF_RTC_UC)
}
