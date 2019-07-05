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
	"fmt"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/internal/pkg/apiutil"
	"github.com/osrg/gobgp/internal/pkg/config"
	"github.com/osrg/gobgp/internal/pkg/table"
	"github.com/osrg/gobgp/pkg/packet/bgp"
)

func TestStop(t *testing.T) {
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
	s.StopBgp(context.Background(), &api.StopBgpRequest{})

	s = NewBgpServer()
	go s.Serve()
	err = s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			As:         1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	assert.Nil(err)
	p := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "2.2.2.2",
			PeerAs:          1,
		},
		RouteServer: &api.RouteServer{
			RouteServerClient: true,
		},
	}
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p})
	assert.Nil(err)
	s.StopBgp(context.Background(), &api.StopBgpRequest{})
}

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

	err = s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: table.NewAPIPolicyFromTableStruct(&table.Policy{Name: "p1"})})
	assert.Nil(err)

	err = s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: table.NewAPIPolicyFromTableStruct(&table.Policy{Name: "p2"})})
	assert.Nil(err)

	err = s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: table.NewAPIPolicyFromTableStruct(&table.Policy{Name: "p3"})})
	assert.Nil(err)

	f := func(l []*config.PolicyDefinition) *api.PolicyAssignment {
		pl := make([]*api.Policy, 0, len(l))
		for _, d := range l {
			pl = append(pl, table.ToPolicyApi(d))
		}
		return &api.PolicyAssignment{
			Policies: pl,
		}
	}

	r := f([]*config.PolicyDefinition{&config.PolicyDefinition{Name: "p1"}, &config.PolicyDefinition{Name: "p2"}, &config.PolicyDefinition{Name: "p3"}})
	r.Direction = api.PolicyDirection_IMPORT
	r.DefaultAction = api.RouteAction_ACCEPT
	r.Name = table.GLOBAL_RIB_NAME
	err = s.AddPolicyAssignment(context.Background(), &api.AddPolicyAssignmentRequest{Assignment: r})
	assert.Nil(err)

	r.Direction = api.PolicyDirection_EXPORT
	err = s.AddPolicyAssignment(context.Background(), &api.AddPolicyAssignmentRequest{Assignment: r})
	assert.Nil(err)

	var ps []*api.PolicyAssignment
	err = s.ListPolicyAssignment(context.Background(), &api.ListPolicyAssignmentRequest{
		Name:      table.GLOBAL_RIB_NAME,
		Direction: api.PolicyDirection_IMPORT}, func(p *api.PolicyAssignment) { ps = append(ps, p) })
	assert.Nil(err)
	assert.Equal(len(ps[0].Policies), 3)

	r = f([]*config.PolicyDefinition{&config.PolicyDefinition{Name: "p1"}})
	r.Direction = api.PolicyDirection_IMPORT
	r.DefaultAction = api.RouteAction_ACCEPT
	r.Name = table.GLOBAL_RIB_NAME
	err = s.DeletePolicyAssignment(context.Background(), &api.DeletePolicyAssignmentRequest{Assignment: r})
	assert.Nil(err)

	ps = []*api.PolicyAssignment{}
	s.ListPolicyAssignment(context.Background(), &api.ListPolicyAssignmentRequest{
		Name:      table.GLOBAL_RIB_NAME,
		Direction: api.PolicyDirection_IMPORT}, func(p *api.PolicyAssignment) { ps = append(ps, p) })
	assert.Equal(len(ps[0].Policies), 2)

	ps = []*api.PolicyAssignment{}
	s.ListPolicyAssignment(context.Background(), &api.ListPolicyAssignmentRequest{
		Name: table.GLOBAL_RIB_NAME,
	}, func(p *api.PolicyAssignment) { ps = append(ps, p) })
	assert.Equal(len(ps), 2)
}

func TestListPolicyAssignment(t *testing.T) {
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

	for i := 1; i < 4; i++ {
		addr := "127.0.0." + strconv.Itoa(i)
		p := &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: addr,
				PeerAs:          uint32(i + 1),
			},
			RouteServer: &api.RouteServer{
				RouteServerClient: true,
			},
		}
		err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p})
		assert.Nil(err)

		err = s.AddPolicy(context.Background(),
			&api.AddPolicyRequest{Policy: table.NewAPIPolicyFromTableStruct(&table.Policy{Name: fmt.Sprintf("p%d", i)})})
		assert.Nil(err)

		pa := &api.PolicyAssignment{
			Direction:     api.PolicyDirection_IMPORT,
			DefaultAction: api.RouteAction_ACCEPT,
			Name:          addr,
			Policies:      []*api.Policy{&api.Policy{Name: fmt.Sprintf("p%d", i)}},
		}
		err = s.AddPolicyAssignment(context.Background(), &api.AddPolicyAssignmentRequest{Assignment: pa})
		assert.Nil(err)
	}

	ps := []*api.PolicyAssignment{}
	err = s.ListPolicyAssignment(context.Background(), &api.ListPolicyAssignmentRequest{
		Name: table.GLOBAL_RIB_NAME,
	}, func(p *api.PolicyAssignment) { ps = append(ps, p) })
	assert.Nil(err)
	assert.Equal(len(ps), 0)

	ps = []*api.PolicyAssignment{}
	err = s.ListPolicyAssignment(context.Background(), &api.ListPolicyAssignmentRequest{}, func(p *api.PolicyAssignment) { ps = append(ps, p) })
	assert.Nil(err)
	assert.Equal(len(ps), 3)

	ps = []*api.PolicyAssignment{}
	err = s.ListPolicyAssignment(context.Background(), &api.ListPolicyAssignmentRequest{
		Direction: api.PolicyDirection_EXPORT,
	}, func(p *api.PolicyAssignment) { ps = append(ps, p) })
	assert.Nil(err)
	assert.Equal(len(ps), 0)
}

func TestListPathEnableFiltered(test *testing.T) {
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

	peer1 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAs:          2,
		},
		Transport: &api.Transport{
			PassiveMode: true,
		},
	}
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer1})
	assert.Nil(err)

	d1 := &api.DefinedSet{
		DefinedType: api.DefinedType_PREFIX,
		Name:        "d1",
		Prefixes: []*api.Prefix{
			&api.Prefix{
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
			},
		},
		Actions: &api.Actions{
			RouteAction: api.RouteAction_REJECT,
		},
	}
	err = s.AddDefinedSet(context.Background(), &api.AddDefinedSetRequest{DefinedSet: d1})
	assert.Nil(err)
	p1 := &api.Policy{
		Name:       "p1",
		Statements: []*api.Statement{s1},
	}
	err = s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: p1})
	assert.Nil(err)
	err = s.AddPolicyAssignment(context.Background(), &api.AddPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          table.GLOBAL_RIB_NAME,
			Direction:     api.PolicyDirection_IMPORT,
			Policies:      []*api.Policy{p1},
			DefaultAction: api.RouteAction_ACCEPT,
		},
	})
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

	family := &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_UNICAST,
	}

	nlri1, _ := ptypes.MarshalAny(&api.IPAddressPrefix{
		Prefix:    "10.1.0.0",
		PrefixLen: 24,
	})

	a1, _ := ptypes.MarshalAny(&api.OriginAttribute{
		Origin: 0,
	})
	a2, _ := ptypes.MarshalAny(&api.NextHopAttribute{
		NextHop: "10.0.0.1",
	})
	attrs := []*any.Any{a1, a2}

	t.AddPath(context.Background(), &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path: &api.Path{
			Family: family,
			Nlri:   nlri1,
			Pattrs: attrs,
		},
	})

	nlri2, _ := ptypes.MarshalAny(&api.IPAddressPrefix{
		Prefix:    "10.2.0.0",
		PrefixLen: 24,
	})
	t.AddPath(context.Background(), &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path: &api.Path{
			Family: family,
			Nlri:   nlri2,
			Pattrs: attrs,
		},
	})

	peer2 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAs:          1,
		},
		Transport: &api.Transport{
			RemotePort: 10179,
		},
	}
	ch := make(chan struct{})
	go s.MonitorPeer(context.Background(), &api.MonitorPeerRequest{}, func(peer *api.Peer) {
		if peer.State.SessionState == api.PeerState_ESTABLISHED {
			close(ch)
		}
	})

	err = t.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer2})
	assert.Nil(err)
	<-ch

	for {
		count := 0
		s.ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_ADJ_IN, Family: family, Name: "127.0.0.1"}, func(d *api.Destination) {
			count++
		})
		if count == 2 {
			break
		}
	}
	count := 0
	s.ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_GLOBAL, Family: family}, func(d *api.Destination) {
		count++
	})
	assert.Equal(1, count)

	filtered := 0
	s.ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_ADJ_IN, Family: family, Name: "127.0.0.1", EnableFiltered: true}, func(d *api.Destination) {
		if d.Paths[0].Filtered {
			filtered++
		}
	})
	assert.Equal(1, filtered)

	d2 := &api.DefinedSet{
		DefinedType: api.DefinedType_PREFIX,
		Name:        "d2",
		Prefixes: []*api.Prefix{
			&api.Prefix{
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
			},
		},
		Actions: &api.Actions{
			RouteAction: api.RouteAction_REJECT,
		},
	}
	err = s.AddDefinedSet(context.Background(), &api.AddDefinedSetRequest{DefinedSet: d2})
	assert.Nil(err)
	p2 := &api.Policy{
		Name:       "p2",
		Statements: []*api.Statement{s2},
	}
	err = s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: p2})
	assert.Nil(err)
	err = s.AddPolicyAssignment(context.Background(), &api.AddPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          table.GLOBAL_RIB_NAME,
			Direction:     api.PolicyDirection_EXPORT,
			Policies:      []*api.Policy{p2},
			DefaultAction: api.RouteAction_ACCEPT,
		},
	})
	assert.Nil(err)

	nlri3, _ := ptypes.MarshalAny(&api.IPAddressPrefix{
		Prefix:    "10.3.0.0",
		PrefixLen: 24,
	})
	s.AddPath(context.Background(), &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path: &api.Path{
			Family: family,
			Nlri:   nlri3,
			Pattrs: attrs,
		},
	})

	nlri4, _ := ptypes.MarshalAny(&api.IPAddressPrefix{
		Prefix:    "10.4.0.0",
		PrefixLen: 24,
	})
	s.AddPath(context.Background(), &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path: &api.Path{
			Family: family,
			Nlri:   nlri4,
			Pattrs: attrs,
		},
	})

	count = 0
	s.ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_GLOBAL, Family: family}, func(d *api.Destination) {
		count++
	})
	assert.Equal(3, count)

	count = 0
	filtered = 0
	s.ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_ADJ_OUT, Family: family, Name: "127.0.0.1", EnableFiltered: true}, func(d *api.Destination) {
		count++
		if d.Paths[0].Filtered {
			filtered++
		}
	})
	assert.Equal(2, count)
	assert.Equal(1, filtered)
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

	p1 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAs:          2,
		},
		Transport: &api.Transport{
			PassiveMode: true,
		},
	}
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p1})
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

	p2 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAs:          1,
		},
		Transport: &api.Transport{
			RemotePort: 10179,
		},
	}
	ch := make(chan struct{})
	go t.MonitorPeer(context.Background(), &api.MonitorPeerRequest{}, func(peer *api.Peer) {
		if peer.State.SessionState == api.PeerState_ESTABLISHED {
			close(ch)
		}
	})

	err = t.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p2})
	assert.Nil(err)

	<-ch

	// Test WatchBestPath.
	w := s.watch(watchBestPath(false))

	// Advertises a route.
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop("10.0.0.1"),
	}
	if err := t.addPathList("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.0.0.0"), false, attrs, time.Now(), false)}); err != nil {
		log.Fatal(err)
	}
	ev := <-w.Event()
	b := ev.(*watchEventBestPath)
	assert.Equal(1, len(b.PathList))
	assert.Equal("10.0.0.0/24", b.PathList[0].GetNlri().String())
	assert.False(b.PathList[0].IsWithdraw)

	// Withdraws the previous route.
	// NOTE: Withdow should not require any path attribute.
	if err := t.addPathList("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.0.0.0"), true, nil, time.Now(), false)}); err != nil {
		log.Fatal(err)
	}
	ev = <-w.Event()
	b = ev.(*watchEventBestPath)
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
	w = s.watch(watchUpdate(true))

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
		log.Fatal(err)
	}
	ev = <-w.Event()
	u = ev.(*watchEventUpdate)
	assert.Equal(1, len(u.PathList))
	assert.Equal("10.2.0.0/24", u.PathList[0].GetNlri().String())
	assert.False(u.PathList[0].IsWithdraw)

	// Withdraws the previous route.
	// NOTE: Withdow should not require any path attribute.
	if err := t.addPathList("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.2.0.0"), true, nil, time.Now(), false)}); err != nil {
		log.Fatal(err)
	}
	ev = <-w.Event()
	u = ev.(*watchEventUpdate)
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
	for i := 0; i < 5; i++ {
		if num == runtime.NumGoroutine() {
			return
		}
	}
	assert.Equal(num, runtime.NumGoroutine())
}

func newPeerandInfo(myAs, as uint32, address string, rib *table.TableManager) (*peer, *table.PeerInfo) {
	nConf := &config.Neighbor{Config: config.NeighborConfig{PeerAs: as, NeighborAddress: address}}
	gConf := &config.Global{Config: config.GlobalConfig{As: myAs}}
	config.SetDefaultNeighborConfigValues(nConf, nil, gConf)
	policy := table.NewRoutingPolicy()
	policy.Reset(&config.RoutingPolicy{}, nil)
	p := newPeer(
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
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: config.NewPeerFromConfigStruct(n)})
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
	ch := make(chan struct{})
	go t.MonitorPeer(context.Background(), &api.MonitorPeerRequest{}, func(peer *api.Peer) {
		if peer.State.SessionState == api.PeerState_ESTABLISHED {
			close(ch)
		}
	})
	err = t.AddPeer(context.Background(), &api.AddPeerRequest{Peer: config.NewPeerFromConfigStruct(m)})
	assert.Nil(err)
	<-ch
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
	ch := make(chan struct{})
	go s2.MonitorPeer(context.Background(), &api.MonitorPeerRequest{}, func(peer *api.Peer) {
		if peer.State.SessionState == api.PeerState_ESTABLISHED {
			close(ch)
		}
	})
	err = s2.AddPeer(context.Background(), &api.AddPeerRequest{Peer: config.NewPeerFromConfigStruct(m)})
	assert.Nil(err)
	<-ch
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

	p1 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAs:          2,
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

	p2 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAs:          1,
		},
		Transport: &api.Transport{
			RemotePort: 10179,
		},
		GracefulRestart: &api.GracefulRestart{
			Enabled:     true,
			RestartTime: 1,
		},
	}

	ch := make(chan struct{})
	go s2.MonitorPeer(context.Background(), &api.MonitorPeerRequest{}, func(peer *api.Peer) {
		if peer.State.SessionState == api.PeerState_ESTABLISHED {
			close(ch)
		}
	})
	err = s2.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p2})
	assert.Nil(err)
	<-ch

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

	done := make(chan struct{})
	// Waiting for Graceful Restart timer expired and moving on to IDLE state.
	for {
		s1.ListPeer(context.Background(), &api.ListPeerRequest{}, func(peer *api.Peer) {
			if peer.State.SessionState == api.PeerState_IDLE {
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

func TestFamiliesForSoftreset(t *testing.T) {
	f := func(f bgp.RouteFamily) config.AfiSafi {
		return config.AfiSafi{
			State: config.AfiSafiState{
				Family: f,
			},
		}
	}
	peer := &peer{
		fsm: &fsm{
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

func runNewServer(as uint32, routerID string, listenPort int32) *BgpServer {
	s := NewBgpServer()
	go s.Serve()
	if err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			As:         as,
			RouterId:   routerID,
			ListenPort: listenPort,
		},
	}); err != nil {
		log.Fatalf("Failed to start server %s: %s", s.bgpConfig.Global.Config.RouterId, err)
	}
	return s
}

func peerServers(t *testing.T, ctx context.Context, servers []*BgpServer, families []config.AfiSafiType) error {
	for i, server := range servers {
		for j, peer := range servers {
			if i == j {
				continue
			}

			neighborConfig := &config.Neighbor{
				Config: config.NeighborConfig{
					NeighborAddress: "127.0.0.1",
					PeerAs:          peer.bgpConfig.Global.Config.As,
				},
				AfiSafis: config.AfiSafis{},
				Transport: config.Transport{
					Config: config.TransportConfig{
						RemotePort: uint16(peer.bgpConfig.Global.Config.Port),
					},
				},
			}

			// first server to get neighbor config is passive to hopefully make handshake faster
			if j > i {
				neighborConfig.Transport.Config.PassiveMode = true
			}

			for _, family := range families {
				neighborConfig.AfiSafis = append(neighborConfig.AfiSafis, config.AfiSafi{
					Config: config.AfiSafiConfig{
						AfiSafiName: family,
						Enabled:     true,
					},
				})
			}

			if err := server.AddPeer(ctx, &api.AddPeerRequest{Peer: config.NewPeerFromConfigStruct(neighborConfig)}); err != nil {
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

func addVrf(t *testing.T, s *BgpServer, vrfName, rdStr string, id uint32) {
	rd, rt, err := parseRDRT(rdStr)
	if err != nil {
		t.Fatal(err)
	}

	req := &api.AddVrfRequest{
		Vrf: &api.Vrf{
			Name:     vrfName,
			ImportRt: apiutil.MarshalRTs([]bgp.ExtendedCommunityInterface{rt}),
			ExportRt: apiutil.MarshalRTs([]bgp.ExtendedCommunityInterface{rt}),
			Rd:       apiutil.MarshalRD(rd),
			Id:       id,
		},
	}
	if err = s.AddVrf(context.Background(), req); err != nil {
		t.Fatal(err)
	}
}

func TestDoNotReactToDuplicateRTCMemberships(t *testing.T) {
	ctx := context.Background()
	log.SetLevel(log.DebugLevel)

	s1 := runNewServer(1, "1.1.1.1", 10179)
	s2 := runNewServer(1, "2.2.2.2", 20179)

	addVrf(t, s1, "vrf1", "111:111", 1)
	addVrf(t, s2, "vrf1", "111:111", 1)

	if err := peerServers(t, ctx, []*BgpServer{s1, s2}, []config.AfiSafiType{config.AFI_SAFI_TYPE_L3VPN_IPV4_UNICAST, config.AFI_SAFI_TYPE_RTC}); err != nil {
		t.Fatal(err)
	}
	watcher := s1.watch(watchUpdate(true))

	// Add route to vrf1 on s2
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop("2.2.2.2"),
	}
	prefix := bgp.NewIPAddrPrefix(24, "10.30.2.0")
	path := apiutil.NewPath(prefix, false, attrs, time.Now())

	if _, err := s2.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_VRF,
		VrfId:     "vrf1",
		Path:      path,
	}); err != nil {
		t.Fatal(err)
	}

	// s1 should receive this route from s2
	t1 := time.NewTimer(time.Duration(30 * time.Second))
	for found := false; !found; {
		select {
		case ev := <-watcher.Event():
			switch msg := ev.(type) {
			case *watchEventUpdate:
				for _, path := range msg.PathList {
					log.Infof("tester received path: %s", path.String())
					if vpnPath, ok := path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix); ok {
						if vpnPath.Prefix.Equal(prefix.Prefix) {
							log.Infof("tester found expected prefix: %s", vpnPath.Prefix)
							found = true
						} else {
							log.Infof("unknown prefix %s != %s", vpnPath.Prefix, prefix.Prefix)
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

	t2 := time.NewTimer(time.Duration(2 * time.Second))
	for done := false; !done; {
		select {
		case ev := <-watcher.Event():
			switch msg := ev.(type) {
			case *watchEventUpdate:
				for _, path := range msg.PathList {
					log.Infof("tester received path: %s", path.String())
					if vpnPath, ok := path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix); ok {
						t.Fatalf("vpn prefix %s was unexpectedly received", vpnPath.Prefix)
					}
				}
			}
		case <-t2.C:
			log.Infof("await update done")
			done = true
		}
	}

	s1.StopBgp(context.Background(), &api.StopBgpRequest{})
	s2.StopBgp(context.Background(), &api.StopBgpRequest{})
}

func TestAddDeletePath(t *testing.T) {
	ctx := context.Background()
	s := runNewServer(1, "1.1.1.1", 10179)

	nlri, _ := ptypes.MarshalAny(&api.IPAddressPrefix{
		Prefix:    "10.0.0.0",
		PrefixLen: 24,
	})

	a1, _ := ptypes.MarshalAny(&api.OriginAttribute{
		Origin: 0,
	})
	a2, _ := ptypes.MarshalAny(&api.NextHopAttribute{
		NextHop: "10.0.0.1",
	})
	attrs := []*any.Any{a1, a2}

	family := &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_UNICAST,
	}

	listRib := func() []*api.Destination {
		l := make([]*api.Destination, 0)
		s.ListPath(ctx, &api.ListPathRequest{TableType: api.TableType_GLOBAL, Family: family}, func(d *api.Destination) { l = append(l, d) })
		return l
	}

	var err error
	// DeletePath(AddPath()) without PeerInfo
	getPath := func() *api.Path {
		return &api.Path{
			Family: family,
			Nlri:   nlri,
			Pattrs: attrs,
		}
	}

	p1 := getPath()
	_, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path:      p1,
	})
	assert.Nil(t, err)
	assert.Equal(t, len(listRib()), 1)
	err = s.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_GLOBAL,
		Path:      p1,
	})
	assert.Nil(t, err)
	assert.Equal(t, len(listRib()), 0)

	// DeletePath(ListPath()) without PeerInfo
	_, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path:      p1,
	})
	assert.Nil(t, err)
	l := listRib()
	assert.Equal(t, len(l), 1)
	err = s.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_GLOBAL,
		Path:      l[0].Paths[0],
	})
	assert.Nil(t, err)
	assert.Equal(t, len(listRib()), 0)

	p2 := getPath()
	p2.SourceAsn = 1
	p2.SourceId = "1.1.1.1"

	// DeletePath(AddPath()) with PeerInfo
	_, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path:      p2,
	})
	assert.Nil(t, err)
	assert.Equal(t, len(listRib()), 1)
	err = s.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_GLOBAL,
		Path:      p2,
	})
	assert.Nil(t, err)
	assert.Equal(t, len(listRib()), 0)

	// DeletePath(ListPath()) with PeerInfo
	_, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path:      p2,
	})
	assert.Nil(t, err)
	l = listRib()
	assert.Equal(t, len(l), 1)
	err = s.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_GLOBAL,
		Path:      l[0].Paths[0],
	})
	assert.Nil(t, err)
	assert.Equal(t, len(listRib()), 0)

	// DeletePath(AddPath()) with different PeerInfo
	_, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path:      p2,
	})
	assert.Nil(t, err)
	assert.Equal(t, len(listRib()), 1)
	p3 := getPath()
	p3.SourceAsn = 2
	p3.SourceId = "1.1.1.2"
	err = s.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_GLOBAL,
		Path:      p3,
	})
	assert.Nil(t, err)
	assert.Equal(t, len(listRib()), 1)
}
