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
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
	"github.com/stretchr/testify/assert"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestModPolicyAssign(t *testing.T) {
	assert := assert.New(t)
	s := NewBgpServer()
	go s.Serve()
	s.Start(&config.Global{
		Config: config.GlobalConfig{
			As:       1,
			RouterId: "1.1.1.1",
		},
	})
	err := s.AddPolicy(&table.Policy{Name: "p1"}, false)
	assert.Nil(err)

	err = s.AddPolicy(&table.Policy{Name: "p2"}, false)
	assert.Nil(err)

	err = s.AddPolicy(&table.Policy{Name: "p3"}, false)
	assert.Nil(err)

	err = s.AddPolicyAssignment("", table.POLICY_DIRECTION_IMPORT,
		[]*config.PolicyDefinition{&config.PolicyDefinition{Name: "p1"}, &config.PolicyDefinition{Name: "p2"}, &config.PolicyDefinition{Name: "p3"}}, table.ROUTE_TYPE_ACCEPT)
	assert.Nil(err)

	err = s.DeletePolicyAssignment("", table.POLICY_DIRECTION_IMPORT,
		[]*config.PolicyDefinition{&config.PolicyDefinition{Name: "p1"}}, false)
	assert.Nil(err)

	_, ps, _ := s.GetPolicyAssignment("", table.POLICY_DIRECTION_IMPORT)
	assert.Equal(len(ps), 2)
}

func TestMonitor(test *testing.T) {
	assert := assert.New(test)
	s := NewBgpServer()
	go s.Serve()
	s.Start(&config.Global{
		Config: config.GlobalConfig{
			As:       1,
			RouterId: "1.1.1.1",
			Port:     10179,
		},
	})
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
	if err := s.AddNeighbor(n); err != nil {
		log.Fatal(err)
	}
	t := NewBgpServer()
	go t.Serve()
	t.Start(&config.Global{
		Config: config.GlobalConfig{
			As:       2,
			RouterId: "2.2.2.2",
			Port:     -1,
		},
	})
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
	if err := t.AddNeighbor(m); err != nil {
		log.Fatal(err)
	}

	for {
		time.Sleep(time.Second)
		if t.GetNeighbor(false)[0].State.SessionState == config.SESSION_STATE_ESTABLISHED {
			break
		}
	}

	w := s.Watch(WatchBestPath(false))

	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop("10.0.0.1"),
	}
	if _, err := t.AddPath("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.0.0.0"), false, attrs, time.Now(), false)}); err != nil {
		log.Fatal(err)
	}

	ev := <-w.Event()
	b := ev.(*WatchEventBestPath)
	assert.Equal(len(b.PathList), 1)
	assert.Equal(b.PathList[0].GetNlri().String(), "10.0.0.0/24")
	assert.Equal(b.PathList[0].IsWithdraw, false)

	if _, err := t.AddPath("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.0.0.0"), true, attrs, time.Now(), false)}); err != nil {
		log.Fatal(err)
	}

	ev = <-w.Event()
	b = ev.(*WatchEventBestPath)
	assert.Equal(len(b.PathList), 1)
	assert.Equal(b.PathList[0].GetNlri().String(), "10.0.0.0/24")
	assert.Equal(b.PathList[0].IsWithdraw, true)

	if _, err := t.AddPath("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(24, "10.0.0.0"), true, attrs, time.Now(), false)}); err != nil {
		log.Fatal(err)
	}
	//stop the watcher still having an item.
	w.Stop()
}

func TestNumGoroutineWithAddDeleteNeighbor(t *testing.T) {
	assert := assert.New(t)
	s := NewBgpServer()
	go s.Serve()
	err := s.Start(&config.Global{
		Config: config.GlobalConfig{
			As:       1,
			RouterId: "1.1.1.1",
			Port:     -1,
		},
	})
	assert.Nil(err)

	num := runtime.NumGoroutine()

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
	err = s.AddNeighbor(n)
	assert.Nil(err)

	err = s.DeleteNeighbor(n)
	assert.Nil(err)
	// wait goroutines to finish (e.g. internal goroutine for
	// InfiniteChannel)
	time.Sleep(time.Second * 5)
	assert.Equal(num, runtime.NumGoroutine())
}

func TestFilterpath(t *testing.T) {
	p1As := uint32(65001)
	p2As := uint32(65002)
	rib := table.NewTableManager([]bgp.RouteFamily{bgp.RF_IPv4_UC})
	newPeerandInfo := func(as uint32, address string) (*Peer, *table.PeerInfo) {
		p := NewPeer(
			&config.Global{Config: config.GlobalConfig{As: 65000}},
			&config.Neighbor{Config: config.NeighborConfig{PeerAs: as, NeighborAddress: address}},
			rib,
			&table.RoutingPolicy{})
		p.fsm.rfMap[bgp.RF_IPv4_UC] = true
		return p, &table.PeerInfo{AS: as, Address: net.ParseIP(address)}
	}
	p1, pi1 := newPeerandInfo(p1As, "192.168.0.1")
	p2, pi2 := newPeerandInfo(p2As, "192.168.0.2")

	nlri := bgp.NewIPAddrPrefix(24, "10.10.10.0")
	pa1 := []bgp.PathAttributeInterface{bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{p1As})}), bgp.NewPathAttributeLocalPref(200)}
	pa2 := []bgp.PathAttributeInterface{bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{p2As})})}

	path1 := table.NewPath(pi1, nlri, false, pa1, time.Now(), false)
	path2 := table.NewPath(pi2, nlri, false, pa2, time.Now(), false)

	cal := func(l []*table.Path) (*table.Path, *table.Path) {
		news, olds, _ := rib.ProcessPaths([]string{table.GLOBAL_RIB_NAME}, l)
		assert.Equal(t, len(news), 1)
		for idx, path := range news[table.GLOBAL_RIB_NAME] {
			var old *table.Path
			if olds != nil {
				old = olds[table.GLOBAL_RIB_NAME][idx]
			}
			return path, old
		}
		return nil, nil
	}

	new, old := cal([]*table.Path{path1, path2})
	assert.Equal(t, new, path1)
	filterpath(p1, new, old)
	filterpath(p2, new, old)

	new, old = cal([]*table.Path{path1.Clone(true)})
	assert.Equal(t, new, path2)
	// p1 and p2 advertized the same prefix and p1's was best. Then p1 withdraw it, so p2 must get withdawal.
	path := filterpath(p2, new, old)
	assert.NotNil(t, path)
	assert.True(t, path.IsWithdraw)

	// p1 should get the new best (from p2)
	assert.Equal(t, filterpath(p1, new, old), path2)
}
