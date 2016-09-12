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
		if t.GetNeighbor()[0].State.SessionState == config.SESSION_STATE_ESTABLISHED {
			break
		}
	}

	w := s.Watch(WatchBestPath())

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

}
