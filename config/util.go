// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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

package config

import (
	"fmt"
	"github.com/osrg/gobgp/packet/bgp"
)

func IsConfederationMember(g *Global, p *Neighbor) bool {
	if p.Config.PeerAs != g.Config.As {
		for _, member := range g.Confederation.Config.MemberAsList {
			if member == p.Config.PeerAs {
				return true
			}
		}
	}
	return false
}

func IsEBGPPeer(g *Global, p *Neighbor) bool {
	return p.Config.PeerAs != g.Config.As
}

type AfiSafis []AfiSafi

func (c AfiSafis) ToRfList() ([]bgp.RouteFamily, error) {
	rfs := make([]bgp.RouteFamily, 0, len(c))
	for _, rf := range c {
		k, err := bgp.GetRouteFamily(string(rf.Config.AfiSafiName))
		if err != nil {
			return nil, fmt.Errorf("invalid address family: %s", rf.Config.AfiSafiName)
		}
		rfs = append(rfs, k)
	}
	return rfs, nil
}

func CreateRfMap(p *Neighbor) map[bgp.RouteFamily]bool {
	rfs, _ := AfiSafis(p.AfiSafis).ToRfList()
	rfMap := make(map[bgp.RouteFamily]bool)
	for _, rf := range rfs {
		rfMap[rf] = true
	}
	return rfMap
}

func GetAfiSafi(p *Neighbor, family bgp.RouteFamily) *AfiSafi {
	for _, a := range p.AfiSafis {
		if string(a.Config.AfiSafiName) == family.String() {
			return &a
		}
	}
	return nil
}

func CheckAfiSafisChange(x, y []AfiSafi) bool {
	if len(x) != len(y) {
		return true
	}
	m := make(map[string]bool)
	for _, e := range x {
		m[string(e.Config.AfiSafiName)] = true
	}
	for _, e := range y {
		if !m[string(e.Config.AfiSafiName)] {
			return true
		}
	}
	return false
}
