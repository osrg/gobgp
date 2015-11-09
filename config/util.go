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
	"github.com/osrg/gobgp/packet"
)

func IsConfederationMember(g *Global, p *Neighbor) bool {
	if p.NeighborConfig.PeerAs != g.GlobalConfig.As {
		for _, member := range g.Confederation.ConfederationConfig.MemberAs {
			if member == p.NeighborConfig.PeerAs {
				return true
			}
		}
	}
	return false
}

func IsEBGPPeer(g *Global, p *Neighbor) bool {
	return p.NeighborConfig.PeerAs != g.GlobalConfig.As
}

func CreateRfMap(p *Neighbor) map[bgp.RouteFamily]bool {
	rfMap := make(map[bgp.RouteFamily]bool)
	for _, rf := range p.AfiSafis.AfiSafiList {
		k, _ := bgp.GetRouteFamily(rf.AfiSafiName)
		rfMap[k] = true
	}
	return rfMap
}
