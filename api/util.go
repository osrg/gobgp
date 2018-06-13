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

package gobgpapi

import (
	"encoding/json"
	"net"

	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
)

func getNLRI(family bgp.RouteFamily, buf []byte) (bgp.AddrPrefixInterface, error) {
	afi, safi := bgp.RouteFamilyToAfiSafi(family)
	nlri, err := bgp.NewPrefixFromRouteFamily(afi, safi)
	if err != nil {
		return nil, err
	}
	if err := nlri.DecodeFromBytes(buf); err != nil {
		return nil, err
	}
	return nlri, nil
}

func (d *Destination) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Paths)
}

func (p *Path) MarshalJSON() ([]byte, error) {
	nlri, _ := p.GetNativeNlri()
	attrs, _ := p.GetNativePathAttributes()
	return json.Marshal(struct {
		Nlri       bgp.AddrPrefixInterface      `json:"nlri"`
		Age        int64                        `json:"age"`
		Best       bool                         `json:"best"`
		Attrs      []bgp.PathAttributeInterface `json:"attrs"`
		Stale      bool                         `json:"stale"`
		Withdrawal bool                         `json:"withdrawal,omitempty"`
		SourceID   net.IP                       `json:"source-id,omitempty"`
		NeighborIP net.IP                       `json:"neighbor-ip,omitempty"`
	}{
		Nlri:       nlri,
		Age:        p.Age,
		Best:       p.Best,
		Attrs:      attrs,
		Stale:      p.Stale,
		Withdrawal: p.IsWithdraw,
		SourceID:   net.ParseIP(p.SourceId),
		NeighborIP: net.ParseIP(p.NeighborIp),
	})
}

func (p *Path) GetNativeNlri() (bgp.AddrPrefixInterface, error) {
	if len(p.Nlri) > 0 {
		return getNLRI(bgp.RouteFamily(p.Family), p.Nlri)
	}
	return UnmarshalNLRI(bgp.RouteFamily(p.Family), p.AnyNlri)
}

func (p *Path) GetNativePathAttributes() ([]bgp.PathAttributeInterface, error) {
	pattrsLen := len(p.Pattrs)
	if pattrsLen > 0 {
		pattrs := make([]bgp.PathAttributeInterface, 0, pattrsLen)
		for _, attr := range p.Pattrs {
			a, err := bgp.GetPathAttribute(attr)
			if err != nil {
				return nil, err
			}
			err = a.DecodeFromBytes(attr)
			if err != nil {
				return nil, err
			}
			pattrs = append(pattrs, a)
		}
		return pattrs, nil
	}
	return UnmarshalPathAttributes(p.AnyPattrs)
}

func extractFamilyFromConfigAfiSafi(c *config.AfiSafi) uint32 {
	if c == nil {
		return 0
	}
	// If address family value is already stored in AfiSafiState structure,
	// we prefer to use this value.
	if c.State.Family != 0 {
		return uint32(c.State.Family)
	}
	// In case that Neighbor structure came from CLI or gRPC, address family
	// value in AfiSafiState structure can be omitted.
	// Here extracts value from AfiSafiName field in AfiSafiConfig structure.
	if rf, err := bgp.GetRouteFamily(string(c.Config.AfiSafiName)); err == nil {
		return uint32(rf)
	}
	// Ignores invalid address family name
	return 0
}
