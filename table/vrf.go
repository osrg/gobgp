// Copyright (C) 2014-2016 Nippon Telegraph and Telephone Corporation.
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

package table

import (
	"fmt"
	"github.com/osrg/gobgp/packet/bgp"
)

type Vrf struct {
	Name     string
	Id       uint32
	Rd       bgp.RouteDistinguisherInterface
	ImportRt []bgp.ExtendedCommunityInterface
	ExportRt []bgp.ExtendedCommunityInterface
}

func (v *Vrf) ToGlobalPath(path *Path) error {
	nlri := path.GetNlri()
	switch rf := path.GetRouteFamily(); rf {
	case bgp.RF_IPv4_UC:
		n := nlri.(*bgp.IPAddrPrefix)
		path.OriginInfo().nlri = bgp.NewLabeledVPNIPAddrPrefix(n.Length, n.Prefix.String(), *bgp.NewMPLSLabelStack(0), v.Rd)
	case bgp.RF_IPv6_UC:
		n := nlri.(*bgp.IPv6AddrPrefix)
		path.OriginInfo().nlri = bgp.NewLabeledVPNIPv6AddrPrefix(n.Length, n.Prefix.String(), *bgp.NewMPLSLabelStack(0), v.Rd)
	case bgp.RF_EVPN:
		n := nlri.(*bgp.EVPNNLRI)
		switch n.RouteType {
		case bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
			n.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute).RD = v.Rd
		case bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG:
			n.RouteTypeData.(*bgp.EVPNMulticastEthernetTagRoute).RD = v.Rd
		}
	default:
		return fmt.Errorf("unsupported route family for vrf: %s", rf)
	}
	path.SetExtCommunities(v.ExportRt, false)
	return nil
}

func (v *Vrf) Clone() *Vrf {
	f := func(rt []bgp.ExtendedCommunityInterface) []bgp.ExtendedCommunityInterface {
		l := make([]bgp.ExtendedCommunityInterface, 0, len(rt))
		for _, v := range rt {
			l = append(l, v)
		}
		return l
	}
	return &Vrf{
		Name:     v.Name,
		Id:       v.Id,
		Rd:       v.Rd,
		ImportRt: f(v.ImportRt),
		ExportRt: f(v.ExportRt),
	}
}

func isLastTargetUser(vrfs map[string]*Vrf, target bgp.ExtendedCommunityInterface) bool {
	for _, vrf := range vrfs {
		for _, rt := range vrf.ImportRt {
			if target.String() == rt.String() {
				return false
			}
		}
	}
	return true
}
