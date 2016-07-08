// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet/bgp"
)

type Vrf struct {
	Name     string
	Rd       bgp.RouteDistinguisherInterface
	ImportRt []bgp.ExtendedCommunityInterface
	ExportRt []bgp.ExtendedCommunityInterface
	LabelMap map[string]uint32
}

func (v *Vrf) ToApiStruct() *api.Vrf {
	f := func(rts []bgp.ExtendedCommunityInterface) [][]byte {
		ret := make([][]byte, 0, len(rts))
		for _, rt := range rts {
			b, _ := rt.Serialize()
			ret = append(ret, b)
		}
		return ret
	}
	rd, _ := v.Rd.Serialize()
	return &api.Vrf{
		Name:     v.Name,
		Rd:       rd,
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
