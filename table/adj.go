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

package table

import (
	"github.com/osrg/gobgp/packet"
	"reflect"
)

type Dest struct {
	pathList []*Path
}

type AdjRib struct {
	id       string
	accepted map[bgp.RouteFamily]int
	table    map[bgp.RouteFamily]map[string]*Dest
}

func NewAdjRib(id string, rfList []bgp.RouteFamily) *AdjRib {
	table := make(map[bgp.RouteFamily]map[string]*Dest)
	for _, rf := range rfList {
		table[rf] = make(map[string]*Dest)
	}
	return &AdjRib{
		id:       id,
		table:    table,
		accepted: make(map[bgp.RouteFamily]int),
	}
}

func (adj *AdjRib) Update(pathList []*Path) {
	for _, path := range pathList {
		if path == nil {
			continue
		}
		rf := path.GetRouteFamily()
		key := path.getPrefix()
		dst := adj.table[rf][key]
		var old *Path
		oldIdx := 0
		if dst == nil {
			dst = &Dest{}
			dst.pathList = make([]*Path, 0)
			adj.table[rf][key] = dst
		} else {
			for i, known := range dst.pathList {
				if known.GetSource() == path.GetSource() {
					old = known
					oldIdx = i
				}
			}
		}
		if path.IsWithdraw {
			if old != nil {
				dst.pathList = append(dst.pathList[:oldIdx], dst.pathList[oldIdx+1:]...)
				if len(dst.pathList) == 0 {
					delete(adj.table[rf], key)
				}

				if old.Filtered(adj.id) == POLICY_DIRECTION_NONE {
					adj.accepted[rf]--
				}
			}
		} else {
			n := path.Filtered(adj.id)
			if old != nil {
				o := old.Filtered(adj.id)
				if o == POLICY_DIRECTION_IN && n == POLICY_DIRECTION_NONE {
					adj.accepted[rf]++
				} else if o == POLICY_DIRECTION_NONE && n == POLICY_DIRECTION_IN {
					adj.accepted[rf]--
				}
			} else {
				if n == POLICY_DIRECTION_NONE {
					adj.accepted[rf]++
				}
			}
			if old != nil {
				dst.pathList[oldIdx] = path
				// avoid updating timestamp for the
				// exact same message due to soft
				// reset, etc
				if reflect.DeepEqual(old.GetPathAttrs(), path.GetPathAttrs()) {
					path.setTimestamp(old.GetTimestamp())
				}
			} else {
				dst.pathList = append(dst.pathList, path)
			}
		}
	}
}

func (adj *AdjRib) RefreshAcceptedNumber(rfList []bgp.RouteFamily) {
	for _, rf := range rfList {
		adj.accepted[rf] = 0
		for _, d := range adj.table[rf] {
			for _, p := range d.pathList {
				if p.Filtered(adj.id) != POLICY_DIRECTION_IN {
					adj.accepted[rf]++
				}
			}
		}
	}
}

func (adj *AdjRib) PathList(rfList []bgp.RouteFamily, accepted bool) []*Path {
	pathList := make([]*Path, 0, adj.Count(rfList))
	for _, rf := range rfList {
		for _, d := range adj.table[rf] {
			for _, p := range d.pathList {
				if accepted && p.Filtered(adj.id) > POLICY_DIRECTION_NONE {
					continue
				}
				pathList = append(pathList, p)
			}
		}
	}
	return pathList
}

func (adj *AdjRib) Count(rfList []bgp.RouteFamily) int {
	count := 0
	for _, rf := range rfList {
		if table, ok := adj.table[rf]; ok {
			for _, d := range table {
				count += len(d.pathList)
			}
		}
	}
	return count
}

func (adj *AdjRib) Accepted(rfList []bgp.RouteFamily) int {
	count := 0
	for _, rf := range rfList {
		if n, ok := adj.accepted[rf]; ok {
			count += n
		}
	}
	return count
}

func (adj *AdjRib) Drop(rfList []bgp.RouteFamily) {
	for _, rf := range rfList {
		if _, ok := adj.table[rf]; ok {
			adj.table[rf] = make(map[string]*Dest)
			adj.accepted[rf] = 0
		}
	}
}
