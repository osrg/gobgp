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
	"github.com/osrg/gobgp/packet/bgp"
	"reflect"
	"sync"
)

type AdjRib struct {
	id          string
	accepted    map[bgp.RouteFamily]int
	table       map[bgp.RouteFamily]map[string]*Path
	isCollector bool
	M           sync.RWMutex
	policy      *RoutingPolicy
	dir         PolicyDirection
}

func NewAdjRib(id string, rfList []bgp.RouteFamily, policy *RoutingPolicy, isCollector bool, dir PolicyDirection) *AdjRib {
	table := make(map[bgp.RouteFamily]map[string]*Path)
	for _, rf := range rfList {
		table[rf] = make(map[string]*Path)
	}
	return &AdjRib{
		id:          id,
		table:       table,
		accepted:    make(map[bgp.RouteFamily]int),
		isCollector: isCollector,
		policy:      policy,
		dir:         dir,
	}
}

func (adj *AdjRib) Update(pathList []*Path) {
	adj.M.Lock()
	defer adj.M.Unlock()
	for _, path := range pathList {
		if path == nil || path.IsEOR() {
			continue
		}
		rf := path.GetRouteFamily()
		key := path.getPrefix()
		if adj.isCollector {
			key += path.GetSource().Address.String()
		}

		old, found := adj.table[rf][key]
		if path.IsWithdraw {
			if found {
				delete(adj.table[rf], key)
				if old.Filtered(adj.id) == POLICY_DIRECTION_NONE {
					adj.accepted[rf]--
				}
			}
		} else {
			n := path.Filtered(adj.id)
			if found {
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
			if found && reflect.DeepEqual(old.GetPathAttrs(), path.GetPathAttrs()) {
				path.setTimestamp(old.GetTimestamp())
			}
			adj.table[rf][key] = path
		}

		option := &PolicyOptions{Found: found}
		if adj.policy != nil && adj.policy.ApplyPolicy(adj.id, adj.dir, path, option) == nil {
			path.Filter(adj.id, adj.dir)
		}
	}
}

func (adj *AdjRib) RefreshAcceptedNumber(rfList []bgp.RouteFamily) {
	adj.M.Lock()
	defer adj.M.Unlock()
	for _, rf := range rfList {
		adj.accepted[rf] = 0
		for _, p := range adj.table[rf] {
			if p.Filtered(adj.id) != POLICY_DIRECTION_IN {
				adj.accepted[rf]++
			}
		}
	}
}

func (adj *AdjRib) PathList(rfList []bgp.RouteFamily, accepted bool) []*Path {
	adj.M.RLock()
	defer adj.M.RUnlock()
	pathList := make([]*Path, 0, adj.Count(rfList))
	for _, rf := range rfList {
		for _, rr := range adj.table[rf] {
			if accepted && rr.Filtered(adj.id) > POLICY_DIRECTION_NONE {
				continue
			}
			pathList = append(pathList, rr)
		}
	}
	return pathList
}

func (adj *AdjRib) Count(rfList []bgp.RouteFamily) int {
	adj.M.RLock()
	defer adj.M.RUnlock()
	count := 0
	for _, rf := range rfList {
		if table, ok := adj.table[rf]; ok {
			count += len(table)
		}
	}
	return count
}

func (adj *AdjRib) Accepted(rfList []bgp.RouteFamily) int {
	adj.M.RLock()
	defer adj.M.RUnlock()
	count := 0
	for _, rf := range rfList {
		if n, ok := adj.accepted[rf]; ok {
			count += n
		}
	}
	return count
}

func (adj *AdjRib) Drop(rfList []bgp.RouteFamily) {
	adj.M.Lock()
	defer adj.M.Unlock()
	for _, rf := range rfList {
		if _, ok := adj.table[rf]; ok {
			adj.table[rf] = make(map[string]*Path)
			adj.accepted[rf] = 0
		}
	}
}

func (adj *AdjRib) DropStale(rfList []bgp.RouteFamily) []*Path {
	adj.M.Lock()
	defer adj.M.Unlock()
	pathList := make([]*Path, 0, adj.Count(rfList))
	for _, rf := range rfList {
		if table, ok := adj.table[rf]; ok {
			for _, p := range table {
				if p.IsStale() {
					delete(table, p.getPrefix())
					if p.Filtered(adj.id) == POLICY_DIRECTION_NONE {
						adj.accepted[rf]--
					}
					pathList = append(pathList, p.Clone(true))
				}
			}
		}
	}
	return pathList
}

func (adj *AdjRib) StaleAll(rfList []bgp.RouteFamily) {
	adj.M.Lock()
	defer adj.M.Unlock()
	for _, rf := range rfList {
		if table, ok := adj.table[rf]; ok {
			for _, p := range table {
				p.MarkStale(true)
			}
		}
	}
}
