// Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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
	"net"
)

// A state of the nexthop mostly for the BGP Next-Hop Tracking.
type NexthopState struct {
	// IP address of the nexthop
	Address net.IP
	// Shows whether the nexthop is unreachable or not.
	IsUnreachable bool
	// Shows the metric to the nexthop calculated by IGP.
	IgpMetric uint32
}

func (s *NexthopState) Equal(other *NexthopState) bool {
	if other == nil {
		return false
	} else if !s.Address.Equal(other.Address) {
		return false
	} else if s.IsUnreachable != other.IsUnreachable {
		return false
	} else if s.IgpMetric != other.IgpMetric {
		return false
	}
	return true
}

type nexthopStateMap map[string]*NexthopState

func (m nexthopStateMap) newNexthopState(address net.IP) *NexthopState {
	if address == nil {
		return nil
	}
	addr := address.String()
	if state, ok := m[addr]; ok {
		return state
	}
	state := &NexthopState{
		Address: address,
	}
	m[addr] = state
	return state
}

func (m nexthopStateMap) updateNexthopState(state *NexthopState) (bool, error) {
	if state == nil {
		return false, fmt.Errorf("cannot update nexthop state with %v", state)
	}
	addr := state.Address.String()
	if s, ok := m[addr]; !ok {
		if state := m.newNexthopState(state.Address); state == nil {
			return false, fmt.Errorf("no such nexthop registered and could not register nexthop: %v", state)
		}
	} else if s.Equal(state) {
		return false, nil
	}
	m[addr].IsUnreachable = state.IsUnreachable
	m[addr].IgpMetric = state.IgpMetric
	return true, nil
}
