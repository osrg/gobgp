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
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/packet"
)

type Table struct {
	routeFamily  bgp.RouteFamily
	destinations map[string]*Destination
}

func NewTable(rf bgp.RouteFamily) *Table {
	return &Table{
		routeFamily:  rf,
		destinations: make(map[string]*Destination),
	}
}

func (t *Table) GetRoutefamily() bgp.RouteFamily {
	return t.routeFamily
}

func (t *Table) insert(path *Path) *Destination {
	var dest *Destination

	t.validatePath(path)
	dest = t.getOrCreateDest(path.GetNlri())

	if path.IsWithdraw {
		// withdraw insert
		dest.addWithdraw(path)
	} else {
		// path insert
		dest.addNewPath(path)
	}
	return dest
}

func (t *Table) DeleteDestByPeer(peerInfo *PeerInfo) []*Destination {
	changedDests := make([]*Destination, 0)
	for _, dest := range t.destinations {
		newKnownPathList := make([]*Path, 0)
		for _, p := range dest.GetKnownPathList() {
			if !p.GetSource().Equal(peerInfo) {
				newKnownPathList = append(newKnownPathList, p)
			}
		}
		if len(newKnownPathList) != len(dest.GetKnownPathList()) {
			changedDests = append(changedDests, dest)
			dest.setKnownPathList(newKnownPathList)
		}
	}
	return changedDests
}

func (t *Table) deletePathsByVrf(vrf *Vrf) []*Path {
	pathList := make([]*Path, 0)
	for _, dest := range t.destinations {
		for _, p := range dest.GetKnownPathList() {
			var rd bgp.RouteDistinguisherInterface
			nlri := p.GetNlri()
			switch nlri.(type) {
			case *bgp.LabeledVPNIPAddrPrefix:
				rd = nlri.(*bgp.LabeledVPNIPAddrPrefix).RD
			case *bgp.LabeledVPNIPv6AddrPrefix:
				rd = nlri.(*bgp.LabeledVPNIPv6AddrPrefix).RD
			case *bgp.EVPNNLRI:
				rd = nlri.(*bgp.EVPNNLRI).RD()
			default:
				return pathList
			}
			if p.IsLocal() && vrf.Rd.String() == rd.String() {
				p.IsWithdraw = true
				pathList = append(pathList, p)
				break
			}
		}
	}
	return pathList
}

func (t *Table) deleteRTCPathsByVrf(vrf *Vrf, vrfs map[string]*Vrf) []*Path {
	pathList := make([]*Path, 0)
	if t.routeFamily != bgp.RF_RTC_UC {
		return pathList
	}
	for _, target := range vrf.ImportRt {
		lhs := target.String()
		for _, dest := range t.destinations {
			nlri := dest.GetNlri().(*bgp.RouteTargetMembershipNLRI)
			rhs := nlri.RouteTarget.String()
			if lhs == rhs && isLastTargetUser(vrfs, target) {
				for _, p := range dest.GetKnownPathList() {
					if p.IsLocal() {
						p.IsWithdraw = true
						pathList = append(pathList, p)
						break
					}
				}
			}
		}
	}
	return pathList
}

func (t *Table) deleteDestByNlri(nlri bgp.AddrPrefixInterface) *Destination {
	destinations := t.GetDestinations()
	dest := destinations[t.tableKey(nlri)]
	if dest != nil {
		delete(destinations, t.tableKey(nlri))
	}
	return dest
}

func (t *Table) deleteDest(dest *Destination) {
	destinations := t.GetDestinations()
	delete(destinations, t.tableKey(dest.GetNlri()))
}

func (t *Table) validatePath(path *Path) {
	if path == nil {
		log.WithFields(log.Fields{
			"Topic": "Table",
			"Key":   t.routeFamily,
		}).Error("path is nil")
	}
	if path.GetRouteFamily() != t.routeFamily {
		log.WithFields(log.Fields{
			"Topic":      "Table",
			"Key":        t.routeFamily,
			"Prefix":     path.GetNlri().String(),
			"ReceivedRf": path.GetRouteFamily().String(),
		}).Error("Invalid path. RouteFamily mismatch")
	}
	if _, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH); attr != nil {
		pathParam := attr.(*bgp.PathAttributeAsPath).Value
		for _, as := range pathParam {
			_, y := as.(*bgp.As4PathParam)
			if !y {
				log.WithFields(log.Fields{
					"Topic": "Table",
					"Key":   t.routeFamily,
					"As":    as,
				}).Fatal("AsPathParam must be converted to As4PathParam")
			}
		}
	}
	if _, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS4_PATH); attr != nil {
		log.WithFields(log.Fields{
			"Topic": "Table",
			"Key":   t.routeFamily,
		}).Fatal("AS4_PATH must be converted to AS_PATH")
	}
	if path.GetNlri() == nil {
		log.WithFields(log.Fields{
			"Topic": "Table",
			"Key":   t.routeFamily,
		}).Fatal("path's nlri is nil")
	}
}

func (t *Table) getOrCreateDest(nlri bgp.AddrPrefixInterface) *Destination {
	tableKey := t.tableKey(nlri)
	dest := t.GetDestination(tableKey)
	// If destination for given prefix does not exist we create it.
	if dest == nil {
		log.WithFields(log.Fields{
			"Topic": "Table",
			"Key":   tableKey,
		}).Debugf("create Destination")
		dest = NewDestination(nlri)
		t.setDestination(tableKey, dest)
	}
	return dest
}

func (t *Table) GetDestinations() map[string]*Destination {
	return t.destinations
}
func (t *Table) setDestinations(destinations map[string]*Destination) {
	t.destinations = destinations
}
func (t *Table) GetDestination(key string) *Destination {
	dest, ok := t.destinations[key]
	if ok {
		return dest
	} else {
		return nil
	}
}

func (t *Table) setDestination(key string, dest *Destination) {
	t.destinations[key] = dest
}

func (t *Table) tableKey(nlri bgp.AddrPrefixInterface) string {
	return nlri.String()
}
