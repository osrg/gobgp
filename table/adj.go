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
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/packet"
	"reflect"
)

type AdjPath struct {
	Path                   *Path
	OriginalPathIdentifier uint32
}

func NewAdjPath(path *Path) *AdjPath {
	return &AdjPath{
		Path: path,
		OriginalPathIdentifier: path.GetNlri().PathIdentifier(),
	}
}

func (p *AdjPath) GetSource() *PeerInfo {
	return p.Path.source
}

type AdjDestination struct {
	rf       bgp.RouteFamily
	nlri     bgp.AddrPrefixInterface
	PathList []*AdjPath
	SendMax  uint8
	Out      bool
	RadixKey string
}

func NewAdjDestination(nlri bgp.AddrPrefixInterface, sendMax uint8, out bool) *AdjDestination {
	if sendMax == 0 {
		sendMax = 1
	}
	key := ""
	switch bgp.AfiSafiToRouteFamily(nlri.AFI(), nlri.SAFI()) {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		key = CidrToRadixkey(nlri.String())
	}

	return &AdjDestination{
		rf:       bgp.AfiSafiToRouteFamily(nlri.AFI(), nlri.SAFI()),
		nlri:     nlri,
		PathList: make([]*AdjPath, 0, sendMax),
		SendMax:  sendMax,
		Out:      out,
		RadixKey: key,
	}
}

func (d *AdjDestination) Update(path *Path) *Path {
	p := NewAdjPath(path)
	found := false
	withdraw := p.Path.IsWithdraw
	idx := 0

	dir := "In"
	if d.Out {
		dir = "Out"
	}

	log.WithFields(log.Fields{
		"Path":     path,
		"Topic":    fmt.Sprintf("AdjRib%s", dir),
		"Withdraw": withdraw,
		"Score":    path.Score(),
	}).Debug("update")

	for i, pp := range d.PathList {
		if p.GetSource().Equal(pp.GetSource()) && p.OriginalPathIdentifier == pp.OriginalPathIdentifier {
			log.WithFields(log.Fields{
				"Path":     path,
				"Topic":    fmt.Sprintf("AdjRib%s", dir),
				"Withdraw": withdraw,
			}).Debug("match to exsiting path")

			found = true
			idx = i
			d.PathList[i] = p
			if reflect.DeepEqual(pp.Path.GetPathAttrs(), path.GetPathAttrs()) {
				path.setTimestamp(pp.Path.GetTimestamp())
			}
			if !withdraw && d.Out {
				path.GetNlri().SetPathIdentifier(uint32(i) + 1)
			}
		}
	}

	if withdraw {
		if found {
			d.PathList = append(d.PathList[:idx], d.PathList[idx+1:]...)
			return path
		} else {
			return nil
		}
	}

	// sendmax limitation
	if d.Out && len(d.PathList) >= int(d.SendMax) {
		// we must send bestpath even in case of send max limitation
		if path.Score() == 0 {
			log.WithFields(log.Fields{
				"Topic": fmt.Sprintf("AdjRib%s", dir),
				"Path":  path,
			}).Debug("replace best")
			d.PathList[0] = p
			path.GetNlri().SetPathIdentifier(1)
			found = true
		} else {
			log.WithFields(log.Fields{
				"Topic": fmt.Sprintf("AdjRib%s", dir),
				"Path":  path,
				"Limit": d.SendMax,
			}).Debug("send max limitation")
			return nil
		}
	}

	if !found {
		if d.Out {
			path.GetNlri().SetPathIdentifier(uint32(len(d.PathList)))
		}
		d.PathList = append(d.PathList, p)
	}
	return path
}

func (d *AdjDestination) GetPathList() []*Path {
	pathList := make([]*Path, 0, len(d.PathList))
	for _, p := range d.PathList {
		pathList = append(pathList, p.Path)
	}
	return pathList
}

type AddPathStatus struct {
	Mode    bgp.BGPAddPathMode
	SendMax uint8
}

type AdjRib struct {
	tables  map[bgp.RouteFamily]map[string]*AdjDestination
	sendMax map[bgp.RouteFamily]uint8
	out     bool
}

func (o *AdjRib) GetPathList(rf bgp.RouteFamily) []*Path {
	t, ok := o.tables[rf]
	if !ok {
		return nil
	}
	paths := make([]*Path, 0, len(t))
	for _, dst := range t {
		paths = append(paths, dst.GetPathList()...)
	}
	return paths
}

func (o *AdjRib) DropAll(rf bgp.RouteFamily) {
	_, ok := o.tables[rf]
	if ok {
		o.tables[rf] = make(map[string]*AdjDestination)
	}
}

func (o *AdjRib) Update(paths []*Path) []*Path {
	sendPaths := make([]*Path, 0, len(paths))
	for _, path := range paths {
		rf := path.GetRouteFamily()
		key := path.GetNlri().String()
		dst, found := o.tables[rf][key]
		if !found {
			dst = NewAdjDestination(path.GetNlri(), o.sendMax[rf], o.out)
			o.tables[rf][key] = dst
		}
		p := dst.Update(path)
		if p != nil {
			sendPaths = append(sendPaths, p)
		}
		if len(dst.PathList) == 0 {
			delete(o.tables[rf], key)
		}
	}
	return sendPaths
}

func (o *AdjRib) GetCount(rf bgp.RouteFamily) int {
	if _, ok := o.tables[rf]; !ok {
		return 0
	}
	return len(o.tables[rf])
}

func (o *AdjRib) GetDestinations(rf bgp.RouteFamily) map[string]*Destination {
	t, ok := o.tables[rf]
	if !ok {
		return nil
	}
	dsts := make(map[string]*Destination)
	for k, d := range t {
		dst := &Destination{
			nlri:          d.nlri,
			knownPathList: d.GetPathList(),
			RadixKey:      d.RadixKey,
		}
		dsts[k] = dst
	}
	return dsts
}

func NewAdjRibOut(rfs []bgp.RouteFamily, m map[bgp.RouteFamily]AddPathStatus) *AdjRib {
	o := &AdjRib{
		tables:  make(map[bgp.RouteFamily]map[string]*AdjDestination),
		sendMax: make(map[bgp.RouteFamily]uint8),
		out:     true,
	}
	for _, rf := range rfs {
		o.tables[rf] = make(map[string]*AdjDestination)
	}
	for rf, status := range m {
		if status.Mode&bgp.BGP_ADD_PATH_SEND > 0 {
			o.sendMax[rf] = status.SendMax
		}
	}
	return o
}

func NewAdjRibIn(rfs []bgp.RouteFamily) *AdjRib {
	i := &AdjRib{
		tables: make(map[bgp.RouteFamily]map[string]*AdjDestination),
		out:    false,
	}
	for _, rf := range rfs {
		i.tables[rf] = make(map[string]*AdjDestination)
	}
	return i
}
