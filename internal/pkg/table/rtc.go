package table

import "github.com/osrg/gobgp/v4/pkg/packet/bgp"

type vpnFamilyRT struct {
	paths map[*Path]struct{}
	peers map[string]struct{}
}

func (el *vpnFamilyRT) empty() bool {
	return len(el.paths) == 0 && len(el.peers) == 0
}

func newVpnFamilyRT() *vpnFamilyRT {
	rtTable := &vpnFamilyRT{
		paths: make(map[*Path]struct{}),
		peers: make(map[string]struct{}),
	}
	return rtTable
}

// rtcHandler interface is used for RTC routes registration.
//
// Tests on rtcHandler have been added to table_test.go and table_manager_test.go.
type rtcHandler interface {
	// register adds path to a rtc map.
	register(path *Path)
	// unregister removes path from a rtc map and deletes elem of the map if it is
	// empty and if deleteEmpty.
	unregister(path *Path, deleteEmpty bool)
}

func newRTCPart(rf bgp.Family, isAdj bool) rtcHandler {
	switch rf {
	case bgp.RF_RTC_UC:
		if isAdj {
			return newRtcFamilyRTCMap()
		}
	default:
		if !isAdj {
			return newVpnFamilyRTCMap()
		}
	}
	return nil
}

// vpnFamilyRTCMap is used for saving map[rt]->{paths aka vpnFamilyRT} in global tables and
// saving lists of routes to answer RTC requests.
// It must register all VPN paths that are added to the Table (currently the only place is
// 'func (t *Table) update(newPath *Path)'). It must unregister all VPN paths that are removed from
// the Table (same place). In other words, it must maintain the same set of paths as the Table does.
type vpnFamilyRTCMap struct {
	rts map[uint64]*vpnFamilyRT
}

func (rtc *vpnFamilyRTCMap) register(path *Path) {
	if path == nil {
		return
	}
	for _, ext := range path.GetExtCommunities() {
		key, err := ExtCommRouteTargetKey(ext)
		if err != nil {
			// ext is not route target, skip it.
			continue
		}
		rtTable, found := rtc.rts[key]
		if !found {
			rtTable = newVpnFamilyRT()
			rtc.rts[key] = rtTable
		}
		rtTable.paths[path] = struct{}{}
	}
}

func (rtc *vpnFamilyRTCMap) unregister(path *Path, deleteEmpty bool) {
	if path == nil {
		return
	}
	for _, ext := range path.GetExtCommunities() {
		key, err := ExtCommRouteTargetKey(ext)
		if err != nil {
			// ext is not route target, skip it.
			continue
		}
		rtTable, found := rtc.rts[key]
		if !found {
			// ext hasn't been registered, skip it.
			continue
		}
		delete(rtTable.paths, path)
		if deleteEmpty && rtTable.empty() {
			delete(rtc.rts, key)
		}
	}
}

func newVpnFamilyRTCMap() *vpnFamilyRTCMap {
	return &vpnFamilyRTCMap{
		rts: make(map[uint64]*vpnFamilyRT),
	}
}

// routeFamilyRTCMap is for tracking the existence of RTC-routes (map[rt]->{number of RTC-routes})
// in Adj tables and filtering outgoing paths.
type routeFamilyRTCMap struct {
	rts map[uint64]int
}

func (rtc *routeFamilyRTCMap) register(path *Path) {
	if path.GetFamily() != bgp.RF_RTC_UC {
		return
	}
	nlri, ok := path.GetNlri().(*bgp.RouteTargetMembershipNLRI)
	if !ok {
		return
	}
	rtHash, err := NlriRouteTargetKey(nlri)
	if err != nil {
		return
	}
	if _, found := rtc.rts[rtHash]; !found {
		rtc.rts[rtHash] = 1
		return
	}
	rtc.rts[rtHash]++
}

func (rtc *routeFamilyRTCMap) unregister(path *Path, deleteEmpty bool) {
	if path.GetFamily() != bgp.RF_RTC_UC {
		return
	}
	nlri, ok := path.GetNlri().(*bgp.RouteTargetMembershipNLRI)
	if !ok {
		return
	}
	rtHash, err := NlriRouteTargetKey(nlri)
	if err != nil {
		return
	}
	if val, found := rtc.rts[rtHash]; found {
		if val > 0 {
			rtc.rts[rtHash]--
		}
		if val <= 1 && deleteEmpty {
			delete(rtc.rts, rtHash)
		}
	}
}

func newRtcFamilyRTCMap() *routeFamilyRTCMap {
	return &routeFamilyRTCMap{
		rts: make(map[uint64]int),
	}
}
