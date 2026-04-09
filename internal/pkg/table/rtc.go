package table

import (
	"sync"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

type vpnFamilyRT map[*Path]struct{}

func (el vpnFamilyRT) empty() bool {
	return len(el) == 0
}

// rtmKey uniquely identifies an RT membership NLRI within a given RT hash bucket.
// The RT value itself is already the outer map key (rtHash), so here we only need to
// distinguish NLRIs that share the same RT. With ADD-PATH, the same (AS, RT) can appear
// multiple times with different path identifiers, so both fields are required.
// pathID comes from Path.RemoteID() (the ADD-PATH path identifier stored on the Path,
// not on the NLRI, in this version of the bgp package).
type rtmKey struct {
	pathID uint32
	as     uint32
}

func newRTMKey(nlri *bgp.RouteTargetMembershipNLRI, pathID uint32) rtmKey {
	return rtmKey{pathID: pathID, as: nlri.AS}
}

func newRTCPart(rf bgp.Family, isAdj bool) *rtcHandler {
	if !isAdj && rf != bgp.RF_RTC_UC {
		return newRTCHandler()
	}
	return nil
}

// rtcHandler tracks VPN paths per RT in global tables.
// It must register all VPN paths that are added to the Table (currently the only place is
// 'func (t *Table) update(newPath *Path)'). It must unregister all VPN paths that are removed from
// the Table (same place). In other words, it must maintain the same set of paths as the Table does.
// Thread-safe: all methods are protected by the embedded RWMutex.
type rtcHandler struct {
	mu sync.RWMutex
	m  map[uint64]vpnFamilyRT
}

func newRTCHandler() *rtcHandler {
	return &rtcHandler{m: make(map[uint64]vpnFamilyRT)}
}

func (rtc *rtcHandler) register(path *Path) {
	if path == nil {
		return
	}
	rtc.mu.Lock()
	defer rtc.mu.Unlock()
	for _, ext := range path.GetExtCommunities() {
		key, err := ExtCommRouteTargetKey(ext)
		if err != nil {
			// ext is not route target, skip it.
			continue
		}
		rtTable, found := rtc.m[key]
		if !found {
			rtTable = make(vpnFamilyRT)
			rtc.m[key] = rtTable
		}
		rtTable[path] = struct{}{}
	}
}

func (rtc *rtcHandler) unregister(path *Path, deleteEmpty bool) {
	if path == nil {
		return
	}
	rtc.mu.Lock()
	defer rtc.mu.Unlock()
	for _, ext := range path.GetExtCommunities() {
		key, err := ExtCommRouteTargetKey(ext)
		if err != nil {
			// ext is not route target, skip it.
			continue
		}
		rtTable, found := rtc.m[key]
		if !found {
			// ext hasn't been registered, skip it.
			continue
		}
		delete(rtTable, path)
		if deleteEmpty && rtTable.empty() {
			delete(rtc.m, key)
		}
	}
}

// maxLen returns the number of VPN paths registered for the given RT hash.
func (rtc *rtcHandler) maxLen(rt uint64) int {
	rtc.mu.RLock()
	defer rtc.mu.RUnlock()
	if vpnPaths, ok := rtc.m[rt]; ok {
		return len(vpnPaths)
	}
	return 0
}

// appendBests appends the best VPN paths for the given RT hash to paths.
// isWithdraw=true clones each path as a withdrawal.
// The RLock is held for the entire iteration to prevent concurrent modification.
func (rtc *rtcHandler) appendBests(paths []*Path, rt uint64, tableId string, as uint32, isWithdraw bool) []*Path {
	rtc.mu.RLock()
	defer rtc.mu.RUnlock()
	rtTable, ok := rtc.m[rt]
	if !ok {
		return paths
	}
	return appendBestPathListForRT(paths, tableId, as, isWithdraw, rtTable)
}

// peerRTMIndex tracks RT membership interest per peer at the TableManager level.
// Layout: rtHash → peerID → {rtmKey set}.
// Set semantics (vs a counter) are required for correctness with ADD-PATH:
// the same (AS, RT) can arrive with multiple path identifiers and each must be
// tracked independently so that a withdraw of one does not cancel the others.
type peerRTMIndex map[uint64]map[string]map[rtmKey]struct{}

func newPeerRTMIndex() peerRTMIndex {
	return make(peerRTMIndex)
}

// addRTM registers (nlri, pathID) for peerID under rtHash.
// Returns true if this is the first RTM for this peer+RT (paths should be sent).
func (idx peerRTMIndex) addRTM(rtHash uint64, peerID string, nlri *bgp.RouteTargetMembershipNLRI, pathID uint32) bool {
	peers, ok := idx[rtHash]
	if !ok {
		peers = make(map[string]map[rtmKey]struct{})
		idx[rtHash] = peers
	}
	keys, ok := peers[peerID]
	if !ok {
		keys = make(map[rtmKey]struct{}, 1)
		peers[peerID] = keys
	}
	key := newRTMKey(nlri, pathID)
	if _, exists := keys[key]; exists {
		return false
	}
	isFirst := len(keys) == 0
	keys[key] = struct{}{}
	return isFirst
}

// deleteRTM unregisters (nlri, pathID) for peerID under rtHash.
// Returns true if this was the last RTM for this peer+RT (paths should be withdrawn).
func (idx peerRTMIndex) deleteRTM(rtHash uint64, peerID string, nlri *bgp.RouteTargetMembershipNLRI, pathID uint32) bool {
	peers, ok := idx[rtHash]
	if !ok {
		return false
	}
	keys, ok := peers[peerID]
	if !ok {
		return false
	}
	key := newRTMKey(nlri, pathID)
	if _, exists := keys[key]; !exists {
		return false
	}
	delete(keys, key)
	isLast := len(keys) == 0
	if isLast {
		delete(peers, peerID)
		if len(peers) == 0 {
			delete(idx, rtHash)
		}
	}
	return isLast
}

// hasPeer reports whether peerID has any active RT membership for rtHash.
func (idx peerRTMIndex) hasPeer(rtHash uint64, peerID string) bool {
	peers, ok := idx[rtHash]
	if !ok {
		return false
	}
	_, ok = peers[peerID]
	return ok
}
