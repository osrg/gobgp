package table

import (
	"sync"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// rtmKey uniquely identifies an RT membership entry within an RT hash bucket.
// With ADD-PATH, the same (AS, RT) NLRI can appear with different path IDs;
// both fields are required so a withdraw of one path-ID or different AS does not cancel others.
type rtmKey struct {
	as     uint32
	pathID uint32
}

// rtmSet tracks which (AS, pathID) pairs are present per RT hash.
// Set semantics make ADD-PATH or different AS withdrawals safe: removing one path-ID does not
// affect others sharing the same RT, and spurious removes are no-ops.
// Thread-safe: add/sub are called under a shard write-lock, has is called from
// interestedIn without any lock, so an internal RWMutex is required.
type rtmSet struct {
	mu sync.RWMutex
	m  map[uint64]map[rtmKey]struct{}
}

func newRtmSet() *rtmSet {
	return &rtmSet{m: make(map[uint64]map[rtmKey]struct{})}
}

func (s *rtmSet) add(path *Path) {
	if s == nil {
		return
	}
	if path.GetFamily() != bgp.RF_RTC_UC {
		return
	}
	nlri, ok := path.GetNlri().(*bgp.RouteTargetMembershipNLRI)
	if !ok {
		return
	}
	rtHash, err := nlriRouteTargetKey(nlri)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, ok := s.m[rtHash]
	if !ok {
		keys = make(map[rtmKey]struct{})
		s.m[rtHash] = keys
	}
	keys[rtmKey{as: nlri.AS, pathID: path.remoteID}] = struct{}{}
}

func (s *rtmSet) sub(path *Path) {
	if s == nil {
		return
	}
	if path.GetFamily() != bgp.RF_RTC_UC {
		return
	}
	nlri, ok := path.GetNlri().(*bgp.RouteTargetMembershipNLRI)
	if !ok {
		return
	}
	rtHash, err := nlriRouteTargetKey(nlri)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, ok := s.m[rtHash]
	if !ok {
		return
	}
	delete(keys, rtmKey{as: nlri.AS, pathID: path.remoteID})
	if len(keys) == 0 {
		delete(s.m, rtHash)
	}
}

func (s *rtmSet) has(rtHash uint64) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m[rtHash]) > 0
}

func (s *rtmSet) reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = make(map[uint64]map[rtmKey]struct{})
}

// RouteTargetMembershipHandler tracks Route Target membership NLRI keys learned from a
// peer that count for RTC constrained route distribution, after import policy.
type RouteTargetMembershipHandler struct {
	s *rtmSet
}

func NewRouteTargetMembershipHandler() *RouteTargetMembershipHandler {
	return &RouteTargetMembershipHandler{s: newRtmSet()}
}

// SyncAfterImport updates the set from the RTC path as seen after import policy:
// accepted advertisements add membership; withdrawals (including import rejects
// represented as withdrawals) remove it.
func (handler *RouteTargetMembershipHandler) SyncAfterImport(path *Path) {
	if handler == nil || handler.s == nil {
		return
	}
	if path == nil || path.IsEOR() || path.GetFamily() != bgp.RF_RTC_UC {
		return
	}
	if path.IsWithdraw {
		handler.s.sub(path)
	} else {
		handler.s.add(path)
	}
}

func (handler *RouteTargetMembershipHandler) HasRouteTarget(routeTarget bgp.ExtendedCommunityInterface) bool {
	if handler == nil || handler.s == nil {
		return false
	}
	key, err := extCommRouteTargetKey(routeTarget)
	if err != nil {
		return false
	}
	return handler.s.has(key)
}

func (handler *RouteTargetMembershipHandler) HasDefaultRouteTarget() bool {
	if handler == nil || handler.s == nil {
		return false
	}
	return handler.s.has(DefaultRT)
}

// Reset clears all tracked memberships (e.g. when Adj-RIB-In for RTC is dropped).
func (handler *RouteTargetMembershipHandler) Reset() {
	if handler == nil || handler.s == nil {
		return
	}
	handler.s.reset()
}
