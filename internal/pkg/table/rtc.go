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
