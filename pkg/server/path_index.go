// Copyright (C) 2026 Pau Nadeu.
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

package server

import (
	"net/netip"
	"slices"

	"github.com/google/uuid"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// localPathKey is the slot a local path takes in the global table: its
// destination, by the identity the table keys it by, and the source and
// path identifier that a later path must share to replace it.
type localPathKey struct {
	family        bgp.Family
	destination   string
	sourceAS      uint32
	sourceID      netip.Addr
	sourceLocalID netip.Addr
	sourceAddress netip.Addr
	pathID        uint32
}

func localPathKeyOf(p *table.Path) localPathKey {
	k := localPathKey{
		family:      p.GetFamily(),
		destination: table.DestinationIdentity(p.GetNlri()),
		pathID:      p.RemoteID(),
	}
	if src := p.GetSource(); src != nil {
		k.sourceAS, k.sourceID, k.sourceLocalID, k.sourceAddress = src.AS, src.ID, src.LocalID, src.Address
	}
	return k
}

// pathIndexEntry is the UUID AddPath gave one local path. The entry names
// the path AddPath wrote. The table may hold a copy of it instead, made by
// an import policy or by a zebra next-hop refresh; every copy has the
// written path as its root (table.Path.Root), so the entry follows them.
type pathIndexEntry struct {
	id      uuid.UUID
	key     localPathKey
	written *table.Path
	vrf     string
}

// pathIndex maps the UUIDs AddPath gives to the paths the global table holds
// for them, so that DeletePath by UUID reads one destination instead of
// walking the table. It is touched only from management operations, which
// run one at a time with shared.mu held, so it has no lock of its own.
//
// An entry holds while its slot holds a path whose root is the written
// path. Every write the API or zebra makes to a slot that has an entry is
// applied one path at a time, and after each the slot is read again: an
// entry whose path is no longer there ends. So an entry ends when another
// write replaces its path, when a withdrawal removes it, and also between
// two writes of one stream message. A refresh that reinstalls a copy of
// the path, such as a zebra next-hop change, keeps it. A delete of all
// local paths of a family ends the entries of that family, and DeleteVrf
// the entries whose path it withdrew. Some withdrawals happen inside the
// table without a write of the API, such as an EVPN MAC move caused by a
// received route; an entry left by one of them stays until its slot is next
// written or read, and a delete by its UUID finds its path gone, deletes
// nothing, and ends it.
type pathIndex struct {
	byUUID    map[uuid.UUID]*pathIndexEntry
	byKey     map[localPathKey]map[*pathIndexEntry]struct{}
	byWritten map[*table.Path]*pathIndexEntry
}

func newPathIndex() *pathIndex {
	return &pathIndex{
		byUUID:    make(map[uuid.UUID]*pathIndexEntry),
		byKey:     make(map[localPathKey]map[*pathIndexEntry]struct{}),
		byWritten: make(map[*table.Path]*pathIndexEntry),
	}
}

func (x *pathIndex) len() int { return len(x.byUUID) }

func (x *pathIndex) remove(e *pathIndexEntry) {
	delete(x.byUUID, e.id)
	delete(x.byWritten, e.written)
	if set := x.byKey[e.key]; set != nil {
		delete(set, e)
		if len(set) == 0 {
			delete(x.byKey, e.key)
		}
	}
}

// add records the UUID of a path AddPath wrote and the table holds.
func (x *pathIndex) add(id uuid.UUID, written *table.Path, vrf string) {
	e := &pathIndexEntry{id: id, key: localPathKeyOf(written), written: written, vrf: vrf}
	x.byUUID[id] = e
	set := x.byKey[e.key]
	if set == nil {
		set = make(map[*pathIndexEntry]struct{})
		x.byKey[e.key] = set
	}
	set[e] = struct{}{}
	x.byWritten[written] = e
}

// holds reports whether the paths of a slot include a version of written.
func holds(held []*table.Path, written *table.Path) bool {
	for _, p := range held {
		if p.Root() == written {
			return true
		}
	}
	return false
}

// reconcile ends the entries of a slot whose path is not among the paths
// the slot holds now. It is linear in the size of the slot.
func (x *pathIndex) reconcile(key localPathKey, held []*table.Path) {
	set := x.byKey[key]
	if len(set) == 0 {
		return
	}
	in := make(map[*table.Path]struct{}, len(held))
	for _, p := range held {
		in[p.Root()] = struct{}{}
	}
	for e := range set {
		if _, ok := in[e.written]; !ok {
			x.remove(e)
		}
	}
}

// endFamilies ends the entries of the families.
func (x *pathIndex) endFamilies(families []bgp.Family) {
	for _, e := range x.byUUID {
		if slices.Contains(families, e.key.family) {
			x.remove(e)
		}
	}
}

// localPathsAt returns the local paths the global table holds in the slot
// of key, reading the one destination of p.
func (s *BgpServer) localPathsAt(p *table.Path, key localPathKey) []*table.Path {
	dest := s.globalRib.GetDestination(p)
	if dest == nil {
		return nil
	}
	var out []*table.Path
	for _, rp := range dest.GetAllKnownPathList() {
		if rp.IsLocal() && localPathKeyOf(rp) == key {
			out = append(out, rp)
		}
	}
	return out
}

// propagateLocal writes local paths to the global table and keeps the index
// right. With an empty index and nothing to capture, the paths go to the
// table as one list, as before. Otherwise the paths whose slot has no entry
// still go as lists, in runs between the others, and only a path whose slot
// has an entry, or that AddPath captures, is written on its own with its
// slot read after it, so that every transition of a watched slot is seen.
// With capture, it returns each path when the table holds a version of it,
// or nil when it holds none (a withdrawal, or a path the import policy
// rejected).
func (s *BgpServer) propagateLocal(paths []*table.Path, capture bool) []*table.Path {
	if !capture && s.pathIndex.len() == 0 {
		s.propagateUpdate(nil, paths)
		return nil
	}
	var installed []*table.Path
	if capture {
		installed = make([]*table.Path, len(paths))
	}
	run := 0
	flush := func(end int) {
		if run < end {
			s.propagateUpdate(nil, paths[run:end])
		}
	}
	for i, p := range paths {
		key := localPathKeyOf(p)
		watched := len(s.pathIndex.byKey[key]) > 0
		take := capture && !p.IsWithdraw
		if !watched && !take {
			continue
		}
		flush(i)
		run = i + 1
		s.propagateUpdate(nil, []*table.Path{p})
		after := s.localPathsAt(p, key)
		if watched {
			s.pathIndex.reconcile(key, after)
		}
		if take && holds(after, p) {
			installed[i] = p
		}
	}
	flush(len(paths))
	return installed
}

// deleteByUUIDs withdraws the paths of the UUIDs and reports whether it
// found any. A UUID deletes every local path in the slot of its path, as
// several can share one with no_implicit_withdraw. A UUID whose path is
// gone ends and deletes nothing.
func (s *BgpServer) deleteByUUIDs(ids []uuid.UUID) bool {
	found := false
	for _, id := range ids {
		e, ok := s.pathIndex.byUUID[id]
		if !ok {
			continue
		}
		held := s.localPathsAt(e.written, e.key)
		if !holds(held, e.written) {
			s.pathIndex.remove(e)
			continue
		}
		found = true
		withdrawals := make([]*table.Path, len(held))
		for i, rp := range held {
			withdrawals[i] = rp.Clone(true)
		}
		// The whole slot is withdrawn, so its entries are reconciled once,
		// after the list, not after each withdrawal.
		s.propagateUpdate(nil, withdrawals)
		s.pathIndex.reconcile(e.key, s.localPathsAt(e.written, e.key))
	}
	return found
}

// reconcileVrf ends the entries of paths written to a VRF that the table no
// longer holds. DeleteVrf does not withdraw every family: a VPN FlowSpec
// path outlives its VRF, and keeps its UUID.
func (s *BgpServer) reconcileVrf(name string) {
	for _, e := range s.pathIndex.byUUID {
		if e.vrf == name && !holds(s.localPathsAt(e.written, e.key), e.written) {
			s.pathIndex.remove(e)
		}
	}
}

// uuidsOf returns the UUIDs of the paths of a table selected from the global
// table, by written path (the root of the paths ListPath reads), for
// ListPath. With a filter the selection is small and is read; without, the
// index is.
func (s *BgpServer) uuidsOf(rib *table.Table, family bgp.Family, filtered bool) map[*table.Path]uuid.UUID {
	if s.pathIndex.len() == 0 || rib == nil {
		return nil
	}
	ids := make(map[*table.Path]uuid.UUID)
	if filtered {
		for _, d := range rib.GetDestinations() {
			for _, rp := range d.GetAllKnownPathList() {
				if e, ok := s.pathIndex.byWritten[rp.Root()]; ok {
					ids[e.written] = e.id
				}
			}
		}
		return ids
	}
	for p, e := range s.pathIndex.byWritten {
		if e.key.family == family {
			ids[p] = e.id
		}
	}
	return ids
}
