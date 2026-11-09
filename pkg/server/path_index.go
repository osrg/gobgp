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

// pathIndexEntry is the UUID AddPath gave one local path.
type pathIndexEntry struct {
	id   uuid.UUID
	key  localPathKey
	path *table.Path
	vrf  string
	// coexisting is set for a path added with no_implicit_withdraw: a
	// later path at the same key does not replace it.
	coexisting bool
}

// pathIndex maps the UUIDs AddPath gives to the slots of the global table,
// so that DeletePath by UUID reads one destination instead of walking the
// table. It is touched only from management operations, which run one at a
// time with shared.mu held, so it has no lock of its own.
//
// An entry ends when another write takes its slot, when a withdrawal or a
// delete leaves no local path in the slot, when its family or its VRF is
// deleted, and when a delete by its UUID finds the slot empty. Some
// withdrawals happen inside the table, such as an import policy that
// rejects a path or an EVPN MAC mobility update; an entry left by one of
// them stays until one of the events above, and a delete by its UUID finds
// nothing, as before.
type pathIndex struct {
	byUUID map[uuid.UUID]*pathIndexEntry
	byKey  map[localPathKey][]*pathIndexEntry
}

func newPathIndex() *pathIndex {
	return &pathIndex{
		byUUID: make(map[uuid.UUID]*pathIndexEntry),
		byKey:  make(map[localPathKey][]*pathIndexEntry),
	}
}

func (x *pathIndex) len() int { return len(x.byUUID) }

func (x *pathIndex) remove(e *pathIndexEntry) {
	delete(x.byUUID, e.id)
	l := slices.DeleteFunc(x.byKey[e.key], func(o *pathIndexEntry) bool { return o == e })
	if len(l) == 0 {
		delete(x.byKey, e.key)
	} else {
		x.byKey[e.key] = l
	}
}

// replaced ends the entry of the path a new path at key replaces. A new
// path replaces the path of the same source and path identifier, unless
// that one was added with no_implicit_withdraw.
func (x *pathIndex) replaced(key localPathKey) {
	for _, e := range slices.Clone(x.byKey[key]) {
		if !e.coexisting {
			x.remove(e)
		}
	}
}

// add records the UUID of a path AddPath put in the table.
func (x *pathIndex) add(id uuid.UUID, p *table.Path, vrf string) {
	e := &pathIndexEntry{id: id, key: localPathKeyOf(p), path: p, vrf: vrf, coexisting: p.NoImplicitWithdraw()}
	x.byUUID[id] = e
	x.byKey[e.key] = append(x.byKey[e.key], e)
}

// endKey ends every entry of a slot.
func (x *pathIndex) endKey(key localPathKey) {
	for _, e := range slices.Clone(x.byKey[key]) {
		x.remove(e)
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

// endVrf ends the entries of paths written to a VRF.
func (x *pathIndex) endVrf(name string) {
	for _, e := range x.byUUID {
		if e.vrf == name {
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

// noteWrites keeps the index right after paths were written to the global
// table: a path takes the slot of the path it replaces, and a withdrawal
// that leaves the slot empty ends its entries.
func (s *BgpServer) noteWrites(paths []*table.Path) {
	if s.pathIndex.len() == 0 {
		return
	}
	for _, p := range paths {
		key := localPathKeyOf(p)
		if len(s.pathIndex.byKey[key]) == 0 {
			continue
		}
		if !p.IsWithdraw {
			s.pathIndex.replaced(key)
		} else if len(s.localPathsAt(p, key)) == 0 {
			s.pathIndex.endKey(key)
		}
	}
}

// deleteByUUIDs returns the withdrawals of the paths of the UUIDs. A UUID
// deletes every local path in its slot, as several can share one with
// no_implicit_withdraw. A UUID whose slot is empty ends.
func (s *BgpServer) deleteByUUIDs(ids []uuid.UUID) []*table.Path {
	var withdrawals []*table.Path
	for _, id := range ids {
		e, ok := s.pathIndex.byUUID[id]
		if !ok {
			continue
		}
		key := e.key
		for _, rp := range s.localPathsAt(e.path, key) {
			withdrawals = append(withdrawals, rp.Clone(true))
		}
		s.pathIndex.endKey(key)
	}
	return withdrawals
}

// uuidsOf returns, by slot, the UUIDs of the local paths of a family for
// ListPath. With a filter the selected table is small and is read;
// without, the index is. A slot shared by several UUIDs, with
// no_implicit_withdraw, reports none.
func (s *BgpServer) uuidsOf(rib *table.Table, family bgp.Family, filtered bool) map[localPathKey]uuid.UUID {
	if s.pathIndex.len() == 0 || rib == nil {
		return nil
	}
	ids := make(map[localPathKey]uuid.UUID)
	if filtered {
		for _, d := range rib.GetDestinations() {
			for _, rp := range d.GetAllKnownPathList() {
				if !rp.IsLocal() {
					continue
				}
				key := localPathKeyOf(rp)
				if l := s.pathIndex.byKey[key]; len(l) == 1 {
					ids[key] = l[0].id
				}
			}
		}
		return ids
	}
	for key, l := range s.pathIndex.byKey {
		if key.family == family && len(l) == 1 {
			ids[key] = l[0].id
		}
	}
	return ids
}
