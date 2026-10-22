package table

import (
	"fmt"
	"iter"
	"slices"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// DestMap holds one value per destination, identifying destinations exactly
// as the RIB does: by tableKey, with the destinations that share a key told
// apart by AddrPrefixOnlyCompare, the comparison the RIB resolves its own
// collisions with. The labels and the path identifier of a path are not part
// of the identity, so every path of a destination finds the same entry.
//
// It is not safe for concurrent use. The methods of a nil DestMap behave as
// those of an empty one, except Set.
type DestMap[V any] struct {
	m map[destMapKey][]destMapEntry[V]
	n int
	// hash is tableKey; tests replace it to force collisions.
	hash func(bgp.NLRI) addrPrefixKey
}

type destMapKey struct {
	family bgp.Family
	key    addrPrefixKey
}

type destMapEntry[V any] struct {
	nlri bgp.NLRI
	v    V
}

// NewDestMap returns an empty DestMap sized for n destinations.
func NewDestMap[V any](n int) *DestMap[V] {
	return &DestMap[V]{m: make(map[destMapKey][]destMapEntry[V], n), hash: tableKey}
}

// key returns the key of the path's destination. It fails for a path whose
// destination cannot be identified: no NLRI, or a BGP-LS NLRI that cannot be
// serialized, which the RIB would key by its string form.
func (d *DestMap[V]) key(p *Path) (destMapKey, bgp.NLRI, error) {
	nlri := p.GetNlri()
	if nlri == nil {
		return destMapKey{}, nil, fmt.Errorf("path without NLRI")
	}
	if ls, ok := nlri.(*bgp.LsAddrPrefix); ok {
		if _, err := ls.Serialize(); err != nil {
			return destMapKey{}, nil, fmt.Errorf("cannot identify the destination %s: %w", nlri, err)
		}
	}
	return destMapKey{family: p.GetFamily(), key: d.hash(nlri)}, nlri, nil
}

// Get returns the value of the path's destination.
func (d *DestMap[V]) Get(p *Path) (v V, ok bool, err error) {
	if d == nil {
		return v, false, nil
	}
	k, nlri, err := d.key(p)
	if err != nil {
		return v, false, err
	}
	for _, e := range d.m[k] {
		if AddrPrefixOnlyCompare(e.nlri, nlri) == 0 {
			return e.v, true, nil
		}
	}
	return v, false, nil
}

// Set stores the value of the path's destination.
func (d *DestMap[V]) Set(p *Path, v V) error {
	k, nlri, err := d.key(p)
	if err != nil {
		return err
	}
	for i, e := range d.m[k] {
		if AddrPrefixOnlyCompare(e.nlri, nlri) == 0 {
			d.m[k][i].v = v
			return nil
		}
	}
	d.m[k] = append(d.m[k], destMapEntry[V]{nlri: nlri, v: v})
	d.n++
	return nil
}

// Delete removes the path's destination.
func (d *DestMap[V]) Delete(p *Path) error {
	if d == nil {
		return nil
	}
	k, nlri, err := d.key(p)
	if err != nil {
		return err
	}
	l := d.m[k]
	for i, e := range l {
		if AddrPrefixOnlyCompare(e.nlri, nlri) == 0 {
			// slices.Delete clears the vacated cell, which would
			// otherwise keep the NLRI and the value reachable.
			l = slices.Delete(l, i, i+1)
			if len(l) == 0 {
				delete(d.m, k)
			} else {
				d.m[k] = l
			}
			d.n--
			return nil
		}
	}
	return nil
}

// Len is the number of destinations.
func (d *DestMap[V]) Len() int {
	if d == nil {
		return 0
	}
	return d.n
}

// Values iterates over the values, in no order.
func (d *DestMap[V]) Values() iter.Seq[V] {
	return func(yield func(V) bool) {
		if d == nil {
			return
		}
		for _, l := range d.m {
			for _, e := range l {
				if !yield(e.v) {
					return
				}
			}
		}
	}
}
