// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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
	"sort"

	radix "github.com/armon/go-radix"
	"github.com/osrg/gobgp/internal/pkg/config"
	"github.com/osrg/gobgp/pkg/packet/bgp"
	log "github.com/sirupsen/logrus"
)

type IPPrefix struct {
	Prefix net.IP
	Length uint8
}

func (p *IPPrefix) String() string {
	return fmt.Sprintf("%s/%d", p.Prefix, p.Length)
}

type ROA struct {
	Family int
	Prefix *IPPrefix
	MaxLen uint8
	AS     uint32
	Src    string
}

func NewROA(family int, prefixByte []byte, prefixLen uint8, maxLen uint8, as uint32, src string) *ROA {
	p := make([]byte, len(prefixByte))
	copy(p, prefixByte)
	return &ROA{
		Family: family,
		Prefix: &IPPrefix{
			Prefix: p,
			Length: prefixLen,
		},
		MaxLen: maxLen,
		AS:     as,
		Src:    src,
	}
}

func (r *ROA) Equal(roa *ROA) bool {
	if r.MaxLen == roa.MaxLen && r.Src == roa.Src && r.AS == roa.AS {
		return true
	}
	return false
}

type roaBucket struct {
	Prefix  *IPPrefix
	entries []*ROA
}

func (r *roaBucket) GetEntries() []*ROA {
	return r.entries
}

type ROATable struct {
	Roas map[bgp.RouteFamily]*radix.Tree
}

func NewROATable() *ROATable {
	m := make(map[bgp.RouteFamily]*radix.Tree)
	m[bgp.RF_IPv4_UC] = radix.New()
	m[bgp.RF_IPv6_UC] = radix.New()
	return &ROATable{
		Roas: m,
	}
}

func (rt *ROATable) roa2tree(roa *ROA) (*radix.Tree, string) {
	tree := rt.Roas[bgp.RF_IPv4_UC]
	if roa.Family == bgp.AFI_IP6 {
		tree = rt.Roas[bgp.RF_IPv6_UC]
	}
	return tree, IpToRadixkey(roa.Prefix.Prefix, roa.Prefix.Length)
}

func (rt *ROATable) Add(roa *ROA) {
	tree, key := rt.roa2tree(roa)
	b, _ := tree.Get(key)
	var bucket *roaBucket
	if b == nil {
		bucket = &roaBucket{
			Prefix:  roa.Prefix,
			entries: make([]*ROA, 0),
		}
		tree.Insert(key, bucket)
	} else {
		bucket = b.(*roaBucket)
		for _, r := range bucket.entries {
			if r.Equal(roa) {
				// we already have the same one
				return
			}
		}
	}
	bucket.entries = append(bucket.entries, roa)
}

func (rt *ROATable) Delete(roa *ROA) {
	tree, key := rt.roa2tree(roa)
	b, _ := tree.Get(key)
	if b != nil {
		bucket := b.(*roaBucket)
		newEntries := make([]*ROA, 0, len(bucket.entries))
		for _, r := range bucket.entries {
			if !r.Equal(roa) {
				newEntries = append(newEntries, r)
			}
		}
		if len(newEntries) != len(bucket.entries) {
			bucket.entries = newEntries
			if len(newEntries) == 0 {
				tree.Delete(key)
			}
			return
		}
	}
	log.WithFields(log.Fields{
		"Topic":         "rpki",
		"Prefix":        roa.Prefix.Prefix.String(),
		"Prefix Length": roa.Prefix.Length,
		"AS":            roa.AS,
		"Max Length":    roa.MaxLen,
	}).Info("Can't withdraw a ROA")
}

func (rt *ROATable) DeleteAll(network string) {
	for _, tree := range rt.Roas {
		deleteKeys := make([]string, 0, tree.Len())
		tree.Walk(func(s string, v interface{}) bool {
			b, _ := v.(*roaBucket)
			newEntries := make([]*ROA, 0, len(b.entries))
			for _, r := range b.entries {
				if r.Src != network {
					newEntries = append(newEntries, r)
				}
			}
			if len(newEntries) > 0 {
				b.entries = newEntries
			} else {
				deleteKeys = append(deleteKeys, s)
			}
			return false
		})
		for _, key := range deleteKeys {
			tree.Delete(key)
		}
	}
}

func validatePath(ownAs uint32, tree *radix.Tree, cidr string, asPath *bgp.PathAttributeAsPath) *Validation {
	var as uint32

	validation := &Validation{
		Status:          config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND,
		Reason:          RPKI_VALIDATION_REASON_TYPE_NONE,
		Matched:         make([]*ROA, 0),
		UnmatchedLength: make([]*ROA, 0),
		UnmatchedAs:     make([]*ROA, 0),
	}

	if asPath == nil || len(asPath.Value) == 0 {
		as = ownAs
	} else {
		param := asPath.Value[len(asPath.Value)-1]
		switch param.GetType() {
		case bgp.BGP_ASPATH_ATTR_TYPE_SEQ:
			asList := param.GetAS()
			if len(asList) == 0 {
				as = ownAs
			} else {
				as = asList[len(asList)-1]
			}
		case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
			as = ownAs
		default:
			return validation
		}
	}
	_, n, _ := net.ParseCIDR(cidr)
	ones, _ := n.Mask.Size()
	prefixLen := uint8(ones)
	key := IpToRadixkey(n.IP, prefixLen)
	_, b, _ := tree.LongestPrefix(key)
	if b == nil {
		return validation
	}

	var bucket *roaBucket
	fn := radix.WalkFn(func(k string, v interface{}) bool {
		bucket, _ = v.(*roaBucket)
		for _, r := range bucket.entries {
			if prefixLen <= r.MaxLen {
				if r.AS != 0 && r.AS == as {
					validation.Matched = append(validation.Matched, r)
				} else {
					validation.UnmatchedAs = append(validation.UnmatchedAs, r)
				}
			} else {
				validation.UnmatchedLength = append(validation.UnmatchedLength, r)
			}
		}
		return false
	})
	tree.WalkPath(key, fn)

	if len(validation.Matched) != 0 {
		validation.Status = config.RPKI_VALIDATION_RESULT_TYPE_VALID
		validation.Reason = RPKI_VALIDATION_REASON_TYPE_NONE
	} else if len(validation.UnmatchedAs) != 0 {
		validation.Status = config.RPKI_VALIDATION_RESULT_TYPE_INVALID
		validation.Reason = RPKI_VALIDATION_REASON_TYPE_AS
	} else if len(validation.UnmatchedLength) != 0 {
		validation.Status = config.RPKI_VALIDATION_RESULT_TYPE_INVALID
		validation.Reason = RPKI_VALIDATION_REASON_TYPE_LENGTH
	} else {
		validation.Status = config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND
		validation.Reason = RPKI_VALIDATION_REASON_TYPE_NONE
	}

	return validation
}

func (rt *ROATable) Validate(path *Path) *Validation {
	if path.IsWithdraw || path.IsEOR() {
		// RPKI isn't enabled or invalid path
		return nil
	}
	if tree, ok := rt.Roas[path.GetRouteFamily()]; ok {
		return validatePath(path.OriginInfo().source.LocalAS, tree, path.GetNlri().String(), path.GetAsPath())
	}
	return nil
}

func (rt *ROATable) Info(family bgp.RouteFamily) (map[string]uint32, map[string]uint32) {
	records := make(map[string]uint32)
	prefixes := make(map[string]uint32)

	tree := rt.Roas[family]
	tree.Walk(func(s string, v interface{}) bool {
		b, _ := v.(*roaBucket)
		tmpRecords := make(map[string]uint32)
		for _, roa := range b.entries {
			tmpRecords[roa.Src]++
		}

		for src, r := range tmpRecords {
			if r > 0 {
				records[src] += r
				prefixes[src]++
			}
		}
		return false
	})
	return records, prefixes
}

func (rt *ROATable) List(family bgp.RouteFamily) ([]*ROA, error) {
	var rfList []bgp.RouteFamily
	switch family {
	case bgp.RF_IPv4_UC:
		rfList = []bgp.RouteFamily{bgp.RF_IPv4_UC}
	case bgp.RF_IPv6_UC:
		rfList = []bgp.RouteFamily{bgp.RF_IPv6_UC}
	default:
		rfList = []bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC}
	}
	l := make([]*ROA, 0)
	for _, rf := range rfList {
		if tree, ok := rt.Roas[rf]; ok {
			tree.Walk(func(s string, v interface{}) bool {
				b, _ := v.(*roaBucket)
				var roaList roas
				for _, r := range b.entries {
					roaList = append(roaList, r)
				}
				sort.Sort(roaList)
				for _, roa := range roaList {
					l = append(l, roa)
				}
				return false
			})
		}
	}
	return l, nil
}

type roas []*ROA

func (r roas) Len() int {
	return len(r)
}

func (r roas) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r roas) Less(i, j int) bool {
	r1 := r[i]
	r2 := r[j]

	if r1.MaxLen < r2.MaxLen {
		return true
	} else if r1.MaxLen > r2.MaxLen {
		return false
	}

	if r1.AS < r2.AS {
		return true
	}
	return false
}
