// Copyright (C) 2024 Nippon Telegraph and Telephone Corporation.
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
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

type aggregateRoute struct {
	prefix       netip.Prefix
	family       bgp.Family
	summaryOnly  bool
	asSet        bool
	policyName   string
	policy       *Policy
	contributors map[string]*Path
	advertised   *Path
}

type AggregateInfo struct {
	Family       bgp.Family
	Prefix       netip.Prefix
	SummaryOnly  bool
	AsSet        bool
	PolicyName   string
	Contributors int
}

// AggregateManager tracks configured aggregate routes and originates/withdraws
// them event-driven as contributor prefixes appear and disappear.
type AggregateManager struct {
	mu            sync.Mutex
	hasAggregates atomic.Bool
	aggregates    map[bgp.Family]map[string]*aggregateRoute
	policy        *RoutingPolicy
	peerInfo      *PeerInfo
	logger        *slog.Logger
}

func NewAggregateManager(logger *slog.Logger, policy *RoutingPolicy, peerInfo *PeerInfo) *AggregateManager {
	return &AggregateManager{
		aggregates: make(map[bgp.Family]map[string]*aggregateRoute),
		policy:     policy,
		peerInfo:   peerInfo,
		logger:     logger,
	}
}

// Active reports whether any aggregates are configured; safe to call without mu.
func (m *AggregateManager) Active() bool {
	return m.hasAggregates.Load()
}

func (m *AggregateManager) AddAggregate(family bgp.Family, prefix netip.Prefix, summaryOnly, asSet bool, policyName string) error {
	var pol *Policy
	if policyName != "" {
		defs := m.policy.GetPolicy(policyName)
		if len(defs) == 0 {
			return fmt.Errorf("policy %s not found", policyName)
		}
		var err error
		pol, err = NewPolicy(*defs[0])
		if err != nil {
			return err
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.aggregates[family]; !ok {
		m.aggregates[family] = make(map[string]*aggregateRoute)
	}
	key := prefix.String()
	if _, exists := m.aggregates[family][key]; exists {
		return fmt.Errorf("aggregate %s already exists", key)
	}
	m.aggregates[family][key] = &aggregateRoute{
		prefix:       prefix,
		family:       family,
		summaryOnly:  summaryOnly,
		asSet:        asSet,
		policyName:   policyName,
		policy:       pol,
		contributors: make(map[string]*Path),
	}
	m.hasAggregates.Store(true)
	return nil
}

func (m *AggregateManager) DeleteAggregate(family bgp.Family, prefix netip.Prefix) (*Path, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmap, ok := m.aggregates[family]
	if !ok {
		return nil, fmt.Errorf("aggregate %s not found", prefix)
	}
	key := prefix.String()
	agg, ok := fmap[key]
	if !ok {
		return nil, fmt.Errorf("aggregate %s not found", prefix)
	}
	delete(fmap, key)

	total := 0
	for _, fm := range m.aggregates {
		total += len(fm)
	}
	m.hasAggregates.Store(total > 0)

	if agg.advertised != nil {
		return agg.advertised.Clone(true), nil
	}
	return nil, nil
}

func (m *AggregateManager) isAggregatePrefix(family bgp.Family, prefix netip.Prefix) bool {
	fam, ok := m.aggregates[family]
	if !ok {
		return false
	}
	_, ok = fam[prefix.String()]
	return ok
}

func (m *AggregateManager) contributes(agg *aggregateRoute, prefix netip.Prefix, path *Path) bool {
	if path == nil || path.IsWithdraw {
		return false
	}
	if prefix.Bits() <= agg.prefix.Bits() || !agg.prefix.Contains(prefix.Addr()) {
		return false
	}
	if path.IsLocal() && m.isAggregatePrefix(path.GetFamily(), prefix) {
		return false
	}
	if agg.policy != nil {
		rt, _ := agg.policy.Apply(m.logger, path, nil)
		return rt == ROUTE_TYPE_ACCEPT
	}
	return true
}

func (m *AggregateManager) evaluate(family bgp.Family, prefix netip.Prefix, best *Path) []*Path {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmap, ok := m.aggregates[family]
	if !ok {
		return nil
	}

	var results []*Path
	for _, agg := range fmap {
		if !agg.prefix.Contains(prefix.Addr()) || prefix.Bits() <= agg.prefix.Bits() {
			continue
		}
		key := prefix.String()
		if m.contributes(agg, prefix, best) {
			agg.contributors[key] = best
		} else {
			delete(agg.contributors, key)
		}
		if p := m.reconcile(agg); p != nil {
			results = append(results, p)
		}
	}
	return results
}

func (m *AggregateManager) reconcile(agg *aggregateRoute) *Path {
	if len(agg.contributors) == 0 {
		if agg.advertised == nil {
			return nil
		}
		withdraw := agg.advertised.Clone(true)
		agg.advertised = nil
		return withdraw
	}

	generated := m.generate(agg)
	if agg.advertised != nil {
		if !agg.asSet {
			return nil
		}
		if asSetEqual(agg.advertised, generated) {
			return nil
		}
	}
	agg.advertised = generated
	return generated
}

func (m *AggregateManager) generate(agg *aggregateRoute) *Path {
	nlri, err := bgp.NewIPAddrPrefix(agg.prefix)
	if err != nil {
		m.logger.Error("aggregate: failed to create NLRI", slog.Any("prefix", agg.prefix), slog.Any("err", err))
		return nil
	}

	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
	}

	if agg.asSet {
		ases := m.contributorASes(agg)
		var params []bgp.AsPathParamInterface
		if len(ases) > 0 {
			params = []bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, ases)}
		}
		attrs = append(attrs, bgp.NewPathAttributeAsPath(params))
	} else {
		attrs = append(attrs, bgp.NewPathAttributeAsPath(nil))
		attrs = append(attrs, bgp.NewPathAttributeAtomicAggregate())
	}

	if agg.family == bgp.RF_IPv6_UC {
		mpAttr, _ := bgp.NewPathAttributeMpReachNLRI(agg.family, []bgp.PathNLRI{{NLRI: nlri}}, netip.IPv6Unspecified())
		attrs = append(attrs, mpAttr)
	} else {
		nhAttr, _ := bgp.NewPathAttributeNextHop(netip.IPv4Unspecified())
		attrs = append(attrs, nhAttr)
	}

	attrs = append(attrs, bgp.NewPathAttributeLocalPref(DEFAULT_LOCAL_PREF))

	if m.peerInfo.LocalID.IsValid() && m.peerInfo.LocalID.Is4() {
		aggAttr, err := bgp.NewPathAttributeAggregator(m.peerInfo.LocalAS, m.peerInfo.LocalID)
		if err == nil {
			attrs = append(attrs, aggAttr)
		}
	}

	return NewPath(agg.family, m.peerInfo, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

func (m *AggregateManager) contributorASes(agg *aggregateRoute) []uint32 {
	seen := make(map[uint32]struct{})
	for _, p := range agg.contributors {
		for _, as := range p.GetAsList() {
			// GetAsList returns 0 for confederation segments; exclude them.
			if as != 0 {
				seen[as] = struct{}{}
			}
		}
	}
	result := make([]uint32, 0, len(seen))
	for as := range seen {
		result = append(result, as)
	}
	slices.Sort(result)
	return result
}

// Suppressed returns true if prefix is covered by a summary-only aggregate that is currently advertised.
func (m *AggregateManager) Suppressed(family bgp.Family, prefix netip.Prefix) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmap, ok := m.aggregates[family]
	if !ok {
		return false
	}
	for _, agg := range fmap {
		if agg.summaryOnly && agg.advertised != nil &&
			agg.prefix.Contains(prefix.Addr()) && prefix.Bits() > agg.prefix.Bits() {
			return true
		}
	}
	return false
}

func (m *AggregateManager) List(family *bgp.Family) []AggregateInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []AggregateInfo
	for fam, fmap := range m.aggregates {
		if family != nil && fam != *family {
			continue
		}
		for _, agg := range fmap {
			result = append(result, AggregateInfo{
				Family:       agg.family,
				Prefix:       agg.prefix,
				SummaryOnly:  agg.summaryOnly,
				AsSet:        agg.asSet,
				PolicyName:   agg.policyName,
				Contributors: len(agg.contributors),
			})
		}
	}
	return result
}

func prefixOf(p *Path) netip.Prefix {
	if nlri, ok := p.GetNlri().(*bgp.IPAddrPrefix); ok {
		return nlri.Prefix
	}
	return netip.Prefix{}
}

func asSetEqual(a, b *Path) bool {
	return slices.Equal(a.GetAsList(), b.GetAsList())
}
