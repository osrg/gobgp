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
	"sync"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

func (m *AggregateManager) contributorCount(family bgp.Family, aggPrefix string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmap, ok := m.aggregates[family]
	if !ok {
		return 0
	}
	agg, ok := fmap[aggPrefix]
	if !ok {
		return 0
	}
	return len(agg.contributors)
}

func localPath(t *testing.T, prefix string, asList []uint32) *Path {
	t.Helper()
	p := netip.MustParsePrefix(prefix)
	nlri, err := bgp.NewIPAddrPrefix(p)
	assert.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP)}
	if len(asList) > 0 {
		attrs = append(attrs, bgp.NewPathAttributeAsPath(
			[]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asList)}))
	}
	pi := &PeerInfo{AS: 65000, LocalAS: 65000, LocalID: netip.MustParseAddr("10.0.0.1")}
	fam := bgp.RF_IPv4_UC
	if p.Addr().Is6() {
		fam = bgp.RF_IPv6_UC
	}
	return NewPath(fam, pi, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Time{}, false)
}

func newTestAggMgr() *AggregateManager {
	pi := &PeerInfo{AS: 65000, LocalAS: 65000, LocalID: netip.MustParseAddr("10.0.0.1")}
	return NewAggregateManager(slog.Default(), NewRoutingPolicy(slog.Default()), pi)
}

func TestAggregateOriginatesWhenContributorAppears(t *testing.T) {
	m := newTestAggMgr()
	agg := netip.MustParsePrefix("10.1.0.0/16")
	assert.NoError(t, m.AddAggregate(bgp.RF_IPv4_UC, agg, false, false, ""))
	out := m.evaluate(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.1.1.0/24"), localPath(t, "10.1.1.0/24", []uint32{65001}))
	assert.Len(t, out, 1)
	assert.False(t, out[0].IsWithdraw)
	assert.Equal(t, agg.String(), out[0].GetNlri().String())
}

func TestAggregateWithdrawsWhenLastContributorLeaves(t *testing.T) {
	m := newTestAggMgr()
	agg := netip.MustParsePrefix("10.1.0.0/16")
	assert.NoError(t, m.AddAggregate(bgp.RF_IPv4_UC, agg, false, false, ""))
	m.evaluate(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.1.1.0/24"), localPath(t, "10.1.1.0/24", []uint32{65001}))
	out := m.evaluate(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.1.1.0/24"), nil)
	assert.Len(t, out, 1)
	assert.True(t, out[0].IsWithdraw)
}

func TestAggregateAsSetCollectsContributorASes(t *testing.T) {
	m := newTestAggMgr()
	agg := netip.MustParsePrefix("10.1.0.0/16")
	assert.NoError(t, m.AddAggregate(bgp.RF_IPv4_UC, agg, false, true, ""))
	m.evaluate(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.1.1.0/24"), localPath(t, "10.1.1.0/24", []uint32{65001}))
	out := m.evaluate(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.1.2.0/24"), localPath(t, "10.1.2.0/24", []uint32{65002}))
	assert.Len(t, out, 1)
	assert.Equal(t, []uint32{65001, 65002}, out[0].GetAsList())
}

func TestSummaryOnlySuppressesMoreSpecifics(t *testing.T) {
	m := newTestAggMgr()
	agg := netip.MustParsePrefix("10.1.0.0/16")
	assert.NoError(t, m.AddAggregate(bgp.RF_IPv4_UC, agg, true, false, ""))
	m.evaluate(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.1.1.0/24"), localPath(t, "10.1.1.0/24", []uint32{65001}))
	assert.True(t, m.Suppressed(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.1.1.0/24")))
	assert.False(t, m.Suppressed(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.2.0.0/24")))
}

func TestIPv6AggregateOriginates(t *testing.T) {
	m := newTestAggMgr()
	agg := netip.MustParsePrefix("2001:db8::/32")
	assert.NoError(t, m.AddAggregate(bgp.RF_IPv6_UC, agg, false, false, ""))
	out := m.evaluate(bgp.RF_IPv6_UC, netip.MustParsePrefix("2001:db8:1::/48"), localPath(t, "2001:db8:1::/48", []uint32{65001}))
	assert.Len(t, out, 1)
	assert.Equal(t, agg.String(), out[0].GetNlri().String())
}

func TestAggregateConcurrentEvaluate(t *testing.T) {
	m := newTestAggMgr()
	aggPrefix := netip.MustParsePrefix("10.1.0.0/16")
	assert.NoError(t, m.AddAggregate(bgp.RF_IPv4_UC, aggPrefix, false, false, ""))

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func() {
			defer wg.Done()
			pfx := netip.MustParsePrefix(fmt.Sprintf("10.1.%d.0/24", i))
			m.evaluate(bgp.RF_IPv4_UC, pfx, localPath(t, pfx.String(), []uint32{uint32(65001 + i)}))
		}()
	}
	wg.Wait()
	assert.Equal(t, n, m.contributorCount(bgp.RF_IPv4_UC, aggPrefix.String()))
}

func TestOverlappingAsSetAggregateNotSelfContributing(t *testing.T) {
	m := newTestAggMgr()
	assert.NoError(t, m.AddAggregate(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.0.0.0/8"), false, true, ""))
	assert.NoError(t, m.AddAggregate(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.1.0.0/16"), false, true, ""))

	contributor := localPath(t, "10.1.5.0/24", []uint32{65001})
	m.evaluate(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.1.5.0/24"), contributor)

	m.mu.Lock()
	agg16 := m.aggregates[bgp.RF_IPv4_UC]["10.1.0.0/16"]
	agg8 := m.aggregates[bgp.RF_IPv4_UC]["10.0.0.0/8"]
	m.mu.Unlock()
	assert.NotNil(t, agg16.advertised, "/16 aggregate must be advertised")
	assert.NotNil(t, agg8.advertised, "/8 aggregate must be advertised")

	// Re-evaluate against /8 with the /16 aggregate path as the candidate.
	m.evaluate(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.1.0.0/16"), agg16.advertised)

	m.mu.Lock()
	_, has16 := agg8.contributors["10.1.0.0/16"]
	m.mu.Unlock()
	assert.False(t, has16, "/16 aggregate must not be a contributor to /8")
}

func TestDeleteAggregateReturnsWithdraw(t *testing.T) {
	m := newTestAggMgr()
	aggPrefix := netip.MustParsePrefix("10.1.0.0/16")
	assert.NoError(t, m.AddAggregate(bgp.RF_IPv4_UC, aggPrefix, false, false, ""))
	m.evaluate(bgp.RF_IPv4_UC, netip.MustParsePrefix("10.1.1.0/24"), localPath(t, "10.1.1.0/24", []uint32{65001}))

	withdraw, err := m.DeleteAggregate(bgp.RF_IPv4_UC, aggPrefix)
	assert.NoError(t, err)
	assert.NotNil(t, withdraw)
	assert.True(t, withdraw.IsWithdraw)

	_, err = m.DeleteAggregate(bgp.RF_IPv4_UC, aggPrefix)
	assert.Error(t, err)
}
