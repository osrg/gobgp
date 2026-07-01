// Copyright (C) 2014-2016 Nippon Telegraph and Telephone Corporation.
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
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// Implementation-agnostic benchmarks that test GoBGP operations
// These benchmarks work on both critbitgo (old) and BART (new) implementations
// Run on both branches to compare performance

// prevent optimization
var globalResult any

// ============================================================================
// Helper Functions - Implementation Agnostic
// ============================================================================

func createPrefixSetFromCIDRs(name string, cidrs []string, family bgp.Family) (*PrefixSet, error) {
	prefixes := make([]*Prefix, len(cidrs))
	for i, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, err
		}
		masklen := prefix.Bits()
		p, err := NewPrefix(oc.Prefix{
			IpPrefix:        prefix,
			MasklengthRange: fmt.Sprintf("%d..%d", masklen, masklen+8),
		})
		if err != nil {
			return nil, err
		}
		prefixes[i] = p
	}

	return NewPrefixSetFromApiStruct(name, prefixes)
}

func generateTestCIDRs(count int, family bgp.Family) []string {
	cidrs := make([]string, count)
	if family == bgp.RF_IPv4_UC {
		for i := range count {
			octet2 := i >> 8 & 0xff
			octet3 := i & 0xff
			cidrs[i] = fmt.Sprintf("10.%d.%d.0/24", octet2, octet3)
		}
	} else {
		for i := range count {
			byte6 := i >> 8 & 0xff
			byte7 := i & 0xff
			cidrs[i] = fmt.Sprintf("2001:db8:%x:%x::/64", byte6, byte7)
		}
	}
	return cidrs
}

func createTestPath(prefix string, family bgp.Family) *Path {
	p := netip.MustParsePrefix(prefix)
	nlri, _ := bgp.NewIPAddrPrefix(p)

	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nexthop,
	}

	return NewPath(family, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

func createTestTable(family bgp.Family, count int) *Table {
	table := NewTable(logger, family)
	cidrs := generateTestCIDRs(count, family)

	for _, cidr := range cidrs {
		path := createTestPath(cidr, family)
		table.update(path)
	}

	return table
}

// ============================================================================
// Benchmark: PrefixSet Operations (Policy)
// ============================================================================

func BenchmarkPrefixSetCreation(b *testing.B) {
	scenarios := []struct {
		name   string
		count  int
		family bgp.Family
	}{
		{"IPv4/100", 100, bgp.RF_IPv4_UC},
		{"IPv4/1K", 1000, bgp.RF_IPv4_UC},
		{"IPv4/10K", 10000, bgp.RF_IPv4_UC},
		{"IPv6/100", 100, bgp.RF_IPv6_UC},
		{"IPv6/1K", 1000, bgp.RF_IPv6_UC},
		{"IPv6/10K", 10000, bgp.RF_IPv6_UC},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			cidrs := generateTestCIDRs(sc.count, sc.family)

			b.ResetTimer()
			for range b.N {
				ps, err := createPrefixSetFromCIDRs("test", cidrs, sc.family)
				if err != nil {
					b.Fatal(err)
				}
				globalResult = ps
			}
		})
	}
}

func BenchmarkPrefixSetMerge(b *testing.B) {
	scenarios := []struct {
		name         string
		count        int
		collisionPct int
		family       bgp.Family
	}{
		{"IPv4/1K/NoCollision", 1000, 0, bgp.RF_IPv4_UC},
		{"IPv4/1K/50%Collision", 1000, 50, bgp.RF_IPv4_UC},
		{"IPv4/10K/NoCollision", 10000, 0, bgp.RF_IPv4_UC},
		{"IPv4/10K/50%Collision", 10000, 50, bgp.RF_IPv4_UC},
		{"IPv6/1K/NoCollision", 1000, 0, bgp.RF_IPv6_UC},
		{"IPv6/1K/50%Collision", 1000, 50, bgp.RF_IPv6_UC},
		{"IPv6/10K/NoCollision", 10000, 0, bgp.RF_IPv6_UC},
		{"IPv6/10K/50%Collision", 10000, 50, bgp.RF_IPv6_UC},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			lhsCIDRs := generateTestCIDRs(sc.count, sc.family)

			// Generate RHS with controlled collision
			offset := sc.count * (100 - sc.collisionPct) / 100
			allRHS := generateTestCIDRs(offset+sc.count, sc.family)
			rhsCIDRs := allRHS[offset:]

			rhs, err := createPrefixSetFromCIDRs("rhs", rhsCIDRs, sc.family)
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				// Create fresh copy for each iteration
				lhsCopy, _ := createPrefixSetFromCIDRs("lhs", lhsCIDRs, sc.family)
				b.StartTimer()

				err := lhsCopy.Append(rhs)
				if err != nil {
					b.Fatal(err)
				}
				globalResult = lhsCopy
			}
		})
	}
}

func BenchmarkPrefixSetRemove(b *testing.B) {
	scenarios := []struct {
		name      string
		count     int
		removePct int
		family    bgp.Family
	}{
		{"IPv4/1K/Remove10%", 1000, 10, bgp.RF_IPv4_UC},
		{"IPv4/1K/Remove50%", 1000, 50, bgp.RF_IPv4_UC},
		{"IPv4/10K/Remove10%", 10000, 10, bgp.RF_IPv4_UC},
		{"IPv4/10K/Remove50%", 10000, 50, bgp.RF_IPv4_UC},
		{"IPv6/1K/Remove10%", 1000, 10, bgp.RF_IPv6_UC},
		{"IPv6/1K/Remove50%", 1000, 50, bgp.RF_IPv6_UC},
		{"IPv6/10K/Remove10%", 10000, 10, bgp.RF_IPv6_UC},
		{"IPv6/10K/Remove50%", 10000, 50, bgp.RF_IPv6_UC},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			lhsCIDRs := generateTestCIDRs(sc.count, sc.family)
			removeCount := sc.count * sc.removePct / 100
			rhsCIDRs := lhsCIDRs[:removeCount]

			rhs, err := createPrefixSetFromCIDRs("rhs", rhsCIDRs, sc.family)
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				lhsCopy, _ := createPrefixSetFromCIDRs("lhs", lhsCIDRs, sc.family)
				b.StartTimer()

				err := lhsCopy.Remove(rhs)
				if err != nil {
					b.Fatal(err)
				}
				globalResult = lhsCopy
			}
		})
	}
}

func BenchmarkPrefixSetList(b *testing.B) {
	scenarios := []struct {
		name   string
		count  int
		family bgp.Family
	}{
		{"IPv4/1K", 1000, bgp.RF_IPv4_UC},
		{"IPv4/10K", 10000, bgp.RF_IPv4_UC},
		{"IPv4/100K", 100000, bgp.RF_IPv4_UC},
		{"IPv6/1K", 1000, bgp.RF_IPv6_UC},
		{"IPv6/10K", 10000, bgp.RF_IPv6_UC},
		{"IPv6/100K", 100000, bgp.RF_IPv6_UC},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			cidrs := generateTestCIDRs(sc.count, sc.family)
			ps, err := createPrefixSetFromCIDRs("test", cidrs, sc.family)
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			for range b.N {
				list := ps.List()
				globalResult = list
			}
		})
	}
}

// ============================================================================
// Benchmark: Policy Evaluation (Critical Path)
// ============================================================================

func BenchmarkPolicyPrefixMatch(b *testing.B) {
	scenarios := []struct {
		name   string
		count  int
		family bgp.Family
	}{
		{"IPv4/100", 100, bgp.RF_IPv4_UC},
		{"IPv4/1K", 1000, bgp.RF_IPv4_UC},
		{"IPv4/10K", 10000, bgp.RF_IPv4_UC},
		{"IPv6/100", 100, bgp.RF_IPv6_UC},
		{"IPv6/1K", 1000, bgp.RF_IPv6_UC},
		{"IPv6/10K", 10000, bgp.RF_IPv6_UC},
	}

	for _, sc := range scenarios {
		b.Run(sc.name+"/Match", func(b *testing.B) {
			cidrs := generateTestCIDRs(sc.count, sc.family)
			ps, err := createPrefixSetFromCIDRs("test", cidrs, sc.family)
			if err != nil {
				b.Fatal(err)
			}

			// Create a matching path
			testCIDR := cidrs[sc.count/2]
			path := createTestPath(testCIDR, sc.family)

			cond := &PrefixCondition{
				set:    ps,
				option: MATCH_OPTION_ANY,
			}

			b.ResetTimer()
			for range b.N {
				result := cond.Evaluate(path, nil)
				globalResult = result
			}
		})

		b.Run(sc.name+"/NoMatch", func(b *testing.B) {
			cidrs := generateTestCIDRs(sc.count, sc.family)
			ps, err := createPrefixSetFromCIDRs("test", cidrs, sc.family)
			if err != nil {
				b.Fatal(err)
			}

			// Create a non-matching path
			var testCIDR string
			if sc.family == bgp.RF_IPv4_UC {
				testCIDR = "192.168.1.0/24"
			} else {
				testCIDR = "fc00::1/64"
			}
			path := createTestPath(testCIDR, sc.family)

			cond := &PrefixCondition{
				set:    ps,
				option: MATCH_OPTION_ANY,
			}

			b.ResetTimer()
			for range b.N {
				result := cond.Evaluate(path, nil)
				globalResult = result
			}
		})
	}
}

// ============================================================================
// Benchmark: Table Operations
// ============================================================================

func BenchmarkTableInsert(b *testing.B) {
	scenarios := []struct {
		name   string
		count  int
		family bgp.Family
	}{
		{"IPv4/1K", 1000, bgp.RF_IPv4_UC},
		{"IPv4/10K", 10000, bgp.RF_IPv4_UC},
		{"IPv4/100K", 100000, bgp.RF_IPv4_UC},
		{"IPv6/1K", 1000, bgp.RF_IPv6_UC},
		{"IPv6/10K", 10000, bgp.RF_IPv6_UC},
		{"IPv6/100K", 100000, bgp.RF_IPv6_UC},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			cidrs := generateTestCIDRs(sc.count, sc.family)
			paths := make([]*Path, len(cidrs))
			for i, cidr := range cidrs {
				paths[i] = createTestPath(cidr, sc.family)
			}

			b.ResetTimer()
			for range b.N {
				table := NewTable(logger, sc.family)
				for _, path := range paths {
					table.update(path)
				}
				globalResult = table
			}
		})
	}
}

func BenchmarkTableGetDestinations(b *testing.B) {
	scenarios := []struct {
		name   string
		count  int
		family bgp.Family
	}{
		{"IPv4/1K", 1000, bgp.RF_IPv4_UC},
		{"IPv4/10K", 10000, bgp.RF_IPv4_UC},
		{"IPv4/100K", 100000, bgp.RF_IPv4_UC},
		{"IPv6/1K", 1000, bgp.RF_IPv6_UC},
		{"IPv6/10K", 10000, bgp.RF_IPv6_UC},
		{"IPv6/100K", 100000, bgp.RF_IPv6_UC},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			table := createTestTable(sc.family, sc.count)

			b.ResetTimer()
			for range b.N {
				dests := table.GetDestinations()
				globalResult = dests
			}
		})
	}
}

func BenchmarkTableGetLongerPrefixDestinations(b *testing.B) {
	scenarios := []struct {
		name      string
		count     int
		lookupKey string
		family    bgp.Family
	}{
		{"IPv4/1K/Lookup16", 1000, "10.1.0.0/16", bgp.RF_IPv4_UC},
		{"IPv4/10K/Lookup16", 10000, "10.1.0.0/16", bgp.RF_IPv4_UC},
		{"IPv4/10K/Lookup20", 10000, "10.1.1.0/20", bgp.RF_IPv4_UC},
		{"IPv4/100K/Lookup8", 100000, "10.0.0.0/8", bgp.RF_IPv4_UC},
		{"IPv6/1K/Lookup32", 1000, "2001:db8::/32", bgp.RF_IPv6_UC},
		{"IPv6/10K/Lookup32", 10000, "2001:db8::/32", bgp.RF_IPv6_UC},
		{"IPv6/10K/Lookup40", 10000, "2001:db8:1::/40", bgp.RF_IPv6_UC},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			table := createTestTable(sc.family, sc.count)

			b.ResetTimer()
			for range b.N {
				dests, err := table.GetLongerPrefixDestinations(sc.lookupKey)
				if err != nil {
					b.Fatal(err)
				}
				globalResult = dests
			}
		})
	}
}

// ============================================================================
// Benchmark: End-to-End Policy Application
// ============================================================================

func BenchmarkPolicyApplicationComplete(b *testing.B) {
	// This benchmark simulates a complete policy evaluation cycle:
	// 1. Create prefix sets (policy configuration)
	// 2. Create paths (BGP updates)
	// 3. Evaluate policy against paths (the hot path)

	scenarios := []struct {
		name        string
		prefixCount int
		pathCount   int
		family      bgp.Family
	}{
		{"IPv4/100Prefixes/100Paths", 100, 100, bgp.RF_IPv4_UC},
		{"IPv4/1KPrefixes/100Paths", 1000, 100, bgp.RF_IPv4_UC},
		{"IPv4/10KPrefixes/100Paths", 10000, 100, bgp.RF_IPv4_UC},
		{"IPv6/100Prefixes/100Paths", 100, 100, bgp.RF_IPv6_UC},
		{"IPv6/1KPrefixes/100Paths", 1000, 100, bgp.RF_IPv6_UC},
		{"IPv6/10KPrefixes/100Paths", 10000, 100, bgp.RF_IPv6_UC},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			// Setup: Create prefix set (policy config)
			policyCIDRs := generateTestCIDRs(sc.prefixCount, sc.family)
			ps, err := createPrefixSetFromCIDRs("policy", policyCIDRs, sc.family)
			if err != nil {
				b.Fatal(err)
			}

			cond := &PrefixCondition{
				set:    ps,
				option: MATCH_OPTION_ANY,
			}

			// Setup: Create test paths (50% match, 50% don't match)
			paths := make([]*Path, sc.pathCount)
			for i := range sc.pathCount {
				var cidr string
				if i%2 == 0 {
					// Matching path
					cidr = policyCIDRs[i%sc.prefixCount]
				} else {
					// Non-matching path
					if sc.family == bgp.RF_IPv4_UC {
						cidr = fmt.Sprintf("192.168.%d.0/24", i)
					} else {
						cidr = fmt.Sprintf("fc00::%x/64", i)
					}
				}
				paths[i] = createTestPath(cidr, sc.family)
			}

			b.ResetTimer()
			for range b.N {
				matchCount := 0
				for _, path := range paths {
					if cond.Evaluate(path, nil) {
						matchCount++
					}
				}
				globalResult = matchCount
			}
		})
	}
}
