// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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
	"log/slog"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/zebra"
)

func Test_newPathFromIPRouteMessage(t *testing.T) {
	assert := assert.New(t)
	for v := zebra.MinZapiVer; v <= zebra.MaxZapiVer; v++ {
		// IPv4 Route Add
		m := &zebra.Message{}
		software := zebra.NewSoftware(v, "")
		flag := zebra.FlagSelected.ToEach(v, software)
		message := zebra.MessageNexthop | zebra.MessageDistance.ToEach(v, software) | zebra.MessageMetric.ToEach(v, software) | zebra.MessageMTU.ToEach(v, software)
		h := &zebra.Header{
			Len:     zebra.HeaderSize(v),
			Marker:  zebra.HeaderMarker(v),
			Version: v,
			Command: zebra.RouteAdd.ToEach(v, software),
		}
		b := &zebra.IPRouteBody{
			Type:    zebra.RouteStatic,
			Flags:   flag,
			Message: message,
			Safi:    zebra.SafiUnicast, // 1, FRR_ZAPI5_SAFI_UNICAST is same
			Prefix: zebra.Prefix{
				Prefix:    netip.MustParseAddr("192.168.100.0"),
				PrefixLen: uint8(24),
			},
			Nexthops: []zebra.Nexthop{
				{
					Gate: netip.IPv4Unspecified(),
				},
				{
					Ifindex: uint32(1),
				},
			},
			Distance: uint8(0),
			Metric:   uint32(100),
			Mtu:      uint32(0),
			API:      zebra.RouteAdd.ToEach(v, software),
		}
		m.Header = *h
		m.Body = b
		logger := slog.Default()
		zebra.BackwardIPv6RouteDelete.ToEach(v, software)
		path := newPathFromIPRouteMessage(logger, m, v, software)
		pp := table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: path.GetNlri()}, path.IsWithdraw, path.GetPathAttrs(), time.Now(), false)
		pp.SetIsFromExternal(path.IsFromExternal())
		assert.Equal("0.0.0.0", pp.GetNexthop().String())
		assert.Equal("192.168.100.0/24", pp.GetNlri().String())
		assert.True(pp.IsFromExternal())
		assert.False(pp.IsWithdraw)

		// IPv4 Route Delete
		h.Command = zebra.RouteDelete.ToEach(v, software)
		b.API = zebra.RouteDelete.ToEach(v, software)
		m.Header = *h
		m.Body = b

		path = newPathFromIPRouteMessage(logger, m, v, software)
		pp = table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: path.GetNlri()}, path.IsWithdraw, path.GetPathAttrs(), time.Now(), false)
		pp.SetIsFromExternal(path.IsFromExternal())
		assert.Equal("0.0.0.0", pp.GetNexthop().String())
		assert.Equal("192.168.100.0/24", pp.GetNlri().String())
		med, _ := pp.GetMed()
		assert.Equal(uint32(100), med)
		assert.True(pp.IsFromExternal())
		assert.True(pp.IsWithdraw)

		// IPv6 Route Add
		h.Command = zebra.RouteAdd.ToEach(v, software)
		if v < 5 {
			h.Command = zebra.BackwardIPv6RouteAdd.ToEach(v, software)
		}
		b.API = zebra.RouteAdd.ToEach(v, software)
		if v < 5 {
			b.API = zebra.BackwardIPv6RouteAdd.ToEach(v, software)
		}
		b.Prefix.Prefix = netip.MustParseAddr("2001:db8:0:f101::")
		b.Prefix.PrefixLen = uint8(64)
		b.Nexthops = []zebra.Nexthop{{Gate: netip.IPv6Unspecified()}}
		m.Header = *h
		m.Body = b

		path = newPathFromIPRouteMessage(logger, m, v, software)
		pp = table.NewPath(bgp.RF_IPv6_UC, nil, bgp.PathNLRI{NLRI: path.GetNlri()}, path.IsWithdraw, path.GetPathAttrs(), time.Now(), false)
		pp.SetIsFromExternal(path.IsFromExternal())
		assert.Equal("::", pp.GetNexthop().String())
		assert.Equal("2001:db8:0:f101::/64", pp.GetNlri().String())
		med, _ = pp.GetMed()
		assert.Equal(uint32(100), med)
		assert.True(pp.IsFromExternal())
		assert.False(pp.IsWithdraw)

		// IPv6 Route Delete
		h.Command = zebra.RouteDelete.ToEach(v, software)
		if v < 5 {
			h.Command = zebra.BackwardIPv6RouteDelete.ToEach(v, software)
		}
		b.API = zebra.RouteDelete.ToEach(v, software)
		if v < 5 {
			b.API = zebra.BackwardIPv6RouteDelete.ToEach(v, software)
		}
		m.Header = *h
		m.Body = b

		path = newPathFromIPRouteMessage(logger, m, v, software)
		pp = table.NewPath(bgp.RF_IPv6_UC, nil, bgp.PathNLRI{NLRI: path.GetNlri()}, path.IsWithdraw, path.GetPathAttrs(), time.Now(), false)
		pp.SetIsFromExternal(path.IsFromExternal())
		assert.Equal("::", pp.GetNexthop().String())
		assert.Equal("2001:db8:0:f101::/64", pp.GetNlri().String())
		assert.True(pp.IsFromExternal())
		assert.True(pp.IsWithdraw)
	}
}

var testNextHop = netip.MustParseAddr("10.3.1.1")

func TestApplyToPathList_UnreachableNoMED(t *testing.T) {
	// Simulates the zebra-nht scenario: a path with no MED and an
	// unreachable nexthop should get IsNexthopInvalid=true.
	assert := assert.New(t)

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.3.2.0/24"))
	nh, _ := bgp.NewPathAttributeNextHop(testNextHop)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
		nh,
	}
	path := table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)

	cache := nexthopStateCache{
		testNextHop: math.MaxUint32, // unreachable
	}

	updated := cache.applyToPathList([]*table.Path{path})
	assert.Len(updated, 1)
	assert.True(updated[0].IsNexthopInvalid)
	assert.False(updated[0].IsWithdraw)

	// Applying again should produce no updates (idempotent)
	updated2 := cache.applyToPathList(updated)
	assert.Len(updated2, 0, "applying to already-invalid path should be a no-op")
}

func TestApplyToPathList_ReachableSetsMED(t *testing.T) {
	assert := assert.New(t)

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.3.1.0/24"))
	nh, _ := bgp.NewPathAttributeNextHop(testNextHop)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
		nh,
	}
	path := table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)

	cache := nexthopStateCache{
		testNextHop: 20, // reachable, metric=20
	}

	updated := cache.applyToPathList([]*table.Path{path})
	assert.Len(updated, 1)
	assert.False(updated[0].IsNexthopInvalid)
	med, err := updated[0].GetMed()
	assert.NoError(err)
	assert.Equal(uint32(20), med)

	// Applying again should be a no-op
	updated2 := cache.applyToPathList(updated)
	assert.Len(updated2, 0, "applying same metric should be a no-op")
}

func TestApplyToPathList_TransitionReachableToUnreachable(t *testing.T) {
	assert := assert.New(t)

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.3.1.0/24"))
	nh, _ := bgp.NewPathAttributeNextHop(testNextHop)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
		bgp.NewPathAttributeMultiExitDisc(20),
		nh,
	}
	path := table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)

	cache := nexthopStateCache{
		testNextHop: math.MaxUint32, // now unreachable
	}

	updated := cache.applyToPathList([]*table.Path{path})
	assert.Len(updated, 1)
	assert.True(updated[0].IsNexthopInvalid)
}

// TestUpdateByNexthopUpdate_Reachable verifies that a NEXTHOP_UPDATE with
// nexthops records the metric in the cache.
func TestUpdateByNexthopUpdate_Reachable(t *testing.T) {
	assert := assert.New(t)

	cache := nexthopStateCache{}
	body := &zebra.NexthopUpdateBody{
		Prefix: zebra.Prefix{
			Prefix:    testNextHop,
			PrefixLen: 32,
		},
		Metric:   20,
		Nexthops: []zebra.Nexthop{{Gate: netip.MustParseAddr("192.168.23.3")}},
	}

	updated := cache.updateByNexthopUpdate(body)
	assert.True(updated)
	assert.Equal(uint32(20), cache[testNextHop])
}

// TestUpdateByNexthopUpdate_UnreachableAfterReachable verifies that an empty
// NEXTHOP_UPDATE transitions an existing entry to unreachable (MaxUint32).
func TestUpdateByNexthopUpdate_UnreachableAfterReachable(t *testing.T) {
	assert := assert.New(t)

	cache := nexthopStateCache{
		testNextHop: 20,
	}
	body := &zebra.NexthopUpdateBody{
		Prefix: zebra.Prefix{
			Prefix:    testNextHop,
			PrefixLen: 32,
		},
		// No Nexthops => unreachable
	}

	updated := cache.updateByNexthopUpdate(body)
	assert.True(updated)
	assert.Equal(uint32(math.MaxUint32), cache[testNextHop])
}

// TestUpdateByNexthopUpdate_InitialEmptyIgnored verifies that the initial empty
// NEXTHOP_UPDATE (sent by zebra as the first response to NEXTHOP_REGISTER) is
// ignored when there is no existing entry in the cache.
func TestUpdateByNexthopUpdate_InitialEmptyIgnored(t *testing.T) {
	assert := assert.New(t)

	cache := nexthopStateCache{}
	body := &zebra.NexthopUpdateBody{
		Prefix: zebra.Prefix{
			Prefix:    testNextHop,
			PrefixLen: 32,
		},
	}

	updated := cache.updateByNexthopUpdate(body)
	assert.False(updated, "initial empty NEXTHOP_UPDATE must be ignored")
	_, ok := cache[testNextHop]
	assert.False(ok, "cache must remain empty")
}

// TestUpdateByNexthopUpdate_MetricChange verifies that a NEXTHOP_UPDATE with
// a different metric updates the cache.
func TestUpdateByNexthopUpdate_MetricChange(t *testing.T) {
	assert := assert.New(t)

	cache := nexthopStateCache{
		testNextHop: 20,
	}
	body := &zebra.NexthopUpdateBody{
		Prefix: zebra.Prefix{
			Prefix:    testNextHop,
			PrefixLen: 32,
		},
		Metric:   30,
		Nexthops: []zebra.Nexthop{{Gate: netip.MustParseAddr("192.168.24.4")}},
	}

	updated := cache.updateByNexthopUpdate(body)
	assert.True(updated)
	assert.Equal(uint32(30), cache[testNextHop])
}

// TestApplyToPathList_UnreachableToReachable verifies that an invalid path
// becomes valid and gets a MED when the nexthop becomes reachable.
func TestApplyToPathList_UnreachableToReachable(t *testing.T) {
	assert := assert.New(t)

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.3.1.0/24"))
	nh, _ := bgp.NewPathAttributeNextHop(testNextHop)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
		nh,
	}
	path := table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
	path.IsNexthopInvalid = true

	cache := nexthopStateCache{
		testNextHop: 30,
	}

	updated := cache.applyToPathList([]*table.Path{path})
	assert.Len(updated, 1)
	assert.False(updated[0].IsNexthopInvalid)
	med, err := updated[0].GetMed()
	assert.NoError(err)
	assert.Equal(uint32(30), med)
}

// TestApplyToPathList_MetricChange verifies that a path MED is updated when
// the cached metric for its nexthop changes.
func TestApplyToPathList_MetricChange(t *testing.T) {
	assert := assert.New(t)

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.3.1.0/24"))
	nh, _ := bgp.NewPathAttributeNextHop(testNextHop)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
		bgp.NewPathAttributeMultiExitDisc(20),
		nh,
	}
	path := table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)

	cache := nexthopStateCache{
		testNextHop: 30, // different from current MED (20)
	}

	updated := cache.applyToPathList([]*table.Path{path})
	assert.Len(updated, 1)
	assert.False(updated[0].IsNexthopInvalid)
	med, err := updated[0].GetMed()
	assert.NoError(err)
	assert.Equal(uint32(30), med)
}

// TestApplyToPathList_UnknownNexthop verifies that paths whose nexthop is not
// in the cache are skipped.
func TestApplyToPathList_UnknownNexthop(t *testing.T) {
	assert := assert.New(t)

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.3.1.0/24"))
	nh, _ := bgp.NewPathAttributeNextHop(testNextHop)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
		nh,
	}
	path := table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)

	cache := nexthopStateCache{} // empty

	updated := cache.applyToPathList([]*table.Path{path})
	assert.Empty(updated, "paths with unknown nexthop must not be updated")
}

// TestApplyToPathList_WithdrawIgnored verifies that withdraw paths are skipped.
func TestApplyToPathList_WithdrawIgnored(t *testing.T) {
	assert := assert.New(t)

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.3.1.0/24"))
	nh, _ := bgp.NewPathAttributeNextHop(testNextHop)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
		nh,
	}
	path := table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, true, attrs, time.Now(), false)

	cache := nexthopStateCache{
		testNextHop: 20,
	}

	updated := cache.applyToPathList([]*table.Path{path})
	assert.Empty(updated, "withdraw paths must be skipped")
}
