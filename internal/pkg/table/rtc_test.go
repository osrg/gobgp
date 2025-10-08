package table

import (
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

func TestAdjRTCLowLevel(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	rt1, _ := bgp.ParseRouteTarget("65520:1000000")
	nlri1 := bgp.NewRouteTargetMembershipNLRI(65000, rt1)
	p1 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri1}, false, attrs, time.Now(), false)
	p1.remoteID = 1
	hash1, err := ExtCommRouteTargetKey(rt1)
	assert.NoError(t, err)

	rt2, _ := bgp.ParseRouteTarget("65520:1000001")
	nlri2 := bgp.NewRouteTargetMembershipNLRI(65000, rt2)
	p2 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri2}, false, attrs, time.Now(), false)
	p2.remoteID = 1
	hash2, err := ExtCommRouteTargetKey(rt2)
	assert.NoError(t, err)
	p22 := p2.Clone(false)

	family := p1.GetFamily()
	assert.Equal(t, family, bgp.RF_RTC_UC)
	families := []bgp.Family{family}
	adj := NewAdjRib(logger, families)

	table, found := adj.table[bgp.RF_RTC_UC]
	assert.True(t, found)
	assert.NotNil(t, table.rtc)
	rtc, ok := table.rtc.(*routeFamilyRTCMap)
	assert.True(t, ok)

	assert.Equal(t, len(rtc.rts), 0)
	rtc.register(p1)
	rtc.register(p2)
	assert.Equal(t, len(rtc.rts), 2)
	assert.True(t, adj.HasRTinRtcTable(hash1))
	assert.True(t, adj.HasRTinRtcTable(hash2))
	rtc.unregister(p1, true)
	assert.Equal(t, len(rtc.rts), 1)
	assert.False(t, adj.HasRTinRtcTable(hash1))

	rtc.unregister(p2, false)
	assert.Equal(t, len(rtc.rts), 1)
	assert.False(t, adj.HasRTinRtcTable(hash2))
	rtc.unregister(p2, false)
	assert.Equal(t, len(rtc.rts), 1)
	assert.False(t, adj.HasRTinRtcTable(hash2))
	rtc.register(p22)
	assert.Equal(t, len(rtc.rts), 1)
	assert.True(t, adj.HasRTinRtcTable(hash2))
	rtc.unregister(p22, true)
	assert.Equal(t, len(rtc.rts), 0)
	assert.False(t, adj.HasRTinRtcTable(hash2))
}
