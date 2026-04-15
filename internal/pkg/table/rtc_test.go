package table

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func TestAdjRTSetAddSubHas(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	rt, err := bgp.ParseRouteTarget("65520:1000000")
	assert.NoError(t, err)
	nlri := bgp.NewRouteTargetMembershipNLRI(65000, rt)
	rtHash, err := nlriRouteTargetKey(nlri)
	assert.NoError(t, err)

	var nilSet *rtmSet
	nilSet.add(nil)
	nilSet.sub(nil)
	assert.False(t, nilSet.has(rtHash))
	assert.False(t, nilSet.has(DefaultRT))

	s := newRtmSet()
	assert.False(t, s.has(rtHash))
	assert.False(t, s.has(DefaultRT))

	// Non-RTC paths are ignored.
	v4 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: &bgp.IPAddrPrefix{}}, false, attrs, time.Now(), false)
	s.add(v4)
	s.sub(v4)
	assert.False(t, s.has(rtHash))

	// Single path: add then withdraw clears the bucket.
	p := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri, ID: 7}, false, attrs, time.Now(), false)
	s.add(p)
	assert.True(t, s.has(rtHash))
	s.sub(p.Clone(true))
	assert.False(t, s.has(rtHash))

	// ADD-PATH: two path IDs for the same (AS, RT); withdrawing one leaves the other.
	p1 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri, ID: 1}, false, attrs, time.Now(), false)
	p2 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri, ID: 2}, false, attrs, time.Now(), false)
	s.add(p1)
	s.add(p2)
	assert.True(t, s.has(rtHash))
	s.sub(p1.Clone(true))
	assert.True(t, s.has(rtHash), "second path-ID must still advertise the RT")
	s.sub(p2.Clone(true))
	assert.False(t, s.has(rtHash))

	// Same RT, different originating AS: independent keys.
	nlriOtherAS := bgp.NewRouteTargetMembershipNLRI(65001, rt)
	pA := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri, ID: 1}, false, attrs, time.Now(), false)
	pB := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlriOtherAS, ID: 1}, false, attrs, time.Now(), false)
	s.add(pA)
	s.add(pB)
	assert.True(t, s.has(rtHash))
	s.sub(pA.Clone(true))
	assert.True(t, s.has(rtHash), "other AS must still hold this RT")
	s.sub(pB.Clone(true))
	assert.False(t, s.has(rtHash))

	// Default (wildcard) RT uses key DefaultRT.
	nlriDef := bgp.NewRouteTargetMembershipNLRI(0, nil)
	pDef := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlriDef, ID: 1}, false, attrs, time.Now(), false)
	s.add(pDef)
	assert.True(t, s.has(DefaultRT))
	s.sub(pDef.Clone(true))
	assert.False(t, s.has(DefaultRT))

	// Spurious withdraw is a no-op on an empty set.
	s.sub(p.Clone(true))
	assert.False(t, s.has(rtHash))
}

func TestAdjRTSetConcurrent(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	rt, _ := bgp.ParseRouteTarget("65520:1000000")
	nlri := bgp.NewRouteTargetMembershipNLRI(65000, rt)
	rtHash, err := nlriRouteTargetKey(nlri)
	assert.NoError(t, err)

	s := newRtmSet()

	const goroutines = 20
	const iters = 500

	var wg sync.WaitGroup

	// Writers: concurrent add and sub.
	for i := range goroutines {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			path := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri, ID: id}, false, attrs, time.Now(), false)
			withdraw := path.Clone(true)
			for range iters {
				s.add(path)
				s.sub(withdraw)
			}
		}(uint32(i))
	}

	// Readers: concurrent has, running throughout the writes.
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iters {
				_ = s.has(rtHash)
				_ = s.has(DefaultRT)
			}
		}()
	}

	wg.Wait()
}

func TestRouteTargetMembershipHandlerDefaultAndRTs(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	rt1, _ := bgp.ParseRouteTarget("65520:1000000")
	_, err := extCommRouteTargetKey(rt1)
	assert.NoError(t, err)
	nlri1 := bgp.NewRouteTargetMembershipNLRI(65000, rt1)
	p1 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri1}, false, attrs, time.Now(), false)
	p1.remoteID = 1

	rt2, _ := bgp.ParseRouteTarget("65520:1000001")
	nlri2 := bgp.NewRouteTargetMembershipNLRI(65000, rt2)
	p2 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri2}, false, attrs, time.Now(), false)
	p2.remoteID = 2

	nlri3 := bgp.NewRouteTargetMembershipNLRI(0, nil)
	p3 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri3}, false, attrs, time.Now(), false)
	p3.remoteID = 3

	rtc := NewRouteTargetMembershipHandler()
	rtc.SyncAfterImport(p1)
	rtc.SyncAfterImport(p2)
	rtc.SyncAfterImport(p3)

	assert.True(t, rtc.HasDefaultRouteTarget())
	assert.True(t, rtc.HasRouteTarget(rt1))
	assert.True(t, rtc.HasRouteTarget(rt2))

	rtc.SyncAfterImport(p1.Clone(true))
	assert.True(t, rtc.HasDefaultRouteTarget())
	assert.False(t, rtc.HasRouteTarget(rt1))
	assert.True(t, rtc.HasRouteTarget(rt2))

	rtc.SyncAfterImport(p3.Clone(true))
	assert.False(t, rtc.HasDefaultRouteTarget())
	assert.True(t, rtc.HasRouteTarget(rt2))

	rtc.SyncAfterImport(p2.Clone(true))
	assert.False(t, rtc.HasRouteTarget(rt2))
}

func TestRouteTargetMembershipHandlerSameRTAddPath(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	rt1, _ := bgp.ParseRouteTarget("65520:1000000")
	nlri1a := bgp.NewRouteTargetMembershipNLRI(65000, rt1)
	nlri1b := bgp.NewRouteTargetMembershipNLRI(65001, rt1) // same RT, different AS

	// Two ADD-PATH paths for the same (AS=65000, RT=rt1) NLRI, different path IDs.
	p1 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri1a, ID: 1}, false, attrs, time.Now(), false)
	p2 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri1a, ID: 2}, false, attrs, time.Now(), false)
	// Different AS, same RT.
	p3 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri1b, ID: 1}, false, attrs, time.Now(), false)

	rtc := NewRouteTargetMembershipHandler()
	rtc.SyncAfterImport(p1)
	rtc.SyncAfterImport(p2)
	rtc.SyncAfterImport(p3)
	assert.True(t, rtc.HasRouteTarget(rt1))

	// Withdraw p1 — p2 and p3 still hold rt1 interest.
	rtc.SyncAfterImport(p1.Clone(true))
	assert.True(t, rtc.HasRouteTarget(rt1), "still has rt1 via p2 and p3")

	// Withdraw p3 — p2 still holds rt1 interest.
	rtc.SyncAfterImport(p3.Clone(true))
	assert.True(t, rtc.HasRouteTarget(rt1), "still has rt1 via p2")

	// Spurious withdraw: same NLRI as p2 but unknown pathID — must be a no-op.
	pSpurious := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri1a, ID: 99}, true, attrs, time.Now(), false)
	rtc.SyncAfterImport(pSpurious)
	assert.True(t, rtc.HasRouteTarget(rt1), "spurious withdraw must not remove rt1 interest")

	// Withdraw p2 — no more rt1 interest.
	rtc.SyncAfterImport(p2.Clone(true))
	assert.False(t, rtc.HasRouteTarget(rt1))
}
