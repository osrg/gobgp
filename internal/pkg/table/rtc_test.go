package table

import (
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func TestRTMSetAddSubHas(t *testing.T) {
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

func TestRTMSetConcurrent(t *testing.T) {
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

func makeVPNNLRI(t *testing.T, prefix string, rdAS, rdVal uint16) bgp.PathNLRI {
	t.Helper()
	rd := bgp.NewRouteDistinguisherTwoOctetAS(rdAS, uint32(rdVal))
	nlri, err := bgp.NewLabeledVPNIPAddrPrefix(
		netip.MustParsePrefix(prefix),
		*bgp.NewMPLSLabelStack(100),
		rd,
	)
	if err != nil {
		t.Fatalf("NewLabeledVPNIPAddrPrefix: %v", err)
	}
	return bgp.PathNLRI{NLRI: nlri}
}

func makeVPNPath(t *testing.T, pi *PeerInfo, rts []bgp.ExtendedCommunityInterface, prefix string) *Path {
	t.Helper()
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeExtendedCommunities(rts),
	}
	return NewPath(bgp.RF_IPv4_VPN, pi, makeVPNNLRI(t, prefix, 65000, 1), false, attrs, time.Now(), false)
}

func TestVPNPathIndexRegisterUnregister(t *testing.T) {
	pi := &PeerInfo{}
	rt1, _ := bgp.ParseRouteTarget("65000:1")
	rt2, _ := bgp.ParseRouteTarget("65000:2")

	p1 := makeVPNPath(t, pi, []bgp.ExtendedCommunityInterface{rt1}, "10.1.0.0/24")
	p2 := makeVPNPath(t, pi, []bgp.ExtendedCommunityInterface{rt2}, "10.2.0.0/24")

	idx := NewVPNPathIndex()

	// Empty index returns nothing.
	assert.Empty(t, idx.GetPathsByRT(rt1))
	assert.Empty(t, idx.GetPathsByRT(nil))

	// Register p1 under rt1.
	idx.RegisterPath(p1)
	assert.Equal(t, []*Path{p1}, idx.GetPathsByRT(rt1))
	assert.Empty(t, idx.GetPathsByRT(rt2))

	// Register p2 under rt2.
	idx.RegisterPath(p2)
	assert.Equal(t, []*Path{p2}, idx.GetPathsByRT(rt2))

	// Nil rt is not a wildcard here: RTC wildcard handling uses a full RIB scan
	// (see TableManager.GetPathsByRT, rtcVPNCandidates), not the per-table index.
	assert.Nil(t, idx.GetPathsByRT(nil))

	// Unregister p1; rt1 bucket should disappear.
	idx.UnregisterPath(p1)
	assert.Empty(t, idx.GetPathsByRT(rt1))
	assert.Equal(t, []*Path{p2}, idx.GetPathsByRT(rt2))

	// Spurious unregister is a no-op.
	idx.UnregisterPath(p1)
	assert.Equal(t, []*Path{p2}, idx.GetPathsByRT(rt2))

	// Withdraw-flagged path is ignored by RegisterPath.
	idx.RegisterPath(p1.Clone(true))
	assert.Empty(t, idx.GetPathsByRT(rt1))
}

func TestVPNPathIndexMultipleRTsPerPath(t *testing.T) {
	pi := &PeerInfo{}
	rt1, _ := bgp.ParseRouteTarget("65000:1")
	rt2, _ := bgp.ParseRouteTarget("65000:2")

	// Single path carrying both RTs.
	p := makeVPNPath(t, pi, []bgp.ExtendedCommunityInterface{rt1, rt2}, "10.3.0.0/24")

	idx := NewVPNPathIndex()
	idx.RegisterPath(p)

	assert.Equal(t, []*Path{p}, idx.GetPathsByRT(rt1))
	assert.Equal(t, []*Path{p}, idx.GetPathsByRT(rt2))

	// Unregistering removes p from both RT buckets.
	idx.UnregisterPath(p)
	assert.Empty(t, idx.GetPathsByRT(rt1))
	assert.Empty(t, idx.GetPathsByRT(rt2))
}

func TestVPNPathIndexNilInputs(t *testing.T) {
	var nilIdx *VPNPathIndex
	// All methods must be no-ops on a nil receiver.
	nilIdx.RegisterPath(nil)
	nilIdx.UnregisterPath(nil)
	assert.Nil(t, nilIdx.GetPathsByRT(nil))

	// Non-nil index, nil / withdraw paths must not be indexed.
	idx := NewVPNPathIndex()
	idx.RegisterPath(nil)

	pi := &PeerInfo{}
	rt1, _ := bgp.ParseRouteTarget("65000:1")
	withdraw := makeVPNPath(t, pi, []bgp.ExtendedCommunityInterface{rt1}, "10.4.0.0/24").Clone(true)
	idx.RegisterPath(withdraw)
	assert.Empty(t, idx.GetPathsByRT(nil))
}

// TestVPNPathIndexCloneUnregister verifies that unregistering a clone of a registered
// path correctly removes it. With pointer-based keys this would be a silent no-op,
// leaving a dangling entry. With vpnPathKey it must succeed.
func TestVPNPathIndexCloneUnregister(t *testing.T) {
	pi := &PeerInfo{}
	rt1, _ := bgp.ParseRouteTarget("65000:1")

	original := makeVPNPath(t, pi, []bgp.ExtendedCommunityInterface{rt1}, "10.5.0.0/24")

	idx := NewVPNPathIndex()
	idx.RegisterPath(original)
	assert.Len(t, idx.GetPathsByRT(rt1), 1)

	// Clone(false) produces a new *Path with the same NLRI and pathID but a different address.
	clone := original.Clone(false)
	assert.NotSame(t, original, clone, "clone must be a distinct pointer")

	idx.UnregisterPath(clone)
	assert.Empty(t, idx.GetPathsByRT(rt1), "unregistering a clone must remove the original entry")
}

func TestVPNPathIndexConcurrent(t *testing.T) {
	pi := &PeerInfo{}
	rt1, _ := bgp.ParseRouteTarget("65000:1")
	rt2, _ := bgp.ParseRouteTarget("65000:2")

	idx := NewVPNPathIndex()

	const goroutines = 20
	const iters = 200

	var wg sync.WaitGroup

	// Concurrent writers: each goroutine registers then unregisters its own paths.
	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Unique prefixes per goroutine to avoid pointer aliasing between goroutines.
			p1 := makeVPNPath(t, pi, []bgp.ExtendedCommunityInterface{rt1},
				"10."+strconv.Itoa(i)+".1.0/24")
			p2 := makeVPNPath(t, pi, []bgp.ExtendedCommunityInterface{rt2},
				"10."+strconv.Itoa(i)+".2.0/24")
			for range iters {
				idx.RegisterPath(p1)
				idx.RegisterPath(p2)
				idx.UnregisterPath(p1)
				idx.UnregisterPath(p2)
			}
		}(i)
	}

	// Concurrent readers running throughout the writes.
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iters {
				_ = idx.GetPathsByRT(rt1)
				_ = idx.GetPathsByRT(nil)
			}
		}()
	}

	wg.Wait()
}
