package table

import (
	"fmt"
	"net/netip"
	"slices"
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
	rtHash, ok := rtPrefixOf(nlri)
	assert.True(t, ok)
	defRT := rtPrefix{}

	var nilSet *rtmSet
	nilSet.add(nil)
	nilSet.sub(nil)
	assert.False(t, nilSet.has(rtHash))
	assert.False(t, nilSet.has(defRT))

	s := newRtmSet()
	assert.False(t, s.has(rtHash))
	assert.False(t, s.has(defRT))

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

	// Default (wildcard) RT uses the zero-length prefix.
	nlriDef := bgp.NewRouteTargetMembershipNLRI(0, nil)
	pDef := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlriDef, ID: 1}, false, attrs, time.Now(), false)
	s.add(pDef)
	assert.True(t, s.has(defRT))
	assert.Equal(t, map[uint8]int{0: 1}, s.count)
	s.sub(pDef.Clone(true))
	assert.False(t, s.has(defRT))
	assert.Empty(t, s.count)

	// Spurious withdraw is a no-op on an empty set.
	s.sub(p.Clone(true))
	assert.False(t, s.has(rtHash))
}

func TestRTMSetConcurrent(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	rt, _ := bgp.ParseRouteTarget("65520:1000000")
	nlri := bgp.NewRouteTargetMembershipNLRI(65000, rt)
	rtKey, err := nlri.RouteTargetKey()
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
				_ = s.contains(rtKey)
				_ = s.containsAll()
			}
		}()
	}

	wg.Wait()
}

func TestRouteTargetMembershipHandlerDefaultAndRTs(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	rt1, _ := bgp.ParseRouteTarget("65520:1000000")
	_, err := bgp.ExtCommRouteTargetKey(rt1)
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

	// The default RT contains every Route Target, including a withdrawn one.
	rtc.SyncAfterImport(p1.Clone(true))
	assert.True(t, rtc.HasDefaultRouteTarget())
	assert.True(t, rtc.HasRouteTarget(rt1))
	assert.True(t, rtc.HasRouteTarget(rt2))

	rtc.SyncAfterImport(p3.Clone(true))
	assert.False(t, rtc.HasDefaultRouteTarget())
	assert.False(t, rtc.HasRouteTarget(rt1))
	assert.True(t, rtc.HasRouteTarget(rt2))

	rtc.SyncAfterImport(p2.Clone(true))
	assert.False(t, rtc.HasRouteTarget(rt2))
}

// rtcPathFromWire decodes an RTC NLRI of length l with the given origin AS
// and the first octets of rt, the way a received NLRI is decoded.
func rtcPathFromWire(t *testing.T, l uint8, as uint32, rt []byte, id uint32) *Path {
	t.Helper()
	wire := []byte{l, byte(as >> 24), byte(as >> 16), byte(as >> 8), byte(as)}
	if l > 32 {
		wire = append(wire, rt[:(int(l)-32+7)/8]...)
	}
	if l == 0 {
		wire = []byte{0}
	}
	nlri, err := bgp.NLRIFromSlice(bgp.RF_RTC_UC, wire)
	if err != nil {
		t.Fatalf("NLRIFromSlice: %v", err)
	}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}
	return NewPath(bgp.RF_RTC_UC, &PeerInfo{}, bgp.PathNLRI{NLRI: nlri, ID: id}, false, attrs, time.Now(), false)
}

// An RT membership is a prefix of the Route Target. It contains every Route
// Target whose first len-32 bits are the same as its own, whatever the
// boundary cuts through.
func TestRouteTargetMembershipHandlerPrefixMatch(t *testing.T) {
	// 65000:100
	advertised := []byte{0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64}

	rts := []string{
		"65000:100",
		"65000:101",
		"65000:200",
		"65000:0",
		"65000:100000",
		"65001:100",
		"0:0",
		"10.0.0.1:1",
		"64000.1000:1",
	}
	for _, tt := range []struct {
		len   uint8
		all   bool
		match []string
	}{
		{32, true, rts},
		// The type high octet: every two-octet AS Route Target.
		{40, false, []string{"65000:100", "65000:101", "65000:200", "65000:0", "65000:100000", "65001:100", "0:0"}},
		{47, false, []string{"65000:100", "65000:101", "65000:200", "65000:0", "65000:100000", "65001:100", "0:0"}},
		{48, false, []string{"65000:100", "65000:101", "65000:200", "65000:0", "65000:100000", "65001:100", "0:0"}},
		// The high octet of the AS: AS 64768 to 65023.
		{56, false, []string{"65000:100", "65000:101", "65000:200", "65000:0", "65000:100000", "65001:100"}},
		// Every Route Target of AS 65000.
		{64, false, []string{"65000:100", "65000:101", "65000:200", "65000:0", "65000:100000"}},
		{80, false, []string{"65000:100", "65000:101", "65000:200", "65000:0"}},
		{95, false, []string{"65000:100", "65000:101"}},
		{96, false, []string{"65000:100"}},
	} {
		t.Run(strconv.Itoa(int(tt.len)), func(t *testing.T) {
			p := rtcPathFromWire(t, tt.len, 65001, advertised, 0)
			rtc := NewRouteTargetMembershipHandler()
			rtc.SyncAfterImport(p)
			assert.Equal(t, tt.all, rtc.HasDefaultRouteTarget())
			for _, s := range rts {
				rt, err := bgp.ParseRouteTarget(s)
				assert.NoError(t, err)
				assert.Equal(t, slices.Contains(tt.match, s), rtc.HasRouteTarget(rt), s)
			}

			rtc.SyncAfterImport(p.Clone(true))
			assert.False(t, rtc.HasDefaultRouteTarget())
			for _, s := range rts {
				rt, _ := bgp.ParseRouteTarget(s)
				assert.False(t, rtc.HasRouteTarget(rt), s)
			}
			assert.Empty(t, rtc.s.count)
		})
	}
}

// A Route Target part that is all zero is not the default RT. That happens
// with an all-zero Route Target at /96, and with a short prefix whose bits
// are all zero after the trailing bits are cleared, such as 65000:100 at
// /40. Neither may contain every Route Target, and neither may cancel the
// default RT when it is withdrawn, although both carry AS 0 like the default
// RT does.
func TestRouteTargetMembershipHandlerZeroRouteTarget(t *testing.T) {
	zero := make([]byte, 8)
	rt100 := []byte{0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64}
	other, _ := bgp.ParseRouteTarget("10.0.0.1:1")

	for _, tt := range []struct {
		name string
		len  uint8
		rt   []byte
	}{
		{"all-zero route target", 96, zero},
		{"route target prefix of one octet", 40, rt100},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := rtcPathFromWire(t, tt.len, 0, tt.rt, 1)
			key, err := p.GetNlri().(*bgp.RouteTargetMembershipNLRI).RouteTargetKey()
			assert.NoError(t, err)
			assert.Zero(t, key, "the NLRI has to have a zero key for this case to test anything")

			rtc := NewRouteTargetMembershipHandler()
			rtc.SyncAfterImport(p)
			assert.False(t, rtc.HasDefaultRouteTarget())
			assert.False(t, rtc.HasRouteTarget(other))

			def := rtcPathFromWire(t, 0, 0, nil, 1)
			rtc.SyncAfterImport(def)
			assert.True(t, rtc.HasDefaultRouteTarget())
			rtc.SyncAfterImport(p.Clone(true))
			assert.True(t, rtc.HasDefaultRouteTarget(), "withdrawing it must leave the default RT alone")
			assert.True(t, rtc.HasRouteTarget(other))
		})
	}
}

// The default RT (/0) and an NLRI without a Route Target (/32) both contain
// every Route Target, but they are different NLRIs. Withdrawing one must keep
// the other, also when the /32 carries origin AS 0 like the default RT.
func TestRouteTargetMembershipHandlerDefaultAndOriginASOnly(t *testing.T) {
	rt, _ := bgp.ParseRouteTarget("65000:100")
	for _, as := range []uint32{65001, 0} {
		for _, first := range []uint8{0, 32} {
			t.Run(fmt.Sprintf("as %d withdraw /%d", as, first), func(t *testing.T) {
				def := rtcPathFromWire(t, 0, 0, nil, 0)
				asOnly := rtcPathFromWire(t, 32, as, nil, 0)
				rtc := NewRouteTargetMembershipHandler()
				rtc.SyncAfterImport(def)
				rtc.SyncAfterImport(asOnly)

				withdrawn, other := def, asOnly
				if first == 32 {
					withdrawn, other = asOnly, def
				}
				rtc.SyncAfterImport(withdrawn.Clone(true))
				assert.True(t, rtc.HasDefaultRouteTarget())
				assert.True(t, rtc.HasRouteTarget(rt))

				rtc.SyncAfterImport(other.Clone(true))
				assert.False(t, rtc.HasDefaultRouteTarget())
				assert.False(t, rtc.HasRouteTarget(rt))
			})
		}
	}
}

// Covers reports whether the present memberships contain every Route Target
// of an NLRI. Only a membership whose Route Target part is not longer can do
// that, and /0 and /32 both have an empty one.
func TestRouteTargetMembershipHandlerCovers(t *testing.T) {
	rt := []byte{0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64}    // 65000:100
	other := []byte{0x00, 0x02, 0xfd, 0xe9, 0x00, 0x00, 0x00, 0x64} // 65001:100
	nlri := func(p *Path) *bgp.RouteTargetMembershipNLRI {
		return p.GetNlri().(*bgp.RouteTargetMembershipNLRI)
	}
	p0 := rtcPathFromWire(t, 0, 0, nil, 0)
	p32 := rtcPathFromWire(t, 32, 65002, nil, 0)
	p64 := rtcPathFromWire(t, 64, 65002, rt, 0)
	p96 := rtcPathFromWire(t, 96, 65002, rt, 0)
	p96other := rtcPathFromWire(t, 96, 65002, other, 0)
	routeOrigin := rtcPathFromWire(t, 96, 65002, []byte{0x00, 0x03, 0xfd, 0xe8, 0, 0, 0, 0x64}, 0)

	for _, tt := range []struct {
		name    string
		present []*Path
		covered []*Path
		not     []*Path
	}{
		{"nothing", nil, nil, []*Path{p0, p32, p64, p96}},
		{"/96", []*Path{p96}, []*Path{p96}, []*Path{p0, p32, p64, p96other}},
		{"/64", []*Path{p64}, []*Path{p64, p96}, []*Path{p0, p32, p96other}},
		{"/32", []*Path{p32}, []*Path{p0, p32, p64, p96, p96other}, nil},
		{"/0", []*Path{p0}, []*Path{p0, p32, p64, p96, p96other}, nil},
		{"not kept", []*Path{p0}, nil, []*Path{routeOrigin}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rtc := NewRouteTargetMembershipHandler()
			for _, p := range tt.present {
				rtc.SyncAfterImport(p)
			}
			for _, p := range tt.covered {
				assert.True(t, rtc.Covers(nlri(p)), nlri(p).String())
			}
			for _, p := range tt.not {
				assert.False(t, rtc.Covers(nlri(p)), nlri(p).String())
			}
		})
	}
}

func TestRouteTargetMembershipContains(t *testing.T) {
	pi := &PeerInfo{}
	rt100, _ := bgp.ParseRouteTarget("65000:100")
	rt300, _ := bgp.ParseRouteTarget("65001:300")
	origin := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_ORIGIN, 65000, 100, true)

	p := makeVPNPath(t, pi, []bgp.ExtendedCommunityInterface{rt100, rt300}, "10.7.0.0/24")
	q := makeVPNPath(t, pi, []bgp.ExtendedCommunityInterface{origin}, "10.8.0.0/24")
	parse := func(s string) *bgp.RouteTargetMembershipNLRI {
		n, err := bgp.ParseRouteTargetMembershipNLRI(s)
		assert.NoError(t, err)
		return n
	}

	assert.True(t, RouteTargetMembershipContains(parse("65002:65000:100"), p))
	assert.False(t, RouteTargetMembershipContains(parse("65002:65000:200"), p))
	assert.True(t, RouteTargetMembershipContains(parse("65002:65001:0/64"), p), "65001:300 is in AS 65001")
	assert.True(t, RouteTargetMembershipContains(parse("65002:65000:0/64"), p))
	assert.False(t, RouteTargetMembershipContains(parse("65002:65003:0/64"), p))
	assert.True(t, RouteTargetMembershipContains(bgp.NewRouteTargetMembershipNLRI(0, nil), p))

	// A Route Origin is not a Route Target, so nothing contains it.
	assert.False(t, RouteTargetMembershipContains(parse("65002:65000:100"), q))
	assert.False(t, RouteTargetMembershipContains(bgp.NewRouteTargetMembershipNLRI(0, nil), q))
}

// rtmSet keeps an RTC NLRI only when its prefix can contain a Route Target.
// The NLRI may cover all of the Type Field, part of it or none of it.
func TestRTMSetRouteTargetOnly(t *testing.T) {
	for _, tt := range []struct {
		name string
		len  uint8
		rt   []byte
		kept bool
	}{
		{"default", 0, nil, true},
		{"origin AS only", 32, nil, true},
		{"two-octet AS route target", 96, []byte{0x00, 0x02, 0xfd, 0xe8, 0, 0, 0, 1}, true},
		{"IPv4 address route target", 96, []byte{0x01, 0x02, 10, 0, 0, 1, 0, 1}, true},
		{"four-octet AS route target", 96, []byte{0x02, 0x02, 0, 0, 0xfd, 0xe8, 0, 1}, true},
		{"route origin", 96, []byte{0x00, 0x03, 0xfd, 0xe8, 0, 0, 0, 1}, false},
		{"IPv4 address route origin", 96, []byte{0x01, 0x03, 10, 0, 0, 1, 0, 1}, false},
		{"all zero", 96, make([]byte, 8), false},
		{"non-transitive route target", 96, []byte{0x40, 0x02, 0xfd, 0xe8, 0, 0, 0, 1}, false},
		{"route origin at /48", 48, []byte{0x00, 0x03}, false},
		// The sub-type 0x03 loses its last bit at /47, so it fits 0x02.
		{"route origin at /47", 47, []byte{0x00, 0x03}, true},
		{"sub-type 0x04 at /47", 47, []byte{0x00, 0x04}, false},
		{"two-octet AS type at /40", 40, []byte{0x00}, true},
		{"IPv4 address type at /40", 40, []byte{0x01}, true},
		{"four-octet AS type at /40", 40, []byte{0x02}, true},
		{"non-transitive type at /40", 40, []byte{0x40}, false},
		// 0x03 loses its last two bits at /38 and fits all three types.
		{"opaque type at /38", 38, []byte{0x03}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newRtmSet()
			p := rtcPathFromWire(t, tt.len, 65001, tt.rt, 0)
			s.add(p)
			if tt.kept {
				assert.Len(t, s.m, 1)
			} else {
				assert.Empty(t, s.m)
				assert.Empty(t, s.count)
			}
			s.sub(p.Clone(true))
			assert.Empty(t, s.m)
			assert.Empty(t, s.count)
		})
	}
}

// rtmSet keeps count in step with the buckets: count[l] is the number of
// prefixes of length l, a length with no prefix is not listed, and reset
// clears it.
func TestRTMSetCount(t *testing.T) {
	rt := []byte{0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64}
	other := []byte{0x00, 0x02, 0xfd, 0xe9, 0x00, 0x00, 0x00, 0x64}
	s := newRtmSet()

	p96a := rtcPathFromWire(t, 96, 65001, rt, 0)
	p96b := rtcPathFromWire(t, 96, 65002, rt, 0)
	p96c := rtcPathFromWire(t, 96, 65001, other, 0)
	p64 := rtcPathFromWire(t, 64, 65001, rt, 0)
	def := rtcPathFromWire(t, 0, 0, nil, 0)

	s.add(p96a)
	s.add(p64)
	s.add(def)
	s.add(p96b)
	s.add(p96c)
	assert.Equal(t, map[uint8]int{0: 1, 64: 1, 96: 2}, s.count, "p96a and p96b share a bucket, p96c has its own")

	s.sub(p96a.Clone(true))
	assert.Equal(t, map[uint8]int{0: 1, 64: 1, 96: 2}, s.count, "p96b still holds the bucket")
	s.sub(p96b.Clone(true))
	assert.Equal(t, map[uint8]int{0: 1, 64: 1, 96: 1}, s.count)
	s.sub(p96b.Clone(true))
	assert.Equal(t, map[uint8]int{0: 1, 64: 1, 96: 1}, s.count, "a spurious withdraw changes nothing")
	s.sub(p96c.Clone(true))
	s.sub(p64.Clone(true))
	assert.Equal(t, map[uint8]int{0: 1}, s.count, "an unused length is deleted")

	s.reset()
	assert.Empty(t, s.count)
	assert.Empty(t, s.m)
	s.add(p96a)
	assert.Equal(t, map[uint8]int{96: 1}, s.count, "the set is usable after reset")
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

	// Withdraw p1 -- p2 and p3 still hold rt1 interest.
	rtc.SyncAfterImport(p1.Clone(true))
	assert.True(t, rtc.HasRouteTarget(rt1), "still has rt1 via p2 and p3")

	// Withdraw p3 -- p2 still holds rt1 interest.
	rtc.SyncAfterImport(p3.Clone(true))
	assert.True(t, rtc.HasRouteTarget(rt1), "still has rt1 via p2")

	// Spurious withdraw: same NLRI as p2 but unknown pathID -- must be a no-op.
	pSpurious := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri1a, ID: 99}, true, attrs, time.Now(), false)
	rtc.SyncAfterImport(pSpurious)
	assert.True(t, rtc.HasRouteTarget(rt1), "spurious withdraw must not remove rt1 interest")

	// Withdraw p2 -- no more rt1 interest.
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

// Only Route Targets are indexed. A Route Origin, or an all-zero extended
// community, uses the same Go type as a two-octet AS Route Target but has a
// different sub-type, so it must not get a bucket.
func TestVPNPathIndexIgnoresNonRouteTargets(t *testing.T) {
	pi := &PeerInfo{}
	rt := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 1, true)
	origin := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_ORIGIN, 65000, 1, true)
	zero := bgp.NewTwoOctetAsSpecificExtended(0, 0, 0, true)

	p := makeVPNPath(t, pi, []bgp.ExtendedCommunityInterface{rt, origin, zero}, "10.6.0.0/24")

	idx := NewVPNPathIndex()
	idx.RegisterPath(p)
	assert.Equal(t, []*Path{p}, idx.GetPathsByRT(rt))
	assert.Empty(t, idx.GetPathsByRT(origin))
	assert.Empty(t, idx.GetPathsByRT(zero))
	assert.Len(t, idx.rts, 1)

	idx.UnregisterPath(p)
	assert.Empty(t, idx.rts)
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
