package table

import (
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

func TestPeerRTMIndex(t *testing.T) {
	rt, _ := bgp.ParseRouteTarget("100:100")
	const rtHash = uint64(12345) // arbitrary, normally from NlriRouteTargetKey()

	// Same RT, different AS → different rtmKeys (ADD-PATH semantics)
	nlri1 := bgp.NewRouteTargetMembershipNLRI(64512, rt)
	nlri2 := bgp.NewRouteTargetMembershipNLRI(64513, rt)

	idx := newPeerRTMIndex()

	// Add first RTM for peer1 — should be "first".
	assert.True(t, idx.addRTM(rtHash, "peer1", nlri1, 0))
	assert.True(t, idx.hasPeer(rtHash, "peer1"))

	// Add same RTM again — duplicate, not first.
	assert.False(t, idx.addRTM(rtHash, "peer1", nlri1, 0))
	assert.True(t, idx.hasPeer(rtHash, "peer1"))

	// Add second RTM (different AS) for peer1 — not first (peer already has one).
	assert.False(t, idx.addRTM(rtHash, "peer1", nlri2, 0))
	assert.True(t, idx.hasPeer(rtHash, "peer1"))

	// Add RTM for peer2 — first for peer2.
	assert.True(t, idx.addRTM(rtHash, "peer2", nlri1, 0))
	assert.True(t, idx.hasPeer(rtHash, "peer2"))

	// Remove nlri1 from peer1 — peer1 still has nlri2, not last.
	assert.False(t, idx.deleteRTM(rtHash, "peer1", nlri1, 0))
	assert.True(t, idx.hasPeer(rtHash, "peer1"))

	// Remove nlri1 again — already gone, no-op.
	assert.False(t, idx.deleteRTM(rtHash, "peer1", nlri1, 0))

	// Remove nlri2 from peer1 — last for peer1.
	assert.True(t, idx.deleteRTM(rtHash, "peer1", nlri2, 0))
	assert.False(t, idx.hasPeer(rtHash, "peer1"))

	// peer2 still present.
	assert.True(t, idx.hasPeer(rtHash, "peer2"))

	// Remove nlri1 from peer2 — last for peer2, index entry for rtHash deleted.
	assert.True(t, idx.deleteRTM(rtHash, "peer2", nlri1, 0))
	assert.False(t, idx.hasPeer(rtHash, "peer2"))
	assert.Equal(t, 0, len(idx))

	// Remove again — no-op.
	assert.False(t, idx.deleteRTM(rtHash, "peer2", nlri1, 0))

	// Withdraw an RTM with an AS that was never registered — must be a safe no-op.
	nlriUnknownAS := bgp.NewRouteTargetMembershipNLRI(999, rt)
	assert.False(t, idx.deleteRTM(rtHash, "peer1", nlriUnknownAS, 0))
	assert.Equal(t, 0, len(idx))
}

func TestVpnFamilyRTEmpty(t *testing.T) {
	rt := make(vpnFamilyRT)
	assert.True(t, rt.empty())
}

// TestRTCPeerTracking tests that UpdateRTC + PeerHasRT correctly track per-peer RT interest.
// Path IDs are set via PathNLRI.ID (the ADD-PATH path identifier stored on the Path).
func TestRTCPeerTracking(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	rt1, _ := bgp.ParseRouteTarget("65520:1000000")
	nlri1 := bgp.NewRouteTargetMembershipNLRI(65000, rt1)
	hash1, err := NlriRouteTargetKey(nlri1)
	assert.NoError(t, err)

	rt2, _ := bgp.ParseRouteTarget("65520:1000001")
	nlri2 := bgp.NewRouteTargetMembershipNLRI(65000, rt2)
	hash2, err := NlriRouteTargetKey(nlri2)
	assert.NoError(t, err)

	// pathID is set via PathNLRI.ID; it becomes Path.remoteID used by UpdateRTC.
	p1 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri1, ID: 1}, false, attrs, time.Now(), false)
	p2 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri2, ID: 2}, false, attrs, time.Now(), false)
	// p22 simulates the same RT with a different path identifier (ADD-PATH).
	nlri2b := bgp.NewRouteTargetMembershipNLRI(65000, rt2)
	p22 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri2b, ID: 3}, false, attrs, time.Now(), false)
	p2Withdraw := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri2, ID: 2}, true, attrs, time.Now(), false)
	p22Withdraw := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri2b, ID: 3}, true, attrs, time.Now(), false)

	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_VPN})
	const peer1 = "192.0.2.1"
	const tableID = "global"
	rfList := []bgp.Family{bgp.RF_IPv4_VPN}

	assert.False(t, tm.PeerHasRT(peer1, hash1))
	assert.False(t, tm.PeerHasRT(peer1, hash2))

	// Register p1 (RT1) for peer1.
	tm.UpdateRTC(peer1, tableID, p1, rfList)
	assert.True(t, tm.PeerHasRT(peer1, hash1))
	assert.False(t, tm.PeerHasRT(peer1, hash2))

	// Register p2 (RT2, pathID=2) for peer1.
	tm.UpdateRTC(peer1, tableID, p2, rfList)
	assert.True(t, tm.PeerHasRT(peer1, hash1))
	assert.True(t, tm.PeerHasRT(peer1, hash2))

	// Withdraw p1 — peer1 no longer has RT1.
	tm.UpdateRTC(peer1, tableID, p1.Clone(true), rfList)
	assert.False(t, tm.PeerHasRT(peer1, hash1))
	assert.True(t, tm.PeerHasRT(peer1, hash2))

	// Withdraw with an ASN that was never registered for RT2 — must not affect filtering.
	nlri2UnknownAS := bgp.NewRouteTargetMembershipNLRI(99999, rt2)
	p2UnknownAS := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri2UnknownAS, ID: 2}, true, attrs, time.Now(), false)
	tm.UpdateRTC(peer1, tableID, p2UnknownAS, rfList)
	assert.True(t, tm.PeerHasRT(peer1, hash2), "spurious withdraw must not remove peer interest")

	// Withdraw p2 (pathID=2, correct ASN) — peer1 no longer has RT2.
	tm.UpdateRTC(peer1, tableID, p2Withdraw, rfList)
	assert.False(t, tm.PeerHasRT(peer1, hash2))

	// Idempotent: withdrawing again should not panic.
	tm.UpdateRTC(peer1, tableID, p2Withdraw, rfList)
	assert.False(t, tm.PeerHasRT(peer1, hash2))

	// Register p22 (same RT2, different pathID) — ADD-PATH case.
	tm.UpdateRTC(peer1, tableID, p22, rfList)
	assert.True(t, tm.PeerHasRT(peer1, hash2))

	// Withdraw p22 — peer1 loses RT2 again.
	tm.UpdateRTC(peer1, tableID, p22Withdraw, rfList)
	assert.False(t, tm.PeerHasRT(peer1, hash2))
}
