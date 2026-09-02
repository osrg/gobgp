package server

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bfd"
	"github.com/stretchr/testify/assert"
)

func Test_NewBfdPeer(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	defer p.Stop()

	assert.NotNil(p)
}

func Test_NewBfdPeerDefaultPort(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Enabled: true,
	}, "")
	defer p.Stop()

	assert.Equal(BfdServerPort, p.peerPort)
}

func Test_BfdPeerRemoteUDPAddrZone(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}

	// link-local peer with an interface zone (unnumbered single-hop BFD): the zone must carry through to
	// the dialed UDP address, otherwise the socket can't reach the link-local peer.
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("fe80::1%eth0"), oc.BfdConfig{
		Port:    13784,
		Enabled: true,
	}, "")
	defer p.Stop()

	addr := p.remoteUDPAddr()
	assert.Equal("eth0", addr.Zone)
	assert.Equal("fe80::1", addr.IP.String())
	assert.Equal(13784, addr.Port)

	// a global peer carries no zone.
	g := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("10.0.0.1"), oc.BfdConfig{
		Port:    13784,
		Enabled: true,
	}, "")
	defer g.Stop()

	assert.Empty(g.remoteUDPAddr().Zone)
}

func Test_BfdPeerStopIdempotent(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:    13784,
		Enabled: true,
	}, "")

	p.Stop()
	p.Stop()

	assert.True(p.stopped.Load())
}

func Test_RxPacket(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")

	assert.Equal(p.stats.rxPacket.Load(), uint64(0))

	p.Rx(&bfd.BFDHeader{MyDiscriminator: 111, DetectTimeMultiplier: 5})

	time.Sleep(2 * time.Second)
	p.Stop()

	assert.NotEqual(p.stats.rxPacket.Load(), uint64(0))
}

func Test_RxPacketRemoteDownResetsPeer(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	defer p.Stop()

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_UP))
	p.yourDiscriminator = 12345

	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      67890,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})

	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, api.BfdSessionState(p.state.Load()))
	assert.Equal(int64(1), atomic.LoadInt64(&ps.resetPeerCount))
}

func Test_RxPacketRFCStateTransitions(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	defer p.Stop()

	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      111,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_INIT, api.BfdSessionState(p.state.Load()))
	assert.Equal(uint32(111), p.yourDiscriminator)

	p.setStateDown()
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateUp,
		MyDiscriminator:      222,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, api.BfdSessionState(p.state.Load()))

	p.setStateInit(333)
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateUp,
		MyDiscriminator:      444,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_UP, api.BfdSessionState(p.state.Load()))
	assert.Equal(uint32(444), p.yourDiscriminator)
}

// Test_NewBfdPeerDesiredMinTxFloor pins RFC 5880 Section 6.8.3: while the session is not Up
// (it starts Down), bfd.DesiredMinTxInterval must be raised to at least one second. The floor
// is a max, not a clamp: a peer configured slower than one second must not speed up while down.
func Test_NewBfdPeerDesiredMinTxFloor(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}

	fast := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DesiredMinimumTxInterval: 200000, // 200ms, faster than the 1s floor
	}, "")
	defer fast.Stop()
	assert.Equal(time.Second, fast.desiredMinTx)
	assert.False(fast.pollSequence)

	slow := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DesiredMinimumTxInterval: 2000000, // 2s, already slower than the 1s floor
	}, "")
	defer slow.Stop()
	assert.Equal(2*time.Second, slow.desiredMinTx)
	assert.False(slow.pollSequence)
}

// Test_RxPacketUpRestoresConfiguredIntervalAndStartsPollSequence pins RFC 5880 Section 6.8.3:
// reaching Up lifts the not-Up floor and restores the configured DesiredMinTxInterval, and
// Section 6.8.3 requires that this change initiate a Poll Sequence.
func Test_RxPacketUpRestoresConfiguredIntervalAndStartsPollSequence(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	defer p.Stop()

	assert.Equal(time.Second, p.desiredMinTx)
	assert.False(p.pollSequence)

	// Down -> Init, same as Test_RxPacketRFCStateTransitions.
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      111,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_INIT, api.BfdSessionState(p.state.Load()))

	// Init -> Up.
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateUp,
		MyDiscriminator:      222,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_UP, api.BfdSessionState(p.state.Load()))
	assert.Equal(200*time.Millisecond, p.desiredMinTx)
	assert.True(p.pollSequence)
}

// Test_RxPacketFinalTerminatesPollSequence pins RFC 5880 Section 6.8.6: "If a Poll Sequence is
// being transmitted by the local system and the Final (F) bit in the received packet is set,
// the Poll Sequence MUST be terminated." A Final received while no sequence is in flight is a
// no-op.
func Test_RxPacketFinalTerminatesPollSequence(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	defer p.Stop()

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_UP))
	p.yourDiscriminator = 12345
	p.pollSequence = true

	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateUp,
		Final:                true,
		MyDiscriminator:      12345,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})
	assert.False(p.pollSequence)
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_UP, p.sessionState())

	// No sequence in flight: Final is a no-op, not a panic or a spurious re-trigger.
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateUp,
		Final:                true,
		MyDiscriminator:      12345,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})
	assert.False(p.pollSequence)
}

// Test_RxPacketLeavingUpRefloorsWithoutPollSequence pins RFC 5880 Section 6.8.3: leaving Up
// re-applies the not-Up floor. That changes bfd.DesiredMinTxInterval, but with the remote
// discriminator gone there is no session left to poll, so no Poll Sequence starts and one in
// flight ends. Otherwise every Down packet would carry the Poll bit next to a zero Your
// Discriminator, asking an unbound peer for a Final that may never come.
func Test_RxPacketLeavingUpRefloorsWithoutPollSequence(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	defer p.Stop()

	// Set up Up state directly, as Test_RxPacketRemoteDownResetsPeer does.
	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_UP))
	p.yourDiscriminator = 12345
	p.desiredMinTx = 200 * time.Millisecond
	p.pollSequence = true

	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      67890,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})

	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, p.sessionState())
	assert.Equal(uint32(0), p.yourDiscriminator)
	assert.Equal(time.Second, p.desiredMinTx)
	assert.False(p.pollSequence)
}

// Test_RxPacketUpWithSlowConfigStartsNoPollSequence pins RFC 5880 Section 6.8.3: a Poll
// Sequence is only required when bfd.DesiredMinTxInterval actually changes. When the
// configured interval is already at or above the not-Up floor, reaching Up is a no-op change,
// so no Poll Sequence is initiated.
func Test_RxPacketUpWithSlowConfigStartsNoPollSequence(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 2000000, // 2s: already above the 1s floor
	}, "")
	defer p.Stop()

	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      111,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_INIT, api.BfdSessionState(p.state.Load()))

	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateUp,
		MyDiscriminator:      222,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_UP, api.BfdSessionState(p.state.Load()))
	assert.Equal(2*time.Second, p.desiredMinTx)
	assert.False(p.pollSequence)
}

// Test_RxPacketFinalThenUpOrdering pins the ordering of the Final check in rxPacket: it must
// run before the state-transition switch, as RFC 5880 Section 6.8.6 lists it. A packet that
// carries Final while taking us from Init to Up must not end the Poll Sequence that its own
// Up transition starts. With the Final check moved after the switch, pollSequence would be
// false here.
func Test_RxPacketFinalThenUpOrdering(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	defer p.Stop()

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_INIT))
	p.yourDiscriminator = 12345
	p.pollSequence = false

	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateUp,
		Final:                true,
		MyDiscriminator:      12345,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	})

	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_UP, p.sessionState())
	assert.Equal(200*time.Millisecond, p.desiredMinTx)
	assert.True(p.pollSequence)
}

// Test_RxPacketDetectionTimeFromRemote pins RFC 5880 Section 6.8.4: the detection time
// must be the remote Detect Mult multiplied by max(local RequiredMinRx,
// remote DesiredMinTx), not our own multiplier multiplied by our own rxInterval.
// With local rx=300ms/mult=3 and remote tx=1000ms, the old detector expired at
// 900ms, before the next remote packet. After the fix it stretches to 3000ms.
func Test_RxPacketDetectionTimeFromRemote(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   300000, // 300ms
		DesiredMinimumTxInterval: 300000,
	}, "")
	defer p.Stop()

	// Before any packet: our-config-only baseline (the old, buggy value).
	assert.Equal(3*300*time.Millisecond, p.expiryInterval)

	// Peer advertises a SLOWER cadence (BIRD default on the tap): tx=1000ms, mult=3.
	p.rxPacket(&bfd.BFDHeader{
		State:                 bfd.StateDown,
		MyDiscriminator:       111,
		YourDiscriminator:     p.myDiscriminator,
		DesiredMinTxInterval:  1000000, // 1000ms
		DetectTimeMultiplier:  3,
		RequiredMinRxInterval: 1000000,
	})
	// Detection must now track the peer: 3 * max(300ms, 1000ms) = 3000ms.
	assert.Equal(3*1000*time.Millisecond, p.expiryInterval)

	// RFC 5880 Section 6.8.6: a packet with Detect Mult == 0 MUST be discarded,
	// so it must NOT collapse the detector to a bogus value -- the previously
	// negotiated detection time stays in effect.
	p.rxPacket(&bfd.BFDHeader{
		State:             bfd.StateUp,
		MyDiscriminator:   111,
		YourDiscriminator: p.myDiscriminator,
	})
	assert.Equal(3*1000*time.Millisecond, p.expiryInterval)
	assert.Equal(uint64(1), p.stats.invalidMultiplier.Load())
}

func Test_RxPacketZeroMultiplierDiscarded(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   300000,
		DesiredMinimumTxInterval: 300000,
	}, "")
	defer p.Stop()

	// RFC 5880 Section 6.8.6: Detect Mult == 0 MUST be discarded before it can
	// drive any state transition or reset the detection timer.
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      111,
		YourDiscriminator:    p.myDiscriminator,
		DesiredMinTxInterval: 1000000,
		DetectTimeMultiplier: 0,
	})
	assert.Equal(uint64(1), p.stats.invalidMultiplier.Load())
	assert.Equal(uint64(0), p.stats.rxPacket.Load())
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, p.sessionState())
}

func Test_RxPacketUnboundDiscriminatorDiscarded(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   300000,
		DesiredMinimumTxInterval: 300000,
	}, "")
	defer p.Stop()

	// RFC 5880 Section 6.8.6: a zero Your Discriminator is only meaningful
	// from a remote system in Down or AdminDown. Init carries no session
	// binding here, so it must not drive the session Up.
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateInit,
		MyDiscriminator:      111,
		YourDiscriminator:    0,
		DetectTimeMultiplier: 3,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, p.sessionState())
	assert.Equal(uint64(1), p.stats.invalidDiscriminator.Load())

	// RFC 5880 Section 6.8.6: a zero My Discriminator MUST be discarded. It
	// is also the value setStateDown uses to mean "no remote session".
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      0,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 3,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, p.sessionState())
	assert.Equal(uint32(0), p.yourDiscriminator)
	assert.Equal(uint64(2), p.stats.invalidDiscriminator.Load())

	// A Down packet with a zero Your Discriminator is still accepted: that is
	// how a remote system that has not learned our discriminator starts up.
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      222,
		YourDiscriminator:    0,
		DetectTimeMultiplier: 3,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_INIT, p.sessionState())
	assert.Equal(uint32(222), p.yourDiscriminator)
}

func Test_RxPacketZeroYourDiscriminatorForeignRemoteDiscarded(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   300000,
		DesiredMinimumTxInterval: 300000,
	}, "")
	defer p.Stop()

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_UP))
	p.yourDiscriminator = 12345

	// The remote discriminator is already bound, so a Down packet that omits
	// Your Discriminator and carries a different My Discriminator did not come
	// from that remote system. Accepting it would reset the BGP peer.
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      67890,
		YourDiscriminator:    0,
		DetectTimeMultiplier: 3,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_UP, p.sessionState())
	assert.Equal(uint32(12345), p.yourDiscriminator)
	assert.Equal(int64(0), atomic.LoadInt64(&ps.resetPeerCount))
	assert.Equal(uint64(1), p.stats.invalidDiscriminator.Load())

	// The bound remote system may still omit Your Discriminator when it
	// signals Down, and that packet has to be honored.
	p.rxPacket(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      12345,
		YourDiscriminator:    0,
		DetectTimeMultiplier: 3,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, p.sessionState())
	assert.Equal(int64(1), atomic.LoadInt64(&ps.resetPeerCount))
}

func Test_ExpiryDoesNotResetAlreadyDownPeer(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:    13784,
		Enabled: true,
	}, "")
	defer p.Stop()

	p.setStateDown()
	p.expiry()

	assert.Equal(int64(0), atomic.LoadInt64(&ps.resetPeerCount))
}

// Test_JitteredTxInterval pins RFC 5880 Section 6.8.7: the transmit interval
// must be reduced per packet by a random value of 0 to 25%, and when the
// detect multiplier is 1, the interval must fall within 75%-90% of the
// negotiated interval rather than the full 75%-100% range. The interval being
// jittered is the Section 6.8.7 transmit interval (effectiveTxInterval), not
// the configured value. Each draw is a drawTxJitter call, as tx() makes one
// per transmission. The observed min/max across many draws must land exactly
// on those endpoints: hitting both inclusive endpoints, including the narrowed
// 90% ceiling, is what pins the bounds rather than merely containing them.
func Test_JitteredTxInterval(t *testing.T) {
	assert := assert.New(t)

	// multiplier > 1: bounds are [75%, 100%] of the transmit interval, here
	// carried by desiredMinTx alone (remoteMinRxInterval left at zero).
	p := &bfdPeer{multiplier: 3, desiredMinTx: 200 * time.Millisecond}

	minSeen, maxSeen := p.desiredMinTx, time.Duration(0)
	for range 1000 {
		p.drawTxJitter()
		d := p.jitteredTxInterval()
		if d < minSeen {
			minSeen = d
		}
		if d > maxSeen {
			maxSeen = d
		}
	}
	// 26 integer percentages in [75, 100], ~38.5 expected hits each in 1000
	// draws; the chance either endpoint is never drawn is about
	// (25/26)^1000 =~ 1e-17, so exact equality here is not flaky.
	assert.Equal(150*time.Millisecond, minSeen)
	assert.Equal(200*time.Millisecond, maxSeen)

	// multiplier == 1: bounds narrow to [75%, 90%] of the transmit interval.
	p1 := &bfdPeer{multiplier: 1, desiredMinTx: 200 * time.Millisecond}

	minSeen1, maxSeen1 := p1.desiredMinTx, time.Duration(0)
	for range 1000 {
		p1.drawTxJitter()
		d := p1.jitteredTxInterval()
		if d < minSeen1 {
			minSeen1 = d
		}
		if d > maxSeen1 {
			maxSeen1 = d
		}
	}
	// 16 integer percentages in [75, 90], ~62.5 expected hits each; the
	// chance either endpoint is missed across 1000 draws is about
	// (15/16)^1000 =~ 1e-28.
	assert.Equal(150*time.Millisecond, minSeen1)
	assert.Equal(180*time.Millisecond, maxSeen1)
}

// Test_JitteredTxIntervalFixedBetweenDraws pins that the jitter belongs to a
// transmission, not to a computation: between two drawTxJitter calls,
// jitteredTxInterval is deterministic and follows the transmit interval with the
// same percentage. armTx relies on this. If it drew afresh on every call, a
// stream of received packets would let the packet go out at the smallest draw
// seen since the last transmission, sinking the cadence toward the 75% floor.
func Test_JitteredTxIntervalFixedBetweenDraws(t *testing.T) {
	assert := assert.New(t)

	p := &bfdPeer{multiplier: 3, desiredMinTx: 200 * time.Millisecond}
	p.drawTxJitter()

	d := p.jitteredTxInterval()
	assert.GreaterOrEqual(d, 150*time.Millisecond)
	assert.LessOrEqual(d, 200*time.Millisecond)
	for range 100 {
		assert.Equal(d, p.jitteredTxInterval())
	}

	// The peer's requirement doubles the transmit interval: the same percentage
	// applies, so the jittered interval doubles exactly (200ms*pct/100 and
	// 400ms*pct/100 are both whole milliseconds).
	p.remoteMinRxInterval = 400 * time.Millisecond
	assert.Equal(2*d, p.jitteredTxInterval())
	for range 100 {
		assert.Equal(2*d, p.jitteredTxInterval())
	}
}

// Test_TxPacketSlowWhileDown replaces the old Test_TxPacket, which asserted more than 3
// packets sent within 4 seconds at a 200ms configured interval. That assumed transmission
// never slows down, which RFC 5880 Section 6.8.3 forbids: a session that is not Up must pace
// at no faster than one second regardless of the configured interval. This observes the wire
// directly: a peer configured for 200ms but still Down must advertise DesiredMinTxInterval ==
// 1s and must not be caught transmitting faster than that.
func Test_TxPacketSlowWhileDown(t *testing.T) {
	assert := assert.New(t)

	conn, err := net.ListenPacket("udp", "127.0.0.1:14700")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     14700,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	defer p.Stop()

	// The peer only dials its UDP client after its 1s start ticker fires, so the first
	// periodic packet can land well after construction. Budget generously for two.
	deadline := time.Now().Add(8 * time.Second)
	buf := make([]byte, 64)
	var arrivals []time.Time
	var headers []bfd.BFDHeader

	for range 2 {
		assert.NoError(conn.SetReadDeadline(deadline))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("reading periodic packet: %v", err)
		}
		arrivals = append(arrivals, time.Now())

		var h bfd.BFDHeader
		assert.NoError(h.UnmarshalBinary(buf[:n]))
		headers = append(headers, h)
	}

	for _, h := range headers {
		assert.Equal(uint32(1000000), h.DesiredMinTxInterval)
		assert.Equal(bfd.StateDown, h.State)
	}

	// Lower bound only: each gap is a fresh jittered draw of the 1s floor, so it is
	// at least 750ms; 700ms leaves slack for receive-side scheduling and still fails
	// immediately at the old code's ~200ms cadence.
	assert.GreaterOrEqual(arrivals[1].Sub(arrivals[0]), 700*time.Millisecond)
}

// Test_PollReplyNeverSetsPollAndFinalTogether pins RFC 5880 Section 6.5: "A BFD Control packet
// MUST NOT have both the Poll (P) and Final (F) bits set." The immediate reply rxPacket sends
// for a received Poll sets Final and clears Poll.
func Test_PollReplyNeverSetsPollAndFinalTogether(t *testing.T) {
	assert := assert.New(t)

	conn, err := net.ListenPacket("udp", "127.0.0.1:14701")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     14701,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	defer p.Stop()

	buf := make([]byte, 64)

	// Wait for the first periodic packet so the UDP client is known to be dialed before
	// the Poll below is injected -- otherwise the immediate reply has nowhere to go.
	assert.NoError(conn.SetReadDeadline(time.Now().Add(8 * time.Second)))
	_, _, err = conn.ReadFrom(buf)
	assert.NoError(err)

	assert.True(p.Rx(&bfd.BFDHeader{
		State:                bfd.StateDown,
		Poll:                 true,
		MyDiscriminator:      111,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 5,
	}))

	deadline := time.Now().Add(8 * time.Second)
	for {
		assert.NoError(conn.SetReadDeadline(deadline))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("no Final packet observed before deadline: %v", err)
		}

		var h bfd.BFDHeader
		assert.NoError(h.UnmarshalBinary(buf[:n]))
		if h.Final {
			assert.False(h.Poll)
			return
		}
	}
}

// Test_TxPacketPollBitAndFastRestoreOnUp pins RFC 5880 Section 6.5 ("the Poll Sequence MUST
// be performed by setting the Poll (P) bit on those scheduled periodic transmissions") and
// Section 6.8.3's restore of the configured DesiredMinTxInterval on reaching Up. It fails if
// the P-bit propagation in tx() is reverted (the periodic Up packets below would carry
// Poll == false), or if nothing re-arms the timer on the transition to Up (the tx() call in
// setStateUp, or failing that the armTx at the end of rxPacket): the timer would stay at the
// 1s floor and the three Up packets would arrive far more than 1.5s apart instead of the
// ~400ms (state-change packet plus two 200ms ticks) the fix produces.
func Test_TxPacketPollBitAndFastRestoreOnUp(t *testing.T) {
	assert := assert.New(t)

	conn, err := net.ListenPacket("udp", "127.0.0.1:14702")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     14702,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	defer p.Stop()

	buf := make([]byte, 64)
	deadline := time.Now().Add(8 * time.Second)

	// Wait for the first periodic packet so the UDP client is known to be dialed before
	// the packets below are injected.
	assert.NoError(conn.SetReadDeadline(deadline))
	_, _, err = conn.ReadFrom(buf)
	assert.NoError(err)

	// The received DetectTimeMultiplier sets the detection time (Section 6.8.4): here
	// 20 x 200ms = 4s. That keeps expiry well after the three Up packets below are
	// collected, even on a slow test runner. The peer's own configured multiplier is
	// still 5; that value only goes out on the wire, and this test does not check it.

	// Down -> Init.
	assert.True(p.Rx(&bfd.BFDHeader{
		State:                bfd.StateDown,
		MyDiscriminator:      111,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 20,
	}))

	// Init -> Up: restores the configured 200ms interval and starts a Poll Sequence
	// (no Final is ever injected in this test, so the sequence stays in flight).
	assert.True(p.Rx(&bfd.BFDHeader{
		State:                bfd.StateInit,
		MyDiscriminator:      111,
		YourDiscriminator:    p.myDiscriminator,
		DetectTimeMultiplier: 20,
	}))

	// Collect the first three Up packets, skipping any pre-Up packets still in flight.
	var arrivals []time.Time
	var headers []bfd.BFDHeader
	for len(headers) < 3 {
		assert.NoError(conn.SetReadDeadline(deadline))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("reading Up packet: %v", err)
		}

		var h bfd.BFDHeader
		assert.NoError(h.UnmarshalBinary(buf[:n]))
		if h.State != bfd.StateUp {
			continue
		}
		arrivals = append(arrivals, time.Now())
		headers = append(headers, h)
	}

	for _, h := range headers {
		assert.True(h.Poll)
		assert.False(h.Final)
		assert.Equal(uint32(200000), h.DesiredMinTxInterval)
	}

	assert.Less(arrivals[2].Sub(arrivals[0]), 1500*time.Millisecond)
}

// Test_EffectiveTxIntervalAcrossStates pins the one RFC 5880 Section 6.8.7 formula
// both halves of this change feed: the transmit interval is the larger of
// bfd.DesiredMinTxInterval (which carries the Section 6.8.3 not-Up floor) and
// bfd.RemoteMinRxInterval (the peer's advertised Required Min RX Interval). It
// walks a session from Down through Init to Up with a peer whose requirement sits
// between our configured rate and the floor, and checks at every step that pacing
// and advertisement are different things: what we send at follows the formula,
// what we advertise (desiredMinTx) does not move with the peer's value.
//
// The peer is stopped before any packet is driven in, so rxPacket runs
// synchronously on the test goroutine with no loop goroutine left to race
// against; the transmit ticker keeps accepting Reset after Stop, and the sends go
// to the txDrop counter because the UDP client was never dialed.
func Test_EffectiveTxIntervalAcrossStates(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	p.Stop()

	// RFC 5880 Section 6.8.1: bfd.RemoteMinRxInterval MUST be initialized to 1.
	// While Down, the Section 6.8.3 floor is the larger term.
	assert.Equal(time.Microsecond, p.remoteMinRxInterval)
	assert.Equal(time.Second, p.desiredMinTx)
	assert.Equal(time.Second, p.effectiveTxInterval())

	rx := func(state bfd.StateType, remoteMinRx uint32) {
		p.rxPacket(&bfd.BFDHeader{
			State:                 state,
			MyDiscriminator:       111,
			YourDiscriminator:     p.myDiscriminator,
			DetectTimeMultiplier:  3,
			DesiredMinTxInterval:  1000000,
			RequiredMinRxInterval: remoteMinRx,
		})
	}

	// Down -> Init with the peer asking for 500ms: stored, but the 1s floor still
	// dominates while not Up, and what we advertise does not change.
	rx(bfd.StateDown, 500000)
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_INIT, p.sessionState())
	assert.Equal(500*time.Millisecond, p.remoteMinRxInterval)
	assert.Equal(time.Second, p.desiredMinTx)
	assert.Equal(time.Second, p.effectiveTxInterval())

	// Init -> Up lifts the floor: we now advertise the configured 200ms, but the
	// peer's 500ms is the larger term, so that is what we pace at.
	rx(bfd.StateInit, 500000)
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_UP, p.sessionState())
	assert.Equal(200*time.Millisecond, p.desiredMinTx)
	assert.Equal(200*time.Millisecond, p.txInterval)
	assert.Equal(500*time.Millisecond, p.effectiveTxInterval())

	// The peer relaxes to 100ms, below our configured rate: our own value is the
	// larger term.
	rx(bfd.StateUp, 100000)
	assert.Equal(100*time.Millisecond, p.remoteMinRxInterval)
	assert.Equal(200*time.Millisecond, p.effectiveTxInterval())

	// A zero advertised Required Min RX Interval is a conscious non-goal:
	// Section 6.8.7 zero-suppression is not implemented, so max() degrades to our
	// own rate.
	rx(bfd.StateUp, 0)
	assert.Equal(time.Duration(0), p.remoteMinRxInterval)
	assert.Equal(200*time.Millisecond, p.effectiveTxInterval())

	// Up -> Down re-applies the floor; the stored remote value survives (nothing in
	// the RFC resets bfd.RemoteMinRxInterval on a state change).
	rx(bfd.StateDown, 500000)
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, p.sessionState())
	assert.Equal(time.Second, p.desiredMinTx)
	assert.Equal(500*time.Millisecond, p.remoteMinRxInterval)
	assert.Equal(time.Second, p.effectiveTxInterval())
}

// Test_StateChangeTransmitsAtOnce pins RFC 5880 Section 6.8.7: a packet whose
// contents would differ from the previous one SHOULD be transmitted between the
// periodic transmissions, to communicate a state change more rapidly. Each
// transition sends exactly one packet as it happens; a packet that changes
// nothing sends none, because the transition's own send is the new anchor and
// the next deadline is at least 150ms away (75% of the 200ms interval).
//
// Same synchronous setup as Test_EffectiveTxIntervalAcrossStates: the peer is
// stopped first, and the sends land on the txDrop counter.
func Test_StateChangeTransmitsAtOnce(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	p.Stop()

	rx := func(state bfd.StateType) {
		p.rxPacket(pacingHeader(p, state, 200000))
	}
	before := txAttempts(p)

	// Down -> Init.
	rx(bfd.StateDown)
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_INIT, p.sessionState())
	assert.Equal(before+1, txAttempts(p))

	// Init -> Up.
	rx(bfd.StateInit)
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_UP, p.sessionState())
	assert.Equal(before+2, txAttempts(p))

	// Up -> Up: nothing changed, nothing is due, nothing is sent.
	rx(bfd.StateUp)
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_UP, p.sessionState())
	assert.Equal(before+2, txAttempts(p))

	// Up -> Down.
	rx(bfd.StateDown)
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, p.sessionState())
	assert.Equal(before+3, txAttempts(p))
	assert.Equal(int64(1), atomic.LoadInt64(&ps.resetPeerCount))
}

// txAttempts counts every periodic transmission attempt, including the drops made
// before the UDP client is dialed (the 1s start ticker) and write errors, so the
// pacing tests below observe the schedule rather than the socket.
func txAttempts(p *bfdPeer) uint64 {
	return p.stats.txPacket.Load() + p.stats.txError.Load() + p.stats.txDrop.Load()
}

// pacingHeader is the packet a remote in state `state` sends us: our discriminator
// bound, a 1s Desired Min TX Interval so the detection time is 3s (3 * 1s) and
// expiry cannot interfere with the pacing tests, and the given Required Min RX
// Interval.
func pacingHeader(p *bfdPeer, state bfd.StateType, remoteMinRx uint32) *bfd.BFDHeader {
	return &bfd.BFDHeader{
		State:                 state,
		MyDiscriminator:       111,
		YourDiscriminator:     p.myDiscriminator,
		DetectTimeMultiplier:  3,
		DesiredMinTxInterval:  1000000,
		RequiredMinRxInterval: remoteMinRx,
	}
}

// rxWait feeds one packet through Rx, the production entry point, retrying while
// the capacity-1 channel is full, and returns once the loop goroutine has
// started processing it (the rxPacket counter moves before the state machine
// runs, so callers that need a resulting state change wait for that state
// explicitly). The pacing tests need the session Up, and while it is not Up the
// Section 6.8.3 floor (1s) hides the fast configured intervals they measure with.
// Feeding through Rx also keeps rxPacket on the loop goroutine: tx() reads
// remoteMinRxInterval and writes lastTx there, so a direct rxPacket call from the
// test goroutine would race those fields for real.
func rxWait(t *testing.T, p *bfdPeer, h *bfd.BFDHeader) {
	t.Helper()
	before := p.stats.rxPacket.Load()
	for !p.Rx(h) {
		time.Sleep(time.Millisecond)
	}
	err := eventually(2*time.Second, func() error {
		if p.stats.rxPacket.Load() > before {
			return nil
		}
		return fmt.Errorf("must be: rxPacket > %d", before)
	})
	assert.NoError(t, err)
}

// waitState waits for the loop goroutine to have moved p into the given state.
func waitState(t *testing.T, p *bfdPeer, want api.BfdSessionState) {
	t.Helper()
	err := eventually(2*time.Second, func() error {
		if p.sessionState() == want {
			return nil
		}
		return fmt.Errorf("must be: state == %s", want)
	})
	assert.NoError(t, err)
}

// bringUp drives p from Down to Up through Rx with a peer advertising remoteMinRx.
func bringUp(t *testing.T, p *bfdPeer, remoteMinRx uint32) {
	t.Helper()
	rxWait(t, p, pacingHeader(p, bfd.StateDown, remoteMinRx))
	rxWait(t, p, pacingHeader(p, bfd.StateInit, remoteMinRx))
	waitState(t, p, api.BfdSessionState_BFD_SESSION_STATE_UP)
}

// Test_RxPacketTxPacingSlowsTransmission is a timing test for RFC 5880 Section
// 6.8.7: once the peer advertises a slower Required Min RX Interval than our
// configured tx rate, the actual transmit cadence must slow down, not just the
// bookkeeping fields.
func Test_RxPacketTxPacingSlowsTransmission(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   100000,
		DesiredMinimumTxInterval: 100000,
	}, "")
	constructedBy := time.Now()

	bringUp(t, p, 100000)

	// Wait for a couple of the fast 100ms tx attempts before changing the pacing.
	err := eventually(4*time.Second, func() error {
		if txAttempts(p) >= 2 {
			return nil
		}
		return fmt.Errorf("must be: txAttempts >= 2")
	})
	assert.NoError(err)

	// Re-arm the tx deadline to 1s.
	rxWait(t, p, pacingHeader(p, bfd.StateUp, 1000000))

	before := txAttempts(p)
	// The deadline is anchored at a lastTx at most ~100ms in the past and, with
	// the 25% jitter, is at least 750ms after it, so the earliest legal fire is
	// ~650ms away. Nothing may be sent inside the peer's new floor -- RFC 5880
	// Section 6.8.7's actual MUST is "never faster". A no-op armTx fires within
	// ~100ms of the advert and fails here.
	time.Sleep(500 * time.Millisecond)
	assert.Equal(before, txAttempts(p))

	time.Sleep(600 * time.Millisecond)
	// At most one deadline fire fits the full 1100ms window, plus scheduling
	// slack for one fire straddling the snapshot. A broken build still firing
	// every 75-100ms would produce roughly 11.
	assert.LessOrEqual(txAttempts(p)-before, uint64(2))

	p.Stop()

	// tx() must advance the pacing anchor: a frozen lastTx leaves the deadline
	// permanently overdue, so armTx would transmit on every received packet.
	// NewBfdPeer seeds lastTx before constructedBy is sampled, so only a real
	// tx() run can move it past constructedBy. Stop's shutdownWait.Wait() makes
	// this plain-field read safe.
	assert.True(p.lastTx.After(constructedBy), "tx() must advance the pacing anchor")
}

// Test_RxPacketTxPacingReducedIntervalSendsPromptly pins RFC 5880 Section 6.8.3's
// fifth paragraph: once a reduced Required Min RX Interval has already elapsed
// since the last transmission, the local system MUST send the next periodic
// packet as soon as practicable, not wait out the deadline that was armed under
// the old, larger interval.
func Test_RxPacketTxPacingReducedIntervalSendsPromptly(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   100000,
		DesiredMinimumTxInterval: 100000,
	}, "")

	bringUp(t, p, 100000)

	err := eventually(4*time.Second, func() error {
		if txAttempts(p) >= 2 {
			return nil
		}
		return fmt.Errorf("must be: txAttempts >= 2")
	})
	assert.NoError(err)

	// Widen the effective interval to 1s.
	rxWait(t, p, pacingHeader(p, bfd.StateUp, 1000000))

	// Let 400ms pass since that widening. The deadline armed above is at least
	// 750ms (the jittered 1s) after a lastTx at most ~100ms before the advert, so
	// it is still at least 250ms away.
	time.Sleep(400 * time.Millisecond)
	before := txAttempts(p)

	// Now the peer reduces its Required Min RX Interval to 300ms -- still above
	// our configured 100ms, so the effective interval becomes 300ms. That interval
	// has already elapsed since the last transmission, so Section 6.8.3 requires
	// sending the next packet as soon as practicable.
	sent := time.Now()
	for !p.Rx(pacingHeader(p, bfd.StateUp, 300000)) {
		time.Sleep(time.Millisecond)
	}

	// An overdue branch that leaves the timer alone fires only at the previously
	// armed deadline, at least ~250ms after sent, and fails this 150ms window.
	// The fix sends while processing the packet, microseconds after Rx enqueues
	// it.
	err = eventually(150*time.Millisecond, func() error {
		if txAttempts(p) > before {
			return nil
		}
		return fmt.Errorf("must be: txAttempts > before")
	})
	assert.NoError(err, "elapsed since reduced interval was received: %s", time.Since(sent))

	// The immediate send becomes the new anchor, so the cadence afterward is the
	// jittered 300ms effective interval (225-300ms), not the configured 100ms
	// (which would produce roughly 2-3 further attempts in this window). The
	// slack of one covers a fire straddling the snapshot.
	time.Sleep(200 * time.Millisecond)
	assert.LessOrEqual(txAttempts(p)-before, uint64(2))

	p.Stop()
}

// Test_RxPacketTxPacingStableUnderFastRxStream pins RFC 5880 Section 6.8.7's
// deadline-anchored pacing against the case a full-period Reset guard starves
// on: a peer that keeps changing its advertised Required Min RX Interval, while
// sending packets faster than our tx interval, cannot postpone transmission
// indefinitely. armTx re-arms only at the absolute deadline
// lastTx + jitteredTxInterval -- or sends at once when already due -- so the
// deadline is bounded by the largest effective interval seen since the last
// transmission regardless of how the advertised value flaps in between.
func Test_RxPacketTxPacingStableUnderFastRxStream(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   300000,
		DesiredMinimumTxInterval: 300000,
	}, "")

	bringUp(t, p, 300000)

	before := txAttempts(p)
	feedStart := time.Now()

	// Feed packets faster (every 50ms) than our 300ms tx interval for about 2
	// seconds, with the advertised Required Min RX Interval alternating between
	// two values that are BOTH ABOVE our tx interval. A full-period Reset on
	// every change would never let the ticker complete a period; deadline
	// anchoring must still transmit. Rx's return value is ignored: the cap-1
	// channel may drop a packet under load, which no assertion below depends on.
	for i := range 40 {
		time.Sleep(50 * time.Millisecond)

		remoteMinRx := uint32(400000)
		if i%2 == 1 {
			remoteMinRx = 500000
		}
		p.Rx(pacingHeader(p, bfd.StateUp, remoteMinRx))
	}

	after := txAttempts(p)
	elapsed := time.Since(feedStart)

	// Expect roughly 4-6 attempts at a jittered 400-500ms deadline cadence over
	// ~2s. A naive per-packet full Reset and a value-change guard both produce 0.
	assert.GreaterOrEqual(after-before, uint64(2))

	// Load-proof upper bound: the deadline cadence is at least 300ms (the 400ms
	// requirement less the 25% jitter), so the feed window fits elapsed/300ms
	// fires, plus slack for one straddling fire and one immediate overdue fire.
	// (A fixed bound would false-fail on a loaded machine, where the 50ms sleeps
	// stretch and lengthen the window.)
	assert.LessOrEqual(after-before, uint64(elapsed/(300*time.Millisecond))+2)

	p.Stop()

	// Stop's shutdownWait.Wait() is the happens-before edge that makes this
	// plain-field read of a loop-goroutine-owned value safe here. Robust to a
	// dropped final packet: whichever of the two alternating values landed last,
	// both exceed our configured interval.
	assert.Greater(p.remoteMinRxInterval, p.txInterval)
}

// Test_RxPacketTxPacingSurvivesRxFlood pins the overdue branch of armTx: once
// the deadline has passed, the overdue packet is sent at once and the anchor
// moves, so a flood gets at most one send per effective interval. A version
// that re-arms from the current instant (now + epsilon) without sending pushes
// the overdue fire out on every packet and starves transmission at high receive
// rates, exactly the failure deadline anchoring exists to prevent.
func Test_RxPacketTxPacingSurvivesRxFlood(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   300000,
		DesiredMinimumTxInterval: 300000,
	}, "")

	bringUp(t, p, 300000)

	before := txAttempts(p)
	feedStart := time.Now()

	// Flood unthrottled for 3s -- far past the ~1kHz threshold where a
	// now-anchored overdue clamp starves transmission -- alternating the
	// advertised Required Min RX Interval between two values above our tx
	// interval. Rx's return value is ignored: drops are fine, nothing below
	// depends on an exact rxPacket count.
	//
	// No sleep: on the dev box a requested 100us sleep actually took ~1.15ms
	// (867/s), below the ~1kHz threshold this test exists to clear. An
	// unthrottled loop is immune to OS sleep-granularity variance and runs at
	// millions of iterations/s, so it clears the threshold on any machine. The
	// two headers are built once and never mutated: rxPacket only reads a header
	// and the channel send just publishes the pointer, so re-sending the same one
	// is safe and avoids allocating millions of headers' worth of garbage.
	header400 := pacingHeader(p, bfd.StateUp, 400000)
	header500 := pacingHeader(p, bfd.StateUp, 500000)

	i := 0
	for time.Since(feedStart) < 3*time.Second {
		h := header400
		if i%2 == 1 {
			h = header500
		}
		i++

		p.Rx(h)
	}

	after := txAttempts(p)
	elapsed := time.Since(feedStart)

	// A now-anchored overdue clamp manages roughly 1 attempt per 3s under this
	// flood; deadline anchoring should still manage roughly 6-10 over ~3s at a
	// jittered 400-500ms cadence.
	assert.GreaterOrEqual(after-before, uint64(3))

	// Same load-proof upper bound as Test_RxPacketTxPacingStableUnderFastRxStream.
	assert.LessOrEqual(after-before, uint64(elapsed/(300*time.Millisecond))+2)

	p.Stop()
}

// Test_ExpiryRefloorsTxPacing pins the one path to Down that does not run through
// rxPacket: expiry. setStateDown raises desiredMinTx back to the Section 6.8.3 floor
// and transmits the change through tx(), which re-arms the timer for the floor; on
// this path nothing else would. A timer left at the Up cadence fires once more at
// the fast interval, one packet closer than Section 6.8.7 allows.
func Test_ExpiryRefloorsTxPacing(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")

	// The remote advertises 200ms, so once Up our detection time is 3 * 200ms = 600ms
	// and expiry follows shortly after the packets stop.
	header := func(state bfd.StateType) *bfd.BFDHeader {
		return &bfd.BFDHeader{
			State:                 state,
			MyDiscriminator:       111,
			YourDiscriminator:     p.myDiscriminator,
			DetectTimeMultiplier:  3,
			DesiredMinTxInterval:  200000,
			RequiredMinRxInterval: 200000,
		}
	}
	rxWait(t, p, header(bfd.StateDown))
	rxWait(t, p, header(bfd.StateInit))
	waitState(t, p, api.BfdSessionState_BFD_SESSION_STATE_UP)

	// No more packets: expiry takes the session Down.
	waitState(t, p, api.BfdSessionState_BFD_SESSION_STATE_DOWN)
	assert.Equal(int64(1), atomic.LoadInt64(&ps.resetPeerCount))

	// setStateDown stores the state before it sends the Down packet, so give the
	// loop goroutine a moment to get that send counted.
	time.Sleep(50 * time.Millisecond)

	// That Down packet is the new anchor and the floor is back, so the next packet
	// is at least the jittered 1s (750ms) away. Nothing may go out in the next
	// 400ms; a timer still at the Up cadence fires within 200ms.
	before := txAttempts(p)
	time.Sleep(400 * time.Millisecond)
	assert.Equal(before, txAttempts(p))

	p.Stop()
	assert.Equal(time.Second, p.desiredMinTx)
}
