package server

import (
	"fmt"
	"log/slog"
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

	p.Rx(&bfd.BFDHeader{DetectTimeMultiplier: 5})

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
	// so it must NOT collapse the detector to a bogus value — the previously
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

func Test_TxPacket(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")

	err := eventually(4*time.Second, func() error {
		if p.stats.txPacket.Load() > 3 {
			return nil
		}
		return fmt.Errorf("must be: txPacket > 3")
	})
	assert.NoError(err)

	p.Stop()
}
