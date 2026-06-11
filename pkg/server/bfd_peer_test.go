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

	p.Rx(&bfd.BFDHeader{})

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
		State:             bfd.StateDown,
		MyDiscriminator:   67890,
		YourDiscriminator: p.myDiscriminator,
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
		State:             bfd.StateDown,
		MyDiscriminator:   111,
		YourDiscriminator: p.myDiscriminator,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_INIT, api.BfdSessionState(p.state.Load()))
	assert.Equal(uint32(111), p.yourDiscriminator)

	p.setStateDown()
	p.rxPacket(&bfd.BFDHeader{
		State:             bfd.StateUp,
		MyDiscriminator:   222,
		YourDiscriminator: p.myDiscriminator,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_DOWN, api.BfdSessionState(p.state.Load()))

	p.setStateInit(333)
	p.rxPacket(&bfd.BFDHeader{
		State:             bfd.StateUp,
		MyDiscriminator:   444,
		YourDiscriminator: p.myDiscriminator,
	})
	assert.Equal(api.BfdSessionState_BFD_SESSION_STATE_UP, api.BfdSessionState(p.state.Load()))
	assert.Equal(uint32(444), p.yourDiscriminator)
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
