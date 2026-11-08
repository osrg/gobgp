package server

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// scriptedPeer is the remote side of a connection collision: it plays the
// BGP messages of a peer by hand on two TCP connections.
type scriptedPeer struct {
	t   *testing.T
	asn uint32
	id  netip.Addr
}

func (p *scriptedPeer) write(c net.Conn, m *bgp.BGPMessage) {
	p.t.Helper()
	b, err := m.Serialize()
	require.NoError(p.t, err)
	_, err = c.Write(b)
	require.NoError(p.t, err)
}

func (p *scriptedPeer) open() *bgp.BGPMessage {
	p.t.Helper()
	m, err := bgp.NewBGPOpenMessage(uint16(p.asn), 90, p.id, []bgp.OptionParameterInterface{
		bgp.NewOptionParameterCapability([]bgp.ParameterCapabilityInterface{
			bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC),
			bgp.NewCapFourOctetASNumber(p.asn),
		}),
	})
	require.NoError(p.t, err)
	return m
}

// read returns the next BGP message on c.
func (p *scriptedPeer) read(c net.Conn) *bgp.BGPMessage {
	p.t.Helper()
	require.NoError(p.t, c.SetReadDeadline(time.Now().Add(10*time.Second)))
	hdr := make([]byte, bgp.BGP_HEADER_LENGTH)
	_, err := io.ReadFull(c, hdr)
	require.NoError(p.t, err)
	body := make([]byte, int(binary.BigEndian.Uint16(hdr[16:18]))-bgp.BGP_HEADER_LENGTH)
	_, err = io.ReadFull(c, body)
	require.NoError(p.t, err)
	m, err := bgp.ParseBGPMessage(append(hdr, body...))
	require.NoError(p.t, err)
	return m
}

func (p *scriptedPeer) expect(c net.Conn, typ uint8) *bgp.BGPMessage {
	p.t.Helper()
	m := p.read(c)
	require.Equal(p.t, typ, m.Header.Type, "message %v", m.Body)
	return m
}

// RFC 4271 Section 6.8 detects a collision when an OPEN arrives, so GoBGP
// must not close the peer's connection before the peer's OPEN arrived on it.
// Here GoBGP (dominant) gets the peer's OPEN on its own connection (A) first
// and is Established there, while the peer's connection (B) has no OPEN yet.
// FRR answers an early close of B by connecting again, and with graceful
// restart that new connection ends the session (BOOTy CI: two drops per
// fault). GoBGP keeps B open, answers the OPEN on B with Cease/Connection
// Collision Resolution, and the session on A stays: exactly one.
func TestCollisionLoserClosedOnlyAfterItsOpen(t *testing.T) {
	ctx := t.Context()
	lc := &net.ListenConfig{}
	peerL, err := lc.Listen(ctx, "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { peerL.Close() })
	l, err := lc.Listen(ctx, "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	gobgpPort := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())

	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: 65001, RouterId: "192.0.2.17", ListenPort: int32(gobgpPort), ListenAddresses: []string{"127.0.0.1"},
	}}))
	t.Cleanup(func() { _ = s.StopBgp(context.Background(), &api.StopBgpRequest{}) })
	p := &scriptedPeer{t: t, asn: 65002, id: netip.MustParseAddr("10.0.0.1")}
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65002},
		Transport: &api.Transport{RemotePort: uint32(peerL.Addr().(*net.TCPAddr).Port)},
		Timers:    &api.Timers{Config: &api.TimersConfig{IdleHoldTimeAfterReset: 1}},
	}}))

	a, err := peerL.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { a.Close() })
	p.expect(a, bgp.BGP_MSG_OPEN)
	b, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(gobgpPort)))
	require.NoError(t, err)
	t.Cleanup(func() { b.Close() })
	p.expect(b, bgp.BGP_MSG_OPEN) // GoBGP is in OpenSent on B

	w := newPeerStateWaiter(s, api.PeerState_SESSION_STATE_ESTABLISHED)
	oa, err := p.open().Serialize()
	require.NoError(t, err)
	ka, err := bgp.NewBGPKeepAliveMessage().Serialize()
	require.NoError(t, err)
	_, err = a.Write(append(oa, ka...))
	require.NoError(t, err)
	p.expect(a, bgp.BGP_MSG_KEEPALIVE)
	w.Wait(t, 5*time.Second)

	// B is still open: no message and no close before the peer's OPEN.
	require.NoError(t, b.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
	_, err = b.Read(make([]byte, 1))
	var ne net.Error
	require.ErrorAs(t, err, &ne, "GoBGP closed the peer's connection before its OPEN: %v", err)
	require.True(t, ne.Timeout())

	// The peer's OPEN on B: GoBGP closes B as the collision loser.
	p.write(b, p.open())
	m := p.expect(b, bgp.BGP_MSG_NOTIFICATION)
	n := m.Body.(*bgp.BGPNotification)
	require.Equal(t, uint8(bgp.BGP_ERROR_CEASE), n.ErrorCode)
	require.Equal(t, uint8(bgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION), n.ErrorSubcode)

	// Exactly one session, which stays up.
	var peer *api.Peer
	require.Never(t, func() bool {
		_ = s.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) { peer = p })
		return peer.GetState().GetSessionState() != api.PeerState_SESSION_STATE_ESTABLISHED
	}, 500*time.Millisecond, 20*time.Millisecond)
	var established uint32
	require.NoError(t, s.mgmtOperation(func() error {
		established = s.neighborMap[netip.MustParseAddr("127.0.0.1")].fsm.pConf.ReadOnly().State.EstablishedCount
		return nil
	}, false))
	require.Equal(t, uint32(1), established, "sessions established")
}

// loserOpensent runs opensent() on the incoming connection with GoBGP
// dominant (RFC 4271 Section 6.8). before is written on the incoming
// connection, then the peer's OPEN arrives on the outgoing connection, and
// the incoming connection loses the collision before the peer's OPEN
// arrived on it. It returns the incoming connection, a function that stops
// the handler, and a goleak option that ignores the goroutines that existed
// before opensent().
func loserOpensent(t *testing.T, before []byte, holdTime float64) (*peer, *MockConnection, context.CancelFunc, goleak.Option) {
	t.Helper()
	incoming := NewMockConnection()
	outgoing := NewMockConnection()
	p, h := makePeerAndHandler(incoming)
	t.Cleanup(func() {
		cleanPeerAndHandler(p, h)
		incoming.Close()
		outgoing.Close()
	})
	p.fsm.opensentHoldTime = holdTime
	p.fsm.gConf.Config.RouterId = netip.MustParseAddr("10.0.0.9")
	conf := p.fsm.pConf.ReadCopy()
	conf.Config.PeerAs = 65002
	p.fsm.pConf.Update(&conf)
	p.fsm.outgoingConnMgr = &outgoingConnManager{fsm: p.fsm}
	p.fsm.outgoingConnMgr.state.Store(bgp.BGP_FSM_OPENSENT)
	open, err := bgp.NewBGPOpenMessage(65002, 90, netip.MustParseAddr("10.0.0.1"), nil)
	require.NoError(t, err)

	baseline := goleak.IgnoreCurrent()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan bgp.FSMState, 1)
	go func() {
		state, _ := h.opensent(ctx)
		done <- state
	}()
	if len(before) > 0 {
		// net.Pipe: Write returns when the recv goroutine has read it.
		_, err = incoming.remote.Write(before)
		require.NoError(t, err)
	}
	p.fsm.outgoingConnCh <- outgoingConn{conn: outgoing, open: open}
	select {
	case state := <-done:
		require.Equal(t, bgp.BGP_FSM_OPENCONFIRM, state)
	case <-time.After(5 * time.Second):
		t.Fatal("the OpenSent handler did not return")
	}
	require.Same(t, outgoing, p.fsm.conn)
	require.Empty(t, incoming.GetSentMessages(), "the losing connection got an answer before the peer sent anything")
	return p, incoming, cancel, baseline
}

// The losing connection answers the first message on it as OpenSent does
// (RFC 4271 Section 8.2.2), a valid OPEN with Cease/Connection Collision
// Resolution, without touching the counters of the session on the other
// connection.
func TestCollisionLoserAnswers(t *testing.T) {
	open := func(as uint16) []byte {
		m, err := bgp.NewBGPOpenMessage(as, 90, netip.MustParseAddr("10.0.0.1"), nil)
		require.NoError(t, err)
		return mustSerialize(t, m)
	}
	ob := open(65002)
	for _, tt := range []struct {
		name   string
		before []byte // on the losing connection before the collision
		after  []byte // and after it
		// the NOTIFICATION that GoBGP sends, none for nil
		want []uint8
	}{
		{"open", nil, ob, []uint8{bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION}},
		// The OPEN header arrives before the collision and the body after
		// it: the message is not cut, it is an OPEN.
		{"split open", ob[:bgp.BGP_HEADER_LENGTH], ob[bgp.BGP_HEADER_LENGTH:], []uint8{bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION}},
		// An invalid OPEN gets its OPEN Message Error, not the Cease.
		{"bad peer as", nil, open(65003), []uint8{bgp.BGP_ERROR_OPEN_MESSAGE_ERROR, bgp.BGP_ERROR_SUB_BAD_PEER_AS}},
		{"keepalive", nil, mustSerialize(t, bgp.NewBGPKeepAliveMessage()), []uint8{bgp.BGP_ERROR_FSM_ERROR, 1}},
		// RFC 4271 Section 8.2.2, OpenSent, Event 24: no answer.
		{"version error", nil, mustSerialize(t, bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_OPEN_MESSAGE_ERROR, bgp.BGP_ERROR_SUB_UNSUPPORTED_VERSION_NUMBER, nil)), nil},
		{"cease", nil, mustSerialize(t, bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION, nil)), []uint8{bgp.BGP_ERROR_FSM_ERROR, 1}},
		// RFC 4271 Section 6.1: a header without the all-ones marker.
		{"bad marker", nil, append(make([]byte, 16), 0, 19, bgp.BGP_MSG_KEEPALIVE), []uint8{bgp.BGP_ERROR_MESSAGE_HEADER_ERROR, bgp.BGP_ERROR_SUB_CONNECTION_NOT_SYNCHRONIZED}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, in, _, baseline := loserOpensent(t, tt.before, 10)
			sent := atomic.LoadUint64(&p.fsm.counterStats.Sent.Notification)
			_, err := in.remote.Write(tt.after)
			require.NoError(t, err)
			// The goroutine that keeps the connection ends after the
			// answer.
			goleak.VerifyNone(t, baseline)
			msgs := in.GetSentMessages()
			if tt.want == nil {
				require.Empty(t, msgs, "GoBGP answered")
			} else {
				require.Len(t, msgs, 1)
				m, err := bgp.ParseBGPMessage(msgs[0])
				require.NoError(t, err)
				require.Equal(t, uint8(bgp.BGP_MSG_NOTIFICATION), m.Header.Type)
				n := m.Body.(*bgp.BGPNotification)
				require.Equal(t, tt.want, []uint8{n.ErrorCode, n.ErrorSubcode})
			}
			require.Equal(t, sent, atomic.LoadUint64(&p.fsm.counterStats.Sent.Notification), "the session's NOTIFICATION counter changed")
		})
	}
}

// The losing connection is closed without an answer, and the goroutine
// that keeps it ends, when the peer closes it, when the handler stops and
// when the OpenSent hold time expires.
func TestCollisionLoserEnds(t *testing.T) {
	t.Run("peer closes", func(t *testing.T) {
		_, in, _, baseline := loserOpensent(t, nil, 10)
		require.NoError(t, in.remote.Close())
		goleak.VerifyNone(t, baseline)
	})
	t.Run("handler stops", func(t *testing.T) {
		_, in, cancel, baseline := loserOpensent(t, nil, 10)
		cancel()
		goleak.VerifyNone(t, baseline)
		require.Empty(t, in.GetSentMessages())
		_, err := in.remote.Write([]byte{0})
		require.ErrorIs(t, err, io.ErrClosedPipe)
	})
	t.Run("hold time", func(t *testing.T) {
		_, in, _, baseline := loserOpensent(t, nil, 1)
		require.Eventually(t, func() bool { return goleak.Find(baseline) == nil }, 5*time.Second, 100*time.Millisecond)
		require.Empty(t, in.GetSentMessages())
		_, err := in.remote.Write([]byte{0})
		require.ErrorIs(t, err, io.ErrClosedPipe)
	})
}

func mustSerialize(t *testing.T, m *bgp.BGPMessage) []byte {
	t.Helper()
	b, err := m.Serialize()
	require.NoError(t, err)
	return b
}
