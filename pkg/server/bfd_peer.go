package server

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bfd"
)

const (
	// https://datatracker.ietf.org/doc/html/rfc5881
	//   The source port MUST be in the range 49152 through 65535
	bfdSourcePortMin = 49152
	bfdSourcePortMax = 65535

	// Some default values
	defaultMultiplier = 3
	defaultRxInterval = 1000 * time.Millisecond
	defaultTxInterval = 1000 * time.Millisecond
)

type bfdPeerStats struct {
	rxPacket             atomic.Uint64
	txPacket             atomic.Uint64
	txDrop               atomic.Uint64
	txError              atomic.Uint64
	invalidDiscriminator atomic.Uint64
	expired              atomic.Uint64
	badInitPacket        atomic.Uint64
}

type bfdPeer struct {
	peerState   peerState
	logger      *slog.Logger
	peerAddress string
	peerPort    int

	udpClient *net.UDPConn

	expiryInterval time.Duration

	state             atomic.Int32
	myDiscriminator   uint32
	yourDiscriminator uint32
	multiplier        uint8
	rxInterval        time.Duration
	txInterval        time.Duration

	eventStart    *time.Ticker
	eventRxPacket chan *bfd.BFDHeader
	eventTx       *time.Ticker
	eventExpiry   *time.Ticker
	eventShutdown chan struct{}

	stats bfdPeerStats
}

func NewBfdPeer(ps peerState, logger *slog.Logger, peerAddress string, config oc.BfdConfig) *bfdPeer {
	p := &bfdPeer{
		peerState:   ps,
		logger:      logger,
		peerAddress: peerAddress,
		peerPort:    int(config.Port),

		myDiscriminator: randomBFDMyDiscriminator(),
		multiplier:      defaultMultiplier,
		rxInterval:      defaultRxInterval,
		txInterval:      defaultTxInterval,

		eventStart:    time.NewTicker(time.Second),
		eventRxPacket: make(chan *bfd.BFDHeader, 1),
		eventShutdown: make(chan struct{}),
	}

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_DOWN))

	if config.DetectionMultiplier > 0 {
		p.multiplier = config.DetectionMultiplier
	}

	if config.RequiredMinimumReceive > 0 {
		p.rxInterval = time.Duration(config.RequiredMinimumReceive) * time.Microsecond
	}

	if config.DesiredMinimumTxInterval > 0 {
		p.txInterval = time.Duration(config.DesiredMinimumTxInterval) * time.Microsecond
	}

	p.expiryInterval = time.Duration(p.multiplier) * p.rxInterval
	p.eventTx = time.NewTicker(p.txInterval)

	p.eventExpiry = time.NewTicker(p.expiryInterval)
	p.eventExpiry.Stop()

	go p.loop()
	return p
}

func (p *bfdPeer) Rx(packet *bfd.BFDHeader) bool {
	select {
	case p.eventRxPacket <- packet:
		return true
	default:
		return false
	}
}

func (p *bfdPeer) Stop() {
	close(p.eventShutdown)
}

func (p *bfdPeer) loop() {
	for {
		select {
		case <-p.eventStart.C:
			success := p.start()
			if success {
				p.eventStart.Stop()
			}
		case bfdPacket := <-p.eventRxPacket:
			p.rxPacket(bfdPacket)
		case <-p.eventTx.C:
			p.tx()
		case <-p.eventExpiry.C:
			p.expiry()
		case <-p.eventShutdown:
			p.shutdown()
			return
		}
	}
}

func (p *bfdPeer) start() bool {
	if p.udpClient == nil {
		p.startClient()
	}

	return p.udpClient != nil
}

func (p *bfdPeer) stop() {
	if p.udpClient == nil {
		return
	}

	err := p.udpClient.Close()
	if err != nil {
		p.logger.Warn("Can't close UDP",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress),
		)
	}

	p.udpClient = nil

	p.logger.Debug("BFD client is stopped",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress),
	)
}

func (p *bfdPeer) startClient() {
	localAddress := &net.UDPAddr{
		Port: randRange(bfdSourcePortMin, bfdSourcePortMax),
	}

	remoteAddress := &net.UDPAddr{
		IP:   net.ParseIP(p.peerAddress),
		Port: p.peerPort,
	}

	var err error
	p.udpClient, err = net.DialUDP("udp", localAddress, remoteAddress)
	if err != nil {
		p.logger.Warn("Can't dial UDP",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress),
			slog.String("LocalAddress", localAddress.String()),
			slog.String("RemoteAddress", remoteAddress.String()),
			slog.Any("Error", err),
		)

		return
	}

	// https://datatracker.ietf.org/doc/html/rfc5881
	//   If BFD authentication is not in use on a session, all BFD Control
	//   packets for the session MUST be sent with a Time to Live (TTL) or Hop
	//   Limit value of 255
	err = netutils.SetUDPTTLSockopt(p.udpClient, 255)
	if err != nil {
		p.logger.Error("Can't set TTL to 255",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress),
			slog.String("LocalAddress", localAddress.String()),
			slog.String("RemoteAddress", remoteAddress.String()),
			slog.Any("Error", err),
		)

		err = p.udpClient.Close()
		if err != nil {
			p.logger.Warn("Can't close UDP",
				slog.String("Topic", "bfd"),
				slog.String("Peer", p.peerAddress),
			)
		}

		p.udpClient = nil
		return
	}

	p.logger.Debug("BFD client is started",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress),
		slog.String("LocalAddress", localAddress.String()),
		slog.String("RemoteAddress", remoteAddress.String()),
	)
}

func (p *bfdPeer) rxPacket(h *bfd.BFDHeader) {
	if h.YourDiscriminator != 0 && h.YourDiscriminator != p.myDiscriminator {
		p.stats.invalidDiscriminator.Add(1)
		return
	}

	p.stats.rxPacket.Add(1)

	// NOTE: remote DesiredMinTxInterval and RequiredMinRxInterval ignored

	switch h.State {
	case bfd.StateDown:
		p.sendPacket(bfd.StateInit, false, false, h.MyDiscriminator)
	case bfd.StateInit:
		if api.BfdSessionState(p.state.Load()) == api.BfdSessionState_BFD_SESSION_STATE_UP {
			p.stats.badInitPacket.Add(1)
			return
		}

		p.setStateUp(h.MyDiscriminator)
	case bfd.StateUp:
		if api.BfdSessionState(p.state.Load()) != api.BfdSessionState_BFD_SESSION_STATE_UP {
			p.setStateUp(h.MyDiscriminator)
		}

		if h.Poll {
			// send final packet
			p.sendPacket(bfd.StateUp, false, true, h.MyDiscriminator)
		}

		p.eventExpiry.Reset(p.expiryInterval)
	}
}

func (p *bfdPeer) tx() {
	if api.BfdSessionState(p.state.Load()) == api.BfdSessionState_BFD_SESSION_STATE_UP {
		p.sendPacket(bfd.StateUp, false, false, p.yourDiscriminator)
	} else {
		p.sendPacket(bfd.StateDown, false, false, 0)
	}
}

func (p *bfdPeer) expiry() {
	p.logger.Warn("Expired",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress),
	)

	if err := p.peerState.ResetPeer(context.Background(), &api.ResetPeerRequest{
		Address:       p.peerAddress,
		Communication: "BFD is down",
		Soft:          false,
	}); err != nil {
		p.logger.Warn("ResetPeer failed",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress),
			slog.String("Err", err.Error()),
		)
	}

	p.stats.expired.Add(1)

	p.setStateDown()
}

func (p *bfdPeer) shutdown() {
	p.stop()
	p.eventTx.Stop()
	p.eventExpiry.Stop()
}

func (p *bfdPeer) sendPacket(state bfd.StateType, poll bool, final bool, yourDiscriminator uint32) {
	if p.udpClient == nil {
		p.stats.txDrop.Add(1)
		return
	}

	packet := &bfd.BFDHeader{
		Version:               1,
		State:                 state,
		Poll:                  poll,
		Final:                 final,
		DetectTimeMultiplier:  p.multiplier,
		MyDiscriminator:       p.myDiscriminator,
		YourDiscriminator:     yourDiscriminator,
		DesiredMinTxInterval:  uint32(p.txInterval.Microseconds()),
		RequiredMinRxInterval: uint32(p.rxInterval.Microseconds()),
	}

	buffer, err := packet.MarshalBinary()
	if err != nil {
		// should never happen
		p.logger.Error("MarshalBinary",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress),
		)
		return
	}

	_, err = p.udpClient.Write(buffer)
	if err != nil {
		p.logger.Debug("Can't send UDP packet",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress),
		)

		p.stats.txError.Add(1)
		return
	}

	p.stats.txPacket.Add(1)
}

func (p *bfdPeer) setStateDown() {
	p.logger.Debug("Set state to DOWN",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress),
	)

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_DOWN))
	p.yourDiscriminator = 0

	p.eventExpiry.Stop()
}

func (p *bfdPeer) setStateUp(yourDiscriminator uint32) {
	p.logger.Debug("Set state to UP",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress),
	)

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_UP))
	p.yourDiscriminator = yourDiscriminator

	p.eventExpiry.Reset(p.expiryInterval)

	// send poll packet
	p.sendPacket(bfd.StateUp, true, false, yourDiscriminator)
}
