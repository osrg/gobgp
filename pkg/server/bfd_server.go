// This is partial implementation of BFD protocol (https://datatracker.ietf.org/doc/html/rfc5880)
// only for fast detection of connection failures between BGP peers.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bfd"
)

// bfdMultihopPort is the RFC 5883 (multihop BFD) UDP control port. The server
// listens on it in addition to the single-hop control port (s.config.Port, the
// RFC 5881 port 3784) so it can receive returns from multihop peers; a peer runs
// multihop by sending to this port (its BfdPeerConfig.Port = 4784). Dispatch is
// by source IP, so a single rxPacket path handles both single-hop and multihop.
const bfdMultihopPort uint16 = 4784

type bfdServerStats struct {
	rxPacket      atomic.Uint64
	rxDrop        atomic.Uint64
	rxError       atomic.Uint64
	invalidPacket atomic.Uint64
	unknownPeer   atomic.Uint64
}

type bfdEventPeerUpdate struct {
	isAdd         bool
	peerAddress   netip.Addr
	config        oc.BfdConfig
	bindInterface string
}

type bfdPeerState struct {
	peerAddress netip.Addr
	state       api.BfdPeerState
}

type peerState interface {
	ResetPeer(ctx context.Context, r *api.ResetPeerRequest) error
}

type bfdServer struct {
	peerState peerState
	logger    *slog.Logger

	config *oc.BfdConfig

	// listenAddrs are the global BGP listen addresses. When non-empty the BFD
	// server binds its control sockets to each SPECIFIC address (e.g.
	// 10.0.0.1:4784) instead of the wildcard (:4784). A specific bind wins the
	// kernel's most-specific-match UDP demux over any wildcard listener already on
	// the port (e.g. a host bfdd owning 0.0.0.0:3784/4784), so an embedded GoBGP
	// can run BFD on a host that also runs a system bfdd. Empty → wildcard bind.
	listenAddrs []string

	udpServers      []*net.UDPConn
	listenInterface string

	peersMutex sync.RWMutex
	peers      map[netip.Addr]*bfdPeer

	eventStartStop  *time.Ticker
	eventConfig     chan *oc.BfdConfig
	eventPeerUpdate chan *bfdEventPeerUpdate
	eventShutdown   chan struct{}
	shutdownOnce    sync.Once
	stopped         atomic.Bool

	shutdownWait sync.WaitGroup

	serverStop chan struct{}
	serverWait sync.WaitGroup

	stats bfdServerStats
}

func NewBfdServer(ps peerState, logger *slog.Logger) *bfdServer {
	s := &bfdServer{
		peerState: ps,
		logger:    logger,

		peers: make(map[netip.Addr]*bfdPeer),

		eventStartStop:  time.NewTicker(time.Second),
		eventConfig:     make(chan *oc.BfdConfig, 1),
		eventPeerUpdate: make(chan *bfdEventPeerUpdate, 1),
		eventShutdown:   make(chan struct{}),
	}

	s.shutdownWait.Add(1)
	go s.loop()
	return s
}

func (s *bfdServer) Start(ctx context.Context, config oc.BfdConfig) error {
	if s.stopped.Load() {
		return errors.New("bfd server stopped")
	}

	select {
	case s.eventConfig <- &config:
		if s.stopped.Load() {
			return errors.New("bfd server stopped")
		}

		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.eventShutdown:
		return errors.New("bfd server stopped")
	}
}

func (s *bfdServer) Stop() {
	s.shutdownOnce.Do(func() {
		s.stopped.Store(true)
		close(s.eventShutdown)
		s.shutdownWait.Wait()
	})
}

func (s *bfdServer) AddPeer(ctx context.Context, peerAddress netip.Addr, config oc.BfdConfig, bindInterface string) error {
	if s.stopped.Load() {
		return errors.New("bfd server stopped")
	}

	if !config.Enabled {
		return nil
	}

	select {
	case s.eventPeerUpdate <- &bfdEventPeerUpdate{isAdd: true, peerAddress: peerAddress, config: config, bindInterface: bindInterface}:
		if s.stopped.Load() {
			return errors.New("bfd server stopped")
		}

		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.eventShutdown:
		return errors.New("bfd server stopped")
	}
}

func (s *bfdServer) DeletePeer(ctx context.Context, peerAddress netip.Addr) error {
	if s.stopped.Load() {
		return errors.New("bfd server stopped")
	}

	select {
	case s.eventPeerUpdate <- &bfdEventPeerUpdate{isAdd: false, peerAddress: peerAddress}:
		if s.stopped.Load() {
			return errors.New("bfd server stopped")
		}

		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.eventShutdown:
		return errors.New("bfd server stopped")
	}
}

func (s *bfdServer) GetPeerState(peerAddress netip.Addr) (*bfdPeerState, error) {
	state := s.getPeerState(peerAddress)
	if state == nil {
		return nil, errors.New("peer not found")
	}
	return state, nil
}

func (s *bfdServer) GetPeerStateList() []*bfdPeerState {
	return s.getPeerStateList()
}

func (s *bfdServer) GetServerStats() *api.BfdState {
	return &api.BfdState{
		ReceivedPacket: s.stats.rxPacket.Load(),
		ReceivedDrop:   s.stats.rxDrop.Load(),
		ReceivedError:  s.stats.rxError.Load(),
		InvalidPacket:  s.stats.invalidPacket.Load(),
		UnknownPeer:    s.stats.unknownPeer.Load(),
	}
}

func (s *bfdServer) loop() {
	defer s.shutdownWait.Done()

	for {
		select {
		case <-s.eventStartStop.C:
			success := true

			s.peersMutex.RLock()
			peersLen := len(s.peers)
			s.peersMutex.RUnlock()

			if peersLen > 0 {
				success = s.start()
			} else {
				s.stop()
			}

			if success {
				s.eventStartStop.Stop()
			}
		case ev := <-s.eventConfig:
			s.config = ev
		case ev := <-s.eventPeerUpdate:
			if ev.isAdd {
				s.addBfdPeer(ev.peerAddress, ev.config, ev.bindInterface)
			} else {
				s.deleteBfdPeer(ev.peerAddress)
			}

			s.eventStartStop.Reset(time.Second)
		case <-s.eventShutdown:
			s.shutdown()
			return
		}
	}
}

func (s *bfdServer) start() bool {
	if len(s.udpServers) == 0 {
		return s.startServer()
	}

	return len(s.udpServers) > 0
}

// startServer binds the BFD listeners and reports whether the server is ready.
//
// The single-hop control port (s.config.Port, RFC 5881) is required: it must
// bind on every configured listen address, otherwise we cannot reliably receive
// single-hop returns and startServer rolls back and reports failure so the
// caller retries. The multihop control port (RFC 5883/4784) is best-effort — it
// is commonly already owned by a host BFD daemon — so a failure there is logged
// but does not, on its own, fail startup.
func (s *bfdServer) startServer() bool {
	if s.config == nil {
		// BFD server not configured
		return false
	}

	// Listen on the single-hop control port (s.config.Port, RFC 5881) AND the
	// multihop control port (RFC 5883/4784), so the server receives returns from
	// both single-hop and multihop peers. rxPacket dispatches by source IP, so it
	// does not matter which socket a packet arrived on.
	primaryPort := s.config.Port
	ports := []uint16{primaryPort}
	if primaryPort != bfdMultihopPort {
		ports = append(ports, bfdMultihopPort)
	}

	var lc net.ListenConfig
	lc.Control = func(network, address string, sc syscall.RawConn) error {
		if s.listenInterface != "" {
			s.logger.Info("binding bfd listener to interface", slog.String("interface", s.listenInterface))
			if err := netutils.SetBindToDevSockopt(sc, s.listenInterface); err != nil {
				return err
			}
		}

		return netutils.SetReuseAddrSockopt(sc)
	}

	// Bind each port on each specific listen address (so a host bfdd's wildcard
	// listener does not steal our returns), or once on the wildcard when no
	// specific address is configured.
	hosts := s.listenAddrs
	if len(hosts) == 0 {
		hosts = []string{""}
	}

	s.serverStop = make(chan struct{})
	primaryBound := 0
	for _, port := range ports {
		for _, host := range hosts {
			addressString := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))

			l, err := lc.ListenPacket(context.Background(), "udp", addressString)
			if err != nil {
				s.logger.Error("Can't listen UDP",
					slog.String("Topic", "bfd"),
					slog.String("Address", addressString),
					slog.Any("Error", err),
				)
				continue
			}

			conn, ok := l.(*net.UDPConn)
			if !ok {
				s.logger.Error("Unexpected connection listener",
					slog.String("Topic", "bfd"),
					slog.String("Address", addressString),
				)
				_ = l.Close()
				continue
			}

			s.udpServers = append(s.udpServers, conn)
			s.serverWait.Add(1)
			go s.serverLoop(conn)
			if port == primaryPort {
				primaryBound++
			}

			s.logger.Info("BFD server is started",
				slog.String("Topic", "bfd"),
				slog.String("Address", addressString),
			)
		}
	}

	// The single-hop port must have bound on every configured listen address.
	// A partial bind here means we cannot reliably receive single-hop returns,
	// so roll back every listener (including any best-effort multihop sockets)
	// and report failure; the caller retries on the next tick.
	if primaryBound < len(hosts) {
		s.logger.Error("Can't listen on BFD single-hop port; retrying",
			slog.String("Topic", "bfd"),
			slog.Int("Port", int(primaryPort)),
			slog.Int("Bound", primaryBound),
			slog.Int("Wanted", len(hosts)),
		)
		s.stop()
		return false
	}

	return true
}

func (s *bfdServer) stop() {
	if len(s.udpServers) == 0 {
		return
	}

	close(s.serverStop)
	for _, conn := range s.udpServers {
		conn.Close()
	}
	s.serverWait.Wait()
	s.udpServers = nil

	s.logger.Info("BFD server is stopped",
		slog.String("Topic", "bfd"),
	)
}

func (s *bfdServer) addBfdPeer(peerAddress netip.Addr, config oc.BfdConfig, bindInterface string) {
	s.peersMutex.RLock()
	_, ok := s.peers[peerAddress]
	s.peersMutex.RUnlock()

	if ok {
		s.logger.Debug("BFD peer already exist",
			slog.String("Topic", "bfd"),
			slog.String("Peer", peerAddress.String()),
		)

		return
	}

	bfdPeer := NewBfdPeer(s.peerState, s.logger, peerAddress, config, bindInterface)
	if bfdPeer != nil {
		s.logger.Info("Insert BFD peer",
			slog.String("Topic", "bfd"),
			slog.String("Peer", peerAddress.String()),
		)

		s.peersMutex.Lock()
		s.peers[peerAddress] = bfdPeer
		s.peersMutex.Unlock()
	}
}

func (s *bfdServer) deleteBfdPeer(peerAddress netip.Addr) {
	s.peersMutex.RLock()
	peer, ok := s.peers[peerAddress]
	s.peersMutex.RUnlock()

	if !ok {
		s.logger.Debug("Unknown BFD peer",
			slog.String("Topic", "bfd"),
			slog.String("Peer", peerAddress.String()),
		)

		return
	}

	s.peersMutex.Lock()
	delete(s.peers, peerAddress)
	s.peersMutex.Unlock()
	peer.Stop()

	s.logger.Info("Remove BFD peer",
		slog.String("Topic", "bfd"),
		slog.String("Peer", peerAddress.String()),
	)
}

func (s *bfdServer) getPeerState(address netip.Addr) *bfdPeerState {
	s.peersMutex.RLock()
	peer, ok := s.peers[address]
	s.peersMutex.RUnlock()

	if !ok {
		return nil
	}

	return &bfdPeerState{
		peerAddress: peer.peerAddress,
		state: api.BfdPeerState{
			SessionState: api.BfdSessionState(peer.state.Load()),
			BfdAsync: &api.BfdAsyncCounters{
				ReceivedPackets:    peer.stats.rxPacket.Load(),
				TransmittedPackets: peer.stats.txPacket.Load(),
			},
		},
	}
}

func (s *bfdServer) getPeerStateList() []*bfdPeerState {
	s.peersMutex.RLock()
	list := make([]*bfdPeerState, 0, len(s.peers))
	for _, peer := range s.peers {
		list = append(list, &bfdPeerState{
			peerAddress: peer.peerAddress,
			state: api.BfdPeerState{
				SessionState: api.BfdSessionState(peer.state.Load()),
				BfdAsync: &api.BfdAsyncCounters{
					ReceivedPackets:    peer.stats.rxPacket.Load(),
					TransmittedPackets: peer.stats.txPacket.Load(),
				},
			},
		})
	}
	s.peersMutex.RUnlock()

	return list
}

func (s *bfdServer) shutdown() {
	s.peersMutex.Lock()
	peers := make([]*bfdPeer, 0, len(s.peers))
	for address, peer := range s.peers {
		peers = append(peers, peer)
		delete(s.peers, address)
	}
	s.peersMutex.Unlock()

	for _, peer := range peers {
		peer.Stop()
	}

	s.stop()
	s.eventStartStop.Stop()
}

func (s *bfdServer) serverLoop(conn *net.UDPConn) {
	defer s.serverWait.Done()

	// buffer size must be more than BFD Control Packet size
	buffer := make([]byte, 4096)
	for {
		length, address, err := conn.ReadFromUDP(buffer)
		if err != nil {
			select {
			case <-s.serverStop:
				return
			default:
				s.stats.rxError.Add(1)
			}

			continue
		}

		bfdPacket := &bfd.BFDHeader{}
		err = bfdPacket.UnmarshalBinary(buffer[:length])
		if err != nil {
			s.logger.Debug("Invalid packet",
				slog.String("Topic", "bfd"),
				slog.Any("Error", err),
			)

			s.stats.invalidPacket.Add(1)
			continue
		}

		s.rxPacket(address, bfdPacket)
	}
}

func (s *bfdServer) rxPacket(address *net.UDPAddr, packet *bfd.BFDHeader) {
	addr := address.AddrPort().Addr().Unmap()

	s.peersMutex.RLock()
	peer, ok := s.peers[addr]
	s.peersMutex.RUnlock()

	if !ok {
		s.logger.Debug("Unknown BFD peer",
			slog.String("Topic", "bfd"),
			slog.Any("Peer", addr),
		)

		s.stats.unknownPeer.Add(1)
		return
	}

	ok = peer.Rx(packet)
	if !ok {
		s.stats.rxDrop.Add(1)
		return
	}

	s.stats.rxPacket.Add(1)
}
