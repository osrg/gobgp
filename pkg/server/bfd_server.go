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

type bfdServerStats struct {
	rxPacket      atomic.Uint64
	rxDrop        atomic.Uint64
	rxError       atomic.Uint64
	invalidPacket atomic.Uint64
	unknownPeer   atomic.Uint64
}

type bfdEventPeerUpdate struct {
	isAdd       bool
	peerAddress string
	address     netip.Addr
	config      oc.BfdConfig
}

type bfdPeerState struct {
	peerAddress string
	state       api.BfdPeerState
}

type bfdEventGetPeerState struct {
	in  netip.Addr
	out chan *bfdPeerState
}

type bfdEventGetPeerStateList struct {
	out chan []*bfdPeerState
}

type peerState interface {
	ResetPeer(ctx context.Context, r *api.ResetPeerRequest) error
}

type bfdServer struct {
	peerState peerState
	logger    *slog.Logger

	config *oc.BfdConfig

	udpServer *net.UDPConn

	peersMutex sync.RWMutex
	peers      map[netip.Addr]*bfdPeer

	eventStartStop   *time.Ticker
	eventConfig      chan *oc.BfdConfig
	eventPeerUpdate  chan *bfdEventPeerUpdate
	eventGetPeer     chan *bfdEventGetPeerState
	eventGetPeerList chan *bfdEventGetPeerStateList
	eventShutdown    chan struct{}

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

		eventStartStop:   time.NewTicker(time.Second),
		eventConfig:      make(chan *oc.BfdConfig, 1),
		eventPeerUpdate:  make(chan *bfdEventPeerUpdate, 1),
		eventGetPeer:     make(chan *bfdEventGetPeerState, 1),
		eventGetPeerList: make(chan *bfdEventGetPeerStateList, 1),
		eventShutdown:    make(chan struct{}),
	}

	s.shutdownWait.Add(1)
	go s.loop()
	return s
}

func (s *bfdServer) Start(config oc.BfdConfig) {
	s.eventConfig <- &config
}

func (s *bfdServer) Stop() {
	close(s.eventShutdown)
	s.shutdownWait.Wait()
}

func (s *bfdServer) AddPeer(peerAddress string, config oc.BfdConfig) error {
	if !config.Enabled {
		return nil
	}

	address, err := convertToIPAddress(peerAddress)
	if err != nil {
		s.logger.Warn("Can't parse peer address",
			slog.String("Topic", "bfd"),
			slog.String("Peer", peerAddress),
		)

		return err
	}

	s.eventPeerUpdate <- &bfdEventPeerUpdate{
		isAdd:       true,
		peerAddress: peerAddress,
		address:     address,
		config:      config,
	}

	return nil
}

func (s *bfdServer) DeletePeer(peerAddress string) error {
	address, err := convertToIPAddress(peerAddress)
	if err != nil {
		s.logger.Warn("Can't parse peer address",
			slog.String("Topic", "bfd"),
			slog.String("Peer", peerAddress),
		)

		return err
	}

	s.eventPeerUpdate <- &bfdEventPeerUpdate{
		isAdd:       false,
		peerAddress: peerAddress,
		address:     address,
	}

	return nil
}

func (s *bfdServer) GetPeerState(ctx context.Context, peerAddress string) (*bfdPeerState, error) {
	address, err := convertToIPAddress(peerAddress)
	if err != nil {
		return nil, err
	}

	list := &bfdEventGetPeerState{
		in:  address,
		out: make(chan *bfdPeerState),
	}

	s.eventGetPeer <- list

	select {
	case out, ok := <-list.out:
		if !ok {
			return nil, errors.New("channel is closed")
		}

		if out == nil {
			return nil, errors.New("peer not found")
		}

		return out, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *bfdServer) GetPeerStateList(ctx context.Context) ([]*bfdPeerState, error) {
	list := &bfdEventGetPeerStateList{
		out: make(chan []*bfdPeerState),
	}

	s.eventGetPeerList <- list

	select {
	case out, ok := <-list.out:
		if !ok {
			return nil, errors.New("channel is closed")
		}

		return out, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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

func convertToIPAddress(stringAddress string) (netip.Addr, error) {
	address, err := netip.ParseAddr(stringAddress)
	if err != nil {
		return netip.IPv4Unspecified(), err
	}

	// ReadFromUDP() return address in format '::ffff:1.2.3.4'
	// Fill peers map in a similar way
	return netip.AddrFrom16(address.As16()), nil
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
				s.addBfdPeer(ev.peerAddress, ev.address, ev.config)
			} else {
				s.deleteBfdPeer(ev.peerAddress, ev.address)
			}

			s.eventStartStop.Reset(time.Second)
		case ev := <-s.eventGetPeer:
			ev.out <- s.getPeerState(ev.in)
			close(ev.out)
		case ev := <-s.eventGetPeerList:
			ev.out <- s.getPeerStateList()
			close(ev.out)
		case <-s.eventShutdown:
			s.shutdown()
			return
		}
	}
}

func (s *bfdServer) start() bool {
	if s.udpServer == nil {
		s.startServer()
	}

	return s.udpServer != nil
}

func (s *bfdServer) startServer() {
	if s.config == nil {
		// BFD server not configured
		return
	}

	addressString := ":" + strconv.FormatUint(uint64(s.config.Port), 10)

	var lc net.ListenConfig
	lc.Control = func(network, address string, sc syscall.RawConn) error {
		return netutils.SetReuseAddrSockopt(sc)
	}

	l, err := lc.ListenPacket(context.Background(), "udp", addressString)
	if err != nil {
		s.logger.Error("Can't listen UDP",
			slog.String("Topic", "bfd"),
			slog.String("Address", addressString),
			slog.Any("Error", err),
		)
		return
	}

	var ok bool
	s.udpServer, ok = l.(*net.UDPConn)
	if !ok {
		s.logger.Error("Unexpected connection listener",
			slog.String("Topic", "bfd"),
			slog.String("Address", addressString),
			slog.Any("Error", err),
		)
		return
	}

	s.logger.Info("BFD server is started",
		slog.String("Topic", "bfd"),
		slog.String("Address", addressString),
	)

	s.serverStop = make(chan struct{})
	s.serverWait.Add(1)
	go s.serverLoop()
}

func (s *bfdServer) stop() {
	if s.udpServer == nil {
		return
	}

	close(s.serverStop)
	s.udpServer.Close()
	s.serverWait.Wait()
	s.udpServer = nil

	s.logger.Info("BFD server is stopped",
		slog.String("Topic", "bfd"),
	)
}

func (s *bfdServer) addBfdPeer(peerAddress string, address netip.Addr, config oc.BfdConfig) {
	s.peersMutex.RLock()
	_, ok := s.peers[address]
	s.peersMutex.RUnlock()

	if ok {
		s.logger.Debug("BFD peer already exist",
			slog.String("Topic", "bfd"),
			slog.String("Peer", peerAddress),
		)

		return
	}

	bfdPeer := NewBfdPeer(s.peerState, s.logger, peerAddress, config)
	if bfdPeer != nil {
		s.logger.Info("Insert BFD peer",
			slog.String("Topic", "bfd"),
			slog.String("Peer", peerAddress),
		)

		s.peersMutex.Lock()
		s.peers[address] = bfdPeer
		s.peersMutex.Unlock()
	}
}

func (s *bfdServer) deleteBfdPeer(peerAddress string, address netip.Addr) {
	s.peersMutex.RLock()
	peer, ok := s.peers[address]
	s.peersMutex.RUnlock()

	if !ok {
		s.logger.Debug("Unknown BFD peer",
			slog.String("Topic", "bfd"),
			slog.String("Peer", peerAddress),
		)

		return
	}

	s.peersMutex.Lock()
	delete(s.peers, address)
	s.peersMutex.Unlock()
	peer.Stop()

	s.logger.Info("Remove BFD peer",
		slog.String("Topic", "bfd"),
		slog.String("Peer", peerAddress),
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

func (s *bfdServer) serverLoop() {
	defer s.serverWait.Done()

	// buffer size must be more than BFD Control Packet size
	buffer := make([]byte, 4096)
	for {
		length, address, err := s.udpServer.ReadFromUDP(buffer)
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
	addr := address.AddrPort().Addr()

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
