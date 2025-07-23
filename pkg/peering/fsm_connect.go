package peering

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"syscall"

	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/utils"
)

func (fsm *fsm) connect(ctx context.Context) *FSMStateTransition {
	c, cancel := context.WithCancel(ctx)
	wg := &sync.WaitGroup{}
	wg.Add(1)

	go fsm.connectLoop(c, wg)

	defer func() {
		cancel()
		wg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return TransitionDying.Copy()
		case transition := <-fsm.transitionCh:
			return transition
		case conn := <-fsm.tracking.connCh:
			// either we accept a remote connection or a local one
			if err := fsm.acceptConn(conn); err != nil {
				return TransitionConnectFailed.Copy(WithData(err))
			}
			return fsm.acceptAllWaitingConns(ctx)
		case stateOp := <-fsm.adminStateCh:
			fsm.changeAdminState(stateOp.state)
			switch stateOp.state {
			case AdminStateDown:
				err := bgp.NewMessageError(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, nil, stateOp.communication)
				return TransitionAdminDown.Copy(WithData(err))
			default:
			}
		}
	}
}

func (fsm *fsm) connectLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	fsm.common.Lock.RLock()
	neighborAddress := fsm.common.PeerConf.State.NeighborAddress
	fsm.common.Lock.RUnlock()

	port := int(bgp.BGP_PORT)
	if fsm.common.PeerConf.Transport.Config.RemotePort != 0 {
		port = int(fsm.common.PeerConf.Transport.Config.RemotePort)
	}
	password := fsm.common.PeerConf.Config.AuthPassword
	ttl := uint8(0)
	ttlMin := uint8(0)

	if fsm.common.PeerConf.TtlSecurity.Config.Enabled {
		ttl = 255
		ttlMin = fsm.common.PeerConf.TtlSecurity.Config.TtlMin
	} else if fsm.common.PeerConf.Config.PeerAs != 0 && fsm.common.PeerConf.Config.PeerType == oc.PEER_TYPE_EXTERNAL {
		ttl = 1
		if fsm.common.PeerConf.EbgpMultihop.Config.Enabled {
			ttl = fsm.common.PeerConf.EbgpMultihop.Config.MultihopTtl
		}
	}
	mss := fsm.common.PeerConf.Transport.Config.TcpMss
	localAddress := fsm.common.PeerConf.Transport.Config.LocalAddress
	localPort := int(fsm.common.PeerConf.Transport.Config.LocalPort)
	bindInterface := fsm.common.PeerConf.Transport.Config.BindInterface

	connectRetryTimeBase := fsm.timers.connectRetryTime
	neighborHostPort := net.JoinHostPort(neighborAddress, strconv.Itoa(port))

	fsm.logger.Warn("connect loop",
		log.Fields{
			"Topic": "Peer",
			"Key":   neighborAddress,
		})

	laddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(localAddress, strconv.Itoa(localPort)))
	if err != nil {
		fsm.sendStateTransition(bgp.BGP_FSM_IDLE, FSMLocalResolveFailed, err)
		return
	}
	dialer := &net.Dialer{
		LocalAddr: laddr,
		KeepAlive: -1,
		Control: func(network, address string, c syscall.RawConn) error {
			return netutils.DialerControl(fsm.logger, network, address, c, ttl, ttlMin, mss, password, bindInterface)
		},
	}

	for func() bool {
		connectRetryTime := utils.Jitterize(connectRetryTimeBase, utils.WithMinFactor(0.75))
		c, cancel := context.WithTimeout(ctx, connectRetryTime)
		defer cancel()

		shouldRetry := false
		conn, err := dialer.DialContext(c, "tcp", neighborHostPort)
		if errors.Is(err, context.DeadlineExceeded) {
			fsm.logger.Warn("connect timeout",
				log.Fields{
					"Topic": "Peer",
					"Key":   neighborAddress,
				})
			shouldRetry = true
		} else if errors.Is(err, syscall.ECONNREFUSED) {
			// ECONNREFUSED is returned when the remote peer is not listening
			// on the port we are trying to connect to. (example yabgp)
			// We retry after the connect retry timer expires, which let the time
			// to the remote peer to try to connect to us or start listening.
			fsm.logger.Warn("connection refused, retrying",
				log.Fields{
					"Topic": "Peer",
					"Key":   neighborAddress,
				})
			<-c.Done()
		} else if errors.Is(err, context.Canceled) {
			fsm.logger.Warn("connect cancelled",
				log.Fields{
					"Topic": "Peer",
					"Key":   neighborAddress,
				})
		} else if err != nil {
			// https://datatracker.ietf.org/doc/html/rfc4271#section-8.2.2
			// connect state with event 18, without delayed open timer
			fsm.sendStateTransition(bgp.BGP_FSM_IDLE, FSMConnectFailed, err)
		} else {
			fsm.logger.Warn("new connection",
				log.Fields{
					"Topic": "Peer",
					"Key":   neighborAddress,
				})
			// we successfully connected to the peer
			fsm.tracking.connCh <- conn
			return false // stop retrying
		}
		// close the current connection, we were not successful
		if conn != nil {
			conn.Close()
		}
		return shouldRetry
	}() {
	}
}
