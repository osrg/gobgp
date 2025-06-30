package peering

import (
	"context"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/utils"
)

func newStateTransition(oldState, nextState bgp.FSMState) *FSMStateTransition {
	return &FSMStateTransition{
		OldState:  oldState,
		NextState: nextState,
	}
}

func (fsm *fsm) step(ctx context.Context) {
	fsm.Lock.RLock()
	oldState := fsm.State
	neighborAddress := fsm.PeerConf.State.NeighborAddress
	fsm.Lock.RUnlock()

	var reason *FSMStateReason
	nextState := bgp.FSMState(-1)

	switch oldState {
	case bgp.BGP_FSM_IDLE:
		nextState, reason = fsm.idle(ctx)
		// case bgp.BGP_FSM_CONNECT:
		// 	nextState = h.connect()
	case bgp.BGP_FSM_ACTIVE:
		nextState, reason = fsm.active(ctx)
	case bgp.BGP_FSM_OPENSENT:
		nextState, reason = fsm.opensent(ctx)
	case bgp.BGP_FSM_OPENCONFIRM:
		nextState, reason = fsm.openconfirm(ctx)
	case bgp.BGP_FSM_ESTABLISHED:
		nextState, reason = fsm.established(ctx)
	}

	fsm.Lock.Lock()
	fsm.Reason = reason
	sentNotification := fsm.SentNotification
	fsm.Lock.Unlock()

	switch nextState {
	case bgp.BGP_FSM_IDLE:
		// If we are going to idle, we should close the connection
		fsm.Lock.Lock()
		fsm.closeIncomingConn()
		fsm.Lock.Unlock()
	case bgp.BGP_FSM_ESTABLISHED:
		if oldState == bgp.BGP_FSM_OPENCONFIRM {
			fsm.Logger.Info("Peer Up",
				log.Fields{
					"Topic": "Peer",
					"Key":   neighborAddress,
					"State": oldState.String(),
				})
		}
	default:
		if oldState == bgp.BGP_FSM_ESTABLISHED {
			// The main goroutine sent the notification due to
			// deconfiguration or something.
			reason := *reason
			if sentNotification != nil {
				reason.Type = FSMNotificationSent
				reason.BGPNotification = sentNotification
			}
			fsm.Logger.Info("Peer Down",
				log.Fields{
					"Topic":  "Peer",
					"Key":    neighborAddress,
					"State":  oldState.String(),
					"Reason": reason.String(),
				})
		}
	}

	fsmMsg := &FSMMsg{
		FSM:         fsm,
		MsgType:     FSMMsgStateChange,
		MsgSrc:      neighborAddress,
		MsgData:     newStateTransition(oldState, nextState),
		StateReason: reason,
	}

	fsm.stateChange(nextState)
	utils.PushWithContext(ctx, fsm.IncomingCh.In(), any(fsmMsg), true)
}

func (fsm *fsm) connectLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	fsm.Lock.RLock()
	retryInterval := max(int(fsm.PeerConf.Timers.Config.ConnectRetry), MinConnectRetryInterval)

	addr := fsm.PeerConf.State.NeighborAddress
	port := int(bgp.BGP_PORT)
	if fsm.PeerConf.Transport.Config.RemotePort != 0 {
		port = int(fsm.PeerConf.Transport.Config.RemotePort)
	}
	password := fsm.PeerConf.Config.AuthPassword
	ttl := uint8(0)
	ttlMin := uint8(0)

	if fsm.PeerConf.TtlSecurity.Config.Enabled {
		ttl = 255
		ttlMin = fsm.PeerConf.TtlSecurity.Config.TtlMin
	} else if fsm.PeerConf.Config.PeerAs != 0 && fsm.PeerConf.Config.PeerType == oc.PEER_TYPE_EXTERNAL {
		ttl = 1
		if fsm.PeerConf.EbgpMultihop.Config.Enabled {
			ttl = fsm.PeerConf.EbgpMultihop.Config.MultihopTtl
		}
	}
	mss := fsm.PeerConf.Transport.Config.TcpMss
	localAddress := fsm.PeerConf.Transport.Config.LocalAddress
	localPort := int(fsm.PeerConf.Transport.Config.LocalPort)
	bindInterface := fsm.PeerConf.Transport.Config.BindInterface
	fsm.Lock.RUnlock()

	tick := MinConnectRetryInterval
	for {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		timer := time.NewTimer(time.Duration(r.Intn(tick*1000)+tick*1000) * time.Millisecond)
		select {
		case <-ctx.Done():
			fsm.Logger.Debug("stop connect loop",
				log.Fields{
					"Topic": "Peer",
					"Key":   addr,
				})
			timer.Stop()
			return
		case <-timer.C:
			if fsm.Logger.GetLevel() >= log.DebugLevel {
				fsm.Logger.Debug("try to connect",
					log.Fields{
						"Topic": "Peer",
						"Key":   addr,
					})
			}
		}

		laddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(localAddress, strconv.Itoa(localPort)))
		if err != nil {
			fsm.Logger.Warn("failed to resolve local address",
				log.Fields{
					"Topic": "Peer",
					"Key":   addr,
				})
		}

		if err == nil {
			d := net.Dialer{
				LocalAddr: laddr,
				Timeout:   time.Duration(max(retryInterval-1, MinConnectRetryInterval)) * time.Second,
				KeepAlive: -1,
				Control: func(network, address string, c syscall.RawConn) error {
					return netutils.DialerControl(fsm.Logger, network, address, c, ttl, ttlMin, mss, password, bindInterface)
				},
			}

			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
			if err != nil {
				if fsm.Logger.GetLevel() >= log.DebugLevel {
					fsm.Logger.Debug("failed to connect",
						log.Fields{
							"Topic": "Peer",
							"Key":   addr,
							"Error": err,
						})
				}
				continue
			}

			pushed := utils.PushWithContext(ctx, fsm.ConnCh, conn, false)
			if !pushed {
				if ctx.Err() == context.Canceled {
					fsm.Logger.Debug("stop connect loop",
						log.Fields{
							"Topic": "Peer",
							"Key":   addr,
						})
					return
				}
				if fsm.Logger.GetLevel() >= log.DebugLevel {
					fsm.Logger.Debug("failed to connect",
						log.Fields{
							"Topic": "Peer",
							"Key":   addr,
							"Error": err,
						})
				}
			}
		}
		tick = retryInterval
	}
}
