package peering

import (
	"context"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (fsm *fsm) openconfirm(ctx context.Context) (bgp.FSMState, *FSMStateReason) {
	ticker := fsm.keepaliveTicker()
	c, cancel := context.WithCancel(ctx)
	recvWg := &sync.WaitGroup{}
	recvWg.Add(1)

	recvChan := make(chan any, 1)
	reasonChan := make(chan *FSMStateReason, 1)
	go fsm.recvMessage(c, recvWg, recvChan, reasonChan)

	defer func() {
		cancel()
		recvWg.Wait()
		close(recvChan)
		close(reasonChan)
	}()

	fsm.Lock.RLock()
	var holdTimer *time.Timer
	if fsm.PeerConf.Timers.State.NegotiatedHoldTime == 0 {
		holdTimer = &time.Timer{}
	} else {
		// RFC 4271 P.65
		// sets the HoldTimer according to the negotiated value
		holdTimer = time.NewTimer(time.Second * time.Duration(fsm.PeerConf.Timers.State.NegotiatedHoldTime))
	}
	fsm.Lock.RUnlock()

	for {
		select {
		case <-ctx.Done():
			fsm.Conn.Close()
			return -1, NewFSMStateReason(FSMDying, nil, nil)
		case conn, ok := <-fsm.ConnCh:
			if !ok {
				break
			}
			conn.Close()
			fsm.Lock.RLock()
			fsm.Logger.Warn("Closed an accepted connection",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
				})
			fsm.Lock.RUnlock()
		case <-fsm.GracefulRestartTimer.C:
			fsm.Lock.RLock()
			restarting := fsm.PeerConf.GracefulRestart.State.PeerRestarting
			fsm.Lock.RUnlock()
			if restarting {
				fsm.Lock.RLock()
				fsm.Logger.Warn("graceful restart timer expired",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.PeerConf.State.NeighborAddress,
						"State": fsm.State.String(),
					})
				fsm.Lock.RUnlock()
				fsm.Conn.Close()
				return bgp.BGP_FSM_IDLE, NewFSMStateReason(FMSRestartTimerExpired, nil, nil)
			}
		case <-ticker.C:
			m := bgp.NewBGPKeepAliveMessage()
			b, _ := m.Serialize()
			// TODO: check error
			fsm.Conn.Write(b)
			fsm.bgpMessageStateUpdate(m.Header.Type, false)
		case i, ok := <-recvChan:
			if !ok {
				continue
			}
			e := i.(*FSMMsg)
			switch m := e.MsgData.(type) {
			case *bgp.BGPMessage:
				if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
					return bgp.BGP_FSM_ESTABLISHED, NewFSMStateReason(FSMOpenMsgNegotiated, nil, nil)
				}
				// send notification ?
				fsm.Conn.Close()
				return bgp.BGP_FSM_IDLE, NewFSMStateReason(FSMInvalidMsg, nil, nil)
			case *bgp.MessageError:
				msg, _ := fsm.sendNotificationFromErrorMsg(m)
				return bgp.BGP_FSM_IDLE, NewFSMStateReason(FSMInvalidMsg, msg, nil)
			default:
				fsm.Logger.Panic("unknown msg type",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.PeerConf.State.NeighborAddress,
						"State": fsm.State.String(),
						"Data":  e.MsgData,
					})
			}
		case err := <-reasonChan:
			fsm.Conn.Close()
			return bgp.BGP_FSM_IDLE, err
		case <-holdTimer.C:
			m, _ := fsm.sendNotification(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil, "hold timer expired")
			return bgp.BGP_FSM_IDLE, NewFSMStateReason(FSMHoldTimerExpired, m, nil)
		case stateOp := <-fsm.AdminStateCh:
			err := fsm.changeAdminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case AdminStateDown:
					fsm.Conn.Close()
					return bgp.BGP_FSM_IDLE, NewFSMStateReason(FSMAdminDown, nil, nil)
				case AdminStateUp:
					fsm.Logger.Panic("code logic bug",
						log.Fields{
							"Topic":      "Peer",
							"Key":        fsm.PeerConf.State.NeighborAddress,
							"State":      fsm.State.String(),
							"adminState": stateOp.State.String(),
						})
				}
			}
		}
	}
}
