package peering

import (
	"context"
	"sync"
	"time"

	"github.com/eapache/channels"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (h *FSMHandler) openconfirm(ctx context.Context) (bgp.FSMState, *FSMStateReason) {
	fsm := h.FSM
	ticker := fsm.keepaliveTicker()
	h.MsgCh = channels.NewInfiniteChannel()
	fsm.Lock.RLock()
	h.Conn = fsm.Conn

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(1)
	go h.recvMessage(ctx, &wg)

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
			h.Conn.Close()
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
				h.Conn.Close()
				return bgp.BGP_FSM_IDLE, NewFSMStateReason(FMSRestartTimerExpired, nil, nil)
			}
		case <-ticker.C:
			m := bgp.NewBGPKeepAliveMessage()
			b, _ := m.Serialize()
			// TODO: check error
			fsm.Conn.Write(b)
			fsm.bgpMessageStateUpdate(m.Header.Type, false)
		case i, ok := <-h.MsgCh.Out():
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
				h.Conn.Close()
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
		case err := <-h.StateReasonCh:
			h.Conn.Close()
			return bgp.BGP_FSM_IDLE, &err
		case <-holdTimer.C:
			m, _ := fsm.sendNotification(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil, "hold timer expired")
			return bgp.BGP_FSM_IDLE, NewFSMStateReason(FSMHoldTimerExpired, m, nil)
		case stateOp := <-fsm.AdminStateCh:
			err := h.changeAdminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case AdminStateDown:
					h.Conn.Close()
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
