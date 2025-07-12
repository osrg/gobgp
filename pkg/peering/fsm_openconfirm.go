package peering

import (
	"context"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (fsm *fsm) openconfirm(ctx context.Context) (bgp.FSMState, *FSMStateReason) {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	recvChan := make(chan any, 1)
	stateReasonCh := make(chan *FSMStateReason, 1)
	go fsm.recvMessage(ctx, recvChan, stateReasonCh, wg)

	keepAliveTicker, keepAliveTickerStop := fsm.keepAliveTicker()
	holdTimer, holdTimerStop := fsm.holdTimer()

	defer func() {
		fsm.Conn.SetReadDeadline(time.Now())
		wg.Wait()
		close(recvChan)
		close(stateReasonCh)
		keepAliveTickerStop()
		holdTimerStop()
	}()

	fsm.Lock.RLock()
	neighborAddress := fsm.PeerConf.State.NeighborAddress
	fsm.Lock.RUnlock()

	for {
		select {
		case <-ctx.Done():
			return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMDying, nil, nil)
		case conn, ok := <-fsm.ConnCh:
			if !ok {
				break
			}
			conn.Close()
			fsm.Logger.Warn("Closed an accepted connection",
				log.Fields{
					"Topic": "Peer",
					"Key":   neighborAddress,
					"State": oc.SESSION_STATE_OPENCONFIRM,
				})
		case <-fsm.GracefulRestartTimer.C:
			fsm.Lock.RLock()
			restarting := fsm.PeerConf.GracefulRestart.State.PeerRestarting
			fsm.Lock.RUnlock()

			if !restarting {
				continue
			}

			fsm.Logger.Warn("graceful restart timer expired",
				log.Fields{
					"Topic": "Peer",
					"Key":   neighborAddress,
					"State": oc.SESSION_STATE_OPENCONFIRM,
				})
			fsm.Conn.Close()
			return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMRestartTimerExpired, nil, nil)
		case <-keepAliveTicker.C:
			m := bgp.NewBGPKeepAliveMessage()
			b, _ := m.Serialize()
			// TODO: check error
			fsm.Conn.Write(b)
			fsm.bgpMessageStateUpdate(m.Header.Type, false)
		case i := <-recvChan:
			e := i.(*FSMMsg)
			state, reason := fsm.openconfirmRecvMsg(e)
			if state != bgp.BGP_FSM_OPENCONFIRM {
				return state, reason
			}
		case err := <-stateReasonCh:
			fsm.Conn.Close()
			return bgp.BGP_FSM_IDLE, err
		case <-holdTimer.C:
			m, _ := fsm.sendNotification(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil, "hold timer expired")
			return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMHoldTimerExpired, m, nil)
		case stateOp := <-fsm.AdminStateCh:
			err := fsm.changeAdminState(stateOp.State)
			if err != nil {
				continue
			}
			switch stateOp.State {
			case AdminStateDown:
				fsm.Conn.Close()
				return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMAdminDown, nil, nil)
			case AdminStateUp:
				fsm.Logger.Panic("code logic bug",
					log.Fields{
						"Topic":      "Peer",
						"Key":        neighborAddress,
						"State":      oc.SESSION_STATE_OPENCONFIRM,
						"adminState": stateOp.State,
					})
			}
		}
	}
}

func (fsm *fsm) openconfirmRecvMsg(e *FSMMsg) (bgp.FSMState, *FSMStateReason) {
	fsm.Lock.RLock()
	neighborAddress := fsm.PeerConf.State.NeighborAddress
	fsm.Lock.RUnlock()

	switch m := e.MsgData.(type) {
	case *bgp.BGPMessage:
		if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
			return bgp.BGP_FSM_ESTABLISHED, NewfsmStateReason(FSMOpenMsgNegotiated, nil, nil)
		}
		// send notification ?
		fsm.Conn.Close()
		return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMInvalidMsg, nil, nil)
	case *bgp.MessageError:
		msg, _ := fsm.sendNotificationFromErrorMsg(m)
		return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMInvalidMsg, msg, nil)
	default:
		fsm.Logger.Panic("unknown msg type",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"State": oc.SESSION_STATE_OPENCONFIRM,
				"Data":  e.MsgData,
			})
	}
	return bgp.BGP_FSM_OPENCONFIRM, nil
}
