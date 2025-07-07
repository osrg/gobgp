// Copyright (C) 2014-2021 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package peering

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/eapache/channels"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/bgputils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
)

func NewfsmStateReason(typ FSMStateReasonType, notif *bgp.BGPMessage, data []byte) *FSMStateReason {
	return &FSMStateReason{
		Type:            typ,
		BGPNotification: notif,
		Data:            data,
	}
}

func (r *FSMStateReason) String() string {
	switch r.Type {
	case FSMDying:
		return "dying"
	case FSMAdminDown:
		return "admin-down"
	case FSMReadFailed:
		return "read-failed"
	case FSMWriteFailed:
		return "write-failed"
	case FSMNotificationSent:
		body := r.BGPNotification.Body.(*bgp.BGPNotification)
		return fmt.Sprintf("notification-sent %s", bgp.NewNotificationErrorCode(body.ErrorCode, body.ErrorSubcode).String())
	case FSMNotificationRecv:
		body := r.BGPNotification.Body.(*bgp.BGPNotification)
		return fmt.Sprintf("notification-received %s", bgp.NewNotificationErrorCode(body.ErrorCode, body.ErrorSubcode).String())
	case FSMHoldTimerExpired:
		return "hold-timer-expired"
	case FSMIdleTimerExpired:
		return "idle-hold-timer-expired"
	case FSMRestartTimerExpired:
		return "restart-timer-expired"
	case FSMGracefulRestart:
		return "graceful-restart"
	case FSMInvalidMsg:
		return "invalid-msg"
	case FSMNewConnection:
		return "new-connection"
	case FSMOpenMsgReceived:
		return "open-msg-received"
	case FSMOpenMsgNegotiated:
		return "open-msg-negotiated"
	case FSMHardReset:
		return "hard-reset"
	default:
		return "unknown"
	}
}

func (s AdminState) String() string {
	switch s {
	case AdminStateUp:
		return "adminStateUp"
	case AdminStateDown:
		return "adminStateDown"
	case AdminStatePfxCt:
		return "adminStatePfxCt"
	default:
		return "Unknown"
	}
}

func newFSMStateTransition(oldState, nextState bgp.FSMState, reason *FSMStateReason) *FSMStateTransition {
	return &FSMStateTransition{
		OldState:  oldState,
		NextState: nextState,
		Reason:    reason,
	}
}

func (fsm *fsm) bgpMessageStateUpdate(MessageType uint8, isIn bool) {
	fsm.Lock.Lock()
	defer fsm.Lock.Unlock()
	state := &fsm.PeerConf.State.Messages
	timer := &fsm.PeerConf.Timers
	if isIn {
		state.Received.Total++
	} else {
		state.Sent.Total++
	}
	switch MessageType {
	case bgp.BGP_MSG_OPEN:
		if isIn {
			state.Received.Open++
		} else {
			state.Sent.Open++
		}
	case bgp.BGP_MSG_UPDATE:
		if isIn {
			state.Received.Update++
			timer.State.UpdateRecvTime = time.Now().Unix()
		} else {
			state.Sent.Update++
		}
	case bgp.BGP_MSG_NOTIFICATION:
		if isIn {
			state.Received.Notification++
		} else {
			state.Sent.Notification++
		}
	case bgp.BGP_MSG_KEEPALIVE:
		if isIn {
			state.Received.Keepalive++
		} else {
			state.Sent.Keepalive++
		}
	case bgp.BGP_MSG_ROUTE_REFRESH:
		if isIn {
			state.Received.Refresh++
		} else {
			state.Sent.Refresh++
		}
	default:
		if isIn {
			state.Received.Discarded++
		} else {
			state.Sent.Discarded++
		}
	}
}

func (fsm *fsm) bmpStatsUpdate(statType uint16, increment int) {
	fsm.Lock.Lock()
	defer fsm.Lock.Unlock()
	stats := &fsm.PeerConf.State.Messages.Received
	switch statType {
	// TODO
	// Support other stat types.
	case bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE:
		stats.WithdrawUpdate += uint32(increment)
	case bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX:
		stats.WithdrawPrefix += uint32(increment)
	}
}

func newFSM(gConf *oc.Global, pConf *oc.Neighbor, callback FSMCallback, logger log.Logger) *fsm {
	if callback == nil {
		callback = func(*FSMMsg) {}
	}
	adminState := AdminStateUp
	if pConf.Config.AdminDown {
		adminState = AdminStateDown
	}
	pConf.State.SessionState = oc.IntToSessionStateMap[int(bgp.BGP_FSM_IDLE)]
	pConf.Timers.State.Downtime = time.Now().Unix()
	gracefulRestartTimer := time.NewTimer(time.Hour)
	gracefulRestartTimer.Stop()
	return &fsm{
		GlobalConf:           gConf,
		PeerConf:             pConf,
		State:                bgp.BGP_FSM_IDLE,
		OutgoingCh:           channels.NewInfiniteChannel(),
		ConnCh:               make(chan net.Conn, 1),
		OpenSentHoldTime:     float64(HoldTimeOpenSent),
		AdminState:           adminState,
		AdminStateCh:         make(chan AdminStateOperation, 1),
		RFMap:                make(map[bgp.Family]bgp.BGPAddPathMode),
		CapMap:               make(map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface),
		PeerInfo:             table.NewPeerInfo(gConf, pConf),
		GracefulRestartTimer: time.NewTimer(time.Hour),
		Notification:         make(chan *bgp.BGPMessage, 1),
		HoldTimerResetCh:     make(chan bool, 1),
		Callback:             callback,
		Logger:               logger,
	}
}

func (fsm *fsm) stateChange(transition *FSMStateTransition) {
	fsm.Lock.Lock()
	defer fsm.Lock.Unlock()

	nextState := transition.NextState
	oldState := transition.OldState
	neighborAddress := fsm.PeerConf.State.NeighborAddress

	fsm.Logger.Debug("state changed",
		log.Fields{
			"Topic":  "Peer",
			"Key":    neighborAddress,
			"old":    oldState.String(),
			"new":    nextState.String(),
			"reason": transition.Reason,
		})
	fsm.State = nextState
	fsm.PeerConf.State.SessionState = oc.IntToSessionStateMap[int(nextState)]

	// peer up
	if nextState == bgp.BGP_FSM_ESTABLISHED && oldState == bgp.BGP_FSM_OPENCONFIRM {
		fsm.Logger.Info("Peer Up",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"State": oldState.String(),
			})
		fsm.PeerConf.Timers.State.Uptime = time.Now().Unix()
		fsm.PeerConf.State.EstablishedCount++
		// reset the state set by the previous session
		fsm.TwoByteAsTrans = false
		if _, y := fsm.CapMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]; !y {
			fsm.TwoByteAsTrans = true
		} else {
			fsm.TwoByteAsTrans = true
			for _, c := range fsm.PeerConf.Capabilities() {
				if _, ok := c.(*bgp.CapFourOctetASNumber); ok {
					fsm.TwoByteAsTrans = false
					break
				}
			}
		}
		// peer down
	} else if oldState == bgp.BGP_FSM_ESTABLISHED {
		// The main goroutine sent the notification due to
		// deconfiguration or something.
		reason := *transition.Reason
		if fsm.SentNotification != nil {
			reason.Type = FSMNotificationSent
			reason.BGPNotification = fsm.SentNotification
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

func (fsm *fsm) RemoteHostPort() (string, uint16) {
	fsm.Lock.RLock()
	defer fsm.Lock.RUnlock()
	if fsm.Conn == nil {
		return "", 0
	}
	return netutils.HostPort(fsm.Conn.RemoteAddr())
}

func (fsm *fsm) LocalHostPort() (string, uint16) {
	fsm.Lock.RLock()
	defer fsm.Lock.RUnlock()
	if fsm.Conn == nil {
		return "", 0
	}
	return netutils.HostPort(fsm.Conn.LocalAddr())
}

func (fsm *fsm) sendNotificationFromErrorMsg(e *bgp.MessageError) (*bgp.BGPMessage, error) {
	fsm.Lock.RLock()
	established := fsm.Conn != nil
	fsm.Lock.RUnlock()

	if established {
		m := bgp.NewBGPNotificationMessage(e.TypeCode, e.SubTypeCode, e.Data)
		b, _ := m.Serialize()
		_, err := fsm.Conn.Write(b)
		if err == nil {
			fsm.bgpMessageStateUpdate(m.Header.Type, false)
			fsm.SentNotification = m
		}
		fsm.Conn.Close()
		fsm.Logger.Warn("sent notification",
			log.Fields{
				"Topic": "Peer",
				"Key":   fsm.PeerConf.State.NeighborAddress,
				"Data":  e,
			})
		return m, nil
	}
	return nil, fmt.Errorf("can't send notification to %s since TCP connection is not established", fsm.PeerConf.State.NeighborAddress)
}

func (fsm *fsm) sendNotification(code, subType uint8, data []byte, msg string) (*bgp.BGPMessage, error) {
	e := bgp.NewMessageError(code, subType, data, msg)
	return fsm.sendNotificationFromErrorMsg(e.(*bgp.MessageError))
}

func (fsm *fsm) SetPeerConnTTL() error {
	fsm.Lock.RLock()
	defer fsm.Lock.RUnlock()

	ttl := 0
	ttlMin := 0

	if fsm.PeerConf.TtlSecurity.Config.Enabled {
		ttl = 255
		ttlMin = int(fsm.PeerConf.TtlSecurity.Config.TtlMin)
	} else if fsm.PeerConf.Config.PeerAs != 0 && fsm.PeerConf.Config.PeerType == oc.PEER_TYPE_EXTERNAL {
		if fsm.PeerConf.EbgpMultihop.Config.Enabled {
			ttl = int(fsm.PeerConf.EbgpMultihop.Config.MultihopTtl)
		} else if fsm.PeerConf.Transport.Config.Ttl != 0 {
			ttl = int(fsm.PeerConf.Transport.Config.Ttl)
		} else {
			ttl = 1
		}
	} else if fsm.PeerConf.Transport.Config.Ttl != 0 {
		ttl = int(fsm.PeerConf.Transport.Config.Ttl)
	}

	if ttl != 0 {
		if err := netutils.SetTCPTTLSockopt(fsm.Conn, ttl); err != nil {
			return fmt.Errorf("failed to set TTL %d: %w", ttl, err)
		}
	}
	if ttlMin != 0 {
		if err := netutils.SetTCPMinTTLSockopt(fsm.Conn, ttlMin); err != nil {
			return fmt.Errorf("failed to set minimal TTL %d: %w", ttlMin, err)
		}
	}
	return nil
}

func (fsm *fsm) SetPeerConnMSS() error {
	fsm.Lock.RLock()
	defer fsm.Lock.RUnlock()

	mss := fsm.PeerConf.Transport.Config.TcpMss
	if mss == 0 {
		return nil
	}
	if err := netutils.SetTCPMSSSockopt(fsm.Conn, mss); err != nil {
		return fmt.Errorf("failed to set MSS %d: %w", mss, err)
	}
	return nil
}

func (fsm *fsm) keepAliveTicker() *time.Ticker {
	fsm.Lock.RLock()
	defer fsm.Lock.RUnlock()

	negotiatedTime := fsm.PeerConf.Timers.State.NegotiatedHoldTime
	if negotiatedTime == 0 {
		return &time.Ticker{}
	}
	sec := time.Second * time.Duration(fsm.PeerConf.Timers.State.KeepaliveInterval)
	if sec == 0 {
		sec = time.Second
	}
	return time.NewTicker(sec)
}

func (fsm *fsm) afiSafiDisable(rf bgp.Family) string {
	fsm.Lock.Lock()
	defer fsm.Lock.Unlock()

	n := bgp.AddressFamilyNameMap[rf]

	for i, a := range fsm.PeerConf.AfiSafis {
		if string(a.Config.AfiSafiName) == n {
			fsm.PeerConf.AfiSafis[i].State.Enabled = false
			break
		}
	}
	newList := make([]bgp.ParameterCapabilityInterface, 0)
	for _, c := range fsm.CapMap[bgp.BGP_CAP_MULTIPROTOCOL] {
		if c.(*bgp.CapMultiProtocol).CapValue == rf {
			continue
		}
		newList = append(newList, c)
	}
	fsm.CapMap[bgp.BGP_CAP_MULTIPROTOCOL] = newList
	return n
}

func (fsm *fsm) handlingError(m *bgp.BGPMessage, e error, useRevisedError bool) bgp.ErrorHandling {
	// ineffectual assignment to handling (ineffassign)
	var handling bgp.ErrorHandling
	if m.Header.Type == bgp.BGP_MSG_UPDATE && useRevisedError {
		factor := e.(*bgp.MessageError)
		handling = factor.ErrorHandling
		switch handling {
		case bgp.ERROR_HANDLING_ATTRIBUTE_DISCARD:
			fsm.Lock.RLock()
			fsm.Logger.Warn("Some attributes were discarded",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
					"Error": e,
				})
			fsm.Lock.RUnlock()
		case bgp.ERROR_HANDLING_TREAT_AS_WITHDRAW:
			m.Body = bgp.TreatAsWithdraw(m.Body.(*bgp.BGPUpdate))
			fsm.Lock.RLock()
			fsm.Logger.Warn("the received Update message was treated as withdraw",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
					"Error": e,
				})
			fsm.Lock.RUnlock()
		case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
			rf := bgputils.ExtractFamily(factor.ErrorAttribute)
			if rf == nil {
				fsm.Lock.RLock()
				fsm.Logger.Warn("Error occurred during AFI/SAFI disabling",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.PeerConf.State.NeighborAddress,
						"State": fsm.State.String(),
					})
				fsm.Lock.RUnlock()
			} else {
				n := fsm.afiSafiDisable(*rf)
				fsm.Lock.RLock()
				fsm.Logger.Warn("Capability was disabled",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.PeerConf.State.NeighborAddress,
						"State": fsm.State.String(),
						"Error": e,
						"Cap":   n,
					})
				fsm.Lock.RUnlock()
			}
		}
	} else {
		handling = bgp.ERROR_HANDLING_SESSION_RESET
	}
	return handling
}

func (fsm *fsm) loop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	fsm.Lock.RLock()
	oldState := fsm.State
	neighborAddress := fsm.PeerConf.State.NeighborAddress
	fsm.Lock.RUnlock()

	var reason *FSMStateReason
	nextState := bgp.BGP_FSM_IDLE

	for ctx.Err() == nil {
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

		transition := newFSMStateTransition(oldState, nextState, reason)
		fsm.stateChange(transition)

		oldState = nextState

		// do not execute the callback if the context is done
		if ctx.Err() != nil {
			break
		}

		msg := &FSMMsg{
			MsgType: FSMMsgStateChange,
			MsgSrc:  neighborAddress,
			MsgData: transition,
		}

		fsm.Callback(msg)
	}

	// context is done, so we need to close the connection
	select {
	case conn := <-fsm.ConnCh:
		conn.Close()
	default:
	}

	if fsm.Conn != nil {
		err := fsm.Conn.Close()
		if err != nil {
			fsm.Logger.Error("failed to close existing tcp connection",
				log.Fields{
					"Topic": "Peer",
					"Key":   neighborAddress,
					"State": nextState,
				})
		}
	}

	close(fsm.ConnCh)
	fsm.OutgoingCh.Close()
}

func (fsm *fsm) changeAdminState(s AdminState) error {
	fsm.Lock.Lock()
	defer fsm.Lock.Unlock()

	if fsm.AdminState == s {
		fsm.Logger.Warn("cannot change to the same state",
			log.Fields{
				"Topic": "Peer",
				"Key":   fsm.PeerConf.State.NeighborAddress,
				"State": fsm.State.String(),
			})
		return fmt.Errorf("cannot change to the same state")
	}

	fsm.Logger.Debug("admin state changed",
		log.Fields{
			"Topic":      "Peer",
			"Key":        fsm.PeerConf.State.NeighborAddress,
			"State":      fsm.State.String(),
			"adminState": s.String(),
		})
	fsm.AdminState = s
	shutdown := false

	switch s {
	case AdminStateUp:
		fsm.Logger.Info("Administrative start",
			log.Fields{
				"Topic": "Peer",
				"Key":   fsm.PeerConf.State.NeighborAddress,
				"State": fsm.State.String(),
			})
	case AdminStateDown:
		shutdown = true
		fsm.Logger.Info("Administrative shutdown",
			log.Fields{
				"Topic": "Peer",
				"Key":   fsm.PeerConf.State.NeighborAddress,
				"State": fsm.State.String(),
			})
	case AdminStatePfxCt:
		shutdown = true
		fsm.Logger.Info("Administrative shutdown(Prefix limit reached)",
			log.Fields{
				"Topic": "Peer",
				"Key":   fsm.PeerConf.State.NeighborAddress,
				"State": fsm.State.String(),
			})
	}
	fsm.PeerConf.State.AdminDown = shutdown
	if shutdown {
		fsm.PeerConf.State.NeighborAddress = fsm.PeerConf.Config.NeighborAddress
		fsm.PeerConf.State.PeerAs = fsm.PeerConf.Config.PeerAs
		fsm.PeerConf.Timers.State = oc.TimersState{}
	}
	return nil
}
