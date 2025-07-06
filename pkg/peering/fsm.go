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
	"fmt"
	"net"
	"time"

	"github.com/eapache/channels"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
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

func newFSM(gConf *oc.Global, pConf *oc.Neighbor, logger log.Logger) *fsm {
	adminState := AdminStateUp
	if pConf.Config.AdminDown {
		adminState = AdminStateDown
	}
	pConf.State.SessionState = oc.IntToSessionStateMap[int(bgp.BGP_FSM_IDLE)]
	pConf.Timers.State.Downtime = time.Now().Unix()
	fsm := &fsm{
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
		Logger:               logger,
	}
	fsm.GracefulRestartTimer.Stop()
	return fsm
}

func (fsm *fsm) StateChange(nextState bgp.FSMState) {
	fsm.Lock.Lock()
	defer fsm.Lock.Unlock()

	fsm.Logger.Debug("state changed",
		log.Fields{
			"Topic":  "Peer",
			"Key":    fsm.PeerConf.State.NeighborAddress,
			"old":    fsm.State.String(),
			"new":    nextState.String(),
			"reason": fsm.Reason,
		})
	fsm.State = nextState
	switch nextState {
	case bgp.BGP_FSM_ESTABLISHED:
		fsm.PeerConf.Timers.State.Uptime = time.Now().Unix()
		fsm.PeerConf.State.EstablishedCount++
		// reset the state set by the previous session
		fsm.TwoByteAsTrans = false
		if _, y := fsm.CapMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]; !y {
			fsm.TwoByteAsTrans = true
			break
		}
		y := func() bool {
			for _, c := range fsm.PeerConf.Capabilities() {
				switch c.(type) {
				case *bgp.CapFourOctetASNumber:
					return true
				}
			}
			return false
		}()
		if !y {
			fsm.TwoByteAsTrans = true
		}
	default:
		fsm.PeerConf.Timers.State.Downtime = time.Now().Unix()
	}
}

func (fsm *fsm) RemoteHostPort() (string, uint16) {
	return netutils.HostPort(fsm.Conn.RemoteAddr())
}

func (fsm *fsm) LocalHostPort() (string, uint16) {
	return netutils.HostPort(fsm.Conn.LocalAddr())
}

func (fsm *fsm) sendNotificationFromErrorMsg(e *bgp.MessageError) (*bgp.BGPMessage, error) {
	fsm.Lock.RLock()
	established := fsm.Handler != nil && fsm.Handler.Conn != nil
	fsm.Lock.RUnlock()

	if established {
		m := bgp.NewBGPNotificationMessage(e.TypeCode, e.SubTypeCode, e.Data)
		b, _ := m.Serialize()
		_, err := fsm.Handler.Conn.Write(b)
		if err == nil {
			fsm.bgpMessageStateUpdate(m.Header.Type, false)
			fsm.Handler.SentNotification = m
		}
		fsm.Handler.Conn.Close()
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

func (fsm *fsm) setPeerConnMSS() error {
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
