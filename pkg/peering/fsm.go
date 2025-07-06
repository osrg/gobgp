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
	"math/rand"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/eapache/channels"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/bgputils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
	"github.com/osrg/gobgp/v4/pkg/utils"
)

const (
	MinConnectRetryInterval = 1
)

type FSMStateReasonType uint8

const (
	FSMDying FSMStateReasonType = iota
	FSMAdminDown
	FSMReadFailed
	FSMWriteFailed
	FSMNotificationSent
	FSMNotificationRecv
	FSMHoldTimerExpired
	FSMIdleTimerExpired
	FSMRestartTimerExpired
	FSMGracefulRestart
	FSMInvalidMsg
	FSMNewConnection
	FSMOpenMsgReceived
	FSMOpenMsgNegotiated
	FSMHardReset
	FSMDeconfigured
)

type FSMStateReason struct {
	Type            FSMStateReasonType
	BGPNotification *bgp.BGPMessage
	Data            []byte
}

func NewfsmStateReason(typ FSMStateReasonType, notif *bgp.BGPMessage, data []byte) *FSMStateReason {
	return &FSMStateReason{
		Type:            typ,
		BGPNotification: notif,
		Data:            data,
	}
}

func (r FSMStateReason) String() string {
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

type FSMMsgType int

const (
	_ FSMMsgType = iota
	FSMMsgStateChange
	FSMMsgBGPMessage
	FSMMsgRouteRefresh
)

type FSMMsg struct {
	MsgType     FSMMsgType
	FSM         *fsm
	MsgSrc      string
	MsgData     any
	StateReason *FSMStateReason
	PathList    []*table.Path
	Timestamp   time.Time
	Payload     []byte
}

type FSMOutgoingMsg struct {
	Paths        []*table.Path
	Notification *bgp.BGPMessage
	StayIdle     bool
}

const (
	HoldTimeOpenSent = 240
	HoldTimeIdle     = 5
)

type AdminState int

const (
	AdminStateUp AdminState = iota
	AdminStateDown
	AdminStatePfxCt
)

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

type AdminStateOperation struct {
	State         AdminState
	Communication []byte
}

type fsm struct {
	Lock                 sync.RWMutex
	GlobalConf           *oc.Global
	PeerConf             *oc.Neighbor
	State                bgp.FSMState
	OutgoingCh           *channels.InfiniteChannel
	Reason               *FSMStateReason
	Conn                 net.Conn
	ConnCh               chan net.Conn
	IdleHoldTime         float64
	OpenSentHoldTime     float64
	AdminState           AdminState
	AdminStateCh         chan AdminStateOperation
	Handler              *FSMHandler
	RFMap                map[bgp.Family]bgp.BGPAddPathMode
	CapMap               map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface
	RecvOpen             *bgp.BGPMessage
	PeerInfo             *table.PeerInfo
	GracefulRestartTimer *time.Timer
	TwoByteAsTrans       bool
	MarshallingOptions   *bgp.MarshallingOption
	Notification         chan *bgp.BGPMessage
	LongLivedRunning     bool
	Logger               log.Logger
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

type FSMCallback func(*FSMMsg)

type FSMHandler struct {
	FSM              *fsm
	Conn             net.Conn
	StateReasonCh    chan FSMStateReason
	Outgoing         *channels.InfiniteChannel
	HoldTimerResetCh chan bool
	SentNotification *bgp.BGPMessage
	Ctx              context.Context
	CtxCancel        context.CancelFunc
	Callback         FSMCallback
}

func newFSMHandler(fsm *fsm, outgoing *channels.InfiniteChannel, wg *sync.WaitGroup, callback FSMCallback) *FSMHandler {
	ctx, cancel := context.WithCancel(context.Background())
	h := &FSMHandler{
		FSM:              fsm,
		StateReasonCh:    make(chan FSMStateReason, 2),
		Outgoing:         outgoing,
		HoldTimerResetCh: make(chan bool, 2),
		Ctx:              ctx,
		CtxCancel:        cancel,
		Callback:         callback,
	}
	wg.Add(1)
	go h.loop(ctx, wg)
	return h
}

func (h *FSMHandler) idle(ctx context.Context) (bgp.FSMState, *FSMStateReason) {
	fsm := h.FSM

	fsm.Lock.RLock()
	idleHoldTimer := time.NewTimer(time.Second * time.Duration(fsm.IdleHoldTime))
	fsm.Lock.RUnlock()

	for {
		select {
		case <-ctx.Done():
			return -1, NewfsmStateReason(FSMDying, nil, nil)
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
				return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMRestartTimerExpired, nil, nil)
			}
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

		case <-idleHoldTimer.C:
			fsm.Lock.RLock()
			adminStateUp := fsm.AdminState == AdminStateUp
			fsm.Lock.RUnlock()

			if adminStateUp {
				fsm.Lock.Lock()
				fsm.Logger.Debug("IdleHoldTimer expired",
					log.Fields{
						"Topic":    "Peer",
						"Key":      fsm.PeerConf.State.NeighborAddress,
						"Duration": fsm.IdleHoldTime,
					})
				fsm.IdleHoldTime = HoldTimeIdle
				fsm.Lock.Unlock()
				return bgp.BGP_FSM_ACTIVE, NewfsmStateReason(FSMIdleTimerExpired, nil, nil)
			} else {
				fsm.Logger.Debug("IdleHoldTimer expired, but stay at idle because the admin state is DOWN",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.PeerConf.State.NeighborAddress,
					})
			}

		case stateOp := <-fsm.AdminStateCh:
			err := fsm.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case AdminStateDown:
					// stop idle hold timer
					idleHoldTimer.Stop()

				case AdminStateUp:
					// restart idle hold timer
					fsm.Lock.RLock()
					idleHoldTimer.Reset(time.Second * time.Duration(fsm.IdleHoldTime))
					fsm.Lock.RUnlock()
				}
			}
		}
	}
}

func (h *FSMHandler) connectLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	fsm := h.FSM

	retryInterval, addr, port, password, ttl, ttlMin, mss, localAddress, localPort, bindInterface := func() (int, string, int, string, uint8, uint8, uint16, string, int, string) {
		fsm.Lock.RLock()
		defer fsm.Lock.RUnlock()

		tick := max(int(fsm.PeerConf.Timers.Config.ConnectRetry), MinConnectRetryInterval)

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
		return tick, addr, port, password, ttl, ttlMin, fsm.PeerConf.Transport.Config.TcpMss, fsm.PeerConf.Transport.Config.LocalAddress, int(fsm.PeerConf.Transport.Config.LocalPort), fsm.PeerConf.Transport.Config.BindInterface
	}()

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

func (h *FSMHandler) active(ctx context.Context) (bgp.FSMState, *FSMStateReason) {
	c, cancel := context.WithCancel(ctx)

	fsm := h.FSM
	var wg sync.WaitGroup

	fsm.Lock.RLock()
	tryConnect := !fsm.PeerConf.Transport.Config.PassiveMode
	fsm.Lock.RUnlock()
	if tryConnect {
		wg.Add(1)
		go h.connectLoop(c, &wg)
	}

	defer func() {
		cancel()
		wg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return -1, NewfsmStateReason(FSMDying, nil, nil)
		case conn, ok := <-fsm.ConnCh:
			if !ok {
				break
			}
			fsm.Lock.Lock()
			fsm.Conn = conn
			fsm.Lock.Unlock()

			fsm.Lock.RLock()
			if err := fsm.SetPeerConnTTL(); err != nil {
				fsm.Logger.Warn("cannot set TTL for peer",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.PeerConf.Config.NeighborAddress,
						"State": fsm.State.String(),
						"Error": err,
					})
			}
			if err := fsm.setPeerConnMSS(); err != nil {
				fsm.Logger.Warn("cannot set MSS for peer",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.PeerConf.Config.NeighborAddress,
						"State": fsm.State.String(),
						"Error": err,
					})
			}
			fsm.Lock.RUnlock()
			// we don't implement delayed open timer so move to opensent right
			// away.
			return bgp.BGP_FSM_OPENSENT, NewfsmStateReason(FSMNewConnection, nil, nil)
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
				return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMRestartTimerExpired, nil, nil)
			}
		case err := <-h.StateReasonCh:
			return bgp.BGP_FSM_IDLE, &err
		case stateOp := <-fsm.AdminStateCh:
			err := h.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case AdminStateDown:
					return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMAdminDown, nil, nil)
				case AdminStateUp:
					fsm.Logger.Panic("code logic bug",
						log.Fields{
							"Topic":      "Peer",
							"Key":        fsm.PeerConf.State.NeighborAddress,
							"State":      fsm.State.String(),
							"AdminState": stateOp.State.String(),
						})
				}
			}
		}
	}
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

func (h *FSMHandler) afiSafiDisable(rf bgp.Family) string {
	h.FSM.Lock.Lock()
	defer h.FSM.Lock.Unlock()

	n := bgp.AddressFamilyNameMap[rf]

	for i, a := range h.FSM.PeerConf.AfiSafis {
		if string(a.Config.AfiSafiName) == n {
			h.FSM.PeerConf.AfiSafis[i].State.Enabled = false
			break
		}
	}
	newList := make([]bgp.ParameterCapabilityInterface, 0)
	for _, c := range h.FSM.CapMap[bgp.BGP_CAP_MULTIPROTOCOL] {
		if c.(*bgp.CapMultiProtocol).CapValue == rf {
			continue
		}
		newList = append(newList, c)
	}
	h.FSM.CapMap[bgp.BGP_CAP_MULTIPROTOCOL] = newList
	return n
}

func (h *FSMHandler) handlingError(m *bgp.BGPMessage, e error, useRevisedError bool) bgp.ErrorHandling {
	// ineffectual assignment to handling (ineffassign)
	var handling bgp.ErrorHandling
	if m.Header.Type == bgp.BGP_MSG_UPDATE && useRevisedError {
		factor := e.(*bgp.MessageError)
		handling = factor.ErrorHandling
		switch handling {
		case bgp.ERROR_HANDLING_ATTRIBUTE_DISCARD:
			h.FSM.Lock.RLock()
			h.FSM.Logger.Warn("Some attributes were discarded",
				log.Fields{
					"Topic": "Peer",
					"Key":   h.FSM.PeerConf.State.NeighborAddress,
					"State": h.FSM.State.String(),
					"Error": e,
				})
			h.FSM.Lock.RUnlock()
		case bgp.ERROR_HANDLING_TREAT_AS_WITHDRAW:
			m.Body = bgp.TreatAsWithdraw(m.Body.(*bgp.BGPUpdate))
			h.FSM.Lock.RLock()
			h.FSM.Logger.Warn("the received Update message was treated as withdraw",
				log.Fields{
					"Topic": "Peer",
					"Key":   h.FSM.PeerConf.State.NeighborAddress,
					"State": h.FSM.State.String(),
					"Error": e,
				})
			h.FSM.Lock.RUnlock()
		case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
			rf := bgputils.ExtractFamily(factor.ErrorAttribute)
			if rf == nil {
				h.FSM.Lock.RLock()
				h.FSM.Logger.Warn("Error occurred during AFI/SAFI disabling",
					log.Fields{
						"Topic": "Peer",
						"Key":   h.FSM.PeerConf.State.NeighborAddress,
						"State": h.FSM.State.String(),
					})
				h.FSM.Lock.RUnlock()
			} else {
				n := h.afiSafiDisable(*rf)
				h.FSM.Lock.RLock()
				h.FSM.Logger.Warn("Capability was disabled",
					log.Fields{
						"Topic": "Peer",
						"Key":   h.FSM.PeerConf.State.NeighborAddress,
						"State": h.FSM.State.String(),
						"Error": e,
						"Cap":   n,
					})
				h.FSM.Lock.RUnlock()
			}
		}
	} else {
		handling = bgp.ERROR_HANDLING_SESSION_RESET
	}
	return handling
}

func (h *FSMHandler) recvMessageWithError(ctx context.Context) (*FSMMsg, error) {
	sendToStateReasonCh := func(typ FSMStateReasonType, notif *bgp.BGPMessage) {
		reason := *NewfsmStateReason(typ, notif, nil)
		pushed := utils.PushWithContext(ctx, h.StateReasonCh, reason, false)
		if !pushed {
			h.FSM.Logger.Warn("failed to push state reason",
				log.Fields{
					"Topic": "Peer",
					"Key":   h.FSM.PeerConf.State.NeighborAddress,
					"State": h.FSM.State.String(),
					"Data":  reason,
				})
		}
	}

	headerBuf, err := netutils.ReadAll(h.Conn, bgp.BGP_HEADER_LENGTH)
	if err == context.Canceled {
		return nil, nil
	} else if err != nil {
		sendToStateReasonCh(FSMReadFailed, nil)
		return nil, err
	}

	hd := &bgp.BGPHeader{}
	err = hd.DecodeFromBytes(headerBuf)
	if err != nil {
		h.FSM.bgpMessageStateUpdate(0, true)
		h.FSM.Lock.RLock()
		h.FSM.Logger.Warn("Session will be reset due to malformed BGP Header",
			log.Fields{
				"Topic": "Peer",
				"Key":   h.FSM.PeerConf.State.NeighborAddress,
				"State": h.FSM.State.String(),
				"Error": err,
			})
		fmsg := &FSMMsg{
			FSM:     h.FSM,
			MsgType: FSMMsgBGPMessage,
			MsgSrc:  h.FSM.PeerConf.State.NeighborAddress,
			MsgData: err,
		}
		h.FSM.Lock.RUnlock()
		return fmsg, err
	}

	bodyBuf, err := netutils.ReadAll(h.Conn, int(hd.Len)-bgp.BGP_HEADER_LENGTH)
	if err == context.Canceled {
		return nil, nil
	} else if err != nil {
		sendToStateReasonCh(FSMReadFailed, nil)
		return nil, err
	}

	now := time.Now()
	handling := bgp.ERROR_HANDLING_NONE

	h.FSM.Lock.RLock()
	useRevisedError := h.FSM.PeerConf.ErrorHandling.Config.TreatAsWithdraw
	options := h.FSM.MarshallingOptions
	h.FSM.Lock.RUnlock()

	m, err := bgp.ParseBGPBody(hd, bodyBuf, options)
	if err != nil {
		handling = h.handlingError(m, err, useRevisedError)
		h.FSM.bgpMessageStateUpdate(0, true)
	} else {
		h.FSM.bgpMessageStateUpdate(m.Header.Type, true)
		err = bgp.ValidateBGPMessage(m)
	}
	h.FSM.Lock.RLock()
	fmsg := &FSMMsg{
		FSM:       h.FSM,
		MsgType:   FSMMsgBGPMessage,
		MsgSrc:    h.FSM.PeerConf.State.NeighborAddress,
		Timestamp: now,
	}
	h.FSM.Lock.RUnlock()

	switch handling {
	case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
		fmsg.MsgData = m
		return fmsg, nil
	case bgp.ERROR_HANDLING_SESSION_RESET:
		h.FSM.Lock.RLock()
		h.FSM.Logger.Warn("Session will be reset due to malformed BGP message",
			log.Fields{
				"Topic": "Peer",
				"Key":   h.FSM.PeerConf.State.NeighborAddress,
				"State": h.FSM.State.String(),
				"Error": err,
			})
		h.FSM.Lock.RUnlock()
		fmsg.MsgData = err
		return fmsg, err
	default:
		fmsg.MsgData = m

		h.FSM.Lock.RLock()
		establishedState := h.FSM.State == bgp.BGP_FSM_ESTABLISHED
		h.FSM.Lock.RUnlock()

		if establishedState {
			switch m.Header.Type {
			case bgp.BGP_MSG_ROUTE_REFRESH:
				fmsg.MsgType = FSMMsgRouteRefresh
			case bgp.BGP_MSG_UPDATE:
				// if the length of h.holdTimerResetCh
				// isn't zero, the timer will be reset
				// soon anyway.
				select {
				case h.HoldTimerResetCh <- true:
				default:
				}
				body := m.Body.(*bgp.BGPUpdate)
				isEBGP := h.FSM.PeerConf.IsEBGPPeer(h.FSM.GlobalConf)
				isConfed := h.FSM.PeerConf.IsConfederationMember(h.FSM.GlobalConf)

				fmsg.Payload = make([]byte, len(headerBuf)+len(bodyBuf))
				copy(fmsg.Payload, headerBuf)
				copy(fmsg.Payload[len(headerBuf):], bodyBuf)

				h.FSM.Lock.RLock()
				rfMap := h.FSM.RFMap
				h.FSM.Lock.RUnlock()

				// Allow updates from host loopback addresses if the BGP connection
				// with the neighbour is both dialed and received on loopback
				// addresses.
				var allowLoopback bool
				if localAddr, peerAddr := h.FSM.PeerInfo.LocalAddress, h.FSM.PeerInfo.Address; localAddr.To4() != nil && peerAddr.To4() != nil {
					allowLoopback = localAddr.IsLoopback() && peerAddr.IsLoopback()
				}
				ok, err := bgp.ValidateUpdateMsg(body, rfMap, isEBGP, isConfed, allowLoopback)
				if !ok {
					handling = h.handlingError(m, err, useRevisedError)
				}
				if handling == bgp.ERROR_HANDLING_SESSION_RESET {
					h.FSM.Lock.RLock()
					h.FSM.Logger.Warn("Session will be reset due to malformed BGP update message",
						log.Fields{
							"Topic": "Peer",
							"Key":   h.FSM.PeerConf.State.NeighborAddress,
							"State": h.FSM.State.String(),
							"error": err,
						})
					h.FSM.Lock.RUnlock()
					fmsg.MsgData = err
					return fmsg, err
				}

				if routes := len(body.WithdrawnRoutes); routes > 0 {
					h.FSM.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
					h.FSM.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
				} else if attr := bgputils.GetPathAttrFromBGPUpdate(body, bgp.BGP_ATTR_TYPE_MP_UNREACH_NLRI); attr != nil {
					mpUnreach := attr.(*bgp.PathAttributeMpUnreachNLRI)
					if routes = len(mpUnreach.Value); routes > 0 {
						h.FSM.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
						h.FSM.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
					}
				}

				table.UpdatePathAttrs4ByteAs(h.FSM.Logger, body)

				if err = table.UpdatePathAggregator4ByteAs(body); err != nil {
					fmsg.MsgData = err
					return fmsg, err
				}

				h.FSM.Lock.RLock()
				peerInfo := h.FSM.PeerInfo
				h.FSM.Lock.RUnlock()
				fmsg.PathList = table.ProcessMessage(m, peerInfo, fmsg.Timestamp)
				fallthrough
			case bgp.BGP_MSG_KEEPALIVE:
				// if the length of h.holdTimerResetCh
				// isn't zero, the timer will be reset
				// soon anyway.
				select {
				case h.HoldTimerResetCh <- true:
				default:
				}
				if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
					return nil, nil
				}
			case bgp.BGP_MSG_NOTIFICATION:
				body := m.Body.(*bgp.BGPNotification)
				if body.ErrorCode == bgp.BGP_ERROR_CEASE && (body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN || body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET) {
					communication, rest := utils.DecodeAdministrativeCommunication(body.Data)
					h.FSM.Lock.RLock()
					h.FSM.Logger.Warn("received notification",
						log.Fields{
							"Topic":               "Peer",
							"Key":                 h.FSM.PeerConf.State.NeighborAddress,
							"Code":                body.ErrorCode,
							"Subcode":             body.ErrorSubcode,
							"Communicated-Reason": communication,
							"Data":                rest,
						})
					h.FSM.Lock.RUnlock()
				} else {
					h.FSM.Lock.RLock()
					h.FSM.Logger.Warn("received notification",
						log.Fields{
							"Topic":   "Peer",
							"Key":     h.FSM.PeerConf.State.NeighborAddress,
							"Code":    body.ErrorCode,
							"Subcode": body.ErrorSubcode,
							"Data":    body.Data,
						})
					h.FSM.Lock.RUnlock()
				}

				h.FSM.Lock.RLock()
				s := h.FSM.PeerConf.GracefulRestart.State
				hardReset := s.Enabled && s.NotificationEnabled && body.ErrorCode == bgp.BGP_ERROR_CEASE && body.ErrorSubcode == bgp.BGP_ERROR_SUB_HARD_RESET
				h.FSM.Lock.RUnlock()
				if hardReset {
					sendToStateReasonCh(FSMHardReset, m)
				} else {
					sendToStateReasonCh(FSMNotificationRecv, m)
				}
				return nil, nil
			}
		}
	}
	return fmsg, nil
}

func (h *FSMHandler) recvMessage(ctx context.Context, recvChan chan<- any, wg *sync.WaitGroup) error {
	defer wg.Done()
	fmsg, _ := h.recvMessageWithError(ctx)
	if fmsg != nil {
		recvChan <- fmsg
	}
	return nil
}

func (h *FSMHandler) opensent(ctx context.Context) (bgp.FSMState, *FSMStateReason) {
	fsm := h.FSM

	fsm.Lock.Lock()
	m := bgputils.BuildOpenMessage(fsm.GlobalConf, fsm.PeerConf)
	fsm.Lock.Unlock()

	b, _ := m.Serialize()
	fsm.Conn.Write(b)
	fsm.bgpMessageStateUpdate(m.Header.Type, false)

	fsm.Lock.RLock()
	h.Conn = fsm.Conn
	fsm.Lock.RUnlock()

	wg := &sync.WaitGroup{}
	wg.Add(1)

	recvChan := make(chan any, 1)
	go h.recvMessage(ctx, recvChan, wg)

	defer func() {
		wg.Wait()
		close(recvChan)
	}()

	// RFC 4271 P.60
	// sets its HoldTimer to a large value
	// A HoldTimer value of 4 minutes is suggested as a "large value"
	// for the HoldTimer
	fsm.Lock.RLock()
	holdTimer := time.NewTimer(time.Second * time.Duration(fsm.OpenSentHoldTime))
	fsm.Lock.RUnlock()

	for {
		select {
		case <-ctx.Done():
			h.Conn.Close()
			return -1, NewfsmStateReason(FSMDying, nil, nil)
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
				return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMRestartTimerExpired, nil, nil)
			}
		case i, ok := <-recvChan:
			if !ok {
				continue
			}
			e := i.(*FSMMsg)
			switch m := e.MsgData.(type) {
			case *bgp.BGPMessage:
				if m.Header.Type == bgp.BGP_MSG_OPEN {
					fsm.Lock.Lock()
					fsm.RecvOpen = m
					fsm.Lock.Unlock()

					body := m.Body.(*bgp.BGPOpen)

					fsm.Lock.RLock()
					fsmPeerAS := fsm.PeerConf.Config.PeerAs
					fsm.Lock.RUnlock()
					peerAs, err := bgp.ValidateOpenMsg(body, fsmPeerAS, fsm.PeerInfo.LocalAS, net.ParseIP(fsm.GlobalConf.Config.RouterId))
					if err != nil {
						m, _ := fsm.sendNotificationFromErrorMsg(err.(*bgp.MessageError))
						return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMInvalidMsg, m, nil)
					}

					// ASN negotiation was skipped
					fsm.Lock.RLock()
					asnNegotiationSkipped := fsm.PeerConf.Config.PeerAs == 0
					fsm.Lock.RUnlock()
					if asnNegotiationSkipped {
						fsm.Lock.Lock()
						typ := oc.PEER_TYPE_EXTERNAL
						if fsm.PeerInfo.LocalAS == peerAs {
							typ = oc.PEER_TYPE_INTERNAL
						}
						fsm.PeerConf.State.PeerType = typ
						fsm.Logger.Info("skipped asn negotiation",
							log.Fields{
								"Topic":    "Peer",
								"Key":      fsm.PeerConf.State.NeighborAddress,
								"State":    fsm.State.String(),
								"Asn":      peerAs,
								"PeerType": typ,
							})
						fsm.Lock.Unlock()
					} else {
						fsm.Lock.Lock()
						fsm.PeerConf.State.PeerType = fsm.PeerConf.Config.PeerType
						fsm.Lock.Unlock()
					}
					fsm.Lock.Lock()
					fsm.PeerConf.State.PeerAs = peerAs
					fsm.PeerInfo.AS = peerAs
					fsm.PeerInfo.ID = body.ID
					fsm.CapMap, fsm.RFMap = bgputils.Open2Cap(body, fsm.PeerConf)

					if _, y := fsm.CapMap[bgp.BGP_CAP_ADD_PATH]; y {
						fsm.MarshallingOptions = &bgp.MarshallingOption{
							AddPath: fsm.RFMap,
						}
					} else {
						fsm.MarshallingOptions = nil
					}

					// calculate HoldTime
					// RFC 4271 P.13
					// a BGP speaker MUST calculate the value of the Hold Timer
					// by using the smaller of its configured Hold Time and the Hold Time
					// received in the OPEN message.
					holdTime := float64(body.HoldTime)
					myHoldTime := fsm.PeerConf.Timers.Config.HoldTime
					if holdTime > myHoldTime {
						fsm.PeerConf.Timers.State.NegotiatedHoldTime = myHoldTime
					} else {
						fsm.PeerConf.Timers.State.NegotiatedHoldTime = holdTime
					}

					keepalive := fsm.PeerConf.Timers.Config.KeepaliveInterval
					if n := fsm.PeerConf.Timers.State.NegotiatedHoldTime; n < myHoldTime {
						keepalive = n / 3
					}
					fsm.PeerConf.Timers.State.KeepaliveInterval = keepalive

					gr, ok := fsm.CapMap[bgp.BGP_CAP_GRACEFUL_RESTART]
					if fsm.PeerConf.GracefulRestart.Config.Enabled && ok {
						state := &fsm.PeerConf.GracefulRestart.State
						state.Enabled = true
						cap := gr[len(gr)-1].(*bgp.CapGracefulRestart)
						state.PeerRestartTime = cap.Time

						for _, t := range cap.Tuples {
							n := bgp.AddressFamilyNameMap[bgp.NewFamily(t.AFI, t.SAFI)]
							for i, a := range fsm.PeerConf.AfiSafis {
								if string(a.Config.AfiSafiName) == n {
									fsm.PeerConf.AfiSafis[i].MpGracefulRestart.State.Enabled = true
									fsm.PeerConf.AfiSafis[i].MpGracefulRestart.State.Received = true
									break
								}
							}
						}

						// RFC 4724 4.1
						// To re-establish the session with its peer, the Restarting Speaker
						// MUST set the "Restart State" bit in the Graceful Restart Capability
						// of the OPEN message.
						if fsm.PeerConf.GracefulRestart.State.PeerRestarting && cap.Flags&0x08 == 0 {
							fsm.Logger.Warn("restart flag is not set",
								log.Fields{
									"Topic": "Peer",
									"Key":   fsm.PeerConf.State.NeighborAddress,
									"State": fsm.State.String(),
								})
							// just ignore
						}

						// RFC 4724 3
						// The most significant bit is defined as the Restart State (R)
						// bit, ...(snip)... When set (value 1), this bit
						// indicates that the BGP speaker has restarted, and its peer MUST
						// NOT wait for the End-of-RIB marker from the speaker before
						// advertising routing information to the speaker.
						if fsm.PeerConf.GracefulRestart.State.LocalRestarting && cap.Flags&0x08 != 0 {
							fsm.Logger.Debug("peer has restarted, skipping wait for EOR",
								log.Fields{
									"Topic": "Peer",
									"Key":   fsm.PeerConf.State.NeighborAddress,
									"State": fsm.State.String(),
								})
							for i := range fsm.PeerConf.AfiSafis {
								fsm.PeerConf.AfiSafis[i].MpGracefulRestart.State.EndOfRibReceived = true
							}
						}
						if fsm.PeerConf.GracefulRestart.Config.NotificationEnabled && cap.Flags&0x04 > 0 {
							fsm.PeerConf.GracefulRestart.State.NotificationEnabled = true
						}
					}
					llgr, ok2 := fsm.CapMap[bgp.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART]
					if fsm.PeerConf.GracefulRestart.Config.LongLivedEnabled && ok && ok2 {
						fsm.PeerConf.GracefulRestart.State.LongLivedEnabled = true
						cap := llgr[len(llgr)-1].(*bgp.CapLongLivedGracefulRestart)
						for _, t := range cap.Tuples {
							n := bgp.AddressFamilyNameMap[bgp.NewFamily(t.AFI, t.SAFI)]
							for i, a := range fsm.PeerConf.AfiSafis {
								if string(a.Config.AfiSafiName) == n {
									fsm.PeerConf.AfiSafis[i].LongLivedGracefulRestart.State.Enabled = true
									fsm.PeerConf.AfiSafis[i].LongLivedGracefulRestart.State.Received = true
									fsm.PeerConf.AfiSafis[i].LongLivedGracefulRestart.State.PeerRestartTime = t.RestartTime
									break
								}
							}
						}
					}

					fsm.Lock.Unlock()
					msg := bgp.NewBGPKeepAliveMessage()
					b, _ := msg.Serialize()
					fsm.Conn.Write(b)
					fsm.bgpMessageStateUpdate(msg.Header.Type, false)
					return bgp.BGP_FSM_OPENCONFIRM, NewfsmStateReason(FSMOpenMsgReceived, nil, nil)
				} else {
					// send notification?
					h.Conn.Close()
					return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMInvalidMsg, nil, nil)
				}
			case *bgp.MessageError:
				msg, _ := fsm.sendNotificationFromErrorMsg(m)
				return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMInvalidMsg, msg, nil)
			default:
				h.FSM.Logger.Panic("unknown msg type",
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
			return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMHoldTimerExpired, m, nil)
		case stateOp := <-fsm.AdminStateCh:
			err := h.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case AdminStateDown:
					h.Conn.Close()
					return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMAdminDown, m, nil)
				case AdminStateUp:
					h.FSM.Logger.Panic("code logic bug",
						log.Fields{
							"Topic":      "Peer",
							"Key":        fsm.PeerConf.State.NeighborAddress,
							"State":      fsm.State.String(),
							"AdminState": stateOp.State.String(),
						})
				}
			}
		}
	}
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

func (h *FSMHandler) openconfirm(ctx context.Context) (bgp.FSMState, *FSMStateReason) {
	fsm := h.FSM
	ticker := fsm.keepAliveTicker()

	fsm.Lock.RLock()
	h.Conn = fsm.Conn

	wg := &sync.WaitGroup{}
	wg.Add(1)

	recvChan := make(chan any, 1)
	go h.recvMessage(ctx, recvChan, wg)

	defer func() {
		wg.Wait()
		close(recvChan)
	}()

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
			return -1, NewfsmStateReason(FSMDying, nil, nil)
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
				return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMRestartTimerExpired, nil, nil)
			}
		case <-ticker.C:
			m := bgp.NewBGPKeepAliveMessage()
			b, _ := m.Serialize()
			// TODO: check error
			fsm.Conn.Write(b)
			fsm.bgpMessageStateUpdate(m.Header.Type, false)
		case i := <-recvChan:
			e := i.(*FSMMsg)
			switch m := e.MsgData.(type) {
			case *bgp.BGPMessage:
				if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
					return bgp.BGP_FSM_ESTABLISHED, NewfsmStateReason(FSMOpenMsgNegotiated, nil, nil)
				}
				// send notification ?
				h.Conn.Close()
				return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMInvalidMsg, nil, nil)
			case *bgp.MessageError:
				msg, _ := fsm.sendNotificationFromErrorMsg(m)
				return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMInvalidMsg, msg, nil)
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
			return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMHoldTimerExpired, m, nil)
		case stateOp := <-fsm.AdminStateCh:
			err := h.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case AdminStateDown:
					h.Conn.Close()
					return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMAdminDown, nil, nil)
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

func (h *FSMHandler) sendMessageloop(ctx context.Context, wg *sync.WaitGroup) error {
	sendToStateReasonCh := func(typ FSMStateReasonType, notif *bgp.BGPMessage) {
		reason := *NewfsmStateReason(typ, notif, nil)
		pushed := utils.PushWithContext(ctx, h.StateReasonCh, reason, false)
		if !pushed {
			h.FSM.Logger.Warn("failed to push state reason",
				log.Fields{
					"Topic": "Peer",
					"Key":   h.FSM.PeerConf.State.NeighborAddress,
					"State": h.FSM.State.String(),
					"Data":  reason,
				})
		}
	}

	defer wg.Done()
	conn := h.Conn
	fsm := h.FSM
	ticker := fsm.keepAliveTicker()
	send := func(m *bgp.BGPMessage) error {
		fsm.Lock.RLock()
		if fsm.TwoByteAsTrans && m.Header.Type == bgp.BGP_MSG_UPDATE {
			fsm.Logger.Debug("update for 2byte AS peer",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
					"Data":  m,
				})
			table.UpdatePathAttrs2ByteAs(m.Body.(*bgp.BGPUpdate))
			table.UpdatePathAggregator2ByteAs(m.Body.(*bgp.BGPUpdate))
		}

		// RFC8538 defines a Hard Reset notification subcode which
		// indicates that the BGP speaker wants to reset the session
		// without triggering graceful restart procedures. Here we map
		// notification subcodes to the Hard Reset subcode following
		// the RFC8538 suggestion.
		//
		// We check Status instead of Config because RFC8538 states
		// that A BGP speaker SHOULD NOT send a Hard Reset to a peer
		// from which it has not received the "N" bit.
		if fsm.PeerConf.GracefulRestart.State.NotificationEnabled && m.Header.Type == bgp.BGP_MSG_NOTIFICATION {
			if body := m.Body.(*bgp.BGPNotification); body.ErrorCode == bgp.BGP_ERROR_CEASE && bgp.ShouldHardReset(body.ErrorSubcode, false) {
				body.ErrorSubcode = bgp.BGP_ERROR_SUB_HARD_RESET
			}
		}

		b, err := m.Serialize(h.FSM.MarshallingOptions)
		fsm.Lock.RUnlock()
		if err != nil {
			fsm.Lock.RLock()
			fsm.Logger.Warn("failed to serialize",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
					"Data":  err,
				})
			fsm.Lock.RUnlock()
			fsm.bgpMessageStateUpdate(0, false)
			return nil
		}
		fsm.Lock.RLock()
		err = conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(fsm.PeerConf.Timers.State.NegotiatedHoldTime)))
		fsm.Lock.RUnlock()
		if err != nil {
			sendToStateReasonCh(FSMWriteFailed, nil)
			conn.Close()
			return fmt.Errorf("failed to set write deadline")
		}
		_, err = conn.Write(b)
		if err != nil {
			fsm.Lock.RLock()
			fsm.Logger.Warn("failed to send",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
					"Data":  err,
				})
			fsm.Lock.RUnlock()
			sendToStateReasonCh(FSMWriteFailed, nil)
			conn.Close()
			return fmt.Errorf("closed")
		}
		fsm.bgpMessageStateUpdate(m.Header.Type, false)

		switch m.Header.Type {
		case bgp.BGP_MSG_NOTIFICATION:
			body := m.Body.(*bgp.BGPNotification)
			if body.ErrorCode == bgp.BGP_ERROR_CEASE && (body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN || body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET) {
				communication, rest := utils.DecodeAdministrativeCommunication(body.Data)
				fsm.Lock.RLock()
				fsm.Logger.Warn("sent notification",
					log.Fields{
						"Topic":               "Peer",
						"Key":                 fsm.PeerConf.State.NeighborAddress,
						"State":               fsm.State.String(),
						"Code":                body.ErrorCode,
						"Subcode":             body.ErrorSubcode,
						"Communicated-Reason": communication,
						"Data":                rest,
					})
				fsm.Lock.RUnlock()
			} else {
				fsm.Lock.RLock()
				fsm.Logger.Warn("sent notification",
					log.Fields{
						"Topic":   "Peer",
						"Key":     fsm.PeerConf.State.NeighborAddress,
						"State":   fsm.State.String(),
						"Code":    body.ErrorCode,
						"Subcode": body.ErrorSubcode,
						"Data":    body.Data,
					})
				fsm.Lock.RUnlock()
			}
			sendToStateReasonCh(FSMNotificationSent, m)
			conn.Close()
			return fmt.Errorf("closed")
		case bgp.BGP_MSG_UPDATE:
			update := m.Body.(*bgp.BGPUpdate)
			if fsm.Logger.GetLevel() >= log.DebugLevel {
				fsm.Lock.RLock()
				fsm.Logger.Debug("sent update",
					log.Fields{
						"Topic":       "Peer",
						"Key":         fsm.PeerConf.State.NeighborAddress,
						"State":       fsm.State.String(),
						"nlri":        update.NLRI,
						"withdrawals": update.WithdrawnRoutes,
						"attributes":  update.PathAttributes,
					})
				fsm.Lock.RUnlock()
			}
		default:
			fsm.Lock.RLock()
			fsm.Logger.Debug("sent",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
					"data":  m,
				})
			fsm.Lock.RUnlock()
		}
		return nil
	}

	sendFromChan := func(o any) {
		switch m := o.(type) {
		case *FSMOutgoingMsg:
			h.FSM.Lock.RLock()
			options := h.FSM.MarshallingOptions
			h.FSM.Lock.RUnlock()
			for _, msg := range table.CreateUpdateMsgFromPaths(m.Paths, options) {
				if err := send(msg); err != nil {
					return
				}
			}
			if m.Notification != nil {
				if m.StayIdle {
					// current user is only prefix-limit
					// fix me if this is not the case
					_ = h.changeadminState(AdminStatePfxCt)
				}
				if err := send(m.Notification); err != nil {
					return
				}
			}
		default:
		}
	}

	for {
		select {
		case <-ctx.Done():
			// send remaining messages
			// before closing the connection
			// (for example, all the dropped routes)
			for {
				select {
				case o := <-h.Outgoing.Out():
					sendFromChan(o)
				default:
					return nil
				}
			}
		case o := <-h.Outgoing.Out():
			sendFromChan(o)
		case <-ticker.C:
			if err := send(bgp.NewBGPKeepAliveMessage()); err != nil {
				return nil
			}
		}
	}
}

func (h *FSMHandler) recvMessageloop(ctx context.Context, wg *sync.WaitGroup) error {
	defer wg.Done()
	for {
		fmsg, err := h.recvMessageWithError(ctx)
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if fmsg != nil {
			h.Callback(fmsg)
		}
		if err != nil {
			return nil
		}
	}
}

func (h *FSMHandler) established(ctx context.Context) (bgp.FSMState, *FSMStateReason) {
	fsm := h.FSM
	fsm.Lock.Lock()
	h.Conn = fsm.Conn
	fsm.Lock.Unlock()

	c, cancel := context.WithCancel(ctx)
	wg := sync.WaitGroup{}
	wg.Add(2)

	defer func() {
		cancel()
		wg.Wait()
	}()

	go h.sendMessageloop(c, &wg)
	go h.recvMessageloop(c, &wg)

	var holdTimer *time.Timer
	if fsm.PeerConf.Timers.State.NegotiatedHoldTime == 0 {
		holdTimer = &time.Timer{}
	} else {
		fsm.Lock.RLock()
		holdTimer = time.NewTimer(time.Second * time.Duration(fsm.PeerConf.Timers.State.NegotiatedHoldTime))
		fsm.Lock.RUnlock()
	}

	fsm.GracefulRestartTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			select {
			case m := <-fsm.Notification:
				// RFC8538 defines a Hard Reset notification subcode which
				// indicates that the BGP speaker wants to reset the session
				// without triggering graceful restart procedures. Here we map
				// notification subcodes to the Hard Reset subcode following
				// the RFC8538 suggestion.
				//
				// We check Status instead of Config because RFC8538 states
				// that A BGP speaker SHOULD NOT send a Hard Reset to a peer
				// from which it has not received the "N" bit.
				if fsm.PeerConf.GracefulRestart.State.NotificationEnabled {
					if body := m.Body.(*bgp.BGPNotification); body.ErrorCode == bgp.BGP_ERROR_CEASE && bgp.ShouldHardReset(body.ErrorSubcode, false) {
						body.ErrorSubcode = bgp.BGP_ERROR_SUB_HARD_RESET
					}
				}
				b, _ := m.Serialize(h.FSM.MarshallingOptions)
				h.Conn.Write(b)
			default:
				// nothing to do
			}
			h.Conn.Close()
			return -1, NewfsmStateReason(FSMDying, nil, nil)
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
		case err := <-h.StateReasonCh:
			h.Conn.Close()
			// if recv goroutine hit an error and sent to
			// stateReasonCh, then tx goroutine might take
			// long until it exits because it waits for
			// ctx.Done() or keepalive timer. So let kill
			// it now.
			h.Outgoing.In() <- err
			fsm.Lock.RLock()
			if s := fsm.PeerConf.GracefulRestart.State; s.Enabled {
				if s.NotificationEnabled && err.Type == FSMNotificationRecv ||
					err.Type == FSMNotificationSent &&
						err.BGPNotification.Body.(*bgp.BGPNotification).ErrorCode == bgp.BGP_ERROR_HOLD_TIMER_EXPIRED ||
					err.Type == FSMReadFailed ||
					err.Type == FSMWriteFailed {
					err = *NewfsmStateReason(FSMGracefulRestart, nil, nil)
					fsm.Logger.Info("peer graceful restart",
						log.Fields{
							"Topic": "Peer",
							"Key":   fsm.PeerConf.State.NeighborAddress,
							"State": fsm.State.String(),
						})
					fsm.GracefulRestartTimer.Reset(time.Duration(fsm.PeerConf.GracefulRestart.State.PeerRestartTime) * time.Second)
				}
			}
			fsm.Lock.RUnlock()
			return bgp.BGP_FSM_IDLE, &err
		case <-holdTimer.C:
			fsm.Lock.RLock()
			fsm.Logger.Warn("hold timer expired",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
				})
			fsm.Lock.RUnlock()
			m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil)
			h.Outgoing.In() <- &FSMOutgoingMsg{Notification: m}
			fsm.Lock.RLock()
			s := fsm.PeerConf.GracefulRestart.State
			fsm.Lock.RUnlock()
			// Do not return hold timer expired to server if graceful restart is enabled
			// Let it fallback to read/write error or fsmNotificationSent handled above
			// Reference: https://github.com/osrg/gobgp/issues/2174
			if !s.Enabled {
				return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMHoldTimerExpired, m, nil)
			}
		case <-h.HoldTimerResetCh:
			fsm.Lock.RLock()
			if fsm.PeerConf.Timers.State.NegotiatedHoldTime != 0 {
				holdTimer.Reset(time.Second * time.Duration(fsm.PeerConf.Timers.State.NegotiatedHoldTime))
			}
			fsm.Lock.RUnlock()
		case stateOp := <-fsm.AdminStateCh:
			err := h.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case AdminStateDown:
					m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, stateOp.Communication)
					h.Outgoing.In() <- &FSMOutgoingMsg{Notification: m}
				}
			}
		}
	}
}

func (h *FSMHandler) loop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	fsm := h.FSM
	fsm.Lock.RLock()
	oldState := fsm.State
	neighborAddress := fsm.PeerConf.State.NeighborAddress
	fsm.Lock.RUnlock()

	var reason *FSMStateReason
	nextState := bgp.FSMState(-1)

	for ctx.Err() == nil {
		switch oldState {
		case bgp.BGP_FSM_IDLE:
			nextState, reason = h.idle(ctx)
			// case bgp.BGP_FSM_CONNECT:
			// 	nextState = h.connect()
		case bgp.BGP_FSM_ACTIVE:
			nextState, reason = h.active(ctx)
		case bgp.BGP_FSM_OPENSENT:
			nextState, reason = h.opensent(ctx)
		case bgp.BGP_FSM_OPENCONFIRM:
			nextState, reason = h.openconfirm(ctx)
		case bgp.BGP_FSM_ESTABLISHED:
			nextState, reason = h.established(ctx)
		}

		fsm.Lock.Lock()
		fsm.Reason = reason
		fsm.Lock.Unlock()

		if nextState == bgp.BGP_FSM_ESTABLISHED && oldState == bgp.BGP_FSM_OPENCONFIRM {
			fsm.Logger.Info("Peer Up",
				log.Fields{
					"Topic": "Peer",
					"Key":   neighborAddress,
					"State": oldState.String(),
				})
		}

		if oldState == bgp.BGP_FSM_ESTABLISHED {
			// The main goroutine sent the notification due to
			// deconfiguration or something.
			reason := *reason
			if fsm.Handler.SentNotification != nil {
				reason.Type = FSMNotificationSent
				reason.BGPNotification = fsm.Handler.SentNotification
			}
			fsm.Logger.Info("Peer Down",
				log.Fields{
					"Topic":  "Peer",
					"Key":    neighborAddress,
					"State":  oldState.String(),
					"Reason": reason.String(),
				})
		}

		if ctx.Err() != nil {
			break
		}

		msg := &FSMMsg{
			FSM:         fsm,
			MsgType:     FSMMsgStateChange,
			MsgSrc:      neighborAddress,
			MsgData:     nextState,
			StateReason: reason,
		}

		h.Callback(msg)
		oldState = nextState
	}

	if oldState == bgp.BGP_FSM_ACTIVE {
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
						"State": oldState,
					})
			}
		}
	}
	close(fsm.ConnCh)
	fsm.OutgoingCh.Close()
}

func (fsm *fsm) changeadminState(s AdminState) error {
	fsm.Lock.Lock()
	defer fsm.Lock.Unlock()

	if fsm.AdminState != s {
		fsm.Logger.Debug("admin state changed",
			log.Fields{
				"Topic":      "Peer",
				"Key":        fsm.PeerConf.State.NeighborAddress,
				"State":      fsm.State.String(),
				"adminState": s.String(),
			})
		fsm.AdminState = s
		fsm.PeerConf.State.AdminDown = !fsm.PeerConf.State.AdminDown

		switch s {
		case AdminStateUp:
			fsm.Logger.Info("Administrative start",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
				})
		case AdminStateDown:
			fsm.Logger.Info("Administrative shutdown",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
				})
		case AdminStatePfxCt:
			fsm.Logger.Info("Administrative shutdown(Prefix limit reached)",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
				})
		}
	} else {
		fsm.Logger.Warn("cannot change to the same state",
			log.Fields{
				"Topic": "Peer",
				"Key":   fsm.PeerConf.State.NeighborAddress,
				"State": fsm.State.String(),
			})
		return fmt.Errorf("cannot change to the same state")
	}
	return nil
}
