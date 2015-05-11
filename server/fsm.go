// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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

package server

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"gopkg.in/tomb.v2"
	"net"
	"time"
)

type fsmMsgType int

const (
	_ fsmMsgType = iota
	FSM_MSG_STATE_CHANGE
	FSM_MSG_BGP_MESSAGE
)

type fsmMsg struct {
	MsgType fsmMsgType
	MsgData interface{}
}

const (
	HOLDTIME_OPENSENT = 240
	HOLDTIME_IDLE     = 5
)

type AdminState int

const (
	ADMIN_STATE_UP AdminState = iota
	ADMIN_STATE_DOWN
)

func (s AdminState) String() string {
	switch s {
	case ADMIN_STATE_UP:
		return "ADMIN_STATE_UP"
	case ADMIN_STATE_DOWN:
		return "ADMIN_STATE_DOWN"
	default:
		return "Unknown"
	}
}

type FSM struct {
	globalConfig       *config.Global
	peerConfig         *config.Neighbor
	keepaliveTicker    *time.Ticker
	state              bgp.FSMState
	conn               net.Conn
	connCh             chan net.Conn
	idleHoldTime       float64
	opensentHoldTime   float64
	negotiatedHoldTime float64
	adminState         AdminState
	adminStateCh       chan AdminState
}

func (fsm *FSM) bgpMessageStateUpdate(MessageType uint8, isIn bool) {
	state := &fsm.peerConfig.BgpNeighborCommonState
	if isIn {
		state.TotalIn++
	} else {
		state.TotalOut++
	}
	switch MessageType {
	case bgp.BGP_MSG_OPEN:
		if isIn {
			state.OpenIn++
		} else {
			state.OpenOut++
		}
	case bgp.BGP_MSG_UPDATE:
		if isIn {
			state.UpdateIn++
			state.UpdateRecvTime = time.Now().Unix()
		} else {
			state.UpdateOut++
		}
	case bgp.BGP_MSG_NOTIFICATION:
		if isIn {
			state.NotifyIn++
		} else {
			state.NotifyOut++
		}
	case bgp.BGP_MSG_KEEPALIVE:
		if isIn {
			state.KeepaliveIn++
		} else {
			state.KeepaliveOut++
		}
	case bgp.BGP_MSG_ROUTE_REFRESH:
		if isIn {
			state.RefreshIn++
		} else {
			state.RefreshOut++
		}
	default:
		if isIn {
			state.DiscardedIn++
		} else {
			state.DiscardedOut++
		}
	}
}

func NewFSM(gConfig *config.Global, pConfig *config.Neighbor, connCh chan net.Conn) *FSM {
	return &FSM{
		globalConfig:     gConfig,
		peerConfig:       pConfig,
		state:            bgp.BGP_FSM_IDLE,
		connCh:           connCh,
		opensentHoldTime: float64(HOLDTIME_OPENSENT),
		adminState:       ADMIN_STATE_UP,
		adminStateCh:     make(chan AdminState, 1),
	}
}

func (fsm *FSM) StateChange(nextState bgp.FSMState) {
	log.WithFields(log.Fields{
		"Topic": "Peer",
		"Key":   fsm.peerConfig.NeighborAddress,
		"old":   fsm.state.String(),
		"new":   nextState.String(),
	}).Debug("state changed")
	fsm.state = nextState
}

func (fsm *FSM) LocalAddr() net.IP {
	addr := fsm.conn.LocalAddr()
	if addr != nil {
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return nil
		}
		return net.ParseIP(host)
	}
	return nil
}

func (fsm *FSM) sendNotificatonFromErrorMsg(conn net.Conn, e *bgp.MessageError) {
	m := bgp.NewBGPNotificationMessage(e.TypeCode, e.SubTypeCode, e.Data)
	b, _ := m.Serialize()
	_, err := conn.Write(b)
	if err != nil {
		fsm.bgpMessageStateUpdate(m.Header.Type, false)
	}
	conn.Close()

	log.WithFields(log.Fields{
		"Topic": "Peer",
		"Key":   fsm.peerConfig.NeighborAddress,
		"Data":  e,
	}).Warn("sent notification")
}

func (fsm *FSM) sendNotification(conn net.Conn, code, subType uint8, data []byte, msg string) {
	e := bgp.NewMessageError(code, subType, data, msg)
	fsm.sendNotificatonFromErrorMsg(conn, e.(*bgp.MessageError))
}

type FSMHandler struct {
	t                tomb.Tomb
	fsm              *FSM
	conn             net.Conn
	msgCh            chan *fsmMsg
	errorCh          chan bool
	incoming         chan *fsmMsg
	outgoing         chan *bgp.BGPMessage
	holdTimerResetCh chan bool
}

func NewFSMHandler(fsm *FSM, incoming chan *fsmMsg, outgoing chan *bgp.BGPMessage) *FSMHandler {
	f := &FSMHandler{
		fsm:              fsm,
		errorCh:          make(chan bool, 2),
		incoming:         incoming,
		outgoing:         outgoing,
		holdTimerResetCh: make(chan bool, 2),
	}
	f.t.Go(f.loop)
	return f
}

func (h *FSMHandler) Wait() error {
	return h.t.Wait()
}

func (h *FSMHandler) Stop() error {
	h.t.Kill(nil)
	return h.t.Wait()
}

func (h *FSMHandler) idle() bgp.FSMState {
	fsm := h.fsm

	if fsm.keepaliveTicker != nil {
		if fsm.negotiatedHoldTime != 0 {
			fsm.keepaliveTicker.Stop()
		}
		fsm.keepaliveTicker = nil
	}

	idleHoldTimer := time.NewTimer(time.Second * time.Duration(fsm.idleHoldTime))
	for {
		select {
		case <-h.t.Dying():
			return 0
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			conn.Close()
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.peerConfig.NeighborAddress,
			}).Warn("Closed an accepted connection")
		case <-idleHoldTimer.C:

			if fsm.adminState == ADMIN_STATE_UP {
				log.WithFields(log.Fields{
					"Topic":    "Peer",
					"Key":      fsm.peerConfig.NeighborAddress,
					"Duration": fsm.idleHoldTime,
				}).Debug("IdleHoldTimer expired")
				fsm.idleHoldTime = HOLDTIME_IDLE
				return bgp.BGP_FSM_ACTIVE

			} else {
				log.Debug("IdleHoldTimer expired, but stay at idle because the admin state is DOWN")
			}

		case s := <-fsm.adminStateCh:
			err := h.changeAdminState(s)
			if err == nil {
				switch s {
				case ADMIN_STATE_DOWN:
					// stop idle hold timer
					idleHoldTimer.Stop()

				case ADMIN_STATE_UP:
					// restart idle hold timer
					idleHoldTimer.Reset(time.Second * time.Duration(fsm.idleHoldTime))
				}
			}
		}
	}
}

func (h *FSMHandler) active() bgp.FSMState {
	fsm := h.fsm
	for {
		select {
		case <-h.t.Dying():
			return 0
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			fsm.conn = conn
			// we don't implement delayed open timer so move to opensent right
			// away.
			return bgp.BGP_FSM_OPENSENT
		case <-h.errorCh:
			return bgp.BGP_FSM_IDLE
		case s := <-fsm.adminStateCh:
			err := h.changeAdminState(s)
			if err == nil {
				switch s {
				case ADMIN_STATE_DOWN:
					return bgp.BGP_FSM_IDLE
				case ADMIN_STATE_UP:
					log.WithFields(log.Fields{
						"Topic":      "Peer",
						"Key":        fsm.peerConfig.NeighborAddress,
						"State":      fsm.state,
						"AdminState": s.String(),
					}).Panic("code logic bug")
				}
			}
		}
	}
}

func capabilitiesFromConfig(global *config.Global, peerConf *config.Neighbor) []bgp.ParameterCapabilityInterface {
	caps := make([]bgp.ParameterCapabilityInterface, 0, 4)
	caps = append(caps, bgp.NewCapRouteRefresh())
	for _, rf := range peerConf.AfiSafiList {
		k, _ := bgp.GetRouteFamily(rf.AfiSafiName)
		afi, safi := bgp.RouteFamilyToAfiSafi(k)
		caps = append(caps, bgp.NewCapMultiProtocol(afi, safi))
	}
	caps = append(caps, bgp.NewCapFourOctetASNumber(global.As))
	return caps
}

func buildopen(global *config.Global, peerConf *config.Neighbor) *bgp.BGPMessage {
	caps := capabilitiesFromConfig(global, peerConf)
	opt := bgp.NewOptionParameterCapability(caps)
	holdTime := uint16(peerConf.Timers.HoldTime)
	as := global.As
	if as > (1<<16)-1 {
		as = bgp.AS_TRANS
	}
	return bgp.NewBGPOpenMessage(uint16(as), holdTime, global.RouterId.String(),
		[]bgp.OptionParameterInterface{opt})
}

func readAll(conn net.Conn, length int) ([]byte, error) {
	buf := make([]byte, length)
	for cur := 0; cur < length; {
		if num, err := conn.Read(buf); err != nil {
			return nil, err
		} else {
			cur += num
		}
	}
	return buf, nil
}

func (h *FSMHandler) recvMessageWithError() error {
	headerBuf, err := readAll(h.conn, bgp.BGP_HEADER_LENGTH)
	if err != nil {
		h.errorCh <- true
		return err
	}

	hd := &bgp.BGPHeader{}
	err = hd.DecodeFromBytes(headerBuf)
	if err != nil {
		h.fsm.bgpMessageStateUpdate(0, true)
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   h.fsm.peerConfig.NeighborAddress,
			"error": err,
		}).Warn("malformed BGP Header")
		h.msgCh <- &fsmMsg{
			MsgType: FSM_MSG_BGP_MESSAGE,
			MsgData: err,
		}
		return err
	}

	bodyBuf, err := readAll(h.conn, int(hd.Len)-bgp.BGP_HEADER_LENGTH)
	if err != nil {
		h.errorCh <- true
		return err
	}

	var fmsg *fsmMsg
	m, err := bgp.ParseBGPBody(hd, bodyBuf)
	if err == nil {
		h.fsm.bgpMessageStateUpdate(m.Header.Type, true)
		err = bgp.ValidateBGPMessage(m)
	} else {
		h.fsm.bgpMessageStateUpdate(0, true)
	}
	if err != nil {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   h.fsm.peerConfig.NeighborAddress,
			"error": err,
		}).Warn("malformed BGP message")
		fmsg = &fsmMsg{
			MsgType: FSM_MSG_BGP_MESSAGE,
			MsgData: err,
		}
	} else {
		fmsg = &fsmMsg{
			MsgType: FSM_MSG_BGP_MESSAGE,
			MsgData: m,
		}
		if h.fsm.state == bgp.BGP_FSM_ESTABLISHED {
			if m.Header.Type == bgp.BGP_MSG_KEEPALIVE || m.Header.Type == bgp.BGP_MSG_UPDATE {
				// if the lenght of h.holdTimerResetCh
				// isn't zero, the timer will be reset
				// soon anyway.
				if len(h.holdTimerResetCh) == 0 {
					h.holdTimerResetCh <- true
				}
			}
		}
	}
	h.msgCh <- fmsg
	return err
}

func (h *FSMHandler) recvMessage() error {
	h.recvMessageWithError()
	return nil
}

func (h *FSMHandler) opensent() bgp.FSMState {
	fsm := h.fsm
	m := buildopen(fsm.globalConfig, fsm.peerConfig)
	b, _ := m.Serialize()
	fsm.conn.Write(b)
	fsm.bgpMessageStateUpdate(m.Header.Type, false)

	h.msgCh = make(chan *fsmMsg)
	h.conn = fsm.conn

	h.t.Go(h.recvMessage)

	// RFC 4271 P.60
	// sets its HoldTimer to a large value
	// A HoldTimer value of 4 minutes is suggested as a "large value"
	// for the HoldTimer
	holdTimer := time.NewTimer(time.Second * time.Duration(fsm.opensentHoldTime))

	for {
		select {
		case <-h.t.Dying():
			h.conn.Close()
			return 0
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			conn.Close()
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.peerConfig.NeighborAddress,
			}).Warn("Closed an accepted connection")
		case e := <-h.msgCh:
			switch e.MsgData.(type) {
			case *bgp.BGPMessage:
				m := e.MsgData.(*bgp.BGPMessage)
				if m.Header.Type == bgp.BGP_MSG_OPEN {
					body := m.Body.(*bgp.BGPOpen)
					err := bgp.ValidateOpenMsg(body, fsm.peerConfig.PeerAs)
					if err != nil {
						fsm.sendNotificatonFromErrorMsg(h.conn, err.(*bgp.MessageError))
						return bgp.BGP_FSM_IDLE
					}

					e := &fsmMsg{
						MsgType: FSM_MSG_BGP_MESSAGE,
						MsgData: m,
					}
					h.incoming <- e
					msg := bgp.NewBGPKeepAliveMessage()
					b, _ := msg.Serialize()
					fsm.conn.Write(b)
					fsm.bgpMessageStateUpdate(msg.Header.Type, false)
					return bgp.BGP_FSM_OPENCONFIRM
				} else {
					// send notification?
					h.conn.Close()
					return bgp.BGP_FSM_IDLE
				}
			case *bgp.MessageError:
				fsm.sendNotificatonFromErrorMsg(h.conn, e.MsgData.(*bgp.MessageError))
				return bgp.BGP_FSM_IDLE
			default:
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   fsm.peerConfig.NeighborAddress,
					"Data":  e.MsgData,
				}).Panic("unknonw msg type")
			}
		case <-h.errorCh:
			h.conn.Close()
			return bgp.BGP_FSM_IDLE
		case <-holdTimer.C:
			fsm.sendNotification(h.conn, bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil, "hold timer expired")
			h.t.Kill(nil)
			return bgp.BGP_FSM_IDLE
		case s := <-fsm.adminStateCh:
			err := h.changeAdminState(s)
			if err == nil {
				switch s {
				case ADMIN_STATE_DOWN:
					h.conn.Close()
					return bgp.BGP_FSM_IDLE
				case ADMIN_STATE_UP:
					log.WithFields(log.Fields{
						"Topic":      "Peer",
						"Key":        fsm.peerConfig.NeighborAddress,
						"State":      fsm.state,
						"AdminState": s.String(),
					}).Panic("code logic bug")
				}
			}
		}
	}
}

func (h *FSMHandler) openconfirm() bgp.FSMState {
	fsm := h.fsm

	h.msgCh = make(chan *fsmMsg)
	h.conn = fsm.conn

	h.t.Go(h.recvMessage)

	var holdTimer *time.Timer
	if fsm.negotiatedHoldTime == 0 {
		fsm.keepaliveTicker = &time.Ticker{}
		holdTimer = &time.Timer{}
	} else {
		sec := time.Second * time.Duration(fsm.peerConfig.Timers.KeepaliveInterval)
		if fsm.negotiatedHoldTime < fsm.peerConfig.Timers.HoldTime {
			sec = time.Second * time.Duration(fsm.negotiatedHoldTime) / 3
		}
		fsm.keepaliveTicker = time.NewTicker(sec)

		// RFC 4271 P.65
		// sets the HoldTimer according to the negotiated value
		holdTimer = time.NewTimer(time.Second * time.Duration(fsm.negotiatedHoldTime))
	}

	for {
		select {
		case <-h.t.Dying():
			h.conn.Close()
			return 0
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			conn.Close()
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.peerConfig.NeighborAddress,
			}).Warn("Closed an accepted connection")
		case <-fsm.keepaliveTicker.C:
			m := bgp.NewBGPKeepAliveMessage()
			b, _ := m.Serialize()
			// TODO: check error
			fsm.conn.Write(b)
			fsm.bgpMessageStateUpdate(m.Header.Type, false)
		case e := <-h.msgCh:
			switch e.MsgData.(type) {
			case *bgp.BGPMessage:
				m := e.MsgData.(*bgp.BGPMessage)
				nextState := bgp.BGP_FSM_IDLE
				if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
					nextState = bgp.BGP_FSM_ESTABLISHED
				} else {
					// send notification ?
					h.conn.Close()
				}
				return nextState
			case *bgp.MessageError:
				fsm.sendNotificatonFromErrorMsg(h.conn, e.MsgData.(*bgp.MessageError))
				return bgp.BGP_FSM_IDLE
			default:
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   fsm.peerConfig.NeighborAddress,
					"Data":  e.MsgData,
				}).Panic("unknonw msg type")
			}
		case <-h.errorCh:
			h.conn.Close()
			return bgp.BGP_FSM_IDLE
		case <-holdTimer.C:
			fsm.sendNotification(h.conn, bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil, "hold timer expired")
			h.t.Kill(nil)
			return bgp.BGP_FSM_IDLE
		case s := <-fsm.adminStateCh:
			err := h.changeAdminState(s)
			if err == nil {
				switch s {
				case ADMIN_STATE_DOWN:
					h.conn.Close()
					return bgp.BGP_FSM_IDLE
				case ADMIN_STATE_UP:
					log.WithFields(log.Fields{
						"Topic":      "Peer",
						"Key":        fsm.peerConfig.NeighborAddress,
						"State":      fsm.state,
						"AdminState": s.String(),
					}).Panic("code logic bug")
				}
			}
		}
	}
	log.WithFields(log.Fields{
		"Topic": "Peer",
		"Key":   fsm.peerConfig.NeighborAddress,
	}).Panic("code logic bug")
	return 0
}

func (h *FSMHandler) sendMessageloop() error {
	conn := h.conn
	fsm := h.fsm
	send := func(m *bgp.BGPMessage) error {
		b, err := m.Serialize()
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.peerConfig.NeighborAddress,
				"Data":  err,
			}).Warn("failed to serialize")
			fsm.bgpMessageStateUpdate(0, false)
			return nil
		}
		_, err = conn.Write(b)
		if err != nil {
			h.errorCh <- true
			return fmt.Errorf("closed")
		}
		fsm.bgpMessageStateUpdate(m.Header.Type, false)

		if m.Header.Type == bgp.BGP_MSG_NOTIFICATION {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.peerConfig.NeighborAddress,
				"Data":  m,
			}).Warn("sent notification")

			h.errorCh <- true
			conn.Close()
			return fmt.Errorf("closed")
		} else {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.peerConfig.NeighborAddress,
				"data":  m,
			}).Debug("sent")
		}
		return nil
	}

	for {
		select {
		case <-h.t.Dying():
			// a) if a configuration is deleted, we need
			// to send notification before we die.
			//
			// b) if a recv goroutin found that the
			// connection is closed and tried to kill us,
			// we need to die immediately. Otherwise fms
			// doesn't go to idle.
			for len(h.outgoing) > 0 {
				m := <-h.outgoing
				err := send(m)
				if err != nil {
					return nil
				}
			}
			return nil
		case m := <-h.outgoing:
			err := send(m)
			if err != nil {
				return nil
			}
		case <-fsm.keepaliveTicker.C:
			m := bgp.NewBGPKeepAliveMessage()
			b, _ := m.Serialize()
			_, err := conn.Write(b)
			if err != nil {
				h.errorCh <- true
				return nil
			}
			fsm.bgpMessageStateUpdate(m.Header.Type, false)
		}
	}
}

func (h *FSMHandler) recvMessageloop() error {
	for {
		err := h.recvMessageWithError()
		if err != nil {
			return nil
		}
	}
}

func (h *FSMHandler) established() bgp.FSMState {
	fsm := h.fsm
	h.conn = fsm.conn
	h.t.Go(h.sendMessageloop)
	h.msgCh = h.incoming
	h.t.Go(h.recvMessageloop)

	var holdTimer *time.Timer
	if fsm.negotiatedHoldTime == 0 {
		holdTimer = &time.Timer{}
	} else {
		holdTimer = time.NewTimer(time.Second * time.Duration(fsm.negotiatedHoldTime))
	}

	for {
		select {
		case <-h.t.Dying():
			return 0
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			conn.Close()
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.peerConfig.NeighborAddress,
			}).Warn("Closed an accepted connection")
		case <-h.errorCh:
			h.conn.Close()
			h.t.Kill(nil)
			return bgp.BGP_FSM_IDLE
		case <-holdTimer.C:
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.peerConfig.NeighborAddress,
				"data":  bgp.BGP_FSM_ESTABLISHED,
			}).Warn("hold timer expired")
			m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil)
			h.outgoing <- m
			return bgp.BGP_FSM_IDLE
		case <-h.holdTimerResetCh:
			if fsm.negotiatedHoldTime != 0 {
				holdTimer.Reset(time.Second * time.Duration(fsm.negotiatedHoldTime))
			}
		case s := <-fsm.adminStateCh:
			err := h.changeAdminState(s)
			if err == nil {
				switch s {
				case ADMIN_STATE_DOWN:
					m := bgp.NewBGPNotificationMessage(
						bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, nil)
					h.outgoing <- m
				}
			}
		}
	}
	return 0
}

func (h *FSMHandler) loop() error {
	fsm := h.fsm
	nextState := bgp.FSMState(0)
	switch fsm.state {
	case bgp.BGP_FSM_IDLE:
		nextState = h.idle()
		//	case bgp.BGP_FSM_CONNECT:
		//		return h.connect()
	case bgp.BGP_FSM_ACTIVE:
		nextState = h.active()
	case bgp.BGP_FSM_OPENSENT:
		nextState = h.opensent()
	case bgp.BGP_FSM_OPENCONFIRM:
		nextState = h.openconfirm()
	case bgp.BGP_FSM_ESTABLISHED:
		nextState = h.established()
	}

	// zero means that tomb.Dying()
	if nextState >= bgp.BGP_FSM_IDLE {
		e := &fsmMsg{
			MsgType: FSM_MSG_STATE_CHANGE,
			MsgData: nextState,
		}
		h.incoming <- e
	}
	return nil
}

func (h *FSMHandler) changeAdminState(s AdminState) error {
	fsm := h.fsm
	if fsm.adminState != s {

		log.WithFields(log.Fields{
			"Topic":      "Peer",
			"Key":        fsm.peerConfig.NeighborAddress,
			"AdminState": s.String(),
		}).Debug("admin state changed")

		fsm.adminState = s

		switch s {
		case ADMIN_STATE_UP:
			log.WithFields(log.Fields{
				"Topic":    "Peer",
				"Key":      h.fsm.peerConfig.NeighborAddress,
				"FSMState": fsm.state.String(),
			}).Info("Administrative start")

		case ADMIN_STATE_DOWN:
			log.WithFields(log.Fields{
				"Topic":    "Peer",
				"Key":      h.fsm.peerConfig.NeighborAddress,
				"FSMState": fsm.state.String(),
			}).Info("Administrative shutdown")
		}

	} else {
		log.WithFields(log.Fields{
			"Topic":    "Peer",
			"Key":      fsm.peerConfig.NeighborAddress,
			"FSMState": fsm.state.String(),
		}).Warn("cannot change to the same state")

		return fmt.Errorf("cannot change to the same state.")
	}
	return nil
}
