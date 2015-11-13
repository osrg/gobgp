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
	"github.com/osrg/gobgp/table"
	"gopkg.in/tomb.v2"
	"io"
	"net"
	"strconv"
	"time"
)

type FsmMsgType int

const (
	_ FsmMsgType = iota
	FSM_MSG_STATE_CHANGE
	FSM_MSG_BGP_MESSAGE
)

type FsmMsg struct {
	MsgType   FsmMsgType
	MsgSrc    string
	MsgDst    string
	MsgData   interface{}
	PathList  []*table.Path
	timestamp time.Time
	payload   []byte
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
	t                  tomb.Tomb
	gConf              *config.Global
	pConf              *config.Neighbor
	state              bgp.FSMState
	conn               net.Conn
	connCh             chan net.Conn
	idleHoldTime       float64
	opensentHoldTime   float64
	negotiatedHoldTime float64
	adminState         AdminState
	adminStateCh       chan AdminState
	getActiveCh        chan struct{}
	h                  *FSMHandler
	rfMap              map[bgp.RouteFamily]bool
	confedCheck        bool
	peerInfo           *table.PeerInfo
	peer               *Peer
}

func (fsm *FSM) bgpMessageStateUpdate(MessageType uint8, isIn bool) {
	state := &fsm.pConf.NeighborState.Messages
	timer := &fsm.pConf.Timers
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
			timer.TimersState.UpdateRecvTime = time.Now().Unix()
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

func NewFSM(gConf *config.Global, pConf *config.Neighbor, peer *Peer) *FSM {
	adminState := ADMIN_STATE_UP
	if pConf.NeighborState.AdminDown == true {
		adminState = ADMIN_STATE_DOWN
	}
	fsm := &FSM{
		gConf:            gConf,
		pConf:            pConf,
		state:            bgp.BGP_FSM_IDLE,
		connCh:           make(chan net.Conn, 1),
		opensentHoldTime: float64(HOLDTIME_OPENSENT),
		adminState:       adminState,
		adminStateCh:     make(chan AdminState, 1),
		getActiveCh:      make(chan struct{}),
		rfMap:            make(map[bgp.RouteFamily]bool),
		confedCheck:      !config.IsConfederationMember(gConf, pConf) && config.IsEBGPPeer(gConf, pConf),
		peerInfo:         table.NewPeerInfo(gConf, pConf),
		peer:             peer,
	}
	fsm.t.Go(fsm.connectLoop)
	return fsm
}

func (fsm *FSM) StateChange(nextState bgp.FSMState) {
	log.WithFields(log.Fields{
		"Topic": "Peer",
		"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
		"old":   fsm.state.String(),
		"new":   nextState.String(),
	}).Debug("state changed")
	fsm.state = nextState
	switch nextState {
	case bgp.BGP_FSM_ESTABLISHED:
		fsm.pConf.Timers.TimersState.Uptime = time.Now().Unix()
		fsm.pConf.NeighborState.EstablishedCount++
	case bgp.BGP_FSM_ACTIVE:
		if !fsm.pConf.Transport.TransportConfig.PassiveMode {
			fsm.getActiveCh <- struct{}{}
		}
		fallthrough
	default:
		fsm.pConf.Timers.TimersState.Downtime = time.Now().Unix()
	}
}

func hostport(addr net.Addr) (string, uint16) {
	if addr != nil {
		host, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			return "", 0
		}
		p, _ := strconv.Atoi(port)
		return host, uint16(p)
	}
	return "", 0
}

func (fsm *FSM) RemoteHostPort() (string, uint16) {
	return hostport(fsm.conn.RemoteAddr())

}

func (fsm *FSM) LocalHostPort() (string, uint16) {
	return hostport(fsm.conn.LocalAddr())
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
		"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
		"Data":  e,
	}).Warn("sent notification")
}

func (fsm *FSM) sendNotification(conn net.Conn, code, subType uint8, data []byte, msg string) {
	e := bgp.NewMessageError(code, subType, data, msg)
	fsm.sendNotificatonFromErrorMsg(conn, e.(*bgp.MessageError))
}

func (fsm *FSM) connectLoop() error {
	var tick int
	if tick = int(fsm.pConf.Timers.TimersConfig.ConnectRetry); tick < MIN_CONNECT_RETRY {
		tick = MIN_CONNECT_RETRY
	}

	ticker := time.NewTicker(time.Duration(tick) * time.Second)
	ticker.Stop()

	connect := func() {
		if fsm.state == bgp.BGP_FSM_ACTIVE {
			addr := fsm.pConf.NeighborConfig.NeighborAddress
			host := net.JoinHostPort(addr.String(), strconv.Itoa(bgp.BGP_PORT))
			// check if LocalAddress has been configured
			laddr := fsm.pConf.Transport.TransportConfig.LocalAddress
			if laddr != nil {
				lhost := net.JoinHostPort(laddr.String(), "0")
				ltcpaddr, err := net.ResolveTCPAddr("tcp", lhost)
				if err != nil {
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
					}).Warnf("failed to resolve ltcpaddr: %s", err)
				} else {
					d := net.Dialer{LocalAddr: ltcpaddr, Timeout: time.Duration(MIN_CONNECT_RETRY-1) * time.Second}
					if conn, err := d.Dial("tcp", host); err == nil {
						fsm.connCh <- conn
					} else {
						log.WithFields(log.Fields{
							"Topic": "Peer",
							"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
						}).Debugf("failed to connect from ltcpaddr", err)
					}
				}

			} else {
				conn, err := net.DialTimeout("tcp", host, time.Duration(MIN_CONNECT_RETRY-1)*time.Second)
				if err == nil {
					fsm.connCh <- conn
				} else {
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
					}).Debugf("failed to connect: %s", err)
				}
			}
		}
	}

	for {
		select {
		case <-fsm.t.Dying():
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
			}).Debug("stop connect loop")
			ticker.Stop()
			return nil
		case <-ticker.C:
			connect()
		case <-fsm.getActiveCh:
			ticker = time.NewTicker(time.Duration(tick) * time.Second)
		}
	}
}

type FSMHandler struct {
	t                tomb.Tomb
	fsm              *FSM
	conn             net.Conn
	msgCh            chan *FsmMsg
	errorCh          chan bool
	incoming         chan *FsmMsg
	outgoing         chan *bgp.BGPMessage
	holdTimerResetCh chan bool
	reason           string
}

func NewFSMHandler(fsm *FSM, incoming chan *FsmMsg, outgoing chan *bgp.BGPMessage) *FSMHandler {
	h := &FSMHandler{
		fsm:              fsm,
		errorCh:          make(chan bool, 2),
		incoming:         incoming,
		outgoing:         outgoing,
		holdTimerResetCh: make(chan bool, 2),
	}
	fsm.t.Go(h.loop)
	return h
}

func (h *FSMHandler) idle() bgp.FSMState {
	fsm := h.fsm

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
				"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
			}).Warn("Closed an accepted connection")
		case <-idleHoldTimer.C:

			if fsm.adminState == ADMIN_STATE_UP {
				log.WithFields(log.Fields{
					"Topic":    "Peer",
					"Key":      fsm.pConf.NeighborConfig.NeighborAddress,
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
			if fsm.gConf.GlobalConfig.As != fsm.pConf.NeighborConfig.PeerAs {
				ttl := 1
				if fsm.pConf.EbgpMultihop.EbgpMultihopConfig.Enabled == true {
					ttl = int(fsm.pConf.EbgpMultihop.EbgpMultihopConfig.MultihopTtl)
				}
				if ttl != 0 {
					SetTcpTTLSockopts(conn.(*net.TCPConn), ttl)
				}
			}
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
						"Key":        fsm.pConf.NeighborConfig.NeighborAddress,
						"State":      fsm.state,
						"AdminState": s.String(),
					}).Panic("code logic bug")
				}
			}
		}
	}
}

func capabilitiesFromConfig(gConf *config.Global, pConf *config.Neighbor) []bgp.ParameterCapabilityInterface {
	caps := make([]bgp.ParameterCapabilityInterface, 0, 4)
	caps = append(caps, bgp.NewCapRouteRefresh())
	for _, rf := range pConf.AfiSafis.AfiSafiList {
		k, _ := bgp.GetRouteFamily(rf.AfiSafiName)
		caps = append(caps, bgp.NewCapMultiProtocol(k))
	}
	caps = append(caps, bgp.NewCapFourOctetASNumber(gConf.GlobalConfig.As))
	return caps
}

func buildopen(gConf *config.Global, pConf *config.Neighbor) *bgp.BGPMessage {
	caps := capabilitiesFromConfig(gConf, pConf)
	opt := bgp.NewOptionParameterCapability(caps)
	holdTime := uint16(pConf.Timers.TimersConfig.HoldTime)
	as := gConf.GlobalConfig.As
	if as > (1<<16)-1 {
		as = bgp.AS_TRANS
	}
	return bgp.NewBGPOpenMessage(uint16(as), holdTime, gConf.GlobalConfig.RouterId.String(),
		[]bgp.OptionParameterInterface{opt})
}

func readAll(conn net.Conn, length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
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
			"Key":   h.fsm.pConf.NeighborConfig.NeighborAddress,
			"State": h.fsm.state,
			"error": err,
		}).Warn("malformed BGP Header")
		h.msgCh <- &FsmMsg{
			MsgType: FSM_MSG_BGP_MESSAGE,
			MsgSrc:  h.fsm.pConf.NeighborConfig.NeighborAddress.String(),
			MsgDst:  h.fsm.pConf.Transport.TransportConfig.LocalAddress.String(),
			MsgData: err,
		}
		return err
	}

	bodyBuf, err := readAll(h.conn, int(hd.Len)-bgp.BGP_HEADER_LENGTH)
	if err != nil {
		h.errorCh <- true
		return err
	}

	now := time.Now()
	m, err := bgp.ParseBGPBody(hd, bodyBuf)
	if err == nil {
		h.fsm.bgpMessageStateUpdate(m.Header.Type, true)
		err = bgp.ValidateBGPMessage(m)
	} else {
		h.fsm.bgpMessageStateUpdate(0, true)
	}
	fmsg := &FsmMsg{
		MsgType:   FSM_MSG_BGP_MESSAGE,
		MsgSrc:    h.fsm.pConf.NeighborConfig.NeighborAddress.String(),
		MsgDst:    h.fsm.pConf.Transport.TransportConfig.LocalAddress.String(),
		timestamp: now,
	}
	if err != nil {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   h.fsm.pConf.NeighborConfig.NeighborAddress,
			"State": h.fsm.state,
			"error": err,
		}).Warn("malformed BGP message")
		fmsg.MsgData = err
	} else {
		fmsg.MsgData = m
		if h.fsm.state == bgp.BGP_FSM_ESTABLISHED {
			switch m.Header.Type {
			case bgp.BGP_MSG_UPDATE:
				body := m.Body.(*bgp.BGPUpdate)
				_, err := bgp.ValidateUpdateMsg(body, h.fsm.rfMap, h.fsm.confedCheck)
				if err != nil {
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   h.fsm.pConf.NeighborConfig.NeighborAddress.String(),
						"error": err,
					}).Warn("malformed BGP update message")
					fmsg.MsgData = err
				} else {
					// FIXME: we should use the original message for bmp/mrt
					table.UpdatePathAttrs4ByteAs(body)
					fmsg.PathList = table.ProcessMessage(m, h.fsm.peerInfo, fmsg.timestamp)
					policyMutex.RLock()
					h.fsm.peer.ApplyPolicy(table.POLICY_DIRECTION_IN, fmsg.PathList)
					policyMutex.RUnlock()
				}
				fmsg.payload = make([]byte, len(headerBuf)+len(bodyBuf))
				copy(fmsg.payload, headerBuf)
				copy(fmsg.payload[len(headerBuf):], bodyBuf)
				fallthrough
			case bgp.BGP_MSG_KEEPALIVE:
				// if the lenght of h.holdTimerResetCh
				// isn't zero, the timer will be reset
				// soon anyway.
				if len(h.holdTimerResetCh) == 0 {
					h.holdTimerResetCh <- true
				}
			case bgp.BGP_MSG_NOTIFICATION:
				h.reason = "Notification received"
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
	m := buildopen(fsm.gConf, fsm.pConf)
	b, _ := m.Serialize()
	fsm.conn.Write(b)
	fsm.bgpMessageStateUpdate(m.Header.Type, false)

	h.msgCh = make(chan *FsmMsg)
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
				"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
				"State": fsm.state,
			}).Warn("Closed an accepted connection")
		case e := <-h.msgCh:
			switch e.MsgData.(type) {
			case *bgp.BGPMessage:
				m := e.MsgData.(*bgp.BGPMessage)
				if m.Header.Type == bgp.BGP_MSG_OPEN {
					body := m.Body.(*bgp.BGPOpen)
					err := bgp.ValidateOpenMsg(body, fsm.pConf.NeighborConfig.PeerAs)
					if err != nil {
						fsm.sendNotificatonFromErrorMsg(h.conn, err.(*bgp.MessageError))
						return bgp.BGP_FSM_IDLE
					}
					fsm.peerInfo.ID = body.ID
					_, fsm.rfMap = open2Cap(body, fsm.pConf)

					e := &FsmMsg{
						MsgType: FSM_MSG_BGP_MESSAGE,
						MsgSrc:  fsm.pConf.NeighborConfig.NeighborAddress.String(),
						MsgDst:  fsm.pConf.Transport.TransportConfig.LocalAddress.String(),
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
					"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
					"State": fsm.state,
					"Data":  e.MsgData,
				}).Panic("unknown msg type")
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
						"Key":        fsm.pConf.NeighborConfig.NeighborAddress,
						"State":      fsm.state,
						"AdminState": s.String(),
					}).Panic("code logic bug")
				}
			}
		}
	}
}

func keepaliveTicker(fsm *FSM) *time.Ticker {
	if fsm.negotiatedHoldTime == 0 {
		return &time.Ticker{}
	}
	sec := time.Second * time.Duration(fsm.pConf.Timers.TimersConfig.KeepaliveInterval)
	if fsm.negotiatedHoldTime < fsm.pConf.Timers.TimersConfig.HoldTime {
		sec = time.Second * time.Duration(fsm.negotiatedHoldTime) / 3
	}
	if sec == 0 {
		sec = 1
	}
	return time.NewTicker(sec)
}

func (h *FSMHandler) openconfirm() bgp.FSMState {
	fsm := h.fsm
	ticker := keepaliveTicker(fsm)
	h.msgCh = make(chan *FsmMsg)
	h.conn = fsm.conn

	h.t.Go(h.recvMessage)

	var holdTimer *time.Timer
	if fsm.negotiatedHoldTime == 0 {
		holdTimer = &time.Timer{}
	} else {
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
				"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
				"State": fsm.state,
			}).Warn("Closed an accepted connection")
		case <-ticker.C:
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
					"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
					"State": fsm.state,
					"Data":  e.MsgData,
				}).Panic("unknown msg type")
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
						"Key":        fsm.pConf.NeighborConfig.NeighborAddress,
						"State":      fsm.state,
						"AdminState": s.String(),
					}).Panic("code logic bug")
				}
			}
		}
	}
	log.WithFields(log.Fields{
		"Topic": "Peer",
		"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
		"State": fsm.state,
	}).Panic("code logic bug")
	return 0
}

func (h *FSMHandler) sendMessageloop() error {
	conn := h.conn
	fsm := h.fsm
	ticker := keepaliveTicker(fsm)
	send := func(m *bgp.BGPMessage) error {
		b, err := m.Serialize()
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
				"State": fsm.state,
				"Data":  err,
			}).Warn("failed to serialize")
			fsm.bgpMessageStateUpdate(0, false)
			return nil
		}
		if err := conn.SetWriteDeadline(time.Now().Add(time.Second * 30)); err != nil {
			h.errorCh <- true
			conn.Close()
			return fmt.Errorf("failed to set write deadline")
		}
		_, err = conn.Write(b)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
				"State": fsm.state,
				"Data":  err,
			}).Warn("failed to send")
			h.errorCh <- true
			conn.Close()
			return fmt.Errorf("closed")
		}
		fsm.bgpMessageStateUpdate(m.Header.Type, false)

		if m.Header.Type == bgp.BGP_MSG_NOTIFICATION {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
				"State": fsm.state,
				"Data":  m,
			}).Warn("sent notification")

			h.errorCh <- true
			h.reason = "Notificaiton sent"
			conn.Close()
			return fmt.Errorf("closed")
		} else {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
				"State": fsm.state,
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
			//
			// we always try to send. in case b), the
			// connection was already closed so it
			// correctly works in both cases.
			if h.fsm.state == bgp.BGP_FSM_ESTABLISHED {
				send(bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED, nil))
			}
			return nil
		case m := <-h.outgoing:
			if err := send(m); err != nil {
				return nil
			}
		case <-ticker.C:
			if err := send(bgp.NewBGPKeepAliveMessage()); err != nil {
				return nil
			}

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
				"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
				"State": fsm.state,
			}).Warn("Closed an accepted connection")
		case <-h.errorCh:
			h.conn.Close()
			h.t.Kill(nil)
			h.reason = "Peer closed the session"
			return bgp.BGP_FSM_IDLE
		case <-holdTimer.C:
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
				"State": fsm.state,
				"data":  bgp.BGP_FSM_ESTABLISHED,
			}).Warn("hold timer expired")
			m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil)
			h.outgoing <- m
			h.reason = "HoldTimer expired"
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
	ch := make(chan bgp.FSMState)
	oldState := fsm.state

	f := func() error {
		nextState := bgp.FSMState(0)
		switch fsm.state {
		case bgp.BGP_FSM_IDLE:
			nextState = h.idle()
			// case bgp.BGP_FSM_CONNECT:
			// 	nextState = h.connect()
		case bgp.BGP_FSM_ACTIVE:
			nextState = h.active()
		case bgp.BGP_FSM_OPENSENT:
			nextState = h.opensent()
		case bgp.BGP_FSM_OPENCONFIRM:
			nextState = h.openconfirm()
		case bgp.BGP_FSM_ESTABLISHED:
			nextState = h.established()
		}

		ch <- nextState
		return nil
	}

	h.t.Go(f)

	nextState := <-ch

	if nextState == bgp.BGP_FSM_ESTABLISHED && oldState == bgp.BGP_FSM_OPENCONFIRM {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
			"State": fsm.state,
		}).Info("Peer Up")
	}

	if oldState == bgp.BGP_FSM_ESTABLISHED {
		log.WithFields(log.Fields{
			"Topic":  "Peer",
			"Key":    fsm.pConf.NeighborConfig.NeighborAddress,
			"State":  fsm.state,
			"Reason": h.reason,
		}).Info("Peer Down")
	}

	e := time.AfterFunc(time.Second*120, func() {
		log.Fatal("failed to free the fsm.h.t for ", fsm.pConf.NeighborConfig.NeighborAddress, oldState, nextState)
	})
	h.t.Wait()
	e.Stop()

	// zero means that tomb.Dying()
	if nextState >= bgp.BGP_FSM_IDLE {
		e := &FsmMsg{
			MsgType: FSM_MSG_STATE_CHANGE,
			MsgSrc:  fsm.pConf.NeighborConfig.NeighborAddress.String(),
			MsgDst:  fsm.pConf.Transport.TransportConfig.LocalAddress.String(),
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
			"Key":        fsm.pConf.NeighborConfig.NeighborAddress,
			"State":      fsm.state,
			"AdminState": s.String(),
		}).Debug("admin state changed")

		fsm.adminState = s

		switch s {
		case ADMIN_STATE_UP:
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
				"State": fsm.state,
			}).Info("Administrative start")

		case ADMIN_STATE_DOWN:
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
				"State": fsm.state,
			}).Info("Administrative shutdown")
		}

	} else {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   fsm.pConf.NeighborConfig.NeighborAddress,
			"State": fsm.state,
		}).Warn("cannot change to the same state")

		return fmt.Errorf("cannot change to the same state.")
	}
	return nil
}
