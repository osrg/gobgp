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

type FSM struct {
	globalConfig    *config.GlobalType
	peerConfig      *config.NeighborType
	keepaliveTicker *time.Ticker
	state           bgp.FSMState
	passiveConn     *net.TCPConn
	passiveConnCh   chan *net.TCPConn
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
			state.UpdateRecvTime = time.Now()
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
	}
}

func NewFSM(gConfig *config.GlobalType, pConfig *config.NeighborType, connCh chan *net.TCPConn) *FSM {
	return &FSM{
		globalConfig:  gConfig,
		peerConfig:    pConfig,
		state:         bgp.BGP_FSM_IDLE,
		passiveConnCh: connCh,
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

type FSMHandler struct {
	t        tomb.Tomb
	fsm      *FSM
	conn     *net.TCPConn
	msgCh    chan *fsmMsg
	errorCh  chan bool
	incoming chan *fsmMsg
	outgoing chan *bgp.BGPMessage
}

func NewFSMHandler(fsm *FSM, incoming chan *fsmMsg, outgoing chan *bgp.BGPMessage) *FSMHandler {
	f := &FSMHandler{
		fsm:      fsm,
		errorCh:  make(chan bool, 2),
		incoming: incoming,
		outgoing: outgoing,
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
	// TODO: support idle hold timer

	if fsm.keepaliveTicker != nil {
		fsm.keepaliveTicker.Stop()
		fsm.keepaliveTicker = nil
	}
	return bgp.BGP_FSM_ACTIVE
}

func (h *FSMHandler) active() bgp.FSMState {
	fsm := h.fsm
	select {
	case <-h.t.Dying():
		return 0
	case conn := <-fsm.passiveConnCh:
		fsm.passiveConn = conn
	}
	// we don't implement delayed open timer so move to opensent right
	// away.
	return bgp.BGP_FSM_OPENSENT
}

func buildopen(global *config.GlobalType, peerConf *config.NeighborType) *bgp.BGPMessage {
	var afi int
	if peerConf.NeighborAddress.To4() != nil {
		afi = bgp.AFI_IP
	} else {
		afi = bgp.AFI_IP6
	}
	p1 := bgp.NewOptionParameterCapability(
		[]bgp.ParameterCapabilityInterface{bgp.NewCapRouteRefresh()})
	p2 := bgp.NewOptionParameterCapability(
		[]bgp.ParameterCapabilityInterface{bgp.NewCapMultiProtocol(uint16(afi), bgp.SAFI_UNICAST)})
	p3 := bgp.NewOptionParameterCapability(
		[]bgp.ParameterCapabilityInterface{bgp.NewCapFourOctetASNumber(global.As)})
	holdTime := uint16(peerConf.Timers.HoldTime)
	as := global.As
	if as > (1<<16)-1 {
		as = bgp.AS_TRANS
	}
	return bgp.NewBGPOpenMessage(uint16(as), holdTime, global.RouterId.String(),
		[]bgp.OptionParameterInterface{p1, p2, p3})
}

func readAll(conn *net.TCPConn, length int) ([]byte, error) {
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
		err = bgp.ValidateBGPMessage(m)
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
		h.fsm.bgpMessageStateUpdate(m.Header.Type, true)
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
	fsm.passiveConn.Write(b)
	fsm.bgpMessageStateUpdate(m.Header.Type, false)

	h.msgCh = make(chan *fsmMsg)
	h.conn = fsm.passiveConn

	h.t.Go(h.recvMessage)

	nextState := bgp.BGP_FSM_IDLE
	select {
	case <-h.t.Dying():
		h.conn.Close()
		return 0
	case e := <-h.msgCh:
		switch e.MsgData.(type) {
		case *bgp.BGPMessage:
			m := e.MsgData.(*bgp.BGPMessage)
			if m.Header.Type == bgp.BGP_MSG_OPEN {
				e := &fsmMsg{
					MsgType: FSM_MSG_BGP_MESSAGE,
					MsgData: m,
				}
				h.incoming <- e
				msg := bgp.NewBGPKeepAliveMessage()
				b, _ := msg.Serialize()
				fsm.passiveConn.Write(b)
				nextState = bgp.BGP_FSM_OPENCONFIRM
				fsm.bgpMessageStateUpdate(msg.Header.Type, false)
			} else {
				// send notification
			}
		case *bgp.MessageError:
			err := e.MsgData.(*bgp.MessageError)
			m := bgp.NewBGPNotificationMessage(err.TypeCode, err.SubTypeCode, err.Data)
			b, _ := m.Serialize()
			fsm.passiveConn.Write(b)
			fsm.bgpMessageStateUpdate(m.Header.Type, false)
			h.conn.Close()
			nextState = bgp.BGP_FSM_IDLE
		default:
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.peerConfig.NeighborAddress,
				"Data":  e.MsgData,
			}).Panic("unknonw msg type")
		}
	case <-h.errorCh:
		h.conn.Close()
	}
	return nextState
}

func (h *FSMHandler) openconfirm() bgp.FSMState {
	fsm := h.fsm
	sec := time.Second * time.Duration(fsm.peerConfig.Timers.KeepaliveInterval)
	fsm.keepaliveTicker = time.NewTicker(sec)

	h.msgCh = make(chan *fsmMsg)
	h.conn = fsm.passiveConn

	h.t.Go(h.recvMessage)

	for {
		select {
		case <-h.t.Dying():
			h.conn.Close()
			return 0
		case <-fsm.keepaliveTicker.C:
			m := bgp.NewBGPKeepAliveMessage()
			b, _ := m.Serialize()
			// TODO: check error
			fsm.passiveConn.Write(b)
			fsm.bgpMessageStateUpdate(m.Header.Type, false)
		case e := <-h.msgCh:
			switch e.MsgData.(type) {
			case *bgp.BGPMessage:
				m := e.MsgData.(*bgp.BGPMessage)
				nextState := bgp.BGP_FSM_IDLE
				if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
					nextState = bgp.BGP_FSM_ESTABLISHED
				} else {
					// send error
				}
				return nextState
			case *bgp.MessageError:
				err := e.MsgData.(*bgp.MessageError)
				m := bgp.NewBGPNotificationMessage(err.TypeCode, err.SubTypeCode, err.Data)
				b, _ := m.Serialize()
				fsm.passiveConn.Write(b)
				fsm.bgpMessageStateUpdate(m.Header.Type, false)
				h.conn.Close()
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
	for {
		select {
		case <-h.t.Dying():
			return nil
		case m := <-h.outgoing:
			b, _ := m.Serialize()
			_, err := conn.Write(b)
			if err != nil {
				h.errorCh <- true
				return nil
			}
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.peerConfig.NeighborAddress,
				"data":  m,
			}).Debug("sent")
			fsm.bgpMessageStateUpdate(m.Header.Type, false)

			if m.Header.Type == bgp.BGP_MSG_NOTIFICATION {
				h.errorCh <- true
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
	h.conn = fsm.passiveConn
	h.t.Go(h.sendMessageloop)
	h.msgCh = h.incoming
	h.t.Go(h.recvMessageloop)

	for {
		select {
		case <-h.errorCh:
			h.conn.Close()
			h.t.Kill(nil)
			return bgp.BGP_FSM_IDLE
		case <-h.t.Dying():
			h.conn.Close()
			return 0
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
