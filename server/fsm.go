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
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"gopkg.in/tomb.v2"
	"net"
	"time"
)

type FSM struct {
	globalConfig    *config.GlobalType
	peerConfig      *config.NeighborType
	keepaliveTicker *time.Ticker
	state           int
	incoming        chan *bgp.BGPMessage
	outgoing        chan *bgp.BGPMessage
	//activeConn *net.TCPConn
	passiveConn   *net.TCPConn
	passiveConnCh chan *net.TCPConn
	stateCh       chan int
}

func NewFSM(gConfig *config.GlobalType, pConfig *config.NeighborType, connCh chan *net.TCPConn, incoming chan *bgp.BGPMessage, outgoing chan *bgp.BGPMessage) *FSM {
	return &FSM{
		globalConfig:  gConfig,
		peerConfig:    pConfig,
		incoming:      incoming,
		outgoing:      outgoing,
		state:         bgp.BGP_FSM_IDLE,
		passiveConnCh: connCh,
		stateCh:       make(chan int),
	}
}

func (fsm *FSM) StateChanged() chan int {
	return fsm.stateCh
}

func (fsm *FSM) StateChange(nextState int) bool {
	fmt.Println("state changed", nextState, fsm.state)
	oldState := fsm.state
	fsm.state = nextState
	if oldState >= bgp.BGP_FSM_OPENSENT && fsm.state == bgp.BGP_FSM_IDLE {
		return true
	}
	return false
}

type FSMHandler struct {
	t       tomb.Tomb
	fsm     *FSM
	conn    *net.TCPConn
	ch      chan *bgp.BGPMessage
	ioError bool
}

func NewFSMHandler(fsm *FSM) *FSMHandler {
	f := &FSMHandler{
		fsm:     fsm,
		ioError: false,
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

func (h *FSMHandler) idle() error {
	fsm := h.fsm
	// TODO: support idle hold timer

	if fsm.keepaliveTicker != nil {
		fsm.keepaliveTicker.Stop()
		fsm.keepaliveTicker = nil
	}
	fsm.stateCh <- bgp.BGP_FSM_ACTIVE
	return nil
}

func (h *FSMHandler) active() error {
	fsm := h.fsm
	select {
	case <-h.t.Dying():
		return nil
	case conn := <-fsm.passiveConnCh:
		fsm.passiveConn = conn
	}
	// we don't implement delayed open timer so move to opensent right
	// away.
	fsm.stateCh <- bgp.BGP_FSM_OPENSENT
	return nil
}

func buildopen(global *config.GlobalType, neighborT *config.NeighborType) *bgp.BGPMessage {
	p1 := bgp.NewOptionParameterCapability(
		[]bgp.ParameterCapabilityInterface{bgp.NewCapRouteRefresh()})
	p2 := bgp.NewOptionParameterCapability(
		[]bgp.ParameterCapabilityInterface{bgp.NewCapMultiProtocol(bgp.AFI_IP, bgp.SAFI_UNICAST)})
	p3 := bgp.NewOptionParameterCapability(
		[]bgp.ParameterCapabilityInterface{bgp.NewCapFourOctetASNumber(global.As)})
	holdTime := uint16(neighborT.Timers.HoldTime)
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

func (h *FSMHandler) recvMessage() error {
	headerBuf, err := readAll(h.conn, bgp.BGP_HEADER_LENGTH)
	if err != nil {
		h.ioError = true
		close(h.ch)
		return nil
	}

	hd := &bgp.BGPHeader{}
	err = hd.DecodeFromBytes(headerBuf)
	if err != nil {
		h.ioError = true
		close(h.ch)
		return nil
	}

	bodyBuf, err := readAll(h.conn, int(hd.Len)-bgp.BGP_HEADER_LENGTH)
	if err != nil {
		h.ioError = true
		close(h.ch)
		return nil
	}

	m, err := bgp.ParseBGPBody(hd, bodyBuf)
	if err != nil {
		h.ioError = true
		close(h.ch)
		return nil
	}
	h.ch <- m
	return nil
}

func (h *FSMHandler) opensent() error {
	fsm := h.fsm
	m := buildopen(fsm.globalConfig, fsm.peerConfig)
	b, _ := m.Serialize()
	fsm.passiveConn.Write(b)

	h.ch = make(chan *bgp.BGPMessage)
	h.conn = fsm.passiveConn

	h.t.Go(h.recvMessage)

	nextState := bgp.BGP_FSM_IDLE
	select {
	case <-h.t.Dying():
		fsm.passiveConn.Close()
		return nil
	case m, ok := <-h.ch:
		if ok {
			if m.Header.Type == bgp.BGP_MSG_OPEN {
				msg := bgp.NewBGPKeepAliveMessage()
				b, _ := msg.Serialize()
				fsm.passiveConn.Write(b)
				nextState = bgp.BGP_FSM_OPENCONFIRM
			} else {
				// send error
			}
		} else {
			// io error
		}
	}
	fsm.stateCh <- nextState
	return nil
}

func (h *FSMHandler) openconfirm() error {
	fsm := h.fsm
	sec := time.Second * time.Duration(fsm.peerConfig.Timers.KeepaliveInterval)
	fsm.keepaliveTicker = time.NewTicker(sec)

	h.ch = make(chan *bgp.BGPMessage)
	h.conn = fsm.passiveConn

	h.t.Go(h.recvMessage)

	for {
		select {
		case <-h.t.Dying():
			fsm.passiveConn.Close()
			return nil
		case <-fsm.keepaliveTicker.C:
			m := bgp.NewBGPKeepAliveMessage()
			b, _ := m.Serialize()
			// TODO: check error
			fsm.passiveConn.Write(b)
		case m, ok := <-h.ch:
			nextState := bgp.BGP_FSM_IDLE
			if ok {
				if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
					nextState = bgp.BGP_FSM_ESTABLISHED
				} else {
					// send error
				}
			} else {
				// io error
			}
			fsm.stateCh <- nextState
			return nil
		}
	}
	// panic
	return nil
}

func (h *FSMHandler) sendMessageloop() error {
	conn := h.conn
	fsm := h.fsm
	for {
		select {
		case <-h.t.Dying():
			return nil
		case m := <-fsm.outgoing:
			b, _ := m.Serialize()
			_, err := conn.Write(b)
			if err != nil {
				return nil
			}
		case <-fsm.keepaliveTicker.C:
			m := bgp.NewBGPKeepAliveMessage()
			b, _ := m.Serialize()
			_, err := conn.Write(b)
			if err != nil {
				return nil
			}
		}
	}
}

func (h *FSMHandler) recvMessageloop() error {
	for {
		h.recvMessage()
		if h.ioError == true {
			return nil
		}
	}
}

func (h *FSMHandler) established() error {
	fsm := h.fsm
	h.conn = fsm.passiveConn
	h.t.Go(h.sendMessageloop)
	// TODO: use incoming directly
	h.ch = make(chan *bgp.BGPMessage, 4096)
	h.t.Go(h.recvMessageloop)

	for {
		select {
		case m, ok := <-h.ch:
			if ok {
				fsm.incoming <- m
			} else {
				h.conn.Close()
				h.t.Kill(nil)
				fsm.stateCh <- bgp.BGP_FSM_IDLE
				return nil
			}
		case <-h.t.Dying():
			h.conn.Close()
			return nil
		}
	}
	return nil
}

func (h *FSMHandler) loop() error {
	fsm := h.fsm
	switch fsm.state {
	case bgp.BGP_FSM_IDLE:
		return h.idle()
		//	case bgp.BGP_FSM_CONNECT:
		//		return h.connect()
	case bgp.BGP_FSM_ACTIVE:
		return h.active()
	case bgp.BGP_FSM_OPENSENT:
		return h.opensent()
	case bgp.BGP_FSM_OPENCONFIRM:
		return h.openconfirm()
	case bgp.BGP_FSM_ESTABLISHED:
		return h.established()
	}
	// panic
	return nil
}
