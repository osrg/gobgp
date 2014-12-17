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
	"encoding/json"
	"fmt"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"gopkg.in/tomb.v2"
	"net"
)

type Peer struct {
	t              tomb.Tomb
	globalConfig   config.GlobalType
	peerConfig     config.NeighborType
	acceptedConnCh chan *net.TCPConn
	incoming       chan *bgp.BGPMessage
	outgoing       chan *bgp.BGPMessage
	fsm            *FSM
	sourceVerNum   int
}

func NewPeer(g config.GlobalType, peer config.NeighborType) *Peer {
	p := &Peer{
		globalConfig:   g,
		peerConfig:     peer,
		acceptedConnCh: make(chan *net.TCPConn),
		incoming:       make(chan *bgp.BGPMessage, 4096),
		outgoing:       make(chan *bgp.BGPMessage, 4096),
		sourceVerNum:   1,
	}
	p.fsm = NewFSM(&g, &peer, p.acceptedConnCh, p.incoming, p.outgoing)
	p.t.Go(p.loop)
	return p
}

// this goroutine handles routing table operations
func (peer *Peer) loop() error {
	for {
		h := NewFSMHandler(peer.fsm)
		sameState := true
		for sameState {
			select {
			case nextState := <-peer.fsm.StateChanged():
				// waits for all goroutines created for the current state
				h.Wait()
				if peer.fsm.StateChange(nextState) {
					peer.sourceVerNum++
				}
				sameState = false
			case <-peer.t.Dying():
				close(peer.acceptedConnCh)
				h.Stop()
				close(peer.incoming)
				close(peer.outgoing)
				return nil
			case m := <-peer.incoming:
				if m != nil {
					j, _ := json.Marshal(m)
					fmt.Println(string(j))
				}
			}
		}
	}
}

func (peer *Peer) Stop() error {
	peer.t.Kill(nil)
	return peer.t.Wait()
}

func (peer *Peer) PassConn(conn *net.TCPConn) {
	peer.acceptedConnCh <- conn
}
