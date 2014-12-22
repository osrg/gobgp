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
	"github.com/osrg/gobgp/table"
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
	inEventCh      chan *message
	outEventCh     chan *message
	fsm            *FSM
	adjRib         *table.AdjRib
	// peer and rib are always not one-to-one so should not be
	// here but it's the simplest and works our first target.
	rib *table.TableManager
}

func NewPeer(g config.GlobalType, peer config.NeighborType, outEventCh chan *message) *Peer {
	p := &Peer{
		globalConfig:   g,
		peerConfig:     peer,
		acceptedConnCh: make(chan *net.TCPConn),
		incoming:       make(chan *bgp.BGPMessage, 4096),
		outgoing:       make(chan *bgp.BGPMessage, 4096),
		inEventCh:      make(chan *message, 4096),
		outEventCh:     outEventCh,
	}
	p.fsm = NewFSM(&g, &peer, p.acceptedConnCh, p.incoming, p.outgoing)
	p.adjRib = table.NewAdjRib()
	p.rib = table.NewTableManager()
	p.t.Go(p.loop)
	return p
}

func (peer *Peer) handleBGPmessage(m *bgp.BGPMessage) {
	j, _ := json.Marshal(m)
	fmt.Println(string(j))
	// TODO: update state here

	if m.Header.Type != bgp.BGP_MSG_UPDATE {
		return
	}

	msg := table.NewProcessMessage(m, peer.fsm.peerInfo)
	pathList := msg.ToPathList()
	if len(pathList) == 0 {
		return
	}

	peer.adjRib.UpdateIn(pathList)

	peer.sendToHub("", PEER_MSG_PATH, pathList)
}

func (peer *Peer) handlePeermessage(m *message) {
	switch m.event {
	case PEER_MSG_PATH:
		pList, wList, _ := peer.rib.ProcessPaths(m.data.([]table.Path))
		// TODO: merge multiple messages
		// TODO: 4bytes and 2bytes conversion.
		adjPathLists := append([]table.Path(nil), pList...)

		msgs := make([]*bgp.BGPMessage, 0)
		for _, p := range pList {
			pathAttrs := p.GetPathAttrs()
			nlri := p.GetNlri().(*bgp.NLRInfo)
			m := bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, pathAttrs, []bgp.NLRInfo{*nlri})
			msgs = append(msgs, m)
		}

		for _, dest := range wList {
			p := dest.GetOldBestPath()
			draw := p.GetNlri().(*bgp.WithdrawnRoute)
			m := bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{*draw}, []bgp.PathAttributeInterface{}, []bgp.NLRInfo{})
			msgs = append(msgs, m)

			adjPathLists = append(adjPathLists, p.Clone(true))
		}

		peer.adjRib.UpdateOut(adjPathLists)

		for _, m := range msgs {
			peer.outgoing <- m
		}
	}
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
				peer.fsm.StateChange(nextState)
				sameState = false
			case <-peer.t.Dying():
				close(peer.acceptedConnCh)
				h.Stop()
				close(peer.incoming)
				close(peer.outgoing)
				return nil
			case m := <-peer.incoming:
				if m == nil {
					continue
				}
				peer.handleBGPmessage(m)
			case m := <-peer.inEventCh:
				peer.handlePeermessage(m)
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

func (peer *Peer) SendMessage(msg *message) {
	peer.inEventCh <- msg
}

func (peer *Peer) sendToHub(destination string, event int, data interface{}) {
	peer.outEventCh <- &message{
		src:   peer.peerConfig.NeighborAddress.String(),
		dst:   destination,
		event: event,
		data:  data,
	}
}
