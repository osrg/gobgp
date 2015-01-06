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
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"gopkg.in/tomb.v2"
	"net"
	"time"
)

type peerMsgType int

const (
	_ peerMsgType = iota
	PEER_MSG_PATH
	PEER_MSG_PEER_DOWN
)

type peerMsg struct {
	msgType peerMsgType
	msgData interface{}
}

type Peer struct {
	t              tomb.Tomb
	globalConfig   config.GlobalType
	peerConfig     config.NeighborType
	acceptedConnCh chan *net.TCPConn
	incoming       chan *fsmMsg
	outgoing       chan *bgp.BGPMessage
	serverMsgCh    chan *serverMsg
	peerMsgCh      chan *peerMsg
	fsm            *FSM
	adjRib         *table.AdjRib
	// peer and rib are always not one-to-one so should not be
	// here but it's the simplest and works our first target.
	rib *table.TableManager
	// for now we support only the same afi as transport
	rf       bgp.RouteFamily
	capMap   map[bgp.BGPCapabilityCode]bgp.ParameterCapabilityInterface
	peerInfo *table.PeerInfo
	siblings map[string]*serverMsgDataPeer
}

func NewPeer(g config.GlobalType, peer config.NeighborType, serverMsgCh chan *serverMsg, peerMsgCh chan *peerMsg, peerList []*serverMsgDataPeer) *Peer {
	p := &Peer{
		globalConfig:   g,
		peerConfig:     peer,
		acceptedConnCh: make(chan *net.TCPConn),
		incoming:       make(chan *fsmMsg, 4096),
		outgoing:       make(chan *bgp.BGPMessage, 4096),
		serverMsgCh:    serverMsgCh,
		peerMsgCh:      peerMsgCh,
		capMap:         make(map[bgp.BGPCapabilityCode]bgp.ParameterCapabilityInterface),
	}
	p.siblings = make(map[string]*serverMsgDataPeer)
	for _, s := range peerList {
		p.siblings[s.address.String()] = s
	}
	p.fsm = NewFSM(&g, &peer, p.acceptedConnCh, p.incoming, p.outgoing)
	peer.BgpNeighborCommonState.State = uint32(bgp.BGP_FSM_IDLE)
	if peer.NeighborAddress.To4() != nil {
		p.rf = bgp.RF_IPv4_UC
	} else {
		p.rf = bgp.RF_IPv6_UC
	}
	p.peerInfo = &table.PeerInfo{
		AS:      peer.PeerAs,
		LocalID: g.RouterId,
		RF:      p.rf,
		Address: peer.NeighborAddress,
	}
	p.adjRib = table.NewAdjRib()
	p.rib = table.NewTableManager()
	p.t.Go(p.loop)
	return p
}

func (peer *Peer) handleBGPmessage(m *bgp.BGPMessage) {
	j, _ := json.Marshal(m)
	log.Debug(string(j))

	switch m.Header.Type {
	case bgp.BGP_MSG_OPEN:
		body := m.Body.(*bgp.BGPOpen)
		peer.peerInfo.ID = m.Body.(*bgp.BGPOpen).ID
		for _, p := range body.OptParams {
			paramCap, y := p.(*bgp.OptionParameterCapability)
			if !y {
				continue
			}
			for _, c := range paramCap.Capability {
				peer.capMap[c.Code()] = c
			}
		}

	case bgp.BGP_MSG_ROUTE_REFRESH:
		pathList := peer.adjRib.GetOutPathList(peer.rf)
		peer.sendMessages(table.CreateUpdateMsgFromPaths(pathList))
	case bgp.BGP_MSG_UPDATE:
		peer.peerConfig.BgpNeighborCommonState.UpdateRecvTime = time.Now()
		body := m.Body.(*bgp.BGPUpdate)
		table.UpdatePathAttrs4ByteAs(body)
		msg := table.NewProcessMessage(m, peer.peerInfo)
		pathList := msg.ToPathList()
		if len(pathList) == 0 {
			return
		}
		peer.adjRib.UpdateIn(pathList)
		pm := &peerMsg{
			msgType: PEER_MSG_PATH,
			msgData: pathList,
		}
		for _, s := range peer.siblings {
			if s.rf != peer.rf {
				continue
			}
			s.peerMsgCh <- pm
		}
	}
}

func (peer *Peer) sendMessages(msgs []*bgp.BGPMessage) {
	for _, m := range msgs {
		if peer.peerConfig.BgpNeighborCommonState.State != uint32(bgp.BGP_FSM_ESTABLISHED) {
			continue
		}

		if m.Header.Type != bgp.BGP_MSG_UPDATE {
			log.Fatal("not update message ", m.Header.Type)
		}

		_, y := peer.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
		if !y {
			log.Debug("update BGPUpdate for 2byte AS peer, ", peer.peerConfig.NeighborAddress.String())
			table.UpdatePathAttrs2ByteAs(m.Body.(*bgp.BGPUpdate))
		}

		peer.outgoing <- m
	}
}

func (peer *Peer) handleREST(restReq *api.RestRequest) {
	result := &api.RestResponse{}
	j, _ := json.Marshal(peer.rib.Tables[peer.rf])
	result.Data = j
	restReq.ResponseCh <- result
	close(restReq.ResponseCh)
}

func (peer *Peer) sendUpdateMsgFromPaths(pList []table.Path, wList []table.Path) {
	pathList := append([]table.Path(nil), pList...)
	pathList = append(pathList, wList...)

	for _, p := range wList {
		if !p.IsWithdraw() {
			log.Fatal("withdraw pathlist has non withdraw path")
		}
	}
	peer.adjRib.UpdateOut(pathList)
	peer.sendMessages(table.CreateUpdateMsgFromPaths(pathList))
}

func (peer *Peer) handlePeerMsg(m *peerMsg) {
	switch m.msgType {
	case PEER_MSG_PATH:
		pList, wList, _ := peer.rib.ProcessPaths(m.msgData.([]table.Path))
		peer.sendUpdateMsgFromPaths(pList, wList)
	case PEER_MSG_PEER_DOWN:
		pList, wList, _ := peer.rib.DeletePathsforPeer(m.msgData.(*table.PeerInfo))
		peer.sendUpdateMsgFromPaths(pList, wList)
	}
}

func (peer *Peer) handleServerMsg(m *serverMsg) {
	switch m.msgType {
	case SRV_MSG_PEER_ADDED:
		d := m.msgData.(*serverMsgDataPeer)
		peer.siblings[d.address.String()] = d
		pathList := peer.adjRib.GetInPathList(d.rf)
		if len(pathList) == 0 {
			return
		}
		pm := &peerMsg{
			msgType: PEER_MSG_PATH,
			msgData: pathList,
		}
		for _, s := range peer.siblings {
			if s.rf != peer.rf {
				continue
			}
			s.peerMsgCh <- pm
		}
	case SRV_MSG_PEER_DELETED:
		d := m.msgData.(*table.PeerInfo)
		_, found := peer.siblings[d.Address.String()]
		if found {
			delete(peer.siblings, d.Address.String())
			pList, wList, _ := peer.rib.DeletePathsforPeer(d)
			peer.sendUpdateMsgFromPaths(pList, wList)
		} else {
			log.Warning("can not find peer: ", d.Address.String())
		}
	case SRV_MSG_API:
		peer.handleREST(m.msgData.(*api.RestRequest))
	default:
		log.Fatal("unknown server msg type ", m.msgType)
	}
}

// this goroutine handles routing table operations
func (peer *Peer) loop() error {
	for {
		h := NewFSMHandler(peer.fsm)
		sameState := true
		for sameState {
			select {
			case <-peer.t.Dying():
				close(peer.acceptedConnCh)
				h.Stop()
				close(peer.incoming)
				close(peer.outgoing)
				return nil
			case e := <-peer.incoming:
				switch e.MsgType {
				case FSM_MSG_STATE_CHANGE:
					nextState := e.MsgData.(bgp.FSMState)
					// waits for all goroutines created for the current state
					h.Wait()
					oldState := bgp.FSMState(peer.peerConfig.BgpNeighborCommonState.State)
					peer.peerConfig.BgpNeighborCommonState.State = uint32(nextState)
					peer.fsm.StateChange(nextState)
					sameState = false
					if nextState == bgp.BGP_FSM_ESTABLISHED {
						pathList := peer.adjRib.GetOutPathList(peer.rf)
						peer.sendMessages(table.CreateUpdateMsgFromPaths(pathList))
						peer.fsm.peerConfig.BgpNeighborCommonState.Uptime = time.Now()
						peer.fsm.peerConfig.BgpNeighborCommonState.EstablishedCount++
					}
					if oldState == bgp.BGP_FSM_ESTABLISHED {
						peer.fsm.peerConfig.BgpNeighborCommonState.Uptime = time.Time{}
						pm := &peerMsg{
							msgType: PEER_MSG_PEER_DOWN,
							msgData: peer.peerInfo,
						}
						for _, s := range peer.siblings {
							s.peerMsgCh <- pm
						}
					}
				case FSM_MSG_BGP_MESSAGE:
					peer.handleBGPmessage(e.MsgData.(*bgp.BGPMessage))
				}
			case m := <-peer.serverMsgCh:
				peer.handleServerMsg(m)
			case m := <-peer.peerMsgCh:
				peer.handlePeerMsg(m)
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

func (peer *Peer) MarshalJSON() ([]byte, error) {

	f := peer.fsm
	c := f.peerConfig

	p := make(map[string]interface{})
	capList := make([]int, 0)
	for k, _ := range peer.capMap {
		capList = append(capList, int(k))
	}

	p["conf"] = struct {
		RemoteIP           string `json:"remote_ip"`
		Id                 string `json:"id"`
		RemoteAS           uint32 `json:"remote_as"`
		CapRefresh         bool   `json:"cap_refresh"`
		CapEnhancedRefresh bool   `json:"cap_enhanced_refresh"`
		RemoteCap          []int
		LocalCap           []int
	}{
		RemoteIP:  c.NeighborAddress.String(),
		Id:        peer.peerInfo.ID.To4().String(),
		RemoteAS:  c.PeerAs,
		RemoteCap: capList,
		LocalCap:  []int{int(bgp.BGP_CAP_MULTIPROTOCOL), int(bgp.BGP_CAP_ROUTE_REFRESH), int(bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER)},
	}

	s := c.BgpNeighborCommonState

	uptime := float64(0)
	if !s.Uptime.IsZero() {
		uptime = time.Now().Sub(s.Uptime).Seconds()
	}
	p["info"] = struct {
		BgpState                  string  `json:"bgp_state"`
		FsmEstablishedTransitions uint32  `json:"fsm_established_transitions"`
		TotalMessageOut           uint32  `json:"total_message_out"`
		TotalMessageIn            uint32  `json:"total_message_in"`
		UpdateMessageOut          uint32  `json:"update_message_out"`
		UpdateMessageIn           uint32  `json:"update_message_in"`
		KeepAliveMessageOut       uint32  `json:"keepalive_message_out"`
		KeepAliveMessageIn        uint32  `json:"keepalive_message_in"`
		OpenMessageOut            uint32  `json:"open_message_out"`
		OpenMessageIn             uint32  `json:"open_message_in"`
		NotificationOut           uint32  `json:"notification_out"`
		NotificationIn            uint32  `json:"notification_in"`
		RefreshMessageOut         uint32  `json:"refresh_message_out"`
		RefreshMessageIn          uint32  `json:"refresh_message_in"`
		Uptime                    float64 `json:"uptime"`
		LastError                 string  `json:"last_error"`
	}{

		BgpState:                  f.state.String(),
		FsmEstablishedTransitions: s.EstablishedCount,
		TotalMessageOut:           s.TotalOut,
		TotalMessageIn:            s.TotalIn,
		UpdateMessageOut:          s.UpdateOut,
		UpdateMessageIn:           s.UpdateIn,
		KeepAliveMessageOut:       s.KeepaliveOut,
		KeepAliveMessageIn:        s.KeepaliveIn,
		OpenMessageOut:            s.OpenOut,
		OpenMessageIn:             s.OpenIn,
		NotificationOut:           s.NotifyOut,
		NotificationIn:            s.NotifyIn,
		RefreshMessageOut:         s.RefreshOut,
		RefreshMessageIn:          s.RefreshIn,
		Uptime:                    uptime,
	}

	return json.Marshal(p)
}
