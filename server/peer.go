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

const (
	FSM_CHANNEL_LENGTH = 1024
	FLOP_THRESHOLD     = time.Second * 30
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
	globalConfig   config.Global
	peerConfig     config.Neighbor
	acceptedConnCh chan net.Conn
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
	outgoing chan *bgp.BGPMessage
}

func NewPeer(g config.Global, peer config.Neighbor, serverMsgCh chan *serverMsg, peerMsgCh chan *peerMsg, peerList []*serverMsgDataPeer) *Peer {
	p := &Peer{
		globalConfig:   g,
		peerConfig:     peer,
		acceptedConnCh: make(chan net.Conn),
		serverMsgCh:    serverMsgCh,
		peerMsgCh:      peerMsgCh,
		capMap:         make(map[bgp.BGPCapabilityCode]bgp.ParameterCapabilityInterface),
	}
	p.siblings = make(map[string]*serverMsgDataPeer)
	for _, s := range peerList {
		p.siblings[s.address.String()] = s
	}
	p.fsm = NewFSM(&g, &peer, p.acceptedConnCh)
	peer.BgpNeighborCommonState.State = uint32(bgp.BGP_FSM_IDLE)
	peer.BgpNeighborCommonState.Downtime = time.Now().Unix()
	if peer.NeighborAddress.To4() != nil {
		p.rf = bgp.RF_IPv4_UC
	} else {
		p.rf = bgp.RF_IPv6_UC
	}
	p.peerInfo = &table.PeerInfo{
		AS:      peer.PeerAs,
		LocalID: g.RouterId,
		Address: peer.NeighborAddress,
	}
	p.adjRib = table.NewAdjRib()
	p.rib = table.NewTableManager(p.peerConfig.NeighborAddress.String(), []bgp.RouteFamily{p.rf})
	p.t.Go(p.loop)
	return p
}

func (peer *Peer) handleBGPmessage(m *bgp.BGPMessage) {
	log.WithFields(log.Fields{
		"Topic": "Peer",
		"Key":   peer.peerConfig.NeighborAddress,
		"data":  m,
	}).Debug("received")

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

		// calculate HoldTime
		// RFC 4271 P.13
		// a BGP speaker MUST calculate the value of the Hold Timer
		// by using the smaller of its configured Hold Time and the Hold Time
		// received in the OPEN message.
		holdTime := float64(body.HoldTime)
		myHoldTime := peer.fsm.peerConfig.Timers.HoldTime
		if holdTime > myHoldTime {
			peer.fsm.negotiatedHoldTime = myHoldTime
		} else {
			peer.fsm.negotiatedHoldTime = holdTime
		}

	case bgp.BGP_MSG_ROUTE_REFRESH:
		rr := m.Body.(*bgp.BGPRouteRefresh)
		rf := bgp.AfiSafiToRouteFamily(rr.AFI, rr.SAFI)
		if peer.rf != rf {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.peerConfig.NeighborAddress,
				"Data":  rf,
			}).Warn("Route family isn't supported")
			return
		}
		if _, ok := peer.capMap[bgp.BGP_CAP_ROUTE_REFRESH]; ok {
			pathList := peer.adjRib.GetOutPathList(peer.rf)
			peer.sendMessages(table.CreateUpdateMsgFromPaths(pathList))
		} else {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.peerConfig.NeighborAddress,
			}).Warn("ROUTE_REFRESH received but the capability wasn't advertised")
		}
	case bgp.BGP_MSG_UPDATE:
		peer.peerConfig.BgpNeighborCommonState.UpdateRecvTime = time.Now().Unix()
		body := m.Body.(*bgp.BGPUpdate)
		_, err := bgp.ValidateUpdateMsg(body, []bgp.RouteFamily{peer.rf})
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.peerConfig.NeighborAddress,
				"error": err,
			}).Warn("malformed BGP update message")
			m := err.(*bgp.MessageError)
			if m.TypeCode != 0 {
				peer.outgoing <- bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data)
			}
			return
		}
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
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.peerConfig.NeighborAddress,
				"data":  m,
			}).Debug("update for 2byte AS peer")
			table.UpdatePathAttrs2ByteAs(m.Body.(*bgp.BGPUpdate))
		}

		peer.outgoing <- m
	}
}

func (peer *Peer) handleREST(restReq *api.RestRequest) {
	result := &api.RestResponse{}
	switch restReq.RequestType {
	case api.REQ_LOCAL_RIB:
		var t table.Table
		if peer.fsm.adminState == ADMIN_STATE_DOWN {
			if peer.rf == bgp.RF_IPv4_UC {
				t = table.NewIPv4Table(0)
			} else {
				t = table.NewIPv6Table(0)
			}
		} else {
			t = peer.rib.Tables[peer.rf]
		}
		j, _ := json.Marshal(t)
		result.Data = j
	case api.REQ_NEIGHBOR_SHUTDOWN:
		peer.outgoing <- bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, nil)
	case api.REQ_NEIGHBOR_RESET:
		peer.fsm.idleHoldTime = peer.peerConfig.Timers.IdleHoldTimeAfterReset
		peer.outgoing <- bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET, nil)
	case api.REQ_NEIGHBOR_SOFT_RESET, api.REQ_NEIGHBOR_SOFT_RESET_IN:
		// soft-reconfiguration inbound
		pathList := peer.adjRib.GetInPathList(peer.rf)
		pm := &peerMsg{
			msgType: PEER_MSG_PATH,
			msgData: pathList,
		}
		for _, s := range peer.siblings {
			s.peerMsgCh <- pm
		}
		if restReq.RequestType == api.REQ_NEIGHBOR_SOFT_RESET_IN {
			break
		}
		fallthrough
	case api.REQ_NEIGHBOR_SOFT_RESET_OUT:
		pathList := peer.adjRib.GetOutPathList(peer.rf)
		peer.sendMessages(table.CreateUpdateMsgFromPaths(pathList))
	case api.REQ_ADJ_RIB_IN, api.REQ_ADJ_RIB_OUT:
		rfs := []bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC}
		adjrib := make(map[string][]table.Path)

		if restReq.RequestType == api.REQ_ADJ_RIB_IN {
			for _, rf := range rfs {
				paths := peer.adjRib.GetInPathList(rf)
				adjrib[rf.String()] = paths
				log.Debugf("RouteFamily=%v adj-rib-in found : %d", rf.String(), len(paths))
			}
		} else {
			for _, rf := range rfs {
				paths := peer.adjRib.GetOutPathList(rf)
				adjrib[rf.String()] = paths
				log.Debugf("RouteFamily=%v adj-rib-out found : %d", rf.String(), len(paths))
			}
		}
		j, _ := json.Marshal(adjrib)
		result.Data = j
	case api.REQ_NEIGHBOR_ENABLE, api.REQ_NEIGHBOR_DISABLE:
		r := make(map[string]string)
		if restReq.RequestType == api.REQ_NEIGHBOR_ENABLE {
			select {
			case peer.fsm.adminStateCh <- ADMIN_STATE_UP:
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.peerConfig.NeighborAddress,
				}).Debug("ADMIN_STATE_UP requested")
				r["result"] = "ADMIN_STATE_UP"
			default:
				log.Warning("previous request is still remaining. : ", peer.peerConfig.NeighborAddress)
				r["result"] = "previous request is still remaining"
			}
		} else {
			select {
			case peer.fsm.adminStateCh <- ADMIN_STATE_DOWN:
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.peerConfig.NeighborAddress,
				}).Debug("ADMIN_STATE_DOWN requested")
				r["result"] = "ADMIN_STATE_DOWN"
			default:
				log.Warning("previous request is still remaining. : ", peer.peerConfig.NeighborAddress)
				r["result"] = "previous request is still remaining"
			}
		}
		j, _ := json.Marshal(r)
		result.Data = j
	}
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
		pList, wList, _ := peer.rib.DeletePathsforPeer(m.msgData.(*table.PeerInfo), peer.rf)
		peer.sendUpdateMsgFromPaths(pList, wList)
	}
}

func (peer *Peer) handleServerMsg(m *serverMsg) {
	switch m.msgType {
	case SRV_MSG_PEER_ADDED:
		d := m.msgData.(*serverMsgDataPeer)
		peer.siblings[d.address.String()] = d
		pathList := peer.adjRib.GetInPathList(peer.rf)
		if len(pathList) == 0 {
			return
		}
		pm := &peerMsg{
			msgType: PEER_MSG_PATH,
			msgData: pathList,
		}
		for _, s := range peer.siblings {
			s.peerMsgCh <- pm
		}
	case SRV_MSG_PEER_DELETED:
		d := m.msgData.(*table.PeerInfo)
		_, found := peer.siblings[d.Address.String()]
		if found {
			delete(peer.siblings, d.Address.String())
			pList, wList, _ := peer.rib.DeletePathsforPeer(d, peer.rf)
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
		incoming := make(chan *fsmMsg, FSM_CHANNEL_LENGTH)
		peer.outgoing = make(chan *bgp.BGPMessage, FSM_CHANNEL_LENGTH)

		h := NewFSMHandler(peer.fsm, incoming, peer.outgoing)
		if peer.peerConfig.BgpNeighborCommonState.State == uint32(bgp.BGP_FSM_ESTABLISHED) {
			pathList := peer.adjRib.GetOutPathList(peer.rf)
			peer.sendMessages(table.CreateUpdateMsgFromPaths(pathList))
			peer.fsm.peerConfig.BgpNeighborCommonState.Uptime = time.Now().Unix()
			peer.fsm.peerConfig.BgpNeighborCommonState.EstablishedCount++
		} else {
			peer.fsm.peerConfig.BgpNeighborCommonState.Downtime = time.Now().Unix()
		}

		sameState := true
		for sameState {
			select {
			case <-peer.t.Dying():
				close(peer.acceptedConnCh)
				peer.outgoing <- bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED, nil)
				// h.t.Kill(nil) will be called
				// internall so even goroutines in
				// non-established will be killed.
				h.Stop()
				return nil
			case e := <-incoming:
				switch e.MsgType {
				case FSM_MSG_STATE_CHANGE:
					nextState := e.MsgData.(bgp.FSMState)
					// waits for all goroutines created for the current state
					h.Wait()
					oldState := bgp.FSMState(peer.peerConfig.BgpNeighborCommonState.State)
					peer.peerConfig.BgpNeighborCommonState.State = uint32(nextState)
					peer.fsm.StateChange(nextState)
					sameState = false
					if oldState == bgp.BGP_FSM_ESTABLISHED {
						t := time.Now()
						if t.Sub(time.Unix(peer.fsm.peerConfig.BgpNeighborCommonState.Uptime, 0)) < FLOP_THRESHOLD {
							peer.fsm.peerConfig.BgpNeighborCommonState.Flops++
						}
						peer.adjRib.DropAllIn(peer.rf)
						pm := &peerMsg{
							msgType: PEER_MSG_PEER_DOWN,
							msgData: peer.peerInfo,
						}
						for _, s := range peer.siblings {
							s.peerMsgCh <- pm
						}
					}

					// clear counter
					if h.fsm.adminState == ADMIN_STATE_DOWN {
						h.fsm.peerConfig.BgpNeighborCommonState = config.BgpNeighborCommonState{}
					}

				case FSM_MSG_BGP_MESSAGE:
					switch m := e.MsgData.(type) {
					case *bgp.MessageError:
						peer.outgoing <- bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data)
					case *bgp.BGPMessage:
						peer.handleBGPmessage(m)
					default:
						log.WithFields(log.Fields{
							"Topic": "Peer",
							"Key":   peer.peerConfig.NeighborAddress,
							"Data":  e.MsgData,
						}).Panic("unknonw msg type")
					}
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

	uptime := int64(0)
	if s.Uptime != 0 {
		uptime = int64(time.Now().Sub(time.Unix(s.Uptime, 0)).Seconds())
	}
	downtime := int64(0)
	if s.Downtime != 0 {
		downtime = int64(time.Now().Sub(time.Unix(s.Downtime, 0)).Seconds())
	}

	advertized := uint32(0)
	if f.state == bgp.BGP_FSM_ESTABLISHED {
		advertized = uint32(peer.adjRib.GetOutCount(peer.rf))
	}

	p["info"] = struct {
		BgpState                  string `json:"bgp_state"`
		AdminState                string
		FsmEstablishedTransitions uint32 `json:"fsm_established_transitions"`
		TotalMessageOut           uint32 `json:"total_message_out"`
		TotalMessageIn            uint32 `json:"total_message_in"`
		UpdateMessageOut          uint32 `json:"update_message_out"`
		UpdateMessageIn           uint32 `json:"update_message_in"`
		KeepAliveMessageOut       uint32 `json:"keepalive_message_out"`
		KeepAliveMessageIn        uint32 `json:"keepalive_message_in"`
		OpenMessageOut            uint32 `json:"open_message_out"`
		OpenMessageIn             uint32 `json:"open_message_in"`
		NotificationOut           uint32 `json:"notification_out"`
		NotificationIn            uint32 `json:"notification_in"`
		RefreshMessageOut         uint32 `json:"refresh_message_out"`
		RefreshMessageIn          uint32 `json:"refresh_message_in"`
		DiscardedOut              uint32
		DiscardedIn               uint32
		Uptime                    int64  `json:"uptime"`
		Downtime                  int64  `json:"downtime"`
		LastError                 string `json:"last_error"`
		Received                  uint32
		Accepted                  uint32
		Advertized                uint32
		OutQ                      int
		Flops                     uint32
	}{

		BgpState:                  f.state.String(),
		AdminState:                f.adminState.String(),
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
		DiscardedOut:              s.DiscardedOut,
		DiscardedIn:               s.DiscardedIn,
		Uptime:                    uptime,
		Downtime:                  downtime,
		Received:                  uint32(peer.adjRib.GetInCount(peer.rf)),
		Accepted:                  uint32(peer.adjRib.GetInCount(peer.rf)),
		Advertized:                advertized,
		OutQ:                      len(peer.outgoing),
		Flops:                     s.Flops,
	}

	return json.Marshal(p)
}
