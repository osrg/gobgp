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
	"strings"
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
	rib         *table.TableManager
	isGlobalRib bool
	rfMap       map[bgp.RouteFamily]bool
	capMap      map[bgp.BGPCapabilityCode]bgp.ParameterCapabilityInterface
	peerInfo    *table.PeerInfo
	siblings    map[string]*serverMsgDataPeer
	outgoing    chan *bgp.BGPMessage
}

func NewPeer(g config.Global, peer config.Neighbor, serverMsgCh chan *serverMsg, peerMsgCh chan *peerMsg, peerList []*serverMsgDataPeer, isGlobalRib bool) *Peer {
	p := &Peer{
		globalConfig:   g,
		peerConfig:     peer,
		acceptedConnCh: make(chan net.Conn),
		serverMsgCh:    serverMsgCh,
		peerMsgCh:      peerMsgCh,
		rfMap:          make(map[bgp.RouteFamily]bool),
		capMap:         make(map[bgp.BGPCapabilityCode]bgp.ParameterCapabilityInterface),
		isGlobalRib:    isGlobalRib,
	}
	p.siblings = make(map[string]*serverMsgDataPeer)
	for _, s := range peerList {
		p.siblings[s.address.String()] = s
	}
	p.fsm = NewFSM(&g, &peer, p.acceptedConnCh)
	peer.BgpNeighborCommonState.State = uint32(bgp.BGP_FSM_IDLE)
	peer.BgpNeighborCommonState.Downtime = time.Now().Unix()
	for _, rf := range peer.AfiSafiList {
		k, _ := bgp.GetRouteFamily(rf.AfiSafiName)
		p.rfMap[k] = true
	}
	p.peerInfo = &table.PeerInfo{
		AS:      peer.PeerAs,
		LocalID: g.RouterId,
		Address: peer.NeighborAddress,
	}
	rfList := p.configuredRFlist()
	p.adjRib = table.NewAdjRib(rfList)
	p.rib = table.NewTableManager(p.peerConfig.NeighborAddress.String(), rfList)
	p.t.Go(p.loop)
	return p
}

func (peer *Peer) configuredRFlist() []bgp.RouteFamily {
	rfList := []bgp.RouteFamily{}
	for _, rf := range peer.peerConfig.AfiSafiList {
		k, _ := bgp.GetRouteFamily(rf.AfiSafiName)
		rfList = append(rfList, k)
	}
	return rfList
}

func (peer *Peer) sendPathsToSiblings(pathList []table.Path) {
	if len(pathList) == 0 {
		return
	}

	for _, p := range pathList {
		table.UpdatePathAttrs4ByteAs(&p)
	}

	pm := &peerMsg{
		msgType: PEER_MSG_PATH,
		msgData: pathList,
	}
	for _, s := range peer.siblings {
		s.peerMsgCh <- pm
	}
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
		r := make(map[bgp.RouteFamily]bool)
		for _, p := range body.OptParams {
			if paramCap, y := p.(*bgp.OptionParameterCapability); y {
				for _, c := range paramCap.Capability {
					peer.capMap[c.Code()] = c
					if c.Code() == bgp.BGP_CAP_MULTIPROTOCOL {
						m := c.(*bgp.CapMultiProtocol)
						r[bgp.AfiSafiToRouteFamily(m.CapValue.AFI, m.CapValue.SAFI)] = true
					}
				}
			}
		}

		for rf, _ := range peer.rfMap {
			if _, y := r[rf]; !y {
				delete(peer.rfMap, rf)
			}
		}

		for _, rf := range peer.configuredRFlist() {
			if _, ok := r[rf]; ok {
				peer.rfMap[rf] = true
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
		if _, ok := peer.rfMap[rf]; !ok {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.peerConfig.NeighborAddress,
				"Data":  rf,
			}).Warn("Route family isn't supported")
			return
		}
		if _, ok := peer.capMap[bgp.BGP_CAP_ROUTE_REFRESH]; ok {
			pathList := peer.adjRib.GetOutPathList(rf)
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
		_, err := bgp.ValidateUpdateMsg(body, peer.rfMap)
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
		msg := table.NewProcessMessage(m, peer.peerInfo)
		pathList := msg.ToPathList()
		peer.adjRib.UpdateIn(pathList)
		peer.sendPathsToSiblings(pathList)
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

		peer.outgoing <- m
	}
}

func (peer *Peer) handleREST(restReq *api.RestRequest) {
	result := &api.RestResponse{}
	switch restReq.RequestType {
	case api.REQ_LOCAL_RIB, api.REQ_GLOBAL_RIB:
		// just empty so we use ipv4 for any route family
		j, _ := json.Marshal(table.NewIPv4Table(0))
		if peer.fsm.adminState != ADMIN_STATE_DOWN {
			if t, ok := peer.rib.Tables[restReq.RouteFamily]; ok {
				j, _ = json.Marshal(t)
			}
		}
		result.Data = j
	case api.REQ_NEIGHBOR_SHUTDOWN:
		peer.outgoing <- bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, nil)
	case api.REQ_NEIGHBOR_RESET:
		peer.fsm.idleHoldTime = peer.peerConfig.Timers.IdleHoldTimeAfterReset
		peer.outgoing <- bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET, nil)
	case api.REQ_NEIGHBOR_SOFT_RESET, api.REQ_NEIGHBOR_SOFT_RESET_IN:
		// soft-reconfiguration inbound
		peer.sendPathsToSiblings(peer.adjRib.GetInPathList(restReq.RouteFamily))
		if restReq.RequestType == api.REQ_NEIGHBOR_SOFT_RESET_IN {
			break
		}
		fallthrough
	case api.REQ_NEIGHBOR_SOFT_RESET_OUT:
		pathList := peer.adjRib.GetOutPathList(restReq.RouteFamily)
		peer.sendMessages(table.CreateUpdateMsgFromPaths(pathList))
	case api.REQ_ADJ_RIB_IN, api.REQ_ADJ_RIB_OUT:
		adjrib := make(map[string][]table.Path)
		rf := restReq.RouteFamily
		if restReq.RequestType == api.REQ_ADJ_RIB_IN {
			paths := peer.adjRib.GetInPathList(rf)
			adjrib[rf.String()] = paths
			log.Debugf("RouteFamily=%v adj-rib-in found : %d", rf.String(), len(paths))
		} else {
			paths := peer.adjRib.GetOutPathList(rf)
			adjrib[rf.String()] = paths
			log.Debugf("RouteFamily=%v adj-rib-out found : %d", rf.String(), len(paths))
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

func (peer *Peer) sendUpdateMsgFromPaths(pList []table.Path) {
	sendpathList := []table.Path{}
	for _, p := range pList {
		_, ok := peer.rfMap[p.GetRouteFamily()]

		if peer.peerConfig.NeighborAddress.Equal(p.GetNexthop()) {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.peerConfig.NeighborAddress,
			}).Debugf("From me. Ignore: %s", p)
			ok = false
		}

		if ok {
			sendpathList = append(sendpathList, p)
		}
	}

	sendpathList = table.CloneAndUpdatePathAttrs(sendpathList, &peer.globalConfig, &peer.peerConfig)

	_, y := peer.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
	if !y {
		for _, p := range sendpathList {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.peerConfig.NeighborAddress,
				"data":  p,
			}).Debug("update for 2byte AS peer")
			table.UpdatePathAttrs2ByteAs(&p)
		}
	}

	peer.adjRib.UpdateOut(sendpathList)
	updateMsgs := table.CreateUpdateMsgFromPaths(sendpathList)
	peer.sendMessages(updateMsgs)
}

func (peer *Peer) handlePeerMsg(m *peerMsg) {
	switch m.msgType {
	case PEER_MSG_PATH:
		pList := m.msgData.([]table.Path)
		if peer.peerConfig.RouteServer.RouteServerClient || peer.isGlobalRib {
			pList, _ = peer.rib.ProcessPaths(pList)
		}

		if peer.isGlobalRib {
			peer.sendPathsToSiblings(pList)
		} else {
			peer.sendUpdateMsgFromPaths(pList)
		}

	case PEER_MSG_PEER_DOWN:
		for _, rf := range peer.configuredRFlist() {
			pList, _ := peer.rib.DeletePathsforPeer(m.msgData.(*table.PeerInfo), rf)
			peer.sendUpdateMsgFromPaths(pList)
		}
	}
}

func (peer *Peer) handleServerMsg(m *serverMsg) {
	switch m.msgType {
	case SRV_MSG_PEER_ADDED:
		if peer.peerConfig.RouteServer.RouteServerClient {
			d := m.msgData.(*serverMsgDataPeer)
			peer.siblings[d.address.String()] = d
			for _, rf := range peer.configuredRFlist() {
				peer.sendPathsToSiblings(peer.adjRib.GetInPathList(rf))
			}
		} else if peer.isGlobalRib {
			d := m.msgData.(*serverMsgDataPeer)
			peer.siblings[d.address.String()] = d
			for _, rf := range peer.configuredRFlist() {
				peer.sendPathsToSiblings(peer.rib.GetPathList(rf))
			}
		}
	case SRV_MSG_PEER_DELETED:
		if peer.peerConfig.RouteServer.RouteServerClient {
			d := m.msgData.(*table.PeerInfo)
			if _, ok := peer.siblings[d.Address.String()]; ok {
				delete(peer.siblings, d.Address.String())
				for _, rf := range peer.configuredRFlist() {
					pList, _ := peer.rib.DeletePathsforPeer(d, rf)
					peer.sendUpdateMsgFromPaths(pList)
				}
			} else {
				log.Warning("can not find peer: ", d.Address.String())
			}
		} else if peer.isGlobalRib {
			//TODO: delete from rib and call sendPathsToSiblings
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
			for rf, _ := range peer.rfMap {
				pathList := peer.adjRib.GetOutPathList(rf)
				peer.sendMessages(table.CreateUpdateMsgFromPaths(pathList))
			}
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

						for _, rf := range peer.configuredRFlist() {
							peer.adjRib.DropAllIn(rf)
						}
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
	localAddr := func(addrPort string) string {
		if strings.Index(addrPort, "[") == -1 {
			return strings.Split(addrPort, ":")[0]
		}
		idx := strings.LastIndex(addrPort, ":")
		return addrPort[1 : idx-1]
	}(conn.LocalAddr().String())

	peer.peerConfig.LocalAddress = net.ParseIP(localAddr)
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
	received := uint32(0)
	accepted := uint32(0)
	if f.state == bgp.BGP_FSM_ESTABLISHED {
		for _, rf := range peer.configuredRFlist() {
			advertized += uint32(peer.adjRib.GetOutCount(rf))
			received += uint32(peer.adjRib.GetInCount(rf))
			accepted += uint32(peer.adjRib.GetInCount(rf))
		}
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
		Received:                  received,
		Accepted:                  accepted,
		Advertized:                advertized,
		OutQ:                      len(peer.outgoing),
		Flops:                     s.Flops,
	}

	return json.Marshal(p)
}
