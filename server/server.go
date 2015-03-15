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
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"net"
	"os"
	"strconv"
	"strings"
)

type serverMsgType int

const (
	_ serverMsgType = iota
	SRV_MSG_PEER_ADDED
	SRV_MSG_PEER_DELETED
	SRV_MSG_API
)

type serverMsg struct {
	msgType serverMsgType
	msgData interface{}
}

type serverMsgDataPeer struct {
	peerMsgCh chan *peerMsg
	address   net.IP
}

type peerMapInfo struct {
	peer        *Peer
	serverMsgCh chan *serverMsg
	peerMsgCh   chan *peerMsg
	peerMsgData *serverMsgDataPeer
}

type BgpServer struct {
	bgpConfig     config.Bgp
	globalTypeCh  chan config.Global
	addedPeerCh   chan config.Neighbor
	deletedPeerCh chan config.Neighbor
	RestReqCh     chan *api.RestRequest
	listenPort    int
	peerMap       map[string]peerMapInfo
	globalRib     *Peer
}

func NewBgpServer(port int) *BgpServer {
	b := BgpServer{}
	b.globalTypeCh = make(chan config.Global)
	b.addedPeerCh = make(chan config.Neighbor)
	b.deletedPeerCh = make(chan config.Neighbor)
	b.RestReqCh = make(chan *api.RestRequest, 1)
	b.listenPort = port
	return &b
}

// avoid mapped IPv6 address
func listenAndAccept(proto string, port int, ch chan *net.TCPConn) (*net.TCPListener, error) {
	service := ":" + strconv.Itoa(port)
	addr, _ := net.ResolveTCPAddr(proto, service)

	l, err := net.ListenTCP(proto, addr)
	if err != nil {
		log.Info(err)
		return nil, err
	}
	go func() {
		for {
			conn, err := l.AcceptTCP()
			if err != nil {
				log.Info(err)
				continue
			}
			// TODO: check ebgp or not
			ttl := 1
			SetTcpTTLSockopts(conn, ttl)
			ch <- conn
		}
	}()

	return l, nil
}

func generateLocalNeighborConf(g *config.Global) config.Neighbor {
	return config.Neighbor{
		NeighborAddress: g.RouterId,
		AfiSafiList: g.AfiSafiList,
	}
}

func (server *BgpServer) Serve() {
	g := <-server.globalTypeCh
	server.bgpConfig.Global = g

	globalSch := make(chan *serverMsg, 8)
	globalPch := make(chan *peerMsg, 4096)
	neighConf := generateLocalNeighborConf(&g)
	server.globalRib = NewPeer(g, neighConf, globalSch, globalPch, nil, true)

	listenerMap := make(map[string]*net.TCPListener)
	acceptCh := make(chan *net.TCPConn)
	l4, err1 := listenAndAccept("tcp4", server.listenPort, acceptCh)
	listenerMap["tcp4"] = l4
	l6, err2 := listenAndAccept("tcp6", server.listenPort, acceptCh)
	listenerMap["tcp6"] = l6
	if err1 != nil && err2 != nil {
		log.Fatal("can't listen either v4 and v6")
		os.Exit(1)
	}

	listenFile := func(addr net.IP) *os.File {
		var l *net.TCPListener
		if addr.To4() != nil {
			l = listenerMap["tcp4"]
		} else {
			l = listenerMap["tcp6"]
		}
		f, _ := l.File()
		return f
	}

	server.peerMap = make(map[string]peerMapInfo)
	for {
		select {
		case conn := <-acceptCh:
			remoteAddr := func(addrPort string) string {
				if strings.Index(addrPort, "[") == -1 {
					return strings.Split(addrPort, ":")[0]
				}
				idx := strings.LastIndex(addrPort, ":")
				return addrPort[1 : idx-1]
			}(conn.RemoteAddr().String())
			info, found := server.peerMap[remoteAddr]
			if found {
				log.Info("accepted a new passive connection from ", remoteAddr)
				info.peer.PassConn(conn)
			} else {
				log.Info("can't find configuration for a new passive connection from ", remoteAddr)
				conn.Close()
			}
		case peer := <-server.addedPeerCh:
			addr := peer.NeighborAddress.String()
			f := listenFile(peer.NeighborAddress)
			SetTcpMD5SigSockopts(int(f.Fd()), addr, peer.AuthPassword)
			sch := make(chan *serverMsg, 8)
			pch := make(chan *peerMsg, 4096)
			var l []*serverMsgDataPeer
			if peer.RouteServer.RouteServerClient {
				l = make([]*serverMsgDataPeer, len(server.peerMap))
				i := 0
				for _, v := range server.peerMap {
					l[i] = v.peerMsgData
					i++
				}
			} else {
				globalRib := &serverMsgDataPeer{
					address:   server.bgpConfig.Global.RouterId,
					peerMsgCh: globalPch,
				}
				l = []*serverMsgDataPeer{globalRib}
			}
			p := NewPeer(server.bgpConfig.Global, peer, sch, pch, l, false)
			d := &serverMsgDataPeer{
				address:   peer.NeighborAddress,
				peerMsgCh: pch,
			}
			msg := &serverMsg{
				msgType: SRV_MSG_PEER_ADDED,
				msgData: d,
			}
			sendServerMsgToAll(server.peerMap, msg)
			globalSch <- msg

			server.peerMap[peer.NeighborAddress.String()] = peerMapInfo{
				peer:        p,
				serverMsgCh: sch,
				peerMsgData: d,
			}
		case peer := <-server.deletedPeerCh:
			addr := peer.NeighborAddress.String()
			f := listenFile(peer.NeighborAddress)
			SetTcpMD5SigSockopts(int(f.Fd()), addr, "")
			info, found := server.peerMap[addr]
			if found {
				log.Info("Delete a peer configuration for ", addr)
				info.peer.Stop()
				delete(server.peerMap, addr)
				msg := &serverMsg{
					msgType: SRV_MSG_PEER_DELETED,
					msgData: info.peer.peerInfo,
				}
				sendServerMsgToAll(server.peerMap, msg)
			} else {
				log.Info("Can't delete a peer configuration for ", addr)
			}
		case restReq := <-server.RestReqCh:
			server.handleRest(restReq)
		}
	}
}

func sendServerMsgToAll(peerMap map[string]peerMapInfo, msg *serverMsg) {
	for _, info := range peerMap {
		info.serverMsgCh <- msg
	}
}

func (server *BgpServer) SetGlobalType(g config.Global) {
	server.globalTypeCh <- g
}

func (server *BgpServer) PeerAdd(peer config.Neighbor) {
	server.addedPeerCh <- peer
}

func (server *BgpServer) PeerDelete(peer config.Neighbor) {
	server.deletedPeerCh <- peer
}

func (server *BgpServer) handleRest(restReq *api.RestRequest) {
	switch restReq.RequestType {
	case api.REQ_NEIGHBORS:
		result := &api.RestResponse{}
		peerList := make([]*Peer, 0)
		for _, info := range server.peerMap {
			peerList = append(peerList, info.peer)
		}
		j, _ := json.Marshal(peerList)
		result.Data = j
		restReq.ResponseCh <- result
		close(restReq.ResponseCh)

	case api.REQ_NEIGHBOR:

		remoteAddr := restReq.RemoteAddr
		result := &api.RestResponse{}
		info, found := server.peerMap[remoteAddr]
		if found {
			j, _ := json.Marshal(info.peer)
			result.Data = j
		} else {
			result.ResponseErr = fmt.Errorf("Neighbor that has %v does not exist.", remoteAddr)
		}
		restReq.ResponseCh <- result
		close(restReq.ResponseCh)
	case api.REQ_LOCAL_RIB, api.REQ_NEIGHBOR_SHUTDOWN, api.REQ_NEIGHBOR_RESET,
		api.REQ_NEIGHBOR_SOFT_RESET, api.REQ_NEIGHBOR_SOFT_RESET_IN, api.REQ_NEIGHBOR_SOFT_RESET_OUT,
		api.REQ_ADJ_RIB_IN, api.REQ_ADJ_RIB_OUT,
		api.REQ_NEIGHBOR_ENABLE, api.REQ_NEIGHBOR_DISABLE:

		remoteAddr := restReq.RemoteAddr
		result := &api.RestResponse{}
		info, found := server.peerMap[remoteAddr]
		if found {
			msg := &serverMsg{
				msgType: SRV_MSG_API,
				msgData: restReq,
			}
			info.peer.serverMsgCh <- msg
		} else {
			result.ResponseErr = fmt.Errorf("Neighbor that has %v does not exist.", remoteAddr)
			restReq.ResponseCh <- result
			close(restReq.ResponseCh)
		}
	}
}
