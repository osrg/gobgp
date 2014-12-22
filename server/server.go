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
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	_ = iota
	PEER_MSG_NEW
	PEER_MSG_PATH
	PEER_MSG_DOWN
)

type message struct {
	src   string
	dst   string
	event int
	data  interface{}
}

type BgpServer struct {
	bgpConfig     config.BgpType
	globalTypeCh  chan config.GlobalType
	addedPeerCh   chan config.NeighborType
	deletedPeerCh chan config.NeighborType
	RestReqCh     chan *api.RestRequest
	listenPort    int
	peerMap       map[string]*Peer
}

func NewBgpServer(port int) *BgpServer {
	b := BgpServer{}
	b.globalTypeCh = make(chan config.GlobalType)
	b.addedPeerCh = make(chan config.NeighborType)
	b.deletedPeerCh = make(chan config.NeighborType)
	b.RestReqCh = make(chan *api.RestRequest, 1)
	b.listenPort = port
	return &b
}

func (server *BgpServer) Serve() {
	server.bgpConfig.Global = <-server.globalTypeCh

	service := ":" + strconv.Itoa(server.listenPort)
	addr, _ := net.ResolveTCPAddr("tcp", service)

	l, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	acceptCh := make(chan *net.TCPConn)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				fmt.Println(err)
				continue
			}
			acceptCh <- conn.(*net.TCPConn)
		}
	}()

	server.peerMap = make(map[string]*Peer)
	broadcastCh := make(chan *message)
	for {
		f, _ := l.File()
		select {
		case conn := <-acceptCh:
			fmt.Println(conn)
			remoteAddr := strings.Split(conn.RemoteAddr().String(), ":")[0]
			peer, found := server.peerMap[remoteAddr]
			if found {
				fmt.Println("found neighbor", remoteAddr)
				peer.PassConn(conn)
			} else {
				fmt.Println("can't found neighbor", remoteAddr)
				conn.Close()
			}
		case peer := <-server.addedPeerCh:
			fmt.Println(peer)
			addr := peer.NeighborAddress.String()
			SetTcpMD5SigSockopts(int(f.Fd()), addr, peer.AuthPassword)
			p := NewPeer(server.bgpConfig.Global, peer, broadcastCh)
			server.peerMap[peer.NeighborAddress.String()] = p
		case peer := <-server.deletedPeerCh:
			fmt.Println(peer)
			addr := peer.NeighborAddress.String()
			SetTcpMD5SigSockopts(int(f.Fd()), addr, "")
			p, found := server.peerMap[addr]
			if found {
				fmt.Println("found neighbor", addr)
				p.Stop()
				delete(server.peerMap, addr)
			} else {
				fmt.Println("can't found neighbor", addr)
			}
		case restReq := <-server.RestReqCh:
			server.handleRest(restReq)

		case msg := <-broadcastCh:
			server.broadcast(msg)
		}
	}
}

func (server *BgpServer) SetGlobalType(g config.GlobalType) {
	server.globalTypeCh <- g
}

func (server *BgpServer) PeerAdd(peer config.NeighborType) {
	server.addedPeerCh <- peer
}

func (server *BgpServer) PeerDelete(peer config.NeighborType) {
	server.deletedPeerCh <- peer
}

func (server *BgpServer) broadcast(msg *message) {
	for key := range server.peerMap {
		if key == msg.src {
			continue
		}
		if msg.dst == "" || msg.dst == key {
			peer := server.peerMap[key]
			peer.SendMessage(msg)
		}
	}
}

func (server *BgpServer) handleRest(restReq *api.RestRequest) {
	defer close(restReq.ResponseCh)
	switch restReq.RequestType {
	case api.REQ_NEIGHBOR: // get neighbor state

		remoteAddr := restReq.RemoteAddr
		result := &api.RestResponseNeighbor{}
		peer, found := server.peerMap[remoteAddr]
		if found {
			c := peer.peerConfig
			result.NeighborState = c.BgpNeighborCommonState.State
			result.RemoteAddr = c.NeighborAddress.String()
			result.RemoteAs = c.PeerAs
		} else {
			result.ResponseErr = fmt.Errorf("Neighbor that has %v does not exist.", remoteAddr)
		}
		restReq.ResponseCh <- result
	}
}
