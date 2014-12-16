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
	"github.com/osrg/gobgp/io"
	"net"
	"os"
	"strconv"
	"strings"
)

type BgpServer struct {
	bgpConfig     config.BgpType
	globalTypeCh  chan config.GlobalType
	addedPeerCh   chan config.NeighborType
	deletedPeerCh chan config.NeighborType
	listenPort    int
}

func NewBgpServer(port int) *BgpServer {
	b := BgpServer{}
	b.globalTypeCh = make(chan config.GlobalType)
	b.addedPeerCh = make(chan config.NeighborType)
	b.deletedPeerCh = make(chan config.NeighborType)
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

	peerMap := make(map[string]*Peer)
	for {
		f, _ := l.File()
		select {
		case conn := <-acceptCh:
			fmt.Println(conn)
			remoteAddr := strings.Split(conn.RemoteAddr().String(), ":")[0]
			peer, found := peerMap[remoteAddr]
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
			io.SetTcpMD5SigSockopts(int(f.Fd()), addr, peer.AuthPassword)
			p := NewPeer(server.bgpConfig.Global, peer)
			peerMap[peer.NeighborAddress.String()] = p
		case peer := <-server.deletedPeerCh:
			fmt.Println(peer)
			addr := peer.NeighborAddress.String()
			io.SetTcpMD5SigSockopts(int(f.Fd()), addr, "")
			p, found := peerMap[addr]
			if found {
				fmt.Println("found neighbor", addr)
				p.Stop()
				delete(peerMap, addr)
			} else {
				fmt.Println("can't found neighbor", addr)
			}
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
