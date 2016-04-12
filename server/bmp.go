// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/packet/bmp"
	"github.com/osrg/gobgp/table"
	"gopkg.in/tomb.v2"
	"net"
	"strconv"
	"time"
)

type bmpServer struct {
	conn *net.TCPConn
	host string
	typ  config.BmpRouteMonitoringPolicyType
}

type bmpConfig struct {
	config config.BmpServerConfig
	del    bool
	errCh  chan error
}

type bmpWatcher struct {
	t         tomb.Tomb
	ch        chan watcherEvent
	apiCh     chan *GrpcRequest
	newConnCh chan *net.TCPConn
	endCh     chan *net.TCPConn
	connMap   map[string]*bmpServer
	ctlCh     chan *bmpConfig
}

func (w *bmpWatcher) notify(t watcherEventType) chan watcherEvent {
	if t == WATCHER_EVENT_UPDATE_MSG || t == WATCHER_EVENT_POST_POLICY_UPDATE_MSG || t == WATCHER_EVENT_STATE_CHANGE {
		return w.ch
	}
	return nil
}

func (w *bmpWatcher) stop() {
	w.t.Kill(nil)
}

func (w *bmpWatcher) tryConnect(server *bmpServer) {
	interval := 1
	host := server.host
	for {
		log.Debug("connecting bmp server: ", host)
		conn, err := net.Dial("tcp", host)
		if err != nil {
			time.Sleep(time.Duration(interval) * time.Second)
			if interval < 30 {
				interval *= 2
			}
		} else {
			log.Info("bmp server is connected, ", host)
			w.newConnCh <- conn.(*net.TCPConn)
			break
		}
	}
}

func (w *bmpWatcher) loop() error {
	for {
		select {
		case <-w.t.Dying():
			for _, server := range w.connMap {
				if server.conn != nil {
					server.conn.Close()
				}
			}
			return nil
		case m := <-w.ctlCh:
			c := m.config
			if m.del {
				host := net.JoinHostPort(c.Address, strconv.Itoa(int(c.Port)))
				if _, y := w.connMap[host]; !y {
					m.errCh <- fmt.Errorf("bmp server %s doesn't exists", host)
					continue
				}
				conn := w.connMap[host].conn
				delete(w.connMap, host)
				conn.Close()
			} else {
				host := net.JoinHostPort(c.Address, strconv.Itoa(int(c.Port)))
				if _, y := w.connMap[host]; y {
					m.errCh <- fmt.Errorf("bmp server %s already exists", host)
					continue
				}
				server := &bmpServer{
					host: host,
					typ:  c.RouteMonitoringPolicy,
				}
				w.connMap[host] = server
				go w.tryConnect(server)
			}
			m.errCh <- nil
			close(m.errCh)
		case newConn := <-w.newConnCh:
			server, y := w.connMap[newConn.RemoteAddr().String()]
			if !y {
				log.Warnf("Can't find bmp server %s", newConn.RemoteAddr().String())
				break
			}
			i := bmp.NewBMPInitiation([]bmp.BMPTLV{})
			buf, _ := i.Serialize()
			if _, err := newConn.Write(buf); err != nil {
				log.Warnf("failed to write to bmp server %s", server.host)
				go w.tryConnect(server)
				break
			}
			req := &GrpcRequest{
				RequestType: REQ_BMP_NEIGHBORS,
				ResponseCh:  make(chan *GrpcResponse, 1),
			}
			w.apiCh <- req
			write := func(req *GrpcRequest) error {
				for res := range req.ResponseCh {
					for _, msg := range res.Data.([]*bmp.BMPMessage) {
						buf, _ = msg.Serialize()
						if _, err := newConn.Write(buf); err != nil {
							log.Warnf("failed to write to bmp server %s %s", server.host, err)
							go w.tryConnect(server)
							return err
						}
					}
				}
				return nil
			}
			if err := write(req); err != nil {
				break
			}
			if server.typ != config.BMP_ROUTE_MONITORING_POLICY_TYPE_POST_POLICY {
				req = &GrpcRequest{
					RequestType: REQ_BMP_ADJ_IN,
					ResponseCh:  make(chan *GrpcResponse, 1),
				}
				w.apiCh <- req
				if err := write(req); err != nil {
					break
				}
			}
			if server.typ != config.BMP_ROUTE_MONITORING_POLICY_TYPE_PRE_POLICY {
				req = &GrpcRequest{
					RequestType: REQ_BMP_GLOBAL,
					ResponseCh:  make(chan *GrpcResponse, 1),
				}
				w.apiCh <- req
				if err := write(req); err != nil {
					break
				}
			}
			server.conn = newConn
		case ev := <-w.ch:
			switch msg := ev.(type) {
			case *watcherEventUpdateMsg:
				info := &table.PeerInfo{
					Address: msg.peerAddress,
					AS:      msg.peerAS,
					ID:      msg.peerID,
				}
				buf, _ := bmpPeerRoute(bmp.BMP_PEER_TYPE_GLOBAL, msg.postPolicy, 0, info, msg.timestamp.Unix(), msg.payload).Serialize()
				for _, server := range w.connMap {
					if server.conn != nil {
						send := server.typ != config.BMP_ROUTE_MONITORING_POLICY_TYPE_POST_POLICY && !msg.postPolicy
						send = send || (server.typ != config.BMP_ROUTE_MONITORING_POLICY_TYPE_PRE_POLICY && msg.postPolicy)
						if send {
							_, err := server.conn.Write(buf)
							if err != nil {
								log.Warnf("failed to write to bmp server %s", server.host)
							}
						}
					}
				}
			case *watcherEventStateChangedMsg:
				var bmpmsg *bmp.BMPMessage
				info := &table.PeerInfo{
					Address: msg.peerAddress,
					AS:      msg.peerAS,
					ID:      msg.peerID,
				}
				if msg.state == bgp.BGP_FSM_ESTABLISHED {
					bmpmsg = bmpPeerUp(msg.localAddress.String(), msg.localPort, msg.peerPort, msg.sentOpen, msg.recvOpen, bmp.BMP_PEER_TYPE_GLOBAL, false, 0, info, msg.timestamp.Unix())
				} else {
					bmpmsg = bmpPeerDown(bmp.BMP_PEER_DOWN_REASON_UNKNOWN, bmp.BMP_PEER_TYPE_GLOBAL, false, 0, info, msg.timestamp.Unix())
				}
				buf, _ := bmpmsg.Serialize()
				for _, server := range w.connMap {
					if server.conn != nil {
						_, err := server.conn.Write(buf)
						if err != nil {
							log.Warnf("failed to write to bmp server %s", server.host)
						}
					}
				}
			default:
				log.Warnf("unknown watcher event")
			}
		case conn := <-w.endCh:
			host := conn.RemoteAddr().String()
			log.Debugf("bmp connection to %s killed", host)
			if _, y := w.connMap[host]; y {
				w.connMap[host].conn = nil
				go w.tryConnect(w.connMap[host])
			}
		}
	}
}

func (w *bmpWatcher) restart(string) error {
	return nil
}

func bmpPeerUp(laddr string, lport, rport uint16, sent, recv *bgp.BGPMessage, t uint8, policy bool, pd uint64, peeri *table.PeerInfo, timestamp int64) *bmp.BMPMessage {
	ph := bmp.NewBMPPeerHeader(t, policy, pd, peeri.Address.String(), peeri.AS, peeri.ID.String(), float64(timestamp))
	return bmp.NewBMPPeerUpNotification(*ph, laddr, lport, rport, sent, recv)
}

func bmpPeerDown(reason uint8, t uint8, policy bool, pd uint64, peeri *table.PeerInfo, timestamp int64) *bmp.BMPMessage {
	ph := bmp.NewBMPPeerHeader(t, policy, pd, peeri.Address.String(), peeri.AS, peeri.ID.String(), float64(timestamp))
	return bmp.NewBMPPeerDownNotification(*ph, reason, nil, []byte{})
}

func bmpPeerRoute(t uint8, policy bool, pd uint64, peeri *table.PeerInfo, timestamp int64, payload []byte) *bmp.BMPMessage {
	ph := bmp.NewBMPPeerHeader(t, policy, pd, peeri.Address.String(), peeri.AS, peeri.ID.String(), float64(timestamp))
	m := bmp.NewBMPRouteMonitoring(*ph, nil)
	body := m.Body.(*bmp.BMPRouteMonitoring)
	body.BGPUpdatePayload = payload
	return m
}

func (w *bmpWatcher) addServer(c config.BmpServerConfig) error {
	ch := make(chan error)
	w.ctlCh <- &bmpConfig{
		config: c,
		errCh:  ch,
	}
	return <-ch
}

func (w *bmpWatcher) deleteServer(c config.BmpServerConfig) error {
	ch := make(chan error)
	w.ctlCh <- &bmpConfig{
		config: c,
		del:    true,
		errCh:  ch,
	}
	return <-ch
}

func (w *bmpWatcher) watchingEventTypes() []watcherEventType {
	state := false
	pre := false
	post := false
	for _, server := range w.connMap {
		if server.conn != nil {
			state = true
			if server.typ != config.BMP_ROUTE_MONITORING_POLICY_TYPE_POST_POLICY {
				pre = true
			}
			if server.typ != config.BMP_ROUTE_MONITORING_POLICY_TYPE_PRE_POLICY {
				post = true
			}
		}
	}
	types := make([]watcherEventType, 0, 3)
	if state {
		types = append(types, WATCHER_EVENT_STATE_CHANGE)
	}
	if pre {
		types = append(types, WATCHER_EVENT_UPDATE_MSG)
	}
	if post {
		types = append(types, WATCHER_EVENT_POST_POLICY_UPDATE_MSG)
	}
	return types
}

func newBmpWatcher(grpcCh chan *GrpcRequest) (*bmpWatcher, error) {
	w := &bmpWatcher{
		ch:        make(chan watcherEvent),
		apiCh:     grpcCh,
		newConnCh: make(chan *net.TCPConn),
		endCh:     make(chan *net.TCPConn),
		connMap:   make(map[string]*bmpServer),
		ctlCh:     make(chan *bmpConfig),
	}
	w.t.Go(w.loop)
	return w, nil
}
