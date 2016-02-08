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
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"github.com/satori/go.uuid"
	"gopkg.in/tomb.v2"
	"net"
	"strconv"
	"time"
)

type bmpServer interface {
	Write([]byte) (int, error)
	Close() error
	Type() config.BmpRouteMonitoringPolicyType
	Name() string
}

type bmpTcpServer struct {
	conn         *net.TCPConn
	host         string
	typ          config.BmpRouteMonitoringPolicyType
	reconnecting bool
}

func (s *bmpTcpServer) Write(p []byte) (int, error) {
	if s.conn != nil {
		return s.conn.Write(p)
	}
	return 0, nil
}

func (s *bmpTcpServer) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *bmpTcpServer) Type() config.BmpRouteMonitoringPolicyType {
	return s.typ
}

func (s *bmpTcpServer) Name() string {
	return s.host
}

type bmpGrpcServer struct {
	req  *GrpcRequest
	name string
}

func (s *bmpGrpcServer) Write(p []byte) (int, error) {
	select {
	case <-s.req.EndCh:
		return 0, fmt.Errorf("request ended")
	default:
	}
	s.req.ResponseCh <- &GrpcResponse{Data: &api.BmpMessage{Data: p}}
	return len(p), nil
}

func (s *bmpGrpcServer) Close() error {
	close(s.req.ResponseCh)
	return nil
}

func (s *bmpGrpcServer) Type() config.BmpRouteMonitoringPolicyType {
	return config.IntToBmpRouteMonitoringPolicyTypeMap[int(s.req.Data.(*api.MonitorBmpArguments).Type)]
}

func (s *bmpGrpcServer) Name() string {
	return s.name
}

func newBmpGrpcServer(req *GrpcRequest) *bmpGrpcServer {
	return &bmpGrpcServer{
		req:  req,
		name: uuid.NewV4().String(),
	}
}

type bmpConfig struct {
	config config.BmpServerConfig
	del    bool
	errCh  chan error
}

type bmpWatcher struct {
	t           tomb.Tomb
	ch          chan watcherEvent
	apiCh       chan *GrpcRequest
	newServerCh chan bmpServer
	endCh       chan bmpServer
	connMap     map[string]bmpServer
	ctlCh       chan *bmpConfig
	reqCh       chan *GrpcRequest
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

func (w *bmpWatcher) tryConnect(server *bmpTcpServer) {
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
			server.conn = conn.(*net.TCPConn)
			go func() {
				buf := make([]byte, 1)
				for {
					_, err := conn.Read(buf)
					if err != nil {
						w.endCh <- server
						return
					}
				}
			}()
			w.newServerCh <- server
			break
		}
	}
}

func (w *bmpWatcher) loop() error {
	for {
		select {
		case <-w.t.Dying():
			for _, server := range w.connMap {
				server.Close()
			}
			return nil
		case req := <-w.reqCh:
			s := newBmpGrpcServer(req)
			w.connMap[s.Name()] = s
			log.Debugf("new grpc bmp monitor request: %s", s.Name())
			go func() { w.newServerCh <- s }()
		case m := <-w.ctlCh:
			c := m.config
			if m.del {
				host := net.JoinHostPort(c.Address, strconv.Itoa(int(c.Port)))
				if _, y := w.connMap[host]; !y {
					m.errCh <- fmt.Errorf("bmp server %s doesn't exists", host)
					continue
				}
				w.connMap[host].Close()
				delete(w.connMap, host)
			} else {
				host := net.JoinHostPort(c.Address, strconv.Itoa(int(c.Port)))
				if _, y := w.connMap[host]; y {
					m.errCh <- fmt.Errorf("bmp server %s already exists", host)
					continue
				}
				server := &bmpTcpServer{
					host: host,
					typ:  c.RouteMonitoringPolicy,
				}
				w.connMap[host] = server
				go w.tryConnect(server)
			}
			m.errCh <- nil
			close(m.errCh)
		case server := <-w.newServerCh:
			if s, y := server.(*bmpTcpServer); y {
				s.reconnecting = false
			}
			i := bgp.NewBMPInitiation([]bgp.BMPTLV{})
			buf, _ := i.Serialize()
			_, err := server.Write(buf)
			if err != nil {
				log.Warnf("failed to write to bmp server %s %s", server.Name(), err)
				go func() { w.endCh <- server }()
				break
			}
			req := &GrpcRequest{
				RequestType: REQ_BMP_NEIGHBORS,
				ResponseCh:  make(chan *GrpcResponse, 1),
			}
			w.apiCh <- req
			write := func(req *GrpcRequest) error {
				for res := range req.ResponseCh {
					for _, msg := range res.Data.([]*bgp.BMPMessage) {
						buf, _ = msg.Serialize()
						_, err := server.Write(buf)
						if err != nil {
							log.Warnf("failed to write to bmp server %s %s", server.Name(), err)
							go func() { w.endCh <- server }()
							return err
						}
					}
				}
				return nil
			}
			if write(req) != nil {
				break
			}
			if server.Type() != config.BMP_ROUTE_MONITORING_POLICY_TYPE_POST_POLICY {
				req = &GrpcRequest{
					RequestType: REQ_BMP_ADJ_IN,
					ResponseCh:  make(chan *GrpcResponse, 1),
				}
				w.apiCh <- req
				if write(req) != nil {
					break
				}
			}
			if server.Type() != config.BMP_ROUTE_MONITORING_POLICY_TYPE_PRE_POLICY {
				req = &GrpcRequest{
					RequestType: REQ_BMP_GLOBAL,
					ResponseCh:  make(chan *GrpcResponse, 1),
				}
				w.apiCh <- req
				if write(req) != nil {
					break
				}
			}
		case ev := <-w.ch:
			switch msg := ev.(type) {
			case *watcherEventUpdateMsg:
				info := &table.PeerInfo{
					Address: msg.peerAddress,
					AS:      msg.peerAS,
					ID:      msg.peerID,
				}
				buf, _ := bmpPeerRoute(bgp.BMP_PEER_TYPE_GLOBAL, msg.postPolicy, 0, info, msg.timestamp.Unix(), msg.payload).Serialize()
				for _, server := range w.connMap {
					send := server.Type() != config.BMP_ROUTE_MONITORING_POLICY_TYPE_POST_POLICY && !msg.postPolicy
					send = send || (server.Type() != config.BMP_ROUTE_MONITORING_POLICY_TYPE_PRE_POLICY && msg.postPolicy)
					if send {
						_, err := server.Write(buf)
						if err != nil {
							log.Warnf("failed to write to bmp server %s", server.Name())
							go func(s bmpServer) { w.endCh <- s }(server)
						}
					}
				}
			case *watcherEventStateChangedMsg:
				var bmpmsg *bgp.BMPMessage
				info := &table.PeerInfo{
					Address: msg.peerAddress,
					AS:      msg.peerAS,
					ID:      msg.peerID,
				}
				if msg.state == bgp.BGP_FSM_ESTABLISHED {
					bmpmsg = bmpPeerUp(msg.localAddress.String(), msg.localPort, msg.peerPort, msg.sentOpen, msg.recvOpen, bgp.BMP_PEER_TYPE_GLOBAL, false, 0, info, msg.timestamp.Unix())
				} else {
					bmpmsg = bmpPeerDown(bgp.BMP_PEER_DOWN_REASON_UNKNOWN, bgp.BMP_PEER_TYPE_GLOBAL, false, 0, info, msg.timestamp.Unix())
				}
				buf, _ := bmpmsg.Serialize()
				for _, server := range w.connMap {
					if _, err := server.Write(buf); err != nil {
						log.Warnf("failed to write to bmp server %s", server.Name())
						go func(s bmpServer) { w.endCh <- s }(server)
					}
				}
			default:
				log.Warnf("unknown watcher event")
			}
		case server := <-w.endCh:
			switch s := server.(type) {
			case *bmpTcpServer:
				if !s.reconnecting {
					log.Debugf("bmp connection to %s killed", s.Name())
					s.reconnecting = true
					s.conn.Close()
					s.conn = nil
					go w.tryConnect(s)
				}
			case *bmpGrpcServer:
				if _, y := w.connMap[s.Name()]; y {
					log.Debugf("grpc monitor bmp request %s killed", s.Name())
					s.Close()
					delete(w.connMap, s.Name())
				}
			}
		}
	}
}

func (w *bmpWatcher) restart(string) error {
	return nil
}

func bmpPeerUp(laddr string, lport, rport uint16, sent, recv *bgp.BGPMessage, t uint8, policy bool, pd uint64, peeri *table.PeerInfo, timestamp int64) *bgp.BMPMessage {
	ph := bgp.NewBMPPeerHeader(t, policy, pd, peeri.Address.String(), peeri.AS, peeri.ID.String(), float64(timestamp))
	return bgp.NewBMPPeerUpNotification(*ph, laddr, lport, rport, sent, recv)
}

func bmpPeerDown(reason uint8, t uint8, policy bool, pd uint64, peeri *table.PeerInfo, timestamp int64) *bgp.BMPMessage {
	ph := bgp.NewBMPPeerHeader(t, policy, pd, peeri.Address.String(), peeri.AS, peeri.ID.String(), float64(timestamp))
	return bgp.NewBMPPeerDownNotification(*ph, reason, nil, []byte{})
}

func bmpPeerRoute(t uint8, policy bool, pd uint64, peeri *table.PeerInfo, timestamp int64, payload []byte) *bgp.BMPMessage {
	ph := bgp.NewBMPPeerHeader(t, policy, pd, peeri.Address.String(), peeri.AS, peeri.ID.String(), float64(timestamp))
	m := bgp.NewBMPRouteMonitoring(*ph, nil)
	body := m.Body.(*bgp.BMPRouteMonitoring)
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

func (w *bmpWatcher) addRequest(req *GrpcRequest) {
	w.reqCh <- req
}

func (w *bmpWatcher) watchingEventTypes() []watcherEventType {
	state := false
	pre := false
	post := false
	for _, server := range w.connMap {
		state = true
		if server.Type() != config.BMP_ROUTE_MONITORING_POLICY_TYPE_POST_POLICY {
			pre = true
		}
		if server.Type() != config.BMP_ROUTE_MONITORING_POLICY_TYPE_PRE_POLICY {
			post = true
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
		ch:          make(chan watcherEvent),
		apiCh:       grpcCh,
		newServerCh: make(chan bmpServer),
		endCh:       make(chan bmpServer),
		connMap:     make(map[string]bmpServer),
		ctlCh:       make(chan *bmpConfig),
		reqCh:       make(chan *GrpcRequest),
	}
	w.t.Go(w.loop)
	return w, nil
}
