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
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"net"
	"strconv"
	"time"
)

type broadcastBMPMsg struct {
	ch      chan *broadcastBMPMsg
	msgList []*bgp.BMPMessage
	conn    *net.TCPConn
}

func (m *broadcastBMPMsg) send() {
	m.ch <- m
}

type bmpServer struct {
	conn *net.TCPConn
	host string
}

type bmpClient struct {
	ch     chan *broadcastBMPMsg
	connCh chan *bmpConn
}

func newBMPClient(conf config.BmpServers, connCh chan *bmpConn) (*bmpClient, error) {
	b := &bmpClient{}
	if len(conf.BmpServerList) == 0 {
		return b, nil
	}

	b.ch = make(chan *broadcastBMPMsg)
	b.connCh = connCh

	endCh := make(chan *net.TCPConn)

	tryConnect := func(host string) {
		interval := 1
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
				go func() {
					buf := make([]byte, 1)
					for {
						_, err := conn.Read(buf)
						if err != nil {
							endCh <- conn.(*net.TCPConn)
							return
						}
					}
				}()
				connCh <- &bmpConn{
					conn: conn.(*net.TCPConn),
					host: host,
				}
				break
			}
		}
	}

	for _, c := range conf.BmpServerList {
		b := c.Config
		go tryConnect(net.JoinHostPort(b.Address, strconv.Itoa(int(b.Port))))
	}

	go func() {
		connMap := make(map[string]*net.TCPConn)
		for {
			select {
			case m := <-b.ch:
				if m.conn != nil {
					i := bgp.NewBMPInitiation([]bgp.BMPTLV{})
					buf, _ := i.Serialize()
					_, err := m.conn.Write(buf)
					if err == nil {
						connMap[m.conn.RemoteAddr().String()] = m.conn
					}
				}

				for host, conn := range connMap {
					if m.conn != nil && m.conn != conn {
						continue
					}

					for _, msg := range m.msgList {
						if msg.Header.Type == bgp.BMP_MSG_ROUTE_MONITORING {
							c := func() *config.BmpServerConfig {
								for _, c := range conf.BmpServerList {
									b := &c.Config
									if host == net.JoinHostPort(b.Address, strconv.Itoa(int(b.Port))) {
										return b
									}
								}
								return nil
							}()
							if c == nil {
								log.Fatal(host)
							}
							ph := msg.PeerHeader
							switch c.RouteMonitoringPolicy {
							case config.BMP_ROUTE_MONITORING_POLICY_TYPE_PRE_POLICY:
								if ph.IsPostPolicy != false {
									continue
								}
							case config.BMP_ROUTE_MONITORING_POLICY_TYPE_POST_POLICY:
								if ph.IsPostPolicy != true {
									continue
								}
							}

						}
						b, _ := msg.Serialize()
						if _, err := conn.Write(b); err != nil {
							break
						}
					}
				}
			case conn := <-endCh:
				host := conn.RemoteAddr().String()
				log.Debugf("bmp connection to %s killed", host)
				delete(connMap, host)
				go tryConnect(host)
			}
		}
	}()

	return b, nil
}

func (c *bmpClient) send() chan *broadcastBMPMsg {
	return c.ch
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
