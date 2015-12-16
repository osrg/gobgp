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

type bmpConn struct {
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

	tryConnect := func(host string) {
		for {
			conn, err := net.Dial("tcp", host)
			if err != nil {
				time.Sleep(30 * time.Second)
			} else {
				log.Info("bmp server is connected, ", host)
				connCh <- &bmpConn{
					conn: conn.(*net.TCPConn),
					host: host,
				}
				break
			}
		}
	}

	for _, c := range conf.BmpServerList {
		b := c.BmpServerConfig
		go tryConnect(net.JoinHostPort(b.Address.String(), strconv.Itoa(int(b.Port))))
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
									b := &c.BmpServerConfig
									if host == net.JoinHostPort(b.Address.String(), strconv.Itoa(int(b.Port))) {
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
						_, err := conn.Write(b)
						if err != nil {
							delete(connMap, host)
							go tryConnect(host)
							break
						}
					}
				}
			}
		}
	}()

	return b, nil
}

func (c *bmpClient) send() chan *broadcastBMPMsg {
	return c.ch
}

func bmpPeerUp(laddr string, lport, rport uint16, sent, recv *bgp.BGPMessage, t int, policy bool, pd uint64, peeri *table.PeerInfo, timestamp int64) *bgp.BMPMessage {
	ph := bgp.NewBMPPeerHeader(uint8(t), policy, pd, peeri.Address.String(), peeri.AS, peeri.LocalID.String(), float64(timestamp))
	return bgp.NewBMPPeerUpNotification(*ph, laddr, lport, rport, sent, recv)
}

func bmpPeerDown(reason uint8, t int, policy bool, pd uint64, peeri *table.PeerInfo, timestamp int64) *bgp.BMPMessage {
	ph := bgp.NewBMPPeerHeader(uint8(t), policy, pd, peeri.Address.String(), peeri.AS, peeri.LocalID.String(), float64(timestamp))
	return bgp.NewBMPPeerDownNotification(*ph, reason, nil, []byte{})
}

func bmpPeerRoute(t int, policy bool, pd uint64, peeri *table.PeerInfo, timestamp int64, payload []byte) *bgp.BMPMessage {
	ph := bgp.NewBMPPeerHeader(uint8(t), policy, pd, peeri.Address.String(), peeri.AS, peeri.LocalID.String(), float64(timestamp))
	m := bgp.NewBMPRouteMonitoring(*ph, nil)
	body := m.Body.(*bgp.BMPRouteMonitoring)
	body.BGPUpdatePayload = payload
	return m
}
