// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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
	"github.com/influxdata/influxdb/client/v2"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
	"strings"
	"time"
)

type Collector struct {
	grpcCh   chan *GrpcRequest
	url      string
	dbName   string
	interval uint64
	ch       chan watcherEvent
	client   client.Client
}

const (
	MEATUREMENT_UPDATE = "update"
	MEATUREMENT_PEER   = "peer"
	MEATUREMENT_TABLE  = "table"
)

func (c *Collector) notify(t watcherEventType) chan watcherEvent {
	if t == WATCHER_EVENT_UPDATE_MSG || t == WATCHER_EVENT_STATE_CHANGE || t == WATCHER_EVENT_ADJ_IN {
		return c.ch
	}
	return nil
}

func (c *Collector) stop() {
}

func (c *Collector) restart(filename string) error {
	return nil
}

func (c *Collector) watchingEventTypes() []watcherEventType {
	return []watcherEventType{WATCHER_EVENT_UPDATE_MSG, WATCHER_EVENT_STATE_CHANGE, WATCHER_EVENT_ADJ_IN}
}

func (c *Collector) writePoints(points []*client.Point) error {
	bp, _ := client.NewBatchPoints(client.BatchPointsConfig{
		Database:  c.dbName,
		Precision: "ms",
	})
	bp.AddPoints(points)
	return c.client.Write(bp)
}

func (c *Collector) writePeer(msg *watcherEventStateChangedMsg) error {
	var state string
	switch msg.state {
	case bgp.BGP_FSM_ESTABLISHED:
		state = "Established"
	case bgp.BGP_FSM_IDLE:
		state = "Idle"
	default:
		return fmt.Errorf("unexpected fsm state %v", msg.state)
	}

	tags := map[string]string{
		"PeerAddress": msg.peerAddress.String(),
		"PeerAS":      fmt.Sprintf("%v", msg.peerAS),
		"State":       state,
	}

	fields := map[string]interface{}{
		"PeerID": msg.peerID.String(),
	}

	pt, err := client.NewPoint(MEATUREMENT_PEER, tags, fields, msg.timestamp)
	if err != nil {
		return err
	}
	return c.writePoints([]*client.Point{pt})
}

func path2data(path *table.Path) (map[string]interface{}, map[string]string) {
	fields := map[string]interface{}{
		"ASPath": path.GetAsPath().String(),
	}
	if origin, err := path.GetOrigin(); err == nil {
		typ := "-"
		switch origin {
		case bgp.BGP_ORIGIN_ATTR_TYPE_IGP:
			typ = "i"
		case bgp.BGP_ORIGIN_ATTR_TYPE_EGP:
			typ = "e"
		case bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE:
			typ = "?"
		}
		fields["Origin"] = typ
	}
	if med, err := path.GetMed(); err == nil {
		fields["Med"] = med
	}

	var prefix, prefixLen string
	l := strings.Split(path.GetNlri().String(), "/")
	if len(l) == 2 {
		prefix = l[0]
		prefixLen = l[1]
	}
	tags := map[string]string{
		"PeerAddress": path.GetSource().Address.String(),
		"PeerAS":      fmt.Sprintf("%v", path.GetSource().AS),
		"Prefix":      prefix,
		"PrefixLen":   prefixLen,
		"NextHop":     path.GetNexthop().String(),
		"OriginAS":    fmt.Sprintf("%v", path.GetSourceAs()),
		"Timestamp":   path.GetTimestamp().String(),
	}
	return fields, tags
}

func (c *Collector) writeUpdate(msg *watcherEventUpdateMsg) error {
	if len(msg.pathList) == 0 {
		// EOR
		return nil
	}
	now := time.Now()
	points := make([]*client.Point, 0, len(msg.pathList))
	for _, path := range msg.pathList {
		fields, tags := path2data(path)
		tags["Withdraw"] = fmt.Sprintf("%v", path.IsWithdraw)
		pt, err := client.NewPoint(MEATUREMENT_UPDATE, tags, fields, now)
		if err != nil {
			return fmt.Errorf("failed to write update, %v", err)
		}
		points = append(points, pt)
	}
	return c.writePoints(points)
}

func (c *Collector) writeTable(msg *watcherEventAdjInMsg) error {
	now := time.Now()
	points := make([]*client.Point, 0, len(msg.pathList))
	for _, path := range msg.pathList {
		fields, tags := path2data(path)
		pt, err := client.NewPoint(MEATUREMENT_TABLE, tags, fields, now)
		if err != nil {
			return fmt.Errorf("failed to write table, %v", err)
		}
		points = append(points, pt)
	}
	return c.writePoints(points)
}

func (c *Collector) loop() {
	ticker := func() *time.Ticker {
		if c.interval == 0 {
			return &time.Ticker{}
		}
		return time.NewTicker(time.Second * time.Duration(c.interval))
	}()

	for {
		select {
		case <-ticker.C:
			go func() {
				ch := make(chan *GrpcResponse)
				c.grpcCh <- &GrpcRequest{
					RequestType: REQ_WATCHER_ADJ_RIB_IN,
					ResponseCh:  ch,
				}
				(<-ch).Err()
			}()
		case ev := <-c.ch:
			switch msg := ev.(type) {
			case *watcherEventUpdateMsg:
				if err := c.writeUpdate(msg); err != nil {
					log.Error(err)
				}
			case *watcherEventStateChangedMsg:
				if err := c.writePeer(msg); err != nil {
					log.Error(err)
				}
			case *watcherEventAdjInMsg:
				if err := c.writeTable(msg); err != nil {
					log.Error(err)
				}
			}
		}
	}
}

func NewCollector(grpcCh chan *GrpcRequest, url, dbName string, interval uint64) (*Collector, error) {
	c, err := client.NewHTTPClient(client.HTTPConfig{
		Addr: url,
	})
	if err != nil {
		return nil, err
	}
	collector := &Collector{
		grpcCh:   grpcCh,
		url:      url,
		dbName:   dbName,
		interval: interval,
		ch:       make(chan watcherEvent, 16),
		client:   c,
	}
	go collector.loop()
	return collector, nil
}
