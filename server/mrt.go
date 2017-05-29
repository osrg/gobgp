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
	"bytes"
	"fmt"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/packet/mrt"
	"github.com/osrg/gobgp/table"
)

const (
	MIN_ROTATION_INTERVAL = 60
	MIN_DUMP_INTERVAL     = 60
)

type mrtWriter struct {
	dead             chan struct{}
	s                *BgpServer
	filename         string
	tablename        string
	file             *os.File
	rotationInterval uint64
	dumpInterval     uint64
	dumpType         config.MrtType
}

func (m *mrtWriter) Stop() {
	close(m.dead)
}

func (m *mrtWriter) loop() error {
	ops := []WatchOption{}
	switch m.dumpType {
	case config.MRT_TYPE_UPDATES:
		ops = append(ops, WatchUpdate(false))
	case config.MRT_TYPE_TABLE:
		if len(m.tablename) > 0 {
			ops = append(ops, WatchTableName(m.tablename))
		}
	}
	w := m.s.Watch(ops...)
	rotator := func() *time.Ticker {
		if m.rotationInterval == 0 {
			return &time.Ticker{}
		}
		return time.NewTicker(time.Second * time.Duration(m.rotationInterval))
	}()
	dump := func() *time.Ticker {
		if m.dumpInterval == 0 {
			return &time.Ticker{}
		}
		return time.NewTicker(time.Second * time.Duration(m.dumpInterval))
	}()

	defer func() {
		if m.file != nil {
			m.file.Close()
		}
		if m.rotationInterval != 0 {
			rotator.Stop()
		}
		if m.dumpInterval != 0 {
			dump.Stop()
		}
		w.Stop()
	}()

	for {
		serialize := func(ev WatchEvent) []*mrt.MRTMessage {
			msg := make([]*mrt.MRTMessage, 0, 1)
			switch m := ev.(type) {
			case *WatchEventUpdate:
				subtype := mrt.MESSAGE_AS4
				mp := mrt.NewBGP4MPMessage(m.PeerAS, m.LocalAS, 0, m.PeerAddress.String(), m.LocalAddress.String(), m.FourBytesAs, nil)
				mp.BGPMessagePayload = m.Payload
				if m.FourBytesAs == false {
					subtype = mrt.MESSAGE
				}
				if bm, err := mrt.NewMRTMessage(uint32(m.Timestamp.Unix()), mrt.BGP4MP, subtype, mp); err != nil {
					log.WithFields(log.Fields{
						"Topic": "mrt",
						"Data":  m,
						"Error": err,
					}).Warn("Failed to create MRT message in serialize()")
				} else {
					msg = append(msg, bm)
				}
			case *WatchEventTable:
				t := uint32(time.Now().Unix())
				peers := make([]*mrt.Peer, 0, len(m.Neighbor))
				for _, pconf := range m.Neighbor {
					peers = append(peers, mrt.NewPeer(pconf.State.RemoteRouterId, pconf.Config.NeighborAddress, pconf.Config.PeerAs, true))
				}
				if bm, err := mrt.NewMRTMessage(t, mrt.TABLE_DUMPv2, mrt.PEER_INDEX_TABLE, mrt.NewPeerIndexTable(m.RouterId, "", peers)); err != nil {
					break
				} else {
					msg = append(msg, bm)
				}

				idx := func(p *table.Path) uint16 {
					for i, pconf := range m.Neighbor {
						if p.GetSource().Address.String() == pconf.Config.NeighborAddress {
							return uint16(i)
						}
					}
					return uint16(len(m.Neighbor))
				}

				subtype := func(p *table.Path) mrt.MRTSubTypeTableDumpv2 {
					switch p.GetRouteFamily() {
					case bgp.RF_IPv4_UC:
						return mrt.RIB_IPV4_UNICAST
					case bgp.RF_IPv4_MC:
						return mrt.RIB_IPV4_MULTICAST
					case bgp.RF_IPv6_UC:
						return mrt.RIB_IPV6_UNICAST
					case bgp.RF_IPv6_MC:
						return mrt.RIB_IPV6_MULTICAST
					}
					return mrt.RIB_GENERIC
				}

				seq := uint32(0)
				for _, pathList := range m.PathList {
					entries := make([]*mrt.RibEntry, 0, len(pathList))
					for _, path := range pathList {
						if path.IsLocal() {
							continue
						}
						entries = append(entries, mrt.NewRibEntry(idx(path), uint32(path.GetTimestamp().Unix()), 0, path.GetPathAttrs()))
					}
					if len(entries) > 0 {
						bm, _ := mrt.NewMRTMessage(t, mrt.TABLE_DUMPv2, subtype(pathList[0]), mrt.NewRib(seq, pathList[0].GetNlri(), entries))
						msg = append(msg, bm)
						seq++
					}
				}
			}
			return msg
		}

		drain := func(ev WatchEvent) {
			events := make([]WatchEvent, 0, 1+len(w.Event()))
			if ev != nil {
				events = append(events, ev)
			}

			for len(w.Event()) > 0 {
				events = append(events, <-w.Event())
			}

			w := func(buf []byte) {
				if _, err := m.file.Write(buf); err == nil {
					m.file.Sync()
				} else {
					log.WithFields(log.Fields{
						"Topic": "mrt",
						"Error": err,
					}).Warn("Can't write to destination MRT file")
				}
			}

			var b bytes.Buffer
			for _, e := range events {
				for _, m := range serialize(e) {
					if buf, err := m.Serialize(); err != nil {
						log.WithFields(log.Fields{
							"Topic": "mrt",
							"Data":  e,
							"Error": err,
						}).Warn("Failed to serialize event")
					} else {
						b.Write(buf)
						if b.Len() > 1*1000*1000 {
							w(b.Bytes())
							b.Reset()
						}
					}
				}
			}
			if b.Len() > 0 {
				w(b.Bytes())
			}
		}
		rotate := func() {
			m.file.Close()
			file, err := mrtFileOpen(m.filename, m.rotationInterval)
			if err == nil {
				m.file = file
			} else {
				log.WithFields(log.Fields{
					"Topic": "mrt",
					"Error": err,
				}).Warn("can't rotate MRT file")
			}
		}

		select {
		case <-m.dead:
			drain(nil)
			return nil
		case e := <-w.Event():
			drain(e)
			if m.dumpType == config.MRT_TYPE_TABLE && m.rotationInterval != 0 {
				rotate()
			}
		case <-rotator.C:
			if m.dumpType == config.MRT_TYPE_UPDATES {
				rotate()
			} else {
				w.Generate(WATCH_EVENT_TYPE_TABLE)
			}
		case <-dump.C:
			w.Generate(WATCH_EVENT_TYPE_TABLE)
		}
	}
}

func mrtFileOpen(filename string, interval uint64) (*os.File, error) {
	realname := filename
	if interval != 0 {
		realname = time.Now().Format(filename)
	}
	log.WithFields(log.Fields{
		"Topic":         "mrt",
		"Filename":      realname,
		"Dump Interval": interval,
	}).Debug("Setting new MRT destination file")

	i := len(realname)
	for i > 0 && os.IsPathSeparator(realname[i-1]) {
		// skip trailing path separators
		i--
	}
	j := i

	for j > 0 && !os.IsPathSeparator(realname[j-1]) {
		j--
	}

	if j > 0 {
		if err := os.MkdirAll(realname[0:j-1], 0755); err != nil {
			log.WithFields(log.Fields{
				"Topic": "mrt",
				"Error": err,
			}).Warn("can't create MRT destination directory")
			return nil, err
		}
	}

	file, err := os.OpenFile(realname, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		log.WithFields(log.Fields{
			"Topic": "mrt",
			"Error": err,
		}).Warn("can't create MRT destination file")
	}
	return file, err
}

func newMrtWriter(s *BgpServer, dumpType config.MrtType, filename, tablename string, rInterval, dInterval uint64) (*mrtWriter, error) {
	file, err := mrtFileOpen(filename, rInterval)
	if err != nil {
		return nil, err
	}
	m := mrtWriter{
		dumpType:         dumpType,
		s:                s,
		filename:         filename,
		file:             file,
		tablename:        tablename,
		rotationInterval: rInterval,
		dumpInterval:     dInterval,
	}
	go m.loop()
	return &m, nil
}

type mrtManager struct {
	bgpServer *BgpServer
	writer    map[string]*mrtWriter
}

func (m *mrtManager) enable(c *config.MrtConfig) error {
	if _, ok := m.writer[c.FileName]; ok {
		return fmt.Errorf("%s already exists", c.FileName)
	}

	rInterval := c.RotationInterval
	dInterval := c.DumpInterval

	setRotationMin := func() {
		if rInterval < MIN_ROTATION_INTERVAL {
			log.WithFields(log.Fields{
				"Topic": "MRT",
			}).Info("minimum mrt rotation interval is %d seconds", MIN_ROTATION_INTERVAL)
			rInterval = MIN_ROTATION_INTERVAL
		}
	}

	if c.DumpType == config.MRT_TYPE_TABLE {
		if rInterval == 0 {
			if dInterval < MIN_DUMP_INTERVAL {
				log.WithFields(log.Fields{
					"Topic": "MRT",
				}).Info("minimum mrt dump interval is %d seconds", MIN_DUMP_INTERVAL)
				dInterval = MIN_DUMP_INTERVAL
			}
		} else if dInterval == 0 {
			setRotationMin()
		} else {
			return fmt.Errorf("can't specify both intervals in the table dump type")
		}
	} else if c.DumpType == config.MRT_TYPE_UPDATES {
		// ignore the dump interval
		dInterval = 0
		if len(c.TableName) > 0 {
			return fmt.Errorf("can't specify the table name with the update dump type")
		}
		setRotationMin()
	}

	w, err := newMrtWriter(m.bgpServer, c.DumpType, c.FileName, c.TableName, rInterval, dInterval)
	if err == nil {
		m.writer[c.FileName] = w
	}
	return err
}

func (m *mrtManager) disable(c *config.MrtConfig) error {
	if w, ok := m.writer[c.FileName]; !ok {
		return fmt.Errorf("%s doesn't exists", c.FileName)
	} else {
		w.Stop()
		delete(m.writer, c.FileName)
	}
	return nil
}

func newMrtManager(s *BgpServer) *mrtManager {
	return &mrtManager{
		bgpServer: s,
		writer:    make(map[string]*mrtWriter),
	}
}
