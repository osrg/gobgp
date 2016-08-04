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
	"github.com/osrg/gobgp/packet/mrt"
)

type mrtWriter struct {
	dead             chan struct{}
	s                *BgpServer
	filename         string
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
	}
	w := m.s.Watch(ops...)
	rotator := func() *time.Ticker {
		if m.rotationInterval == 0 {
			return &time.Ticker{}
		}
		return time.NewTicker(time.Second * time.Duration(m.rotationInterval))
	}()
	table := func() *time.Ticker {
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
		if m.dumpInterval == 0 {
			table.Stop()
		}
		w.Stop()
	}()

	for {
		serialize := func(ev WatchEvent) ([]byte, error) {
			var bm *mrt.MRTMessage
			switch m := ev.(type) {
			case *WatchEventUpdate:
				subtype := mrt.MESSAGE_AS4
				mp := mrt.NewBGP4MPMessage(m.PeerAS, m.LocalAS, 0, m.PeerAddress.String(), m.LocalAddress.String(), m.FourBytesAs, nil)
				mp.BGPMessagePayload = m.Payload
				if m.FourBytesAs == false {
					subtype = mrt.MESSAGE
				}
				var err error
				bm, err = mrt.NewMRTMessage(uint32(m.Timestamp.Unix()), mrt.BGP4MP, subtype, mp)
				if err != nil {
					log.WithFields(log.Fields{
						"Topic": "mrt",
						"Data":  m,
						"Error": err,
					}).Warn("Failed to create MRT message in serialize()")
					return nil, err
				}
			case *WatchEventTable:
			}
			return bm.Serialize()
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
				buf, err := serialize(e)
				if err != nil {
					log.WithFields(log.Fields{
						"Topic": "mrt",
						"Data":  e,
						"Error": err,
					}).Warn("Failed to serialize event")
					continue
				}
				b.Write(buf)
				if b.Len() > 1*1000*1000 {
					w(b.Bytes())
					b.Reset()
				}
			}
			if b.Len() > 0 {
				w(b.Bytes())
			}
		}
		select {
		case <-m.dead:
			drain(nil)
			return nil
		case e := <-w.Event():
			drain(e)
		case <-rotator.C:
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
		case <-table.C:
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

func newMrtWriter(s *BgpServer, dumpType config.MrtType, filename string, rInterval, dInterval uint64) (*mrtWriter, error) {
	file, err := mrtFileOpen(filename, rInterval)
	if err != nil {
		return nil, err
	}
	m := mrtWriter{
		dumpType:         dumpType,
		s:                s,
		filename:         filename,
		file:             file,
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
	if rInterval != 0 && rInterval < 30 {
		log.Info("minimum mrt dump interval is 30 seconds")
		rInterval = 30
	}
	dInterval := c.DumpInterval
	if c.DumpType == config.MRT_TYPE_TABLE {
		if dInterval < 60 {
			log.Info("minimum mrt dump interval is 30 seconds")
			dInterval = 60
		}
	} else if c.DumpType == config.MRT_TYPE_UPDATES {
		dInterval = 0
	}

	w, err := newMrtWriter(m.bgpServer, c.DumpType, c.FileName, rInterval, dInterval)
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
