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
	"bytes"
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"gopkg.in/tomb.v2"
	"net"
	"os"
	"time"
)

type broadcastWatcherMsg struct {
	ch    chan watcherEvent
	event watcherEvent
}

func (m *broadcastWatcherMsg) send() {
	m.ch <- m.event
}

type watcherType uint8

const (
	_           watcherType = iota
	WATCHER_MRT             // UPDATE MSG
	WATCHER_BMP
	WATCHER_ZEBRA
	WATCHER_GRPC_BESTPATH
	WATCHER_GRPC_INCOMING
)

type watcherEventType uint8

const (
	_ watcherEventType = iota
	WATCHER_EVENT_UPDATE_MSG
	WATCHER_EVENT_STATE_CHANGE
	WATCHER_EVENT_BESTPATH_CHANGE
	WATCHER_EVENT_POST_POLICY_UPDATE_MSG
)

type watcherEvent interface {
}

type watcherEventUpdateMsg struct {
	message      *bgp.BGPMessage
	peerAS       uint32
	localAS      uint32
	peerAddress  net.IP
	localAddress net.IP
	peerID       net.IP
	fourBytesAs  bool
	timestamp    time.Time
	payload      []byte
	postPolicy   bool
	pathList     []*table.Path
}

type watcherEventStateChangedMsg struct {
	peerAS       uint32
	localAS      uint32
	peerAddress  net.IP
	localAddress net.IP
	peerPort     uint16
	localPort    uint16
	peerID       net.IP
	sentOpen     *bgp.BGPMessage
	recvOpen     *bgp.BGPMessage
	state        bgp.FSMState
	timestamp    time.Time
}

type watcher interface {
	notify(watcherEventType) chan watcherEvent
	restart(string) error
	stop()
	watchingEventTypes() []watcherEventType
}

type mrtWatcher struct {
	t        tomb.Tomb
	filename string
	file     *os.File
	ch       chan watcherEvent
	interval uint64
}

func (w *mrtWatcher) notify(t watcherEventType) chan watcherEvent {
	if t == WATCHER_EVENT_UPDATE_MSG {
		return w.ch
	}
	return nil
}

func (w *mrtWatcher) stop() {
	w.t.Kill(nil)
}

func (w *mrtWatcher) restart(filename string) error {
	return nil
}

func (w *mrtWatcher) loop() error {
	c := func() *time.Ticker {
		if w.interval == 0 {
			return &time.Ticker{}
		}
		return time.NewTicker(time.Second * time.Duration(w.interval))
	}()

	defer func() {
		if w.file != nil {
			w.file.Close()
		}
		if w.interval != 0 {
			c.Stop()
		}
	}()

	for {
		serialize := func(ev watcherEvent) ([]byte, error) {
			m := ev.(*watcherEventUpdateMsg)
			subtype := bgp.MESSAGE_AS4
			mp := bgp.NewBGP4MPMessage(m.peerAS, m.localAS, 0, m.peerAddress.String(), m.localAddress.String(), m.fourBytesAs, nil)
			mp.BGPMessagePayload = m.payload
			if m.fourBytesAs == false {
				subtype = bgp.MESSAGE
			}
			bm, err := bgp.NewMRTMessage(uint32(m.timestamp.Unix()), bgp.BGP4MP, subtype, mp)
			if err != nil {
				log.WithFields(log.Fields{
					"Topic": "mrt",
					"Data":  m,
				}).Warn(err)
				return nil, err
			}
			return bm.Serialize()
		}

		drain := func(ev watcherEvent) {
			events := make([]watcherEvent, 0, 1+len(w.ch))
			if ev != nil {
				events = append(events, ev)
			}

			for len(w.ch) > 0 {
				e := <-w.ch
				events = append(events, e)
			}

			w := func(buf []byte) {
				if _, err := w.file.Write(buf); err == nil {
					w.file.Sync()
				} else {
					log.WithFields(log.Fields{
						"Topic": "mrt",
						"Error": err,
					}).Warn(err)
				}
			}

			var b bytes.Buffer
			for _, e := range events {
				buf, err := serialize(e)
				if err != nil {
					log.WithFields(log.Fields{
						"Topic": "mrt",
						"Data":  e,
					}).Warn(err)
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
		case <-w.t.Dying():
			drain(nil)
			return nil
		case e := <-w.ch:
			drain(e)
		case <-c.C:
			w.file.Close()
			file, err := mrtFileOpen(w.filename, w.interval)
			if err == nil {
				w.file = file
			} else {
				log.Info("can't rotate mrt file", err)
			}
		}
	}
}

func (w *mrtWatcher) watchingEventTypes() []watcherEventType {
	return []watcherEventType{WATCHER_EVENT_UPDATE_MSG}
}

func mrtFileOpen(filename string, interval uint64) (*os.File, error) {
	realname := filename
	if interval != 0 {
		realname = time.Now().Format(filename)
	}

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
			log.Warn(err)
			return nil, err
		}
	}

	file, err := os.OpenFile(realname, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		log.Warn(err)
	}
	return file, err
}

func newMrtWatcher(dumpType int32, filename string, interval uint64) (*mrtWatcher, error) {
	file, err := mrtFileOpen(filename, interval)
	if err != nil {
		return nil, err
	}
	w := mrtWatcher{
		filename: filename,
		file:     file,
		ch:       make(chan watcherEvent, 1<<16),
		interval: interval,
	}
	w.t.Go(w.loop)
	return &w, nil
}
