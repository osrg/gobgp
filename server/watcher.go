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
	"github.com/osrg/gobgp/packet"
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
)

type watcherEventType uint8

const (
	_ watcherEventType = iota
	WATCHER_EVENT_UPDATE_MSG
	WATCHER_EVENT_STATE_CHANGE
	WATCHER_EVENT_BESTPATH_CHANGE
)

type watcherEvent interface {
}

type watcherEventUpdateMsg struct {
	message      *bgp.BGPMessage
	peerAS       uint32
	localAS      uint32
	peerAddress  net.IP
	localAddress net.IP
	fourBytesAs  bool
	timestamp    time.Time
	payload      []byte
}

type watcher interface {
	notify(watcherEventType) chan watcherEvent
	restart(string) error
	stop()
}

type mrtWatcherOp struct {
	filename string //used for rotate
	result   chan error
}

type mrtWatcher struct {
	t        tomb.Tomb
	filename string
	file     *os.File
	ch       chan watcherEvent
	opCh     chan *mrtWatcherOp
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
	adminOp := &mrtWatcherOp{
		filename: filename,
		result:   make(chan error),
	}
	select {
	case w.opCh <- adminOp:
	default:
		return fmt.Errorf("already an admin operaiton in progress")
	}
	return <-adminOp.result
}

func (w *mrtWatcher) loop() error {
	defer w.file.Close()
	for {
		write := func(ev watcherEvent) {
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
				return
			}
			buf, err := bm.Serialize()
			if err == nil {
				_, err = w.file.Write(buf)
			}

			if err != nil {
				log.WithFields(log.Fields{
					"Topic": "mrt",
					"Data":  m,
				}).Warn(err)
			}
		}

		drain := func() {
			for len(w.ch) > 0 {
				m := <-w.ch
				write(m)
			}
		}

		select {
		case <-w.t.Dying():
			drain()
			return nil
		case m := <-w.ch:
			write(m)
		case adminOp := <-w.opCh:
			var err error
			if adminOp.filename != "" {
				err = os.Rename(w.file.Name(), adminOp.filename)
			}
			if err == nil {
				var file *os.File
				file, err = mrtFileOpen(w.file.Name())
				if err == nil {
					w.file.Close()
					w.file = file
				}
			}
			adminOp.result <- err
		}
	}
}

func mrtFileOpen(filename string) (*os.File, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		log.Warn(err)
	}
	return file, err
}

func newMrtWatcher(filename string) (*mrtWatcher, error) {
	file, err := mrtFileOpen(filename)
	if err != nil {
		return nil, err
	}
	w := mrtWatcher{
		filename: filename,
		file:     file,
		ch:       make(chan watcherEvent),
		opCh:     make(chan *mrtWatcherOp, 1),
	}
	w.t.Go(w.loop)
	return &w, nil
}
