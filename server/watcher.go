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
	"net"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/eapache/channels"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
	"gopkg.in/tomb.v2"
)

type watcherType uint8

const (
	_           watcherType = iota
	WATCHER_MRT             // UPDATE MSG
	WATCHER_BMP
	WATCHER_ZEBRA
	WATCHER_COLLECTOR
	WATCHER_GRPC_MONITOR
)

type watcherEventType uint8

const (
	_ watcherEventType = iota
	WATCHER_EVENT_UPDATE_MSG
	WATCHER_EVENT_STATE_CHANGE
	WATCHER_EVENT_BESTPATH_CHANGE
	WATCHER_EVENT_POST_POLICY_UPDATE_MSG
	WATCHER_EVENT_ADJ_IN
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
	adminState   AdminState
	timestamp    time.Time
}

type watcherEventAdjInMsg struct {
	pathList []*table.Path
}

type watcherEventBestPathMsg struct {
	pathList      []*table.Path
	multiPathList [][]*table.Path
}

type watcher interface {
	notify(watcherEventType) chan watcherEvent
	restart(string) error
	stop()
	watchingEventTypes() []watcherEventType
}

type watcherMsg struct {
	typ watcherEventType
	ev  watcherEvent
}

type watcherManager struct {
	t  tomb.Tomb
	mu sync.RWMutex
	m  map[watcherType]watcher
	ch *channels.InfiniteChannel
}

func (m *watcherManager) watching(typ watcherEventType) bool {
	for _, w := range m.m {
		for _, ev := range w.watchingEventTypes() {
			if ev == typ {
				return true
			}
		}
	}
	return false
}

// this will be called from server's main goroutine.
// shouldn't block.
func (m *watcherManager) notify(typ watcherEventType, ev watcherEvent) {
	m.ch.In() <- &watcherMsg{typ, ev}
}

func (m *watcherManager) loop() error {
	for {
		select {
		case i, ok := <-m.ch.Out():
			if !ok {
				continue
			}
			msg := i.(*watcherMsg)
			m.mu.RLock()
			for _, w := range m.m {
				if ch := w.notify(msg.typ); ch != nil {
					t := time.NewTimer(time.Second)
					select {
					case ch <- msg.ev:
					case <-t.C:
						log.WithFields(log.Fields{
							"Topic": "Watcher",
						}).Warnf("notification to %s timeout expired")
					}
				}
			}
			m.mu.RUnlock()
		}
	}
}

func (m *watcherManager) watcher(typ watcherType) (watcher, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	w, y := m.m[typ]
	return w, y
}

func (m *watcherManager) addWatcher(typ watcherType, w watcher) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, y := m.m[typ]; y {
		return fmt.Errorf("already exists %s watcher", typ)
	}
	m.m[typ] = w
	return nil
}

func (m *watcherManager) delWatcher(typ watcherType) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, y := m.m[typ]; !y {
		return fmt.Errorf("not found %s watcher", typ)
	}
	w := m.m[typ]
	w.stop()
	delete(m.m, typ)
	return nil
}

func newWatcherManager() *watcherManager {
	m := &watcherManager{
		m:  make(map[watcherType]watcher),
		ch: channels.NewInfiniteChannel(),
	}
	m.t.Go(m.loop)
	return m
}
