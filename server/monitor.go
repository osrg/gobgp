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
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
	"gopkg.in/tomb.v2"
)

type grpcWatcher struct {
	t     tomb.Tomb
	ch    chan watcherEvent
	ctlCh chan *GrpcRequest
	reqs  map[watcherEventType][]*GrpcRequest
}

func (w *grpcWatcher) notify(t watcherEventType) chan watcherEvent {
	if t == WATCHER_EVENT_BESTPATH_CHANGE || t == WATCHER_EVENT_UPDATE_MSG || t == WATCHER_EVENT_POST_POLICY_UPDATE_MSG {
		return w.ch
	}
	return nil
}

func (w *grpcWatcher) stop() {
	w.t.Kill(nil)
}

func (w *grpcWatcher) watchingEventTypes() []watcherEventType {
	types := make([]watcherEventType, 0, 3)
	for _, t := range []watcherEventType{WATCHER_EVENT_UPDATE_MSG, WATCHER_EVENT_POST_POLICY_UPDATE_MSG, WATCHER_EVENT_BESTPATH_CHANGE} {
		if len(w.reqs[t]) > 0 {
			types = append(types, t)
		}
	}
	return types
}

func (w *grpcWatcher) loop() error {
	for {
		select {
		case <-w.t.Dying():
			for _, rs := range w.reqs {
				for _, req := range rs {
					close(req.ResponseCh)
				}
			}
			return nil
		case req := <-w.ctlCh:
			tbl := req.Data.(*api.Table)
			var reqType watcherEventType
			switch tbl.Type {
			case api.Resource_GLOBAL:
				reqType = WATCHER_EVENT_BESTPATH_CHANGE
			case api.Resource_ADJ_IN:
				if tbl.PostPolicy {
					reqType = WATCHER_EVENT_POST_POLICY_UPDATE_MSG
				} else {
					reqType = WATCHER_EVENT_UPDATE_MSG
				}
			default:
				continue
			}
			reqs := w.reqs[reqType]
			if reqs == nil {
				reqs = make([]*GrpcRequest, 0, 16)
			}
			reqs = append(reqs, req)
			w.reqs[reqType] = reqs
		case ev := <-w.ch:
			sendPaths := func(reqType watcherEventType, paths []*table.Path) {
				for _, path := range paths {
					if path == nil {
						continue
					}
					remains := make([]*GrpcRequest, 0, len(w.reqs[reqType]))
					result := &GrpcResponse{
						Data: &api.Destination{
							Prefix: path.GetNlri().String(),
							Paths:  []*api.Path{path.ToApiStruct(table.GLOBAL_RIB_NAME)},
						},
					}
					for _, req := range w.reqs[reqType] {
						select {
						case <-req.EndCh:
							continue
						default:
						}
						remains = append(remains, req)
						if req.RouteFamily != bgp.RouteFamily(0) && req.RouteFamily != path.GetRouteFamily() {
							continue
						}
						if req.Name != "" && req.Name != path.GetSource().Address.String() {
							continue
						}
						req.ResponseCh <- result
					}
					w.reqs[reqType] = remains
				}
			}
			switch msg := ev.(type) {
			case *watcherEventBestPathMsg:
				sendPaths(WATCHER_EVENT_BESTPATH_CHANGE, msg.pathList)
			case *watcherEventUpdateMsg:
				if msg.postPolicy {
					sendPaths(WATCHER_EVENT_POST_POLICY_UPDATE_MSG, msg.pathList)
				} else {
					sendPaths(WATCHER_EVENT_UPDATE_MSG, msg.pathList)
				}
			}

		}
	}
}

func (w *grpcWatcher) restart(string) error {
	return nil
}

func (w *grpcWatcher) addRequest(req *GrpcRequest) error {
	w.ctlCh <- req
	return nil
}

func newGrpcWatcher() (*grpcWatcher, error) {
	w := &grpcWatcher{
		ch:    make(chan watcherEvent),
		ctlCh: make(chan *GrpcRequest),
		reqs:  make(map[watcherEventType][]*GrpcRequest),
	}
	w.t.Go(w.loop)
	return w, nil
}
