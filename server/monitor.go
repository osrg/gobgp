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
	reqs  []*GrpcRequest
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
	pre := false
	post := false
	best := false
	for _, req := range w.reqs {
		tbl := req.Data.(*api.Table)
		if tbl.Type == api.Resource_GLOBAL {
			best = true
		} else if tbl.PostPolicy {
			post = true
		} else {
			pre = true
		}
	}
	types := make([]watcherEventType, 0, 3)
	if best {
		types = append(types, WATCHER_EVENT_BESTPATH_CHANGE)
	}
	if pre {
		types = append(types, WATCHER_EVENT_UPDATE_MSG)
	}
	if post {
		types = append(types, WATCHER_EVENT_POST_POLICY_UPDATE_MSG)
	}
	return types
}

func (w *grpcWatcher) loop() error {
	for {
		select {
		case <-w.t.Dying():
			for _, req := range w.reqs {
				close(req.ResponseCh)
			}
			return nil
		case req := <-w.ctlCh:
			w.reqs = append(w.reqs, req)
		case ev := <-w.ch:
			var paths []*table.Path
			switch msg := ev.(type) {
			case *watcherEventUpdateMsg:
				paths = msg.pathList
			case *watcherEventBestPathMsg:
				paths = msg.pathList
			}

			for _, path := range paths {
				if path == nil {
					continue
				}
				remains := make([]*GrpcRequest, 0, len(w.reqs))
				result := &GrpcResponse{
					Data: &api.Destination{
						Prefix: path.GetNlri().String(),
						Paths:  []*api.Path{path.ToApiStruct(table.GLOBAL_RIB_NAME)},
					},
				}
				for _, req := range w.reqs {
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
				w.reqs = remains
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
		reqs:  make([]*GrpcRequest, 0, 16),
	}
	w.t.Go(w.loop)
	return w, nil
}
