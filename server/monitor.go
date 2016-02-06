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
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"gopkg.in/tomb.v2"
)

type grpcIncomingWatcher struct {
	t     tomb.Tomb
	ch    chan watcherEvent
	ctlCh chan *GrpcRequest
	reqs  []*GrpcRequest
}

func (w *grpcIncomingWatcher) notify(t watcherEventType) chan watcherEvent {
	if t == WATCHER_EVENT_UPDATE_MSG || t == WATCHER_EVENT_POST_POLICY_UPDATE_MSG {
		return w.ch
	}
	return nil
}

func (w *grpcIncomingWatcher) stop() {
	w.t.Kill(nil)
}

func (w *grpcIncomingWatcher) watchingEventTypes() []watcherEventType {
	pre := false
	post := false
	for _, req := range w.reqs {
		if req.Data.(*api.Table).PostPolicy {
			post = true
		} else {
			pre = true
		}
	}
	types := make([]watcherEventType, 0, 2)
	if pre {
		types = append(types, WATCHER_EVENT_UPDATE_MSG)
	}
	if post {
		types = append(types, WATCHER_EVENT_POST_POLICY_UPDATE_MSG)
	}
	return types
}

func (w *grpcIncomingWatcher) loop() error {
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
			msg := ev.(*watcherEventUpdateMsg)
			for _, path := range msg.pathList {
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

func (w *grpcIncomingWatcher) restart(string) error {
	return nil
}

func (w *grpcIncomingWatcher) addRequest(req *GrpcRequest) error {
	w.ctlCh <- req
	return nil
}

func newGrpcIncomingWatcher() (*grpcIncomingWatcher, error) {
	w := &grpcIncomingWatcher{
		ch:    make(chan watcherEvent),
		ctlCh: make(chan *GrpcRequest),
		reqs:  make([]*GrpcRequest, 0, 16),
	}
	w.t.Go(w.loop)
	return w, nil
}
