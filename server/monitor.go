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
	if t == WATCHER_EVENT_BESTPATH_CHANGE || t == WATCHER_EVENT_UPDATE_MSG || t == WATCHER_EVENT_POST_POLICY_UPDATE_MSG || t == WATCHER_EVENT_STATE_CHANGE {
		return w.ch
	}
	return nil
}

func (w *grpcWatcher) stop() {
	w.t.Kill(nil)
}

func (w *grpcWatcher) watchingEventTypes() []watcherEventType {
	types := make([]watcherEventType, 0, 4)
	for _, t := range []watcherEventType{WATCHER_EVENT_UPDATE_MSG, WATCHER_EVENT_POST_POLICY_UPDATE_MSG, WATCHER_EVENT_BESTPATH_CHANGE, WATCHER_EVENT_STATE_CHANGE} {
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
			var reqType watcherEventType
			switch req.RequestType {
			case REQ_MONITOR_RIB:
				tbl := req.Data.(*api.Table)
				switch tbl.Type {
				case api.Resource_GLOBAL:
					reqType = WATCHER_EVENT_BESTPATH_CHANGE
				case api.Resource_ADJ_IN:
					if tbl.PostPolicy {
						reqType = WATCHER_EVENT_POST_POLICY_UPDATE_MSG
					} else {
						reqType = WATCHER_EVENT_UPDATE_MSG
					}
				}
			case REQ_MONITOR_NEIGHBOR_PEER_STATE:
				reqType = WATCHER_EVENT_STATE_CHANGE
			}
			reqs := w.reqs[reqType]
			if reqs == nil {
				reqs = make([]*GrpcRequest, 0, 16)
			}
			reqs = append(reqs, req)
			w.reqs[reqType] = reqs
		case ev := <-w.ch:
			sendMultiPaths := func(reqType watcherEventType, dsts [][]*table.Path) {
				for _, dst := range dsts {
					paths := make([]*api.Path, 0, len(dst))
					for _, path := range dst {
						paths = append(paths, path.ToApiStruct(table.GLOBAL_RIB_NAME))
					}
					if len(paths) == 0 {
						continue
					}
					remains := make([]*GrpcRequest, 0, len(w.reqs[reqType]))
					result := &GrpcResponse{
						Data: &api.Destination{
							Prefix: dst[0].GetNlri().String(),
							Paths:  paths,
						},
					}
					for _, req := range w.reqs[reqType] {
						select {
						case <-req.EndCh:
							continue
						default:
						}
						remains = append(remains, req)
						if req.RouteFamily != bgp.RouteFamily(0) && req.RouteFamily != dst[0].GetRouteFamily() {
							continue
						}
						if req.Name != "" && req.Name != paths[0].NeighborIp {
							continue
						}
						req.ResponseCh <- result
					}
					w.reqs[reqType] = remains
				}
			}
			sendPaths := func(reqType watcherEventType, paths []*table.Path) {
				dsts := make([][]*table.Path, 0, len(paths))
				for _, path := range paths {
					if path == nil {
						continue
					}
					dsts = append(dsts, []*table.Path{path})
				}
				sendMultiPaths(reqType, dsts)
			}
			switch msg := ev.(type) {
			case *watcherEventBestPathMsg:
				if table.UseMultiplePaths.Enabled {
					sendMultiPaths(WATCHER_EVENT_BESTPATH_CHANGE, msg.multiPathList)
				} else {
					sendPaths(WATCHER_EVENT_BESTPATH_CHANGE, msg.pathList)
				}
			case *watcherEventUpdateMsg:
				if msg.postPolicy {
					sendPaths(WATCHER_EVENT_POST_POLICY_UPDATE_MSG, msg.pathList)
				} else {
					sendPaths(WATCHER_EVENT_UPDATE_MSG, msg.pathList)
				}
			case *watcherEventStateChangedMsg:
				peer := &api.Peer{
					Conf: &api.PeerConf{
						PeerAs:          msg.peerAS,
						LocalAs:         msg.localAS,
						NeighborAddress: msg.peerAddress.String(),
						Id:              msg.peerID.String(),
					},
					Info: &api.PeerState{
						PeerAs:          msg.peerAS,
						LocalAs:         msg.localAS,
						NeighborAddress: msg.peerAddress.String(),
						BgpState:        msg.state.String(),
						AdminState:      msg.adminState.String(),
					},
					Transport: &api.Transport{
						LocalAddress: msg.localAddress.String(),
						LocalPort:    uint32(msg.localPort),
						RemotePort:   uint32(msg.peerPort),
					},
				}
				reqType := WATCHER_EVENT_STATE_CHANGE
				remains := make([]*GrpcRequest, 0, len(w.reqs[reqType]))
				result := &GrpcResponse{
					Data: peer,
				}
				for _, req := range w.reqs[reqType] {
					select {
					case <-req.EndCh:
						continue
					default:
					}
					remains = append(remains, req)
					if req.Name != "" && req.Name != peer.Conf.NeighborAddress {
						continue
					}
					req.ResponseCh <- result
				}
				w.reqs[reqType] = remains
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
