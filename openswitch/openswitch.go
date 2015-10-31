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

package openswitch

import (
	"code.google.com/p/go-uuid/uuid"
	"fmt"
	log "github.com/Sirupsen/logrus"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/server"
	ovsdb "github.com/osrg/libovsdb"
	"net"
	"reflect"
)

type Notifier struct {
	updateCh chan *ovsdb.TableUpdates
}

func (n Notifier) Update(context interface{}, tableUpdates ovsdb.TableUpdates) {
	n.updateCh <- &tableUpdates
}
func (n Notifier) Locked([]interface{}) {
}
func (n Notifier) Stolen([]interface{}) {
}
func (n Notifier) Echo([]interface{}) {
}
func (n Notifier) Disconnected(client *ovsdb.OvsdbClient) {
}

func NewNotifier(ch chan *ovsdb.TableUpdates) *Notifier {
	return &Notifier{
		updateCh: ch,
	}
}

type OpsConfigManager struct {
	client   *ovsdb.OvsdbClient
	grpcCh   chan *server.GrpcRequest
	updateCh chan *ovsdb.TableUpdates
	cache    map[string]map[string]ovsdb.Row
}

func (m *OpsConfigManager) populateCache(updates ovsdb.TableUpdates) {
	for table, tableUpdate := range updates.Updates {
		if _, ok := m.cache[table]; !ok {
			m.cache[table] = make(map[string]ovsdb.Row)

		}
		for uuid, row := range tableUpdate.Rows {
			empty := ovsdb.Row{}
			if !reflect.DeepEqual(row.New, empty) {
				m.cache[table][uuid] = row.New
			} else {
				delete(m.cache[table], uuid)
			}
		}
	}
}

func extractUUID(v interface{}) uuid.UUID {
	vv, ok := v.([]interface{})
	if !ok {
		return nil
	}
	if len(vv) != 2 || vv[0].(string) != "uuid" {
		return nil
	}
	return uuid.Parse(vv[1].(string))
}

func (m *OpsConfigManager) getBGPRouterUUID() (uint32, uuid.UUID, error) {
	var asn uint32
	vrfs, ok := m.cache["VRF"]
	if !ok {
		return asn, nil, fmt.Errorf("no vrf table")
	}
	for _, v := range vrfs {
		if v.Fields["name"] == "vrf_default" {
			routers := v.Fields["bgp_routers"].(ovsdb.OvsMap).GoMap
			if len(routers) < 1 {
				return asn, nil, fmt.Errorf("no bgp router configured")
			}
			if len(routers) > 1 {
				return asn, nil, fmt.Errorf("default vrf has multiple bgp router setting")
			}
			for k, v := range routers {
				asn = uint32(k.(float64))
				id := extractUUID(v)
				if id == nil {
					return asn, nil, fmt.Errorf("invalid bgp router schema")
				}
				return asn, id, nil
			}
		}
	}
	return asn, nil, fmt.Errorf("not found")
}

func (m *OpsConfigManager) getBGPNeighborUUIDs(id uuid.UUID) ([]net.IP, []uuid.UUID, error) {
	global, ok := m.cache["BGP_Router"]
	if !ok {
		return nil, nil, fmt.Errorf("BGP_Router table not found")
	}
	for k, v := range global {
		if uuid.Equal(id, uuid.Parse(k)) {
			neighbors := v.Fields["bgp_neighbors"].(ovsdb.OvsMap).GoMap
			if len(neighbors) < 1 {
				return nil, nil, fmt.Errorf("no bgp neighbor configured")
			}
			addrs := make([]net.IP, 0, len(neighbors))
			ids := make([]uuid.UUID, 0, len(neighbors))
			for k, v := range neighbors {
				addrs = append(addrs, net.ParseIP(k.(string)))
				id := extractUUID(v)
				if id == nil {
					return nil, nil, fmt.Errorf("invalid uuid schema")
				}
				ids = append(ids, id)
			}
			return addrs, ids, nil
		}
	}
	return nil, nil, fmt.Errorf("not found")
}

func (m *OpsConfigManager) handleVrfUpdate(update ovsdb.TableUpdate) *server.GrpcRequest {
	for _, v := range update.Rows {
		if len(v.Old.Fields) == 0 {
			log.WithFields(log.Fields{
				"Topic": "openswitch",
			}).Debug("new vrf")
		} else if _, ok := v.Old.Fields["bgp_routers"]; ok {
			_, _, err := m.getBGPRouterUUID()
			if err != nil {
				return server.NewGrpcRequest(server.REQ_MOD_GLOBAL_CONFIG, "", bgp.RouteFamily(0), &api.ModGlobalConfigArguments{
					Operation: api.Operation_DEL,
				})
			}
		}
	}
	return nil
}

func (m *OpsConfigManager) handleBgpRouterUpdate(update ovsdb.TableUpdate) []*server.GrpcRequest {
	asn, id, err := m.getBGPRouterUUID()
	if err != nil {
		log.Debugf("%s", err)
		return nil
	}
	reqs := []*server.GrpcRequest{}
	for k, v := range update.Rows {
		if uuid.Equal(id, uuid.Parse(k)) {
			initial := false
			if len(v.Old.Fields) == 0 {
				log.WithFields(log.Fields{
					"Topic": "openswitch",
				}).Debug("new bgp router")
				initial = true
			}
			if _, ok := v.Old.Fields["router_id"]; initial || ok {
				r, ok := v.New.Fields["router_id"].(string)
				if !ok {
					log.Debugf("router-id is not configured yet")
					return nil
				}
				reqs = append(reqs, server.NewGrpcRequest(server.REQ_MOD_GLOBAL_CONFIG, "", bgp.RouteFamily(0), &api.ModGlobalConfigArguments{
					Operation: api.Operation_ADD,
					Global: &api.Global{
						As:       asn,
						RouterId: r,
					},
				}))
			}
			if o, ok := v.Old.Fields["bgp_neighbors"]; ok {
				oldNeighMap := o.(ovsdb.OvsMap).GoMap
				newNeighMap := v.New.Fields["bgp_neighbors"].(ovsdb.OvsMap).GoMap
				for k, _ := range oldNeighMap {
					if _, ok := newNeighMap[k]; !ok {
						reqs = append(reqs, server.NewGrpcRequest(server.REQ_MOD_NEIGHBOR, "", bgp.RouteFamily(0), &api.ModNeighborArguments{
							Operation: api.Operation_DEL,
							Peer: &api.Peer{
								Conf: &api.PeerConf{
									NeighborAddress: k.(string),
								},
							},
						}))
					}
				}
			}
		}
	}
	return reqs
}

func (m *OpsConfigManager) handleNeighborUpdate(update ovsdb.TableUpdate) []*server.GrpcRequest {
	_, id, _ := m.getBGPRouterUUID()
	addrs, ids, err := m.getBGPNeighborUUIDs(id)
	if err != nil {
		return nil
	}
	reqs := make([]*server.GrpcRequest, 0, len(addrs))
	for k, v := range update.Rows {
		for idx, id := range ids {
			if uuid.Equal(id, uuid.Parse(k)) {
				asn, ok := v.New.Fields["remote_as"].(float64)
				if !ok {
					log.Debugf("remote-as is not configured yet")
					continue
				}
				reqs = append(reqs, server.NewGrpcRequest(server.REQ_MOD_NEIGHBOR, "", bgp.RouteFamily(0), &api.ModNeighborArguments{
					Operation: api.Operation_ADD,
					Peer: &api.Peer{
						Conf: &api.PeerConf{
							NeighborAddress: addrs[idx].String(),
							PeerAs:          uint32(asn),
						},
					},
				}))
			}
		}
	}
	return reqs
}

func (m *OpsConfigManager) Serve() error {
	initial, err := m.client.MonitorAll("OpenSwitch", "")
	if err != nil {
		return err
	}
	go func() {
		m.updateCh <- initial
	}()
	reqs := make([]*server.GrpcRequest, 0)
	ress := make([]*server.GrpcRequest, 0)
	for {
		var req, res *server.GrpcRequest
		var reqCh chan *server.GrpcRequest
		var resCh chan *server.GrpcResponse
		if len(reqs) > 0 {
			req = reqs[0]
			reqCh = m.grpcCh
		}
		if len(ress) > 0 {
			res = ress[0]
			resCh = res.ResponseCh
		}
		select {
		case updates := <-m.updateCh:
			m.populateCache(*updates)
			t, ok := updates.Updates["VRF"]
			if ok {
				req := m.handleVrfUpdate(t)
				if req != nil {
					reqs = append(reqs, req)
				}
			}
			t, ok = updates.Updates["BGP_Router"]
			if ok {
				routerReqs := m.handleBgpRouterUpdate(t)
				if len(routerReqs) > 0 {
					reqs = append(reqs, routerReqs...)
				}
			}
			t, ok = updates.Updates["BGP_Neighbor"]
			if ok {
				neighborReqs := m.handleNeighborUpdate(t)
				if len(neighborReqs) > 0 {
					reqs = append(reqs, neighborReqs...)
				}
			}
		case reqCh <- req:
			ress = append(ress, req)
			reqs = reqs[1:]
		case r := <-resCh:
			if err := r.Err(); err != nil {
				log.Errorf("operation failed. reqtype: %d, err: %s", res.RequestType, err)
			}
			ress = ress[1:]
		}
	}
	return nil
}

func NewOpsConfigManager(ch chan *server.GrpcRequest) (*OpsConfigManager, error) {
	cli, err := ovsdb.ConnectUnix("")
	if err != nil {
		return nil, err
	}
	updateCh := make(chan *ovsdb.TableUpdates)
	n := NewNotifier(updateCh)
	cli.Register(n)
	return &OpsConfigManager{
		client:   cli,
		grpcCh:   ch,
		updateCh: updateCh,
		cache:    make(map[string]map[string]ovsdb.Row),
	}, nil
}
