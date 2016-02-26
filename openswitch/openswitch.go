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
	"fmt"
	log "github.com/Sirupsen/logrus"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/gobgp/cmd"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/server"
	ovsdb "github.com/osrg/libovsdb"
	"github.com/satori/go.uuid"
	"net"
	"reflect"
	"strconv"
	"time"
)

const (
	TARGET_TABLE = "OpenSwitch"
)

const (
	NEXTHOP_TRANSACT_NUUID = "nexthop"
	ROUTE_TRANSACT_NUUID   = "route"
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

func (m *OpsManager) populateCache(updates ovsdb.TableUpdates) {
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
		return uuid.Nil
	}
	if len(vv) != 2 || vv[0].(string) != "uuid" {
		return uuid.Nil
	}
	return uuid.FromStringOrNil(vv[1].(string))
}

func (m *OpsManager) getRootUUID() (uuid.UUID, error) {
	for k, _ := range m.cache[TARGET_TABLE] {
		return uuid.FromStringOrNil(k), nil
	}
	return uuid.Nil, fmt.Errorf("OpenSwitch table not found")
}

func (m *OpsManager) getVrfUUID() (uuid.UUID, error) {
	vrfs, ok := m.cache["VRF"]
	if !ok {
		return uuid.Nil, fmt.Errorf("VRF table not found")
	}
	for k, _ := range vrfs {
		return uuid.FromStringOrNil(k), nil
	}
	return uuid.Nil, fmt.Errorf("uuid not found in VRF table")
}

func (m *OpsManager) getBGPRouterUUID() (uint32, uuid.UUID, error) {
	var asn uint32
	vrfs, ok := m.cache["VRF"]
	if !ok {
		return asn, uuid.Nil, fmt.Errorf("VRF table not found")
	}
	for _, v := range vrfs {
		if v.Fields["name"] == "vrf_default" {
			routers := v.Fields["bgp_routers"].(ovsdb.OvsMap).GoMap
			if len(routers) < 1 {
				return asn, uuid.Nil, fmt.Errorf("no bgp router configured")
			}
			if len(routers) > 1 {
				return asn, uuid.Nil, fmt.Errorf("default vrf has multiple bgp router setting")
			}
			for k, v := range routers {
				asn = uint32(k.(float64))
				id := extractUUID(v)
				if id == uuid.Nil {
					return asn, uuid.Nil, fmt.Errorf("invalid bgp router schema")
				}
				return asn, id, nil
			}
		}
	}
	return asn, uuid.Nil, fmt.Errorf("row not found in vrf table")
}

func parseRouteToGobgp(route ovsdb.RowUpdate, nexthops map[string]ovsdb.Row) (*api.Path, bool, bool, error) {
	var nlri bgp.AddrPrefixInterface
	path := &api.Path{
		IsFromExternal: true,
		Pattrs:         make([][]byte, 0),
	}
	isWithdraw := false
	isFromGobgp := false
	prefix := route.New.Fields["prefix"].(string)
	safi := route.New.Fields["sub_address_family"].(string)
	afi := route.New.Fields["address_family"].(string)
	m := route.New.Fields["metric"].(float64)
	attrs := route.New.Fields["path_attributes"].(ovsdb.OvsMap).GoMap

	if attrs["IsFromGobgp"] == "true" {
		isFromGobgp = true
	}

	nh := make([]interface{}, 0)
	nhId, ok := route.New.Fields["bgp_nexthops"].(ovsdb.UUID)
	if ok {
		for id, n := range nexthops {
			if id == nhId.GoUuid {
				nh = append(nh, n.Fields["ip_address"])
			}
		}
	}

	nexthop := "0.0.0.0"
	if afi == "ipv6" {
		nexthop = "::"
	}
	if len(nh) == 0 {
		log.Debug("nexthop addres does not exist")
	} else if len(nh) == 1 {
		if net.ParseIP(nh[0].(string)) == nil {
			return nil, isWithdraw, isFromGobgp, fmt.Errorf("invalid nexthop address")
		} else {
			nexthop = nh[0].(string)
		}
	} else {
		return nil, isWithdraw, isFromGobgp, fmt.Errorf("route has multiple nexthop address")
	}

	med, _ := bgp.NewPathAttributeMultiExitDisc(uint32(m)).Serialize()
	path.Pattrs = append(path.Pattrs, med)

	lpref, err := strconv.Atoi(attrs["BGP_loc_pref"].(string))
	if err != nil {
		return nil, isWithdraw, isFromGobgp, err
	}
	localPref, _ := bgp.NewPathAttributeLocalPref(uint32(lpref)).Serialize()
	path.Pattrs = append(path.Pattrs, localPref)

	var origin_t int
	switch attrs["BGP_origin"].(string) {
	case "i":
		origin_t = bgp.BGP_ORIGIN_ATTR_TYPE_IGP
	case "e":
		origin_t = bgp.BGP_ORIGIN_ATTR_TYPE_EGP
	case "?":
		origin_t = bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE
	default:
		return nil, isWithdraw, isFromGobgp, fmt.Errorf("invalid origin")
	}
	origin, _ := bgp.NewPathAttributeOrigin(uint8(origin_t)).Serialize()
	path.Pattrs = append(path.Pattrs, origin)

	switch afi {
	case "ipv4", "ipv6":
		ip, net, err := net.ParseCIDR(prefix)
		if err != nil {
			return nil, isWithdraw, isFromGobgp, err
		}
		ones, _ := net.Mask.Size()
		if afi == "ipv4" {
			if ip.To4() == nil {
				return nil, isWithdraw, isFromGobgp, fmt.Errorf("invalid ipv4 prefix")
			}
			nlri = bgp.NewIPAddrPrefix(uint8(ones), ip.String())
		} else {
			if ip.To16() == nil {
				return nil, isWithdraw, isFromGobgp, fmt.Errorf("invalid ipv6 prefix")
			}
			nlri = bgp.NewIPv6AddrPrefix(uint8(ones), ip.String())
		}
	default:
		return nil, isWithdraw, isFromGobgp, fmt.Errorf("unsupported address family: %s", afi)
	}

	if afi == "ipv4" && safi == "unicast" {
		path.Nlri, _ = nlri.Serialize()
		n, _ := bgp.NewPathAttributeNextHop(nexthop).Serialize()
		path.Pattrs = append(path.Pattrs, n)
	} else {
		mpreach, _ := bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}).Serialize()
		path.Pattrs = append(path.Pattrs, mpreach)
	}
	if attrs["BGP_flags"].(string) == "512" {
		isWithdraw = true
	}

	return path, isWithdraw, isFromGobgp, nil
}

func (m *OpsManager) getBGPNeighborUUIDs(id uuid.UUID) ([]net.IP, []uuid.UUID, error) {
	global, ok := m.cache["BGP_Router"]
	if !ok {
		return nil, nil, fmt.Errorf("BGP_Router table not found")
	}
	for k, v := range global {
		if uuid.Equal(id, uuid.FromStringOrNil(k)) {
			neighbors := v.Fields["bgp_neighbors"].(ovsdb.OvsMap).GoMap
			if len(neighbors) < 1 {
				return nil, nil, fmt.Errorf("no bgp neighbor configured")
			}
			addrs := make([]net.IP, 0, len(neighbors))
			ids := make([]uuid.UUID, 0, len(neighbors))
			for k, v := range neighbors {
				addrs = append(addrs, net.ParseIP(k.(string)))
				id := extractUUID(v)
				if id == uuid.Nil {
					return nil, nil, fmt.Errorf("invalid uuid schema")
				}
				ids = append(ids, id)
			}
			return addrs, ids, nil
		}
	}
	return nil, nil, fmt.Errorf("neighbor not found")
}

func (m *OpsManager) handleVrfUpdate(update ovsdb.TableUpdate) *server.GrpcRequest {
	for _, v := range update.Rows {
		if len(v.Old.Fields) == 0 {
			log.WithFields(log.Fields{
				"Topic": "openswitch",
			}).Debug("new vrf")
		} else if _, ok := v.Old.Fields["bgp_routers"]; ok {
			_, _, err := m.getBGPRouterUUID()
			if err != nil {
				return server.NewGrpcRequest(server.REQ_MOD_GLOBAL_CONFIG, "del", bgp.RouteFamily(0), &api.ModGlobalConfigArguments{
					Operation: api.Operation_DEL,
				})
			}
		}
	}
	return nil
}

func (m *OpsManager) handleBgpRouterUpdate(update ovsdb.TableUpdate) []*server.GrpcRequest {
	asn, id, err := m.getBGPRouterUUID()
	if err != nil {
		log.Debugf("%s", err)
		return nil
	}
	reqs := []*server.GrpcRequest{}
	for k, v := range update.Rows {
		if uuid.Equal(id, uuid.FromStringOrNil(k)) {
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
					log.WithFields(log.Fields{
						"Topic": "openswitch",
					}).Debug("router-id is not configured yet")
					return nil
				}
				reqs = append(reqs, server.NewGrpcRequest(server.REQ_MOD_GLOBAL_CONFIG, "add", bgp.RouteFamily(0), &api.ModGlobalConfigArguments{
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
						reqs = append(reqs, server.NewGrpcRequest(server.REQ_MOD_NEIGHBOR, "del", bgp.RouteFamily(0), &api.ModNeighborArguments{
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

func (m *OpsManager) handleNeighborUpdate(update ovsdb.TableUpdate) []*server.GrpcRequest {
	_, id, _ := m.getBGPRouterUUID()
	addrs, ids, err := m.getBGPNeighborUUIDs(id)
	if err != nil {
		return nil
	}
	reqs := make([]*server.GrpcRequest, 0, len(addrs))
	for k, v := range update.Rows {
		for idx, id := range ids {
			if uuid.Equal(id, uuid.FromStringOrNil(k)) {
				asn, ok := v.New.Fields["remote_as"].(float64)
				if !ok {
					log.WithFields(log.Fields{
						"Topic": "openswitch",
					}).Debug("remote-as is not configured yet")
					continue
				}
				reqs = append(reqs, server.NewGrpcRequest(server.REQ_MOD_NEIGHBOR, "add", bgp.RouteFamily(0), &api.ModNeighborArguments{
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

func (m *OpsManager) handleRouteUpdate(update ovsdb.TableUpdate) []*server.GrpcRequest {
	id, _ := m.getVrfUUID()
	reqs := []*server.GrpcRequest{}
	for _, v := range update.Rows {
		vrf := v.New.Fields["vrf"]
		if vrf == nil {
			continue
		}
		idx := vrf.(ovsdb.UUID).GoUuid
		if uuid.Equal(id, uuid.FromStringOrNil(idx)) {
			path, isWithdraw, isFromGobgp, err := parseRouteToGobgp(v, m.cache["BGP_Nexthop"])
			if err != nil {
				log.WithFields(log.Fields{
					"Topic": "openswitch",
					"Path":  path,
					"Err":   err,
				}).Debug("failed to parse path")
				return nil
			}
			if isWithdraw {
				reqs = append(reqs, server.NewGrpcRequest(server.REQ_MOD_PATH, "del", bgp.RouteFamily(0), &api.ModPathArguments{
					Operation: api.Operation_DEL,
					Resource:  api.Resource_GLOBAL,
					Name:      "",
					Path:      path,
				}))
			} else {
				if isFromGobgp {
					return nil
				}
				reqs = append(reqs, server.NewGrpcRequest(server.REQ_MOD_PATH, "add", bgp.RouteFamily(0), &api.ModPathArguments{
					Operation: api.Operation_ADD,
					Resource:  api.Resource_GLOBAL,
					Name:      "",
					Path:      path,
				}))
			}
		}
	}
	return reqs
}

func parseRouteToOps(pl []*cmd.Path) (map[string]interface{}, bool, error) {
	route := map[string]interface{}{"metric": 0, "peer": "Remote announcement"}
	IsWithdraw := false
	for _, p := range pl {
		var nexthop string
		pathAttr := map[string]string{"BGP_iBGP": "false",
			"BGP_flags":    "16",
			"BGP_internal": "false",
			"BGP_loc_pref": "0",
			"IsFromGobgp":  "true",
		}
		for _, a := range p.PathAttrs {
			switch a.GetType() {
			case bgp.BGP_ATTR_TYPE_NEXT_HOP:
				nexthop = a.(*bgp.PathAttributeNextHop).Value.String()
			case bgp.BGP_ATTR_TYPE_MP_REACH_NLRI:
				n := a.(*bgp.PathAttributeMpReachNLRI).Nexthop
				if n != nil {
					nexthop = n.String()
				} else {
					nexthop = ""
				}
			case bgp.BGP_ATTR_TYPE_AS_PATH:
				pathAttr["BGP_AS_path"] = a.(*bgp.PathAttributeAsPath).String()
			case bgp.BGP_ATTR_TYPE_ORIGIN:
				origin := "-"
				switch a.(*bgp.PathAttributeOrigin).Value[0] {
				case bgp.BGP_ORIGIN_ATTR_TYPE_IGP:
					origin = "i"
				case bgp.BGP_ORIGIN_ATTR_TYPE_EGP:
					origin = "e"
				case bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE:
					origin = "?"
				}
				pathAttr["BGP_origin"] = origin
			case bgp.BGP_ATTR_TYPE_LOCAL_PREF:
				pathAttr["BGP_loc_pref"] = fmt.Sprintf("%v", a.(*bgp.PathAttributeLocalPref).Value)
			case bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC:
				route["metric"] = a.(*bgp.PathAttributeMultiExitDisc).Value
			default:
				continue
			}
		}
		IsWithdraw = p.IsWithdraw
		afi := "ipv4"
		if p.Nlri.AFI() != bgp.AFI_IP {
			afi = "ipv6"
		}
		safi := "unicast"

		route["prefix"] = p.Nlri.String()
		route["address_family"] = afi
		route["sub_address_family"] = safi
		route["bgp_nexthops"] = nexthop
		route["path_attributes"] = pathAttr
		break
	}

	return route, IsWithdraw, nil
}

func insertNextHop(opsRoute map[string]interface{}) ovsdb.Operation {
	nexthop := make(map[string]interface{})
	nexthop["ip_address"] = opsRoute["bgp_nexthops"]
	nexthop["type"] = opsRoute["sub_address_family"]
	insNextHopOp := ovsdb.Operation{
		Op:       "insert",
		Table:    "BGP_Nexthop",
		Row:      nexthop,
		UUIDName: NEXTHOP_TRANSACT_NUUID,
	}
	return insNextHopOp
}

func insertRoute(vrfId uuid.UUID, opsRoute map[string]interface{}) (ovsdb.Operation, error) {
	v := []ovsdb.UUID{ovsdb.UUID{vrfId.String()}}
	vrfSet, _ := ovsdb.NewOvsSet(v)
	opsRoute["vrf"] = vrfSet

	nexthop := []ovsdb.UUID{ovsdb.UUID{NEXTHOP_TRANSACT_NUUID}}
	nexthopSet, _ := ovsdb.NewOvsSet(nexthop)
	opsRoute["bgp_nexthops"] = nexthopSet

	attrMap, err := ovsdb.NewOvsMap(opsRoute["path_attributes"])
	if err != nil {
		return ovsdb.Operation{}, err
	}

	opsRoute["path_attributes"] = attrMap

	insRouteOp := ovsdb.Operation{
		Op:       "insert",
		Table:    "BGP_Route",
		Row:      opsRoute,
		UUIDName: ROUTE_TRANSACT_NUUID,
	}
	return insRouteOp, nil
}

func deleteRoute(opsRoute map[string]interface{}) ovsdb.Operation {
	condition := ovsdb.NewCondition("prefix", "==", opsRoute["prefix"])
	deleteOp := ovsdb.Operation{
		Op:    "delete",
		Table: "BGP_Route",
		Where: []interface{}{condition},
	}
	return deleteOp
}

func (m *OpsManager) TransactPreparation(p []*cmd.Path) (*OpsOperation, error) {
	v, err := m.getVrfUUID()
	if err != nil {
		return nil, err
	}
	opsRoute, isWithdraw, err := parseRouteToOps(p)
	if err != nil {
		return nil, err
	}

	var o []ovsdb.Operation
	if !isWithdraw {
		insNextHopOp := insertNextHop(opsRoute)
		insRouteOp, err := insertRoute(v, opsRoute)
		if err != nil {
			return nil, err
		}
		o = []ovsdb.Operation{insNextHopOp, insRouteOp}
	} else {
		delRouteOp := deleteRoute(opsRoute)
		o = []ovsdb.Operation{delRouteOp}
	}
	oOperation := &OpsOperation{
		operations: o,
	}
	return oOperation, nil
}

func (m *OpsManager) Transact(operations []ovsdb.Operation) error {
	ops := m.ops
	reply, err := ops.Transact(TARGET_TABLE, operations...)
	if err != nil {
		return err
	}
	if len(reply) < len(operations) {
		return fmt.Errorf("number of replies should be atleast equal to number of Operations")
	}
	var repErr error
	for i, o := range reply {
		if o.Error != "" && i < len(operations) {
			repErr = fmt.Errorf("transaction failed due to an error :", o.Error, " details:", o.Details, " in ", operations[i])
		} else if o.Error != "" {
			repErr = fmt.Errorf("transaction failed due to an error :", o.Error)
		}
	}
	if repErr != nil {
		return repErr
	}
	return nil
}

func (m *OpsManager) GobgpMonitor(ready *bool) {
	time.Sleep(time.Duration(time.Second * 2))
	reqCh := m.grpcCh
	family := bgp.RF_IPv4_UC
	arg := &api.Arguments{
		Resource: api.Resource_GLOBAL,
		Family:   uint32(family),
	}
	for {
		if !*ready {
			return
		}
		req := server.NewGrpcRequest(server.REQ_MONITOR_GLOBAL_BEST_CHANGED, "", bgp.RouteFamily(0), arg)
		reqCh <- req
		res := <-req.ResponseCh
		if err := res.Err(); err != nil {
			log.WithFields(log.Fields{
				"Topic":       "openswitch",
				"Type":        "Monitor",
				"RequestType": req.RequestType,
				"Err":         err,
			}).Error("grpc operation failed")
		}
		d := res.Data.(*api.Destination)
		bPath := d.Paths[0]
		if bPath.IsFromExternal && !bPath.IsWithdraw {
			continue
		}
		p, err := cmd.ApiStruct2Path(bPath)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "openswitch",
				"Type":  "MonitorRequest",
				"Err":   err,
			}).Error("failed parse path of gobgp")
		}
		o, err := m.TransactPreparation(p)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "openswitch",
				"Type":  "Monitor",
				"Err":   err,
			}).Error("failed transact preparation of ops")
		}
		m.opsCh <- o
	}
}

func (m *OpsManager) GobgpServe() error {
	monitorReady := false
	for {
		var grpcReq *server.GrpcRequest
		var grpcRes chan *server.GrpcResponse
		if len(m.grpcQueue) < 1 {
			time.Sleep(time.Duration(time.Millisecond * 10))
			continue
		}
		grpcReq = m.grpcQueue[0]
		grpcRes = grpcReq.ResponseCh

		m.grpcCh <- grpcReq
		m.grpcQueue = m.grpcQueue[1:]
		r := <-grpcRes

		if r.Err() != nil {
			log.WithFields(log.Fields{
				"Topic": "openswitch",
				"Type":  "ModRequest",
				"Err":   r.Err(),
			}).Error("grpc operation failed")
		} else {
			if monitorReady {
				if grpcReq.RequestType == server.REQ_MOD_GLOBAL_CONFIG && grpcReq.Name == "del" {
					monitorReady = false
				}
			} else {
				if grpcReq.RequestType == server.REQ_MOD_GLOBAL_CONFIG && grpcReq.Name == "add" {
					monitorReady = true
					go m.GobgpMonitor(&monitorReady)
				}
			}
		}
	}
	return nil
}

func (m *OpsManager) OpsServe() error {
	initial, err := m.ops.MonitorAll(TARGET_TABLE, "")
	if err != nil {
		return err
	}
	go func() {
		m.opsUpdateCh <- initial
	}()
	for {
		select {
		case updates := <-m.opsUpdateCh:
			m.populateCache(*updates)
			t, ok := updates.Updates["VRF"]
			if ok {
				req := m.handleVrfUpdate(t)
				if req != nil {
					m.grpcQueue = append(m.grpcQueue, req)
				}
			}
			t, ok = updates.Updates["BGP_Router"]
			if ok {
				routerReqs := m.handleBgpRouterUpdate(t)
				if len(routerReqs) > 0 {
					m.grpcQueue = append(m.grpcQueue, routerReqs...)
				}
			}
			t, ok = updates.Updates["BGP_Neighbor"]
			if ok {
				neighborReqs := m.handleNeighborUpdate(t)
				if len(neighborReqs) > 0 {
					m.grpcQueue = append(m.grpcQueue, neighborReqs...)
				}
			}
			t, ok = updates.Updates["BGP_Route"]
			if ok {
				routeReqs := m.handleRouteUpdate(t)
				if len(routeReqs) > 0 {
					m.grpcQueue = append(m.grpcQueue, routeReqs...)
				}
			}
		case r := <-m.opsCh:
			if err := m.Transact(r.operations); err != nil {
			}
		}
	}
	return nil
}

func (m *OpsManager) Serve() error {
	go m.OpsServe()
	go m.GobgpServe()
	return nil
}

type OpsOperation struct {
	operations []ovsdb.Operation
}

type GrpcChs struct {
	grpcCh chan *server.GrpcRequest
}

type OpsChs struct {
	opsCh       chan *OpsOperation
	opsUpdateCh chan *ovsdb.TableUpdates
}

type OpsManager struct {
	ops         *ovsdb.OvsdbClient
	grpcCh      chan *server.GrpcRequest
	opsCh       chan *OpsOperation
	opsUpdateCh chan *ovsdb.TableUpdates
	grpcQueue   []*server.GrpcRequest
	bgpReady    bool
	cache       map[string]map[string]ovsdb.Row
}

func NewOpsManager(grpcCh chan *server.GrpcRequest) (*OpsManager, error) {
	ops, err := ovsdb.ConnectUnix("")
	if err != nil {
		return nil, err
	}
	gQueue := make([]*server.GrpcRequest, 0)
	opsUpdateCh := make(chan *ovsdb.TableUpdates)
	n := NewNotifier(opsUpdateCh)
	ops.Register(n)

	return &OpsManager{
		ops:         ops,
		grpcCh:      grpcCh,
		opsCh:       make(chan *OpsOperation, 1024),
		opsUpdateCh: opsUpdateCh,
		grpcQueue:   gQueue,
		bgpReady:    false,
		cache:       make(map[string]map[string]ovsdb.Row),
	}, nil
}
