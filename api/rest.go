// Copyright (C) 2014,2015 Nippon Telegraph and Telephone Corporation.
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

package api

import (
	log "github.com/Sirupsen/logrus"
	"github.com/fukata/golang-stats-api-handler"
	"github.com/gorilla/mux"
	"github.com/osrg/gobgp/packet"
	"net/http"
	"strconv"
)

const (
	_ = iota
	REQ_NEIGHBOR
	REQ_NEIGHBORS
	REQ_ADJ_RIB_IN
	REQ_ADJ_RIB_OUT
	REQ_LOCAL_RIB
	REQ_NEIGHBOR_SHUTDOWN
	REQ_NEIGHBOR_RESET
	REQ_NEIGHBOR_SOFT_RESET
	REQ_NEIGHBOR_SOFT_RESET_IN
	REQ_NEIGHBOR_SOFT_RESET_OUT
	REQ_NEIGHBOR_ENABLE
	REQ_NEIGHBOR_DISABLE
)

const (
	BASE_VERSION = "/v1"
	NEIGHBOR     = "/bgp/neighbor"
	NEIGHBORS    = "/bgp/neighbors"

	PARAM_REMOTE_PEER_ADDR = "remotePeerAddr"
	PARAM_SHOW_OBJECT      = "showObject"
	PARAM_OPERATION        = "operation"
	PARAM_ROUTE_FAMILY     = "routeFamily"

	STATS = "/stats"
)

const REST_PORT = 8080

// trigger struct for exchanging information in the rest and peer.
// rest and peer operated at different thread.

type RestRequest struct {
	RequestType int
	RemoteAddr  string
	RouteFamily bgp.RouteFamily
	ResponseCh  chan *RestResponse
	Err         error
}

func NewRestRequest(reqType int, remoteAddr string, rf bgp.RouteFamily) *RestRequest {
	r := &RestRequest{
		RequestType: reqType,
		RouteFamily: rf,
		RemoteAddr:  remoteAddr,
		ResponseCh:  make(chan *RestResponse),
	}
	return r
}

type RestResponse struct {
	ResponseErr error
	Data        []byte
}

func (r *RestResponse) Err() error {
	return r.ResponseErr
}

type RestServer struct {
	port        int
	bgpServerCh chan *RestRequest
}

func NewRestServer(port int, bgpServerCh chan *RestRequest) *RestServer {
	rs := &RestServer{
		port:        port,
		bgpServerCh: bgpServerCh}
	return rs
}

// Main thread of rest service.
// URL than can receive.
//   get state of neighbors.
//     -- curl -i -X GET http://<ownIP>:8080/v1/bgp/neighbors
//   get state of neighbor.
//     -- curl -i -X GET http://<ownIP>:8080/v1/bgp/neighbor/<remote address of target neighbor>
//   get adj-rib-in of each neighbor.
//     -- curl -i -X GET http://<ownIP>:8080/v1/bgp/neighbor/<remote address of target neighbor>/adj-rib-in/<rf>
//   get adj-rib-out of each neighbor.
//     -- curl -i -X GET http://<ownIP>:8080/v1/bgp/neighbor/<remote address of target neighbor>/adj-rib-out/<rf>
//   get local-rib of each neighbor.
//     -- curl -i -X GET http://<ownIP>:8080/v1/bgp/neighbor/<remote address of target neighbor>/local-rib/<rf>
func (rs *RestServer) Serve() {
	neighbor := BASE_VERSION + NEIGHBOR
	neighbors := BASE_VERSION + NEIGHBORS

	r := mux.NewRouter()
	perPeerURL := "/{" + PARAM_REMOTE_PEER_ADDR + "}"
	showObjectURL := "/{" + PARAM_SHOW_OBJECT + "}"
	operationURL := "/{" + PARAM_OPERATION + "}"
	routeFamilyURL := "/{" + PARAM_ROUTE_FAMILY + "}"
	r.HandleFunc(neighbors, rs.NeighborGET).Methods("GET")
	r.HandleFunc(neighbor+perPeerURL, rs.NeighborGET).Methods("GET")
	r.HandleFunc(neighbor+perPeerURL+showObjectURL+routeFamilyURL, rs.NeighborGET).Methods("GET")
	r.HandleFunc(neighbor+perPeerURL+operationURL, rs.NeighborPOST).Methods("POST")
	r.HandleFunc(neighbor+perPeerURL+operationURL+routeFamilyURL, rs.NeighborPOST).Methods("POST")

	// stats
	r.HandleFunc(STATS, stats_api.Handler).Methods("GET")

	// Handler when not found url
	r.NotFoundHandler = http.HandlerFunc(NotFoundHandler)
	http.Handle("/", r)

	http.ListenAndServe(":"+strconv.Itoa(rs.port), nil)

}

func (rs *RestServer) neighbor(w http.ResponseWriter, r *http.Request, reqType int) {
	params := mux.Vars(r)
	remoteAddr, _ := params[PARAM_REMOTE_PEER_ADDR]
	log.Debugf("Look up neighbor with the remote address : %v", remoteAddr)
	var rf bgp.RouteFamily
	routeFamily, ok := params[PARAM_ROUTE_FAMILY]
	if ok {
		switch routeFamily {
		case "ipv4":
			rf = bgp.RF_IPv4_UC
		case "ipv6":
			rf = bgp.RF_IPv6_UC
		case "evpn":
			rf = bgp.RF_EVPN
		default:
			NotFoundHandler(w, r)
		}
	}

	//Send channel of request parameter.
	req := NewRestRequest(reqType, remoteAddr, rf)
	rs.bgpServerCh <- req

	//Wait response
	res := <-req.ResponseCh
	if e := res.Err(); e != nil {
		log.Debug(e.Error())
		http.Error(w, e.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(res.Data)
}

func (rs *RestServer) NeighborPOST(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	switch params[PARAM_OPERATION] {
	case "shutdown":
		rs.neighbor(w, r, REQ_NEIGHBOR_SHUTDOWN)
	case "reset":
		rs.neighbor(w, r, REQ_NEIGHBOR_RESET)
	case "softreset":
		rs.neighbor(w, r, REQ_NEIGHBOR_SOFT_RESET)
	case "softresetin":
		rs.neighbor(w, r, REQ_NEIGHBOR_SOFT_RESET_IN)
	case "softresetout":
		rs.neighbor(w, r, REQ_NEIGHBOR_SOFT_RESET_OUT)
	case "enable":
		rs.neighbor(w, r, REQ_NEIGHBOR_ENABLE)
	case "disable":
		rs.neighbor(w, r, REQ_NEIGHBOR_DISABLE)
	default:
		NotFoundHandler(w, r)
	}
}

func (rs *RestServer) NeighborGET(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	if _, ok := params[PARAM_REMOTE_PEER_ADDR]; !ok {
		rs.neighbor(w, r, REQ_NEIGHBORS)
		return
	}

	if showObject, ok := params[PARAM_SHOW_OBJECT]; ok {
		switch showObject {
		case "local-rib":
			rs.neighbor(w, r, REQ_LOCAL_RIB)
		case "adj-rib-in":
			rs.neighbor(w, r, REQ_ADJ_RIB_IN)
		case "adj-rib-out":
			rs.neighbor(w, r, REQ_ADJ_RIB_OUT)
		default:
			NotFoundHandler(w, r)
		}
	} else {
		rs.neighbor(w, r, REQ_NEIGHBOR)
	}
}

func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}
