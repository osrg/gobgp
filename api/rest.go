// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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
	"net/http"
	"strconv"
	"strings"
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
)

const (
	BASE_VERSION = "/v1"
	NEIGHBOR     = "/bgp/neighbor"
	NEIGHBORS    = "/bgp/neighbors"

	PARAM_REMOTE_PEER_ADDR = "remotePeerAddr"
	STATS                  = "/stats"
)

const REST_PORT = 8080

// trigger struct for exchanging information in the rest and peer.
// rest and peer operated at different thread.

type RestRequest struct {
	RequestType int
	RemoteAddr  string
	ResponseCh  chan *RestResponse
	Err         error
}

func NewRestRequest(reqType int, remoteAddr string) *RestRequest {
	r := &RestRequest{
		RequestType: reqType,
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
//     -- curl -i -X GET http://<ownIP>:8080/v1/bgp/neighbor/<remote address of target neighbor>/adj-rib-in
//   get adj-rib-out of each neighbor.
//     -- curl -i -X GET http://<ownIP>:8080/v1/bgp/neighbor/<remote address of target neighbor>/adj-rib-out
//   get local-rib of each neighbor.
//     -- curl -i -X GET http://<ownIP>:8080/v1/bgp/neighbor/<remote address of target neighbor>/local-rib
func (rs *RestServer) Serve() {
	neighbor := BASE_VERSION + NEIGHBOR
	neighbors := BASE_VERSION + NEIGHBORS

	r := mux.NewRouter()

	perPeerURL := "/{" + PARAM_REMOTE_PEER_ADDR + "}"
	r.HandleFunc(neighbors, rs.Neighbors).Methods("GET")
	r.HandleFunc(neighbor+perPeerURL, rs.Neighbor).Methods("GET")
	r.HandleFunc(neighbor+perPeerURL+"/"+"local-rib", rs.NeighborLocalRib).Methods("GET")
	r.HandleFunc(neighbor+perPeerURL+"/"+"shutdown", rs.NeighborPostHandler).Methods("POST")
	r.HandleFunc(neighbor+perPeerURL+"/"+"reset", rs.NeighborPostHandler).Methods("POST")
	r.HandleFunc(neighbor+perPeerURL+"/"+"softreset", rs.NeighborPostHandler).Methods("POST")
	r.HandleFunc(neighbor+perPeerURL+"/"+"softresetin", rs.NeighborPostHandler).Methods("POST")
	r.HandleFunc(neighbor+perPeerURL+"/"+"softresetout", rs.NeighborPostHandler).Methods("POST")

	// stats
	r.HandleFunc(STATS, stats_api.Handler).Methods("GET")

	// Handler when not found url
	r.NotFoundHandler = http.HandlerFunc(NotFoundHandler)
	http.Handle("/", r)

	http.ListenAndServe(":"+strconv.Itoa(rs.port), nil)

}

// TODO: merge the above function
func (rs *RestServer) neighbor(w http.ResponseWriter, r *http.Request, reqType int) {
	params := mux.Vars(r)
	remoteAddr, found := params[PARAM_REMOTE_PEER_ADDR]
	if !found {
		errStr := "neighbor address is not specified"
		log.Debug(errStr)
		http.Error(w, errStr, http.StatusInternalServerError)
		return
	}

	log.Debugf("Look up neighbor with the remote address : %v", remoteAddr)

	//Send channel of request parameter.
	req := NewRestRequest(reqType, remoteAddr)
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

func (rs *RestServer) NeighborPostHandler(w http.ResponseWriter, r *http.Request) {
	action := strings.Split(r.URL.Path, "/")
	switch action[len(action)-1] {
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
	}
}

func (rs *RestServer) Neighbor(w http.ResponseWriter, r *http.Request) {
	rs.neighbor(w, r, REQ_NEIGHBOR)
}

func (rs *RestServer) NeighborLocalRib(w http.ResponseWriter, r *http.Request) {
	rs.neighbor(w, r, REQ_LOCAL_RIB)
}

func (rs *RestServer) Neighbors(w http.ResponseWriter, r *http.Request) {
	//Send channel of request parameter.
	req := NewRestRequest(REQ_NEIGHBORS, "")
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

func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}
