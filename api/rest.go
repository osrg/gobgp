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
)

const (
	_ = iota
	REQ_NEIGHBOR
	REQ_NEIGHBORS
	REQ_ADJ_RIB_IN
	REQ_ADJ_RIB_OUT
	REQ_LOCAL_RIB
)

const (
	BASE_VERSION       = "/v1"
	NEIGHBOR           = "/bgp/neighbor"
	NEIGHBORS          = "/bgp/neighbors"
	ADJ_RIB_IN         = "/bgp/adj-rib-in"
	ADJ_RIB_OUT        = "/bgp/adj-rib-out"
	ADJ_RIB_LOCAL      = "/bgp/adj-rib-local"
	ADJ_RIB_LOCAL_BEST = "/bgp/adj-rib-local/best"

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
	// adjRibIn := BASE_VERSION + ADJ_RIB_IN
	// adjRibOut := BASE_VERSION + ADJ_RIB_OUT
	// adjRibLocal := BASE_VERSION + ADJ_RIB_LOCAL
	// adjRibLocalBest := BASE_VERSION + ADJ_RIB_LOCAL_BEST

	r := mux.NewRouter()
	// set URLs
	r.HandleFunc(neighbors, rs.Neighbors).Methods("GET")
	r.HandleFunc(neighbor+"/{"+PARAM_REMOTE_PEER_ADDR+"}", rs.Neighbor).Methods("GET")
	// r.HandleFunc(adjRibIn+"/{"+PARAM_REMOTE_PEER_ADDR+"}", rs.AdjRibIn).Methods("GET")
	// r.HandleFunc(adjRibOut+"/{"+PARAM_REMOTE_PEER_ADDR+"}", rs.AdjRibOut).Methods("GET")
	r.HandleFunc(neighbor+"/{"+PARAM_REMOTE_PEER_ADDR+"}/"+"local-rib", rs.NeighborLocalRib).Methods("GET")
	// stats
	r.HandleFunc(STATS, stats_api.Handler)

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
