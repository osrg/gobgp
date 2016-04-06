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

package gobgpapi

import (
	"fmt"

	"github.com/osrg/gobgp/packet/bgp"
)

const (
	_ = iota
	REQ_GLOBAL_CONFIG
	REQ_MOD_GLOBAL_CONFIG
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
	REQ_MOD_NEIGHBOR
	REQ_ADD_NEIGHBOR
	REQ_DEL_NEIGHBOR
	REQ_GLOBAL_RIB
	REQ_MONITOR_GLOBAL_BEST_CHANGED
	REQ_MONITOR_INCOMING
	REQ_MONITOR_NEIGHBOR_PEER_STATE
	REQ_MONITOR_ROA_VALIDATION_RESULT
	REQ_MRT_GLOBAL_RIB
	REQ_MRT_LOCAL_RIB
	REQ_MOD_MRT
	REQ_MOD_BMP
	REQ_RPKI
	REQ_MOD_RPKI
	REQ_ROA
	REQ_VRF
	REQ_VRFS
	REQ_VRF_MOD
	REQ_MOD_PATH
	REQ_MOD_PATHS
	REQ_DEFINED_SET
	REQ_MOD_DEFINED_SET
	REQ_STATEMENT
	REQ_MOD_STATEMENT
	REQ_POLICY
	REQ_MOD_POLICY
	REQ_POLICY_ASSIGNMENT
	REQ_MOD_POLICY_ASSIGNMENT
	REQ_BMP_NEIGHBORS
	REQ_BMP_GLOBAL
	REQ_BMP_ADJ_IN
	REQ_DEFERRAL_TIMER_EXPIRED
	REQ_LOG
	REQ_SEND_NOTIFICATION
)

type Request struct {
	Type  int
	ResCh chan *Response
	EndCh chan struct{}
	Err   error
	Data  interface{}
}

func (req *Request) Name() (string, error) {
	switch arg := req.Data.(type) {
	case *Arguments:
		return arg.Name, nil
	case *ModPathArguments:
		return arg.Name, nil
	case *ModPathsArguments:
		return arg.Name, nil
	case *MrtArguments:
		return arg.NeighborAddress, nil
	case *Table:
		return arg.Name, nil
	case *SendNotificationArguments:
		return arg.Name, nil
	}
	return "", fmt.Errorf("request doesn't have a name field")
}

func (req *Request) Family() bgp.RouteFamily {
	switch arg := req.Data.(type) {
	case *Arguments:
		return bgp.RouteFamily(arg.Family)
	case *MrtArguments:
		return bgp.RouteFamily(arg.Family)
	case *Table:
		return bgp.RouteFamily(arg.Family)
	case *Path:
		return bgp.RouteFamily(arg.Family)
	case *ModPathArguments:
		return bgp.RouteFamily(arg.Family)
	}
	return bgp.RouteFamily(0)
}

func NewRequest(typ int, d interface{}) *Request {
	return &Request{
		Type:  typ,
		ResCh: make(chan *Response, 8),
		EndCh: make(chan struct{}, 1),
		Data:  d,
	}
}

type Response struct {
	Err  error
	Data interface{}
}

func HandleMultipleResponses(req *Request, f func(*Response) error) error {
	for res := range req.ResCh {
		if res.Err != nil {
			req.EndCh <- struct{}{}
			return res.Err
		}
		if err := f(res); err != nil {
			req.EndCh <- struct{}{}
			return err
		}
	}
	return nil
}
