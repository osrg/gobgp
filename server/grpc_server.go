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

package server

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"net"
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
	REQ_NEIGHBOR_POLICY
	REQ_NEIGHBOR_POLICY_ADD_IMPORT
	REQ_NEIGHBOR_POLICY_ADD_EXPORT
	REQ_NEIGHBOR_POLICY_ADD_IN
	REQ_NEIGHBOR_POLICY_DEL_IMPORT
	REQ_NEIGHBOR_POLICY_DEL_EXPORT
	REQ_NEIGHBOR_POLICY_DEL_IN
	REQ_GLOBAL_RIB
	REQ_POLICY_PREFIX
	REQ_POLICY_PREFIXES
	REQ_POLICY_PREFIX_ADD
	REQ_POLICY_PREFIX_DELETE
	REQ_POLICY_PREFIXES_DELETE
	REQ_POLICY_NEIGHBOR
	REQ_POLICY_NEIGHBORS
	REQ_POLICY_NEIGHBOR_ADD
	REQ_POLICY_NEIGHBOR_DELETE
	REQ_POLICY_NEIGHBORS_DELETE
	REQ_POLICY_ASPATH
	REQ_POLICY_ASPATHS
	REQ_POLICY_ASPATH_ADD
	REQ_POLICY_ASPATH_DELETE
	REQ_POLICY_ASPATHS_DELETE
	REQ_POLICY_ROUTEPOLICIES
	REQ_POLICY_ROUTEPOLICY
	REQ_POLICY_ROUTEPOLICY_ADD
	REQ_POLICY_ROUTEPOLICY_DELETE
	REQ_POLICY_ROUTEPOLICIES_DELETE
	REQ_POLICY_COMMUNITY
	REQ_POLICY_COMMUNITIES
	REQ_POLICY_COMMUNITY_ADD
	REQ_POLICY_COMMUNITY_DELETE
	REQ_POLICY_COMMUNITIES_DELETE
	REQ_POLICY_EXTCOMMUNITY
	REQ_POLICY_EXTCOMMUNITIES
	REQ_POLICY_EXTCOMMUNITY_ADD
	REQ_POLICY_EXTCOMMUNITY_DELETE
	REQ_POLICY_EXTCOMMUNITIES_DELETE
	REQ_MONITOR_GLOBAL_BEST_CHANGED
	REQ_MONITOR_NEIGHBOR_PEER_STATE
	REQ_MRT_GLOBAL_RIB
	REQ_MRT_LOCAL_RIB
	REQ_RPKI
	REQ_ROA
	REQ_VRF
	REQ_VRFS
	REQ_VRF_MOD
	REQ_MOD_PATH
	REQ_GLOBAL_POLICY
)

const GRPC_PORT = 8080

type Server struct {
	grpcServer  *grpc.Server
	bgpServerCh chan *GrpcRequest
}

func (s *Server) Serve() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", GRPC_PORT))
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	s.grpcServer.Serve(lis)
	return nil
}

func (s *Server) GetNeighbor(ctx context.Context, arg *api.Arguments) (*api.Peer, error) {
	var rf bgp.RouteFamily
	req := NewGrpcRequest(REQ_NEIGHBOR, arg.Name, rf, nil)
	s.bgpServerCh <- req

	res := <-req.ResponseCh
	if err := res.Err(); err != nil {
		log.Debug(err.Error())
		return nil, err
	}

	return res.Data.(*api.Peer), nil
}

func handleMultipleResponses(req *GrpcRequest, f func(*GrpcResponse) error) error {
	for res := range req.ResponseCh {
		if err := res.Err(); err != nil {
			log.Debug(err.Error())
			req.EndCh <- struct{}{}
			return err
		}
		if err := f(res); err != nil {
			req.EndCh <- struct{}{}
			return err
		}
	}
	return nil
}

func (s *Server) GetNeighbors(_ *api.Arguments, stream api.GobgpApi_GetNeighborsServer) error {
	var rf bgp.RouteFamily
	req := NewGrpcRequest(REQ_NEIGHBORS, "", rf, nil)
	s.bgpServerCh <- req

	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.Peer))
	})
}

func (s *Server) GetRib(arg *api.Arguments, stream api.GobgpApi_GetRibServer) error {
	var reqType int
	switch arg.Resource {
	case api.Resource_LOCAL:
		reqType = REQ_LOCAL_RIB
	case api.Resource_GLOBAL:
		reqType = REQ_GLOBAL_RIB
	case api.Resource_ADJ_IN:
		reqType = REQ_ADJ_RIB_IN
	case api.Resource_ADJ_OUT:
		reqType = REQ_ADJ_RIB_OUT
	case api.Resource_VRF:
		reqType = REQ_VRF
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}

	req := NewGrpcRequest(reqType, arg.Name, bgp.RouteFamily(arg.Rf), nil)
	s.bgpServerCh <- req

	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.Destination))
	})
}

func (s *Server) MonitorBestChanged(arg *api.Arguments, stream api.GobgpApi_MonitorBestChangedServer) error {
	var reqType int
	switch arg.Resource {
	case api.Resource_GLOBAL:
		reqType = REQ_MONITOR_GLOBAL_BEST_CHANGED
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}

	req := NewGrpcRequest(reqType, "", bgp.RouteFamily(arg.Rf), nil)
	s.bgpServerCh <- req

	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.Destination))
	})
}

func (s *Server) MonitorPeerState(arg *api.Arguments, stream api.GobgpApi_MonitorPeerStateServer) error {
	var rf bgp.RouteFamily
	req := NewGrpcRequest(REQ_MONITOR_NEIGHBOR_PEER_STATE, arg.Name, rf, nil)
	s.bgpServerCh <- req

	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.Peer))
	})
}

func (s *Server) neighbor(reqType int, arg *api.Arguments) (*api.Error, error) {
	none := &api.Error{}
	req := NewGrpcRequest(reqType, arg.Name, bgp.RouteFamily(arg.Rf), nil)
	s.bgpServerCh <- req

	res := <-req.ResponseCh
	if err := res.Err(); err != nil {
		log.Debug(err.Error())
		return nil, err
	}
	return none, nil
}

func (s *Server) Reset(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(REQ_NEIGHBOR_RESET, arg)
}

func (s *Server) SoftReset(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(REQ_NEIGHBOR_SOFT_RESET, arg)
}

func (s *Server) SoftResetIn(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(REQ_NEIGHBOR_SOFT_RESET_IN, arg)
}

func (s *Server) SoftResetOut(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(REQ_NEIGHBOR_SOFT_RESET_OUT, arg)
}

func (s *Server) Shutdown(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(REQ_NEIGHBOR_SHUTDOWN, arg)
}

func (s *Server) Enable(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(REQ_NEIGHBOR_ENABLE, arg)
}

func (s *Server) Disable(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(REQ_NEIGHBOR_DISABLE, arg)
}

func (s *Server) ModPath(stream api.GobgpApi_ModPathServer) error {
	for {
		arg, err := stream.Recv()

		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if arg.Resource != api.Resource_GLOBAL && arg.Resource != api.Resource_VRF {
			return fmt.Errorf("unsupported resource: %s", arg.Resource)
		}

		req := NewGrpcRequest(REQ_MOD_PATH, arg.Name, bgp.RouteFamily(0), arg)
		s.bgpServerCh <- req

		res := <-req.ResponseCh
		if err := res.Err(); err != nil {
			log.Debug(err.Error())
			return err
		}
	}
	err := stream.SendAndClose(&api.Error{
		Code: api.Error_SUCCESS,
	})

	return err
}

func (s *Server) GetNeighborPolicy(ctx context.Context, arg *api.Arguments) (*api.ApplyPolicy, error) {
	if arg.Resource != api.Resource_LOCAL && arg.Resource != api.Resource_GLOBAL {
		return nil, fmt.Errorf("unsupported resource: %s", arg.Resource)
	}
	var req *GrpcRequest
	if arg.Resource == api.Resource_LOCAL {
		req = NewGrpcRequest(REQ_NEIGHBOR_POLICY, arg.Name, bgp.RouteFamily(arg.Rf), nil)
	} else {
		req = NewGrpcRequest(REQ_GLOBAL_POLICY, "", bgp.RouteFamily(arg.Rf), nil)
	}
	s.bgpServerCh <- req

	res := <-req.ResponseCh
	if err := res.Err(); err != nil {
		log.Debug(err.Error())
		return nil, err
	}
	return res.Data.(*api.ApplyPolicy), nil
}

func (s *Server) ModNeighborPolicy(stream api.GobgpApi_ModNeighborPolicyServer) error {
	for {
		arg, err := stream.Recv()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}

		if arg.Resource != api.Resource_POLICY_ROUTEPOLICY {
			return fmt.Errorf("unsupported resource: %s", arg.Resource)
		}
		var rf bgp.RouteFamily
		var reqType int
		switch arg.Operation {
		case api.Operation_ADD:
			switch arg.Name {
			case "import":
				reqType = REQ_NEIGHBOR_POLICY_ADD_IMPORT
			case "export":
				reqType = REQ_NEIGHBOR_POLICY_ADD_EXPORT
			case "in":
				reqType = REQ_NEIGHBOR_POLICY_ADD_IN
			}
		case api.Operation_DEL:
			switch arg.Name {
			case "import":
				reqType = REQ_NEIGHBOR_POLICY_DEL_IMPORT
			case "export":
				reqType = REQ_NEIGHBOR_POLICY_DEL_EXPORT
			case "in":
				reqType = REQ_NEIGHBOR_POLICY_DEL_IN
			}
		}
		req := NewGrpcRequest(reqType, arg.NeighborAddress, rf, arg.ApplyPolicy)
		s.bgpServerCh <- req
		res := <-req.ResponseCh
		if err := res.Err(); err != nil {
			log.Debug(err.Error())
			return err
		}
		err = stream.Send(&api.Error{
			Code: api.Error_SUCCESS,
		})
		if err != nil {
			return err
		}
	}
}

func (s *Server) modPolicy(arg *api.PolicyArguments, stream interface{}) error {
	var rf bgp.RouteFamily
	var reqType int
	var err error
	switch arg.Resource {
	case api.Resource_POLICY_PREFIX:
		switch arg.Operation {
		case api.Operation_ADD:
			reqType = REQ_POLICY_PREFIX_ADD
		case api.Operation_DEL:
			reqType = REQ_POLICY_PREFIX_DELETE
		case api.Operation_DEL_ALL:
			reqType = REQ_POLICY_PREFIXES_DELETE
		default:
			return fmt.Errorf("unsupported operation: %s", arg.Operation)
		}
	case api.Resource_POLICY_NEIGHBOR:
		switch arg.Operation {
		case api.Operation_ADD:
			reqType = REQ_POLICY_NEIGHBOR_ADD
		case api.Operation_DEL:
			reqType = REQ_POLICY_NEIGHBOR_DELETE
		case api.Operation_DEL_ALL:
			reqType = REQ_POLICY_NEIGHBORS_DELETE
		default:
			return fmt.Errorf("unsupported operation: %s", arg.Operation)
		}
	case api.Resource_POLICY_ASPATH:
		switch arg.Operation {
		case api.Operation_ADD:
			reqType = REQ_POLICY_ASPATH_ADD
		case api.Operation_DEL:
			reqType = REQ_POLICY_ASPATH_DELETE
		case api.Operation_DEL_ALL:
			reqType = REQ_POLICY_ASPATHS_DELETE
		default:
			return fmt.Errorf("unsupported operation: %s", arg.Operation)
		}
	case api.Resource_POLICY_COMMUNITY:
		switch arg.Operation {
		case api.Operation_ADD:
			reqType = REQ_POLICY_COMMUNITY_ADD
		case api.Operation_DEL:
			reqType = REQ_POLICY_COMMUNITY_DELETE
		case api.Operation_DEL_ALL:
			reqType = REQ_POLICY_COMMUNITIES_DELETE
		default:
			return fmt.Errorf("unsupported operation: %s", arg.Operation)
		}
	case api.Resource_POLICY_EXTCOMMUNITY:
		switch arg.Operation {
		case api.Operation_ADD:
			reqType = REQ_POLICY_EXTCOMMUNITY_ADD
		case api.Operation_DEL:
			reqType = REQ_POLICY_EXTCOMMUNITY_DELETE
		case api.Operation_DEL_ALL:
			reqType = REQ_POLICY_EXTCOMMUNITIES_DELETE
		default:
			return fmt.Errorf("unsupported operation: %s", arg.Operation)
		}
	case api.Resource_POLICY_ROUTEPOLICY:
		switch arg.Operation {
		case api.Operation_ADD:
			reqType = REQ_POLICY_ROUTEPOLICY_ADD
		case api.Operation_DEL:
			reqType = REQ_POLICY_ROUTEPOLICY_DELETE
		case api.Operation_DEL_ALL:
			reqType = REQ_POLICY_ROUTEPOLICIES_DELETE
		default:
			return fmt.Errorf("unsupported operation: %s", arg.Operation)
		}
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}
	req := NewGrpcRequest(reqType, "", rf, arg.PolicyDefinition)
	s.bgpServerCh <- req

	res := <-req.ResponseCh
	if err := res.Err(); err != nil {
		log.Debug(err.Error())
		return err
	}
	err = stream.(api.GobgpApi_ModPolicyRoutePolicyServer).Send(&api.Error{
		Code: api.Error_SUCCESS,
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) GetPolicyRoutePolicies(arg *api.PolicyArguments, stream api.GobgpApi_GetPolicyRoutePoliciesServer) error {
	var rf bgp.RouteFamily
	var reqType int
	switch arg.Resource {
	case api.Resource_POLICY_PREFIX:
		reqType = REQ_POLICY_PREFIXES
	case api.Resource_POLICY_NEIGHBOR:
		reqType = REQ_POLICY_NEIGHBORS
	case api.Resource_POLICY_ASPATH:
		reqType = REQ_POLICY_ASPATHS
	case api.Resource_POLICY_COMMUNITY:
		reqType = REQ_POLICY_COMMUNITIES
	case api.Resource_POLICY_EXTCOMMUNITY:
		reqType = REQ_POLICY_EXTCOMMUNITIES
	case api.Resource_POLICY_ROUTEPOLICY:
		reqType = REQ_POLICY_ROUTEPOLICIES
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}
	req := NewGrpcRequest(reqType, "", rf, nil)
	s.bgpServerCh <- req
	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.PolicyDefinition))
	})
}

func (s *Server) GetPolicyRoutePolicy(ctx context.Context, arg *api.PolicyArguments) (*api.PolicyDefinition, error) {
	var rf bgp.RouteFamily
	var reqType int
	switch arg.Resource {
	case api.Resource_POLICY_PREFIX:
		reqType = REQ_POLICY_PREFIX
	case api.Resource_POLICY_NEIGHBOR:
		reqType = REQ_POLICY_NEIGHBOR
	case api.Resource_POLICY_ASPATH:
		reqType = REQ_POLICY_ASPATH
	case api.Resource_POLICY_COMMUNITY:
		reqType = REQ_POLICY_COMMUNITY
	case api.Resource_POLICY_EXTCOMMUNITY:
		reqType = REQ_POLICY_EXTCOMMUNITY
	case api.Resource_POLICY_ROUTEPOLICY:
		reqType = REQ_POLICY_ROUTEPOLICY
	default:
		return nil, fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}
	req := NewGrpcRequest(reqType, "", rf, arg.Name)
	s.bgpServerCh <- req

	res := <-req.ResponseCh
	if err := res.Err(); err != nil {
		log.Debug(err.Error())
		return nil, err
	}
	return res.Data.(*api.PolicyDefinition), nil
}

func (s *Server) ModPolicyRoutePolicy(stream api.GobgpApi_ModPolicyRoutePolicyServer) error {
	for {
		arg, err := stream.Recv()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		if err := s.modPolicy(arg, stream); err != nil {
			return err
		}
		return nil
	}
}

func (s *Server) GetMrt(arg *api.MrtArguments, stream api.GobgpApi_GetMrtServer) error {
	var reqType int
	switch arg.Resource {
	case api.Resource_GLOBAL:
		reqType = REQ_MRT_GLOBAL_RIB
	case api.Resource_LOCAL:
		reqType = REQ_MRT_LOCAL_RIB
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}
	req := NewGrpcRequest(reqType, arg.NeighborAddress, bgp.RouteFamily(arg.Rf), arg.Interval)
	s.bgpServerCh <- req
	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.MrtMessage))
	})
}

func (s *Server) GetRPKI(arg *api.Arguments, stream api.GobgpApi_GetRPKIServer) error {
	req := NewGrpcRequest(REQ_RPKI, "", bgp.RouteFamily(arg.Rf), nil)
	s.bgpServerCh <- req

	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.RPKI))
	})
}

func (s *Server) GetROA(arg *api.Arguments, stream api.GobgpApi_GetROAServer) error {
	req := NewGrpcRequest(REQ_ROA, arg.Name, bgp.RouteFamily(arg.Rf), nil)
	s.bgpServerCh <- req

	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.ROA))
	})
}

func (s *Server) GetVrfs(arg *api.Arguments, stream api.GobgpApi_GetVrfsServer) error {
	req := NewGrpcRequest(REQ_VRFS, "", bgp.RouteFamily(0), nil)
	s.bgpServerCh <- req

	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.Vrf))
	})
}

func (s *Server) ModVrf(ctx context.Context, arg *api.ModVrfArguments) (*api.Error, error) {
	none := &api.Error{}
	req := NewGrpcRequest(REQ_VRF_MOD, "", bgp.RouteFamily(0), arg)
	s.bgpServerCh <- req

	res := <-req.ResponseCh
	if err := res.Err(); err != nil {
		return none, err
	}
	return none, nil
}

type GrpcRequest struct {
	RequestType int
	Name        string
	RouteFamily bgp.RouteFamily
	ResponseCh  chan *GrpcResponse
	EndCh       chan struct{}
	Err         error
	Data        interface{}
}

func NewGrpcRequest(reqType int, name string, rf bgp.RouteFamily, d interface{}) *GrpcRequest {
	r := &GrpcRequest{
		RequestType: reqType,
		RouteFamily: rf,
		Name:        name,
		ResponseCh:  make(chan *GrpcResponse, 8),
		EndCh:       make(chan struct{}, 1),
		Data:        d,
	}
	return r
}

type GrpcResponse struct {
	ResponseErr error
	Data        interface{}
}

func (r *GrpcResponse) Err() error {
	return r.ResponseErr
}

func NewGrpcServer(port int, bgpServerCh chan *GrpcRequest) *Server {
	grpcServer := grpc.NewServer()
	server := &Server{
		grpcServer:  grpcServer,
		bgpServerCh: bgpServerCh,
	}
	api.RegisterGobgpApiServer(grpcServer, server)
	return server
}
