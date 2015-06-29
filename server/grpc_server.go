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
	"github.com/osrg/gobgp/api"
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
	REQ_NEIGHBOR_POLICY_ADD_DISTRIBUTE
	REQ_NEIGHBOR_POLICY_DEL_IMPORT
	REQ_NEIGHBOR_POLICY_DEL_EXPORT
	REQ_NEIGHBOR_POLICY_DEL_DISTRIBUTE
	REQ_GLOBAL_RIB
	REQ_GLOBAL_ADD
	REQ_GLOBAL_DELETE
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
	REQ_MONITOR_GLOBAL_BEST_CHANGED
	REQ_MONITOR_NEIGHBOR_PEER_STATE
)

const GRPC_PORT = 8080

func convertAf2Rf(af *api.AddressFamily) (bgp.RouteFamily, error) {
	if af == nil {
		return bgp.RouteFamily(0), fmt.Errorf("address family is nil")
	}
	if af.Equal(api.AF_IPV4_UC) {
		return bgp.RF_IPv4_UC, nil
	} else if af.Equal(api.AF_IPV6_UC) {
		return bgp.RF_IPv6_UC, nil
	} else if af.Equal(api.AF_EVPN) {
		return bgp.RF_EVPN, nil
	} else if af.Equal(api.AF_ENCAP) {
		return bgp.RF_ENCAP, nil
	} else if af.Equal(api.AF_RTC) {
		return bgp.RF_RTC_UC, nil
	}

	return bgp.RouteFamily(0), fmt.Errorf("unsupported address family: %v", af)
}

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
	req := NewGrpcRequest(REQ_NEIGHBOR, arg.RouterId, rf, nil)
	s.bgpServerCh <- req

	res := <-req.ResponseCh
	if err := res.Err(); err != nil {
		log.Debug(err.Error())
		return nil, err
	}

	return res.Data.(*api.Peer), nil
}

func (s *Server) GetNeighbors(_ *api.Arguments, stream api.Grpc_GetNeighborsServer) error {
	var rf bgp.RouteFamily
	req := NewGrpcRequest(REQ_NEIGHBORS, "", rf, nil)
	s.bgpServerCh <- req

	for res := range req.ResponseCh {
		if err := res.Err(); err != nil {
			log.Debug(err.Error())
			return err
		}
		if err := stream.Send(res.Data.(*api.Peer)); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) GetAdjRib(arg *api.Arguments, stream api.Grpc_GetAdjRibServer) error {
	var reqType int
	switch arg.Resource {
	case api.Resource_ADJ_IN:
		reqType = REQ_ADJ_RIB_IN
	case api.Resource_ADJ_OUT:
		reqType = REQ_ADJ_RIB_OUT
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}

	rf, err := convertAf2Rf(arg.Af)
	if err != nil {
		return err
	}

	req := NewGrpcRequest(reqType, arg.RouterId, rf, nil)
	s.bgpServerCh <- req

	for res := range req.ResponseCh {
		if err := res.Err(); err != nil {
			log.Debug(err.Error())
			return err
		}
		if err := stream.Send(res.Data.(*api.Path)); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) GetRib(arg *api.Arguments, stream api.Grpc_GetRibServer) error {
	var reqType int
	switch arg.Resource {
	case api.Resource_LOCAL:
		reqType = REQ_LOCAL_RIB
	case api.Resource_GLOBAL:
		reqType = REQ_GLOBAL_RIB
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}

	rf, err := convertAf2Rf(arg.Af)
	if err != nil {
		return err
	}

	req := NewGrpcRequest(reqType, arg.RouterId, rf, nil)
	s.bgpServerCh <- req

	for res := range req.ResponseCh {
		if err := res.Err(); err != nil {
			log.Debug(err.Error())
			return err
		}
		if err := stream.Send(res.Data.(*api.Destination)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) MonitorBestChanged(arg *api.Arguments, stream api.Grpc_MonitorBestChangedServer) error {
	var reqType int
	switch arg.Resource {
	case api.Resource_GLOBAL:
		reqType = REQ_MONITOR_GLOBAL_BEST_CHANGED
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}

	rf, err := convertAf2Rf(arg.Af)
	if err != nil {
		return err
	}

	req := NewGrpcRequest(reqType, "", rf, nil)
	s.bgpServerCh <- req

	for res := range req.ResponseCh {
		if err = res.Err(); err != nil {
			log.Debug(err.Error())
			goto END
		}
		if err = stream.Send(res.Data.(*api.Path)); err != nil {
			goto END
		}
	}
END:
	req.EndCh <- struct{}{}
	return err
}

func (s *Server) MonitorPeerState(arg *api.Arguments, stream api.Grpc_MonitorPeerStateServer) error {
	var rf bgp.RouteFamily
	req := NewGrpcRequest(REQ_MONITOR_NEIGHBOR_PEER_STATE, arg.RouterId, rf, nil)
	s.bgpServerCh <- req

	var err error

	for res := range req.ResponseCh {
		if err = res.Err(); err != nil {
			log.Debug(err.Error())
			goto END
		}
		if err = stream.Send(res.Data.(*api.Peer)); err != nil {
			goto END
		}
	}
END:
	req.EndCh <- struct{}{}
	return err
}

func (s *Server) neighbor(reqType int, arg *api.Arguments) (*api.Error, error) {
	rf, err := convertAf2Rf(arg.Af)
	if err != nil {
		return nil, err
	}

	none := &api.Error{}
	req := NewGrpcRequest(reqType, arg.RouterId, rf, nil)
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

func (s *Server) ModPath(stream api.Grpc_ModPathServer) error {
	for {
		arg, err := stream.Recv()

		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if arg.Resource != api.Resource_GLOBAL {
			return fmt.Errorf("unsupported resource: %s", arg.Resource)
		}

		reqType := REQ_GLOBAL_ADD
		if arg.Path.IsWithdraw {
			reqType = REQ_GLOBAL_DELETE
		}

		rf, err := convertAf2Rf(arg.Path.Nlri.Af)
		if err != nil {
			return err
		}
		req := NewGrpcRequest(reqType, "", rf, arg.Path)
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
	rf, err := convertAf2Rf(arg.Af)
	if err != nil {
		return nil, err
	}

	req := NewGrpcRequest(REQ_NEIGHBOR_POLICY, arg.RouterId, rf, nil)
	s.bgpServerCh <- req

	res := <-req.ResponseCh
	if err := res.Err(); err != nil {
		log.Debug(err.Error())
		return nil, err
	}
	return res.Data.(*api.ApplyPolicy), nil
}

func (s *Server) ModNeighborPolicy(stream api.Grpc_ModNeighborPolicyServer) error {
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
			case "distribute":
				reqType = REQ_NEIGHBOR_POLICY_ADD_DISTRIBUTE
			}
		case api.Operation_DEL:
			switch arg.Name {
			case "import":
				reqType = REQ_NEIGHBOR_POLICY_DEL_IMPORT
			case "export":
				reqType = REQ_NEIGHBOR_POLICY_DEL_EXPORT
			case "distribute":
				reqType = REQ_NEIGHBOR_POLICY_DEL_DISTRIBUTE
			}
		}
		req := NewGrpcRequest(reqType, arg.RouterId, rf, arg.ApplyPolicy)
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
	err = stream.(api.Grpc_ModPolicyRoutePolicyServer).Send(&api.Error{
		Code: api.Error_SUCCESS,
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) GetPolicyRoutePolicies(arg *api.PolicyArguments, stream api.Grpc_GetPolicyRoutePoliciesServer) error {
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
	case api.Resource_POLICY_ROUTEPOLICY:
		reqType = REQ_POLICY_ROUTEPOLICIES
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}
	req := NewGrpcRequest(reqType, "", rf, nil)
	s.bgpServerCh <- req
	for res := range req.ResponseCh {
		if err := res.Err(); err != nil {
			log.Debug(err.Error())
			return err
		}
		if err := stream.(api.Grpc_GetPolicyRoutePoliciesServer).Send(res.Data.(*api.PolicyDefinition)); err != nil {
			return err
		}
	}
	return nil
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

func (s *Server) ModPolicyRoutePolicy(stream api.Grpc_ModPolicyRoutePolicyServer) error {
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

type GrpcRequest struct {
	RequestType int
	RemoteAddr  string
	RouteFamily bgp.RouteFamily
	ResponseCh  chan *GrpcResponse
	EndCh       chan struct{}
	Err         error
	Data        interface{}
}

func NewGrpcRequest(reqType int, remoteAddr string, rf bgp.RouteFamily, d interface{}) *GrpcRequest {
	r := &GrpcRequest{
		RequestType: reqType,
		RouteFamily: rf,
		RemoteAddr:  remoteAddr,
		ResponseCh:  make(chan *GrpcResponse),
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
	api.RegisterGrpcServer(grpcServer, server)
	return server
}
