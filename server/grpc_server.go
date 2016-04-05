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
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"net"
)

type Server struct {
	grpcServer  *grpc.Server
	bgpServerCh chan *api.Request
	port        int
}

func (s *Server) Serve() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	s.grpcServer.Serve(lis)
	return nil
}

func (s *Server) get(typ int, d interface{}) (interface{}, error) {
	req := api.NewRequest(typ, d)
	s.bgpServerCh <- req
	res := <-req.ResCh
	if err := res.Err; err != nil {
		return nil, err
	}
	return res.Data, nil
}

func (s *Server) mod(typ int, d interface{}) (*api.Error, error) {
	none := &api.Error{}
	req := api.NewRequest(typ, d)
	s.bgpServerCh <- req
	res := <-req.ResCh
	if err := res.Err; err != nil {
		return none, err
	}
	return none, nil
}

func (s *Server) neighbor(reqType int, arg *api.Arguments) (*api.Error, error) {
	none := &api.Error{}
	req := api.NewRequest(reqType, arg)
	s.bgpServerCh <- req

	res := <-req.ResCh
	if err := res.Err; err != nil {
		log.Debug(err.Error())
		return nil, err
	}
	return none, nil
}

func (s *Server) GetNeighbor(ctx context.Context, arg *api.Arguments) (*api.Peer, error) {
	req := api.NewRequest(api.REQ_NEIGHBOR, arg)
	s.bgpServerCh <- req

	res := <-req.ResCh
	if err := res.Err; err != nil {
		log.Debug(err.Error())
		return nil, err
	}

	return res.Data.(*api.Peer), nil
}

func (s *Server) GetNeighbors(arg *api.Arguments, stream api.GobgpApi_GetNeighborsServer) error {
	req := api.NewRequest(api.REQ_NEIGHBORS, arg)
	s.bgpServerCh <- req

	return api.HandleMultipleResponses(req, func(res *api.Response) error {
		return stream.Send(res.Data.(*api.Peer))
	})
}

func (s *Server) GetRib(ctx context.Context, arg *api.Table) (*api.Table, error) {
	var reqType int
	switch arg.Type {
	case api.Resource_LOCAL:
		reqType = api.REQ_LOCAL_RIB
	case api.Resource_GLOBAL:
		reqType = api.REQ_GLOBAL_RIB
	case api.Resource_ADJ_IN:
		reqType = api.REQ_ADJ_RIB_IN
	case api.Resource_ADJ_OUT:
		reqType = api.REQ_ADJ_RIB_OUT
	case api.Resource_VRF:
		reqType = api.REQ_VRF
	default:
		return nil, fmt.Errorf("unsupported resource type: %v", arg.Type)
	}
	d, err := s.get(reqType, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.Table), nil
}

func (s *Server) MonitorBestChanged(arg *api.Arguments, stream api.GobgpApi_MonitorBestChangedServer) error {
	var reqType int
	switch arg.Resource {
	case api.Resource_GLOBAL:
		reqType = api.REQ_MONITOR_GLOBAL_BEST_CHANGED
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}

	req := api.NewRequest(reqType, arg)
	s.bgpServerCh <- req

	return api.HandleMultipleResponses(req, func(res *api.Response) error {
		return stream.Send(res.Data.(*api.Destination))
	})
}

func (s *Server) MonitorRib(arg *api.Table, stream api.GobgpApi_MonitorRibServer) error {
	switch arg.Type {
	case api.Resource_ADJ_IN:
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Type)
	}

	req := api.NewRequest(api.REQ_MONITOR_INCOMING, arg)
	s.bgpServerCh <- req
	return api.HandleMultipleResponses(req, func(res *api.Response) error {
		return stream.Send(res.Data.(*api.Destination))
	})
}

func (s *Server) MonitorPeerState(arg *api.Arguments, stream api.GobgpApi_MonitorPeerStateServer) error {
	req := api.NewRequest(api.REQ_MONITOR_NEIGHBOR_PEER_STATE, arg)
	s.bgpServerCh <- req

	return api.HandleMultipleResponses(req, func(res *api.Response) error {
		return stream.Send(res.Data.(*api.Peer))
	})
}

func (s *Server) MonitorROAValidation(arg *api.Arguments, stream api.GobgpApi_MonitorROAValidationServer) error {
	req := api.NewRequest(api.REQ_MONITOR_ROA_VALIDATION_RESULT, arg)
	s.bgpServerCh <- req

	return api.HandleMultipleResponses(req, func(res *api.Response) error {
		return stream.Send(res.Data.(*api.ROAResult))
	})
}

func (s *Server) Reset(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(api.REQ_NEIGHBOR_RESET, arg)
}

func (s *Server) SoftReset(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(api.REQ_NEIGHBOR_SOFT_RESET, arg)
}

func (s *Server) SoftResetIn(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(api.REQ_NEIGHBOR_SOFT_RESET_IN, arg)
}

func (s *Server) SoftResetOut(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(api.REQ_NEIGHBOR_SOFT_RESET_OUT, arg)
}

func (s *Server) Shutdown(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(api.REQ_NEIGHBOR_SHUTDOWN, arg)
}

func (s *Server) Enable(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(api.REQ_NEIGHBOR_ENABLE, arg)
}

func (s *Server) Disable(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(api.REQ_NEIGHBOR_DISABLE, arg)
}

func (s *Server) ModPath(ctx context.Context, arg *api.ModPathArguments) (*api.ModPathResponse, error) {
	d, err := s.get(api.REQ_MOD_PATH, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.ModPathResponse), nil
}

func (s *Server) ModPaths(stream api.GobgpApi_ModPathsServer) error {
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

		req := api.NewRequest(api.REQ_MOD_PATHS, arg)
		s.bgpServerCh <- req

		res := <-req.ResCh
		if err := res.Err; err != nil {
			log.Debug(err.Error())
			return err
		}
	}
	err := stream.SendAndClose(&api.Error{
		Code: api.Error_SUCCESS,
	})

	return err
}

func (s *Server) GetMrt(arg *api.MrtArguments, stream api.GobgpApi_GetMrtServer) error {
	var reqType int
	switch arg.Resource {
	case api.Resource_GLOBAL:
		reqType = api.REQ_MRT_GLOBAL_RIB
	case api.Resource_LOCAL:
		reqType = api.REQ_MRT_LOCAL_RIB
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}
	req := api.NewRequest(reqType, arg)
	s.bgpServerCh <- req
	return api.HandleMultipleResponses(req, func(res *api.Response) error {
		return stream.Send(res.Data.(*api.MrtMessage))
	})
}

func (s *Server) ModMrt(ctx context.Context, arg *api.ModMrtArguments) (*api.Error, error) {
	return s.mod(api.REQ_MOD_MRT, arg)
}

func (s *Server) ModBmp(ctx context.Context, arg *api.ModBmpArguments) (*api.Error, error) {
	return s.mod(api.REQ_MOD_BMP, arg)
}

func (s *Server) ModRPKI(ctx context.Context, arg *api.ModRpkiArguments) (*api.Error, error) {
	return s.mod(api.REQ_MOD_RPKI, arg)
}

func (s *Server) GetRPKI(arg *api.Arguments, stream api.GobgpApi_GetRPKIServer) error {
	req := api.NewRequest(api.REQ_RPKI, arg)
	s.bgpServerCh <- req
	return api.HandleMultipleResponses(req, func(res *api.Response) error {
		return stream.Send(res.Data.(*api.RPKI))
	})
}

func (s *Server) GetROA(arg *api.Arguments, stream api.GobgpApi_GetROAServer) error {
	req := api.NewRequest(api.REQ_ROA, arg)
	s.bgpServerCh <- req
	return api.HandleMultipleResponses(req, func(res *api.Response) error {
		return stream.Send(res.Data.(*api.ROA))
	})
}

func (s *Server) GetVrfs(arg *api.Arguments, stream api.GobgpApi_GetVrfsServer) error {
	req := api.NewRequest(api.REQ_VRFS, arg)
	s.bgpServerCh <- req
	return api.HandleMultipleResponses(req, func(res *api.Response) error {
		return stream.Send(res.Data.(*api.Vrf))
	})
}

func (s *Server) ModVrf(ctx context.Context, arg *api.ModVrfArguments) (*api.Error, error) {
	return s.mod(api.REQ_VRF_MOD, arg)
}

func (s *Server) ModNeighbor(ctx context.Context, arg *api.ModNeighborArguments) (*api.Error, error) {
	return s.mod(api.REQ_MOD_NEIGHBOR, arg)
}

func (s *Server) GetDefinedSet(ctx context.Context, arg *api.DefinedSet) (*api.DefinedSet, error) {
	d, err := s.get(api.REQ_DEFINED_SET, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.DefinedSet), nil
}

func (s *Server) GetDefinedSets(arg *api.DefinedSet, stream api.GobgpApi_GetDefinedSetsServer) error {
	req := api.NewRequest(api.REQ_DEFINED_SET, arg)
	s.bgpServerCh <- req
	return api.HandleMultipleResponses(req, func(res *api.Response) error {
		return stream.Send(res.Data.(*api.DefinedSet))
	})
}

func (s *Server) ModDefinedSet(ctx context.Context, arg *api.ModDefinedSetArguments) (*api.Error, error) {
	return s.mod(api.REQ_MOD_DEFINED_SET, arg)
}

func (s *Server) GetStatement(ctx context.Context, arg *api.Statement) (*api.Statement, error) {
	d, err := s.get(api.REQ_STATEMENT, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.Statement), nil
}

func (s *Server) GetStatements(arg *api.Statement, stream api.GobgpApi_GetStatementsServer) error {
	req := api.NewRequest(api.REQ_STATEMENT, arg)
	s.bgpServerCh <- req
	return api.HandleMultipleResponses(req, func(res *api.Response) error {
		return stream.Send(res.Data.(*api.Statement))
	})
}

func (s *Server) ModStatement(ctx context.Context, arg *api.ModStatementArguments) (*api.Error, error) {
	return s.mod(api.REQ_MOD_STATEMENT, arg)
}

func (s *Server) GetPolicy(ctx context.Context, arg *api.Policy) (*api.Policy, error) {
	d, err := s.get(api.REQ_POLICY, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.Policy), nil
}

func (s *Server) GetPolicies(arg *api.Policy, stream api.GobgpApi_GetPoliciesServer) error {
	req := api.NewRequest(api.REQ_POLICY, arg)
	s.bgpServerCh <- req
	return api.HandleMultipleResponses(req, func(res *api.Response) error {
		return stream.Send(res.Data.(*api.Policy))
	})
}

func (s *Server) ModPolicy(ctx context.Context, arg *api.ModPolicyArguments) (*api.Error, error) {
	return s.mod(api.REQ_MOD_POLICY, arg)
}

func (s *Server) GetPolicyAssignment(ctx context.Context, arg *api.PolicyAssignment) (*api.PolicyAssignment, error) {
	d, err := s.get(api.REQ_POLICY_ASSIGNMENT, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.PolicyAssignment), nil
}

func (s *Server) ModPolicyAssignment(ctx context.Context, arg *api.ModPolicyAssignmentArguments) (*api.Error, error) {
	return s.mod(api.REQ_MOD_POLICY_ASSIGNMENT, arg)
}

func (s *Server) GetGlobalConfig(ctx context.Context, arg *api.Arguments) (*api.Global, error) {
	d, err := s.get(api.REQ_GLOBAL_CONFIG, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.Global), nil
}

func (s *Server) ModGlobalConfig(ctx context.Context, arg *api.ModGlobalConfigArguments) (*api.Error, error) {
	return s.mod(api.REQ_MOD_GLOBAL_CONFIG, arg)
}

func NewGrpcServer(port int, bgpServerCh chan *api.Request) *Server {
	grpcServer := grpc.NewServer()
	server := &Server{
		grpcServer:  grpcServer,
		bgpServerCh: bgpServerCh,
		port:        port,
	}
	api.RegisterGobgpApiServer(grpcServer, server)
	return server
}
