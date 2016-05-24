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
	"github.com/osrg/gobgp/packet/bgp"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"net"
	"strings"
	"sync"
)

const (
	_ = iota
	REQ_GET_SERVER
	REQ_START_SERVER
	REQ_STOP_SERVER
	REQ_NEIGHBOR
	REQ_ADJ_RIB_IN
	REQ_ADJ_RIB_OUT
	REQ_LOCAL_RIB
	REQ_NEIGHBOR_RESET
	REQ_NEIGHBOR_SOFT_RESET
	REQ_NEIGHBOR_SOFT_RESET_IN
	REQ_NEIGHBOR_SOFT_RESET_OUT
	REQ_NEIGHBOR_SHUTDOWN
	REQ_NEIGHBOR_ENABLE
	REQ_NEIGHBOR_DISABLE
	REQ_ADD_NEIGHBOR
	REQ_DEL_NEIGHBOR
	// FIXME: we should merge
	REQ_GRPC_ADD_NEIGHBOR
	REQ_GRPC_DELETE_NEIGHBOR
	REQ_UPDATE_NEIGHBOR
	REQ_GLOBAL_RIB
	REQ_MONITOR_RIB
	REQ_MONITOR_NEIGHBOR_PEER_STATE
	REQ_ENABLE_MRT
	REQ_DISABLE_MRT
	REQ_INJECT_MRT
	REQ_ADD_BMP
	REQ_DELETE_BMP
	REQ_VALIDATE_RIB
	// TODO: delete
	REQ_INITIALIZE_RPKI
	REQ_GET_RPKI
	REQ_ADD_RPKI
	REQ_DELETE_RPKI
	REQ_ENABLE_RPKI
	REQ_DISABLE_RPKI
	REQ_RESET_RPKI
	REQ_SOFT_RESET_RPKI
	REQ_ROA
	REQ_ADD_VRF
	REQ_DELETE_VRF
	REQ_VRF
	REQ_GET_VRF
	REQ_ADD_PATH
	REQ_DELETE_PATH
	REQ_GET_DEFINED_SET
	REQ_ADD_DEFINED_SET
	REQ_DELETE_DEFINED_SET
	REQ_REPLACE_DEFINED_SET
	REQ_GET_STATEMENT
	REQ_ADD_STATEMENT
	REQ_DELETE_STATEMENT
	REQ_REPLACE_STATEMENT
	REQ_GET_POLICY
	REQ_ADD_POLICY
	REQ_DELETE_POLICY
	REQ_REPLACE_POLICY
	REQ_GET_POLICY_ASSIGNMENT
	REQ_ADD_POLICY_ASSIGNMENT
	REQ_DELETE_POLICY_ASSIGNMENT
	REQ_REPLACE_POLICY_ASSIGNMENT
	REQ_BMP_NEIGHBORS
	REQ_BMP_GLOBAL
	REQ_BMP_ADJ_IN
	REQ_DEFERRAL_TIMER_EXPIRED
	REQ_RELOAD_POLICY
	REQ_INITIALIZE_ZEBRA
	REQ_INITIALIZE_COLLECTOR
	REQ_WATCHER_ADJ_RIB_IN // FIXME
)

type Server struct {
	grpcServer  *grpc.Server
	bgpServerCh chan *GrpcRequest
	hosts       string
}

func (s *Server) Serve() error {
	var wg sync.WaitGroup
	l := strings.Split(s.hosts, ",")
	wg.Add(len(l))

	serve := func(host string) {
		for {
			defer wg.Done()
			lis, err := net.Listen("tcp", fmt.Sprintf(host))
			if err != nil {
				log.WithFields(log.Fields{
					"Topic": "grpc",
					"Key":   host,
					"Error": err,
				}).Warn("listen failed")
				return
			}
			err = s.grpcServer.Serve(lis)
			log.WithFields(log.Fields{
				"Topic": "grpc",
				"Key":   host,
				"Error": err,
			}).Warn("accept failed")
		}
	}
	for _, host := range l {
		go serve(host)
	}
	wg.Wait()
	return nil
}

func (s *Server) GetNeighbor(ctx context.Context, arg *api.GetNeighborRequest) (*api.GetNeighborResponse, error) {
	var rf bgp.RouteFamily
	req := NewGrpcRequest(REQ_NEIGHBOR, "", rf, nil)
	s.bgpServerCh <- req
	res := <-req.ResponseCh
	if res.Err() != nil {
		return nil, res.Err()
	}
	return res.Data.(*api.GetNeighborResponse), nil
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

func (s *Server) GetRib(ctx context.Context, arg *api.GetRibRequest) (*api.GetRibResponse, error) {
	var reqType int
	switch arg.Table.Type {
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
		return nil, fmt.Errorf("unsupported resource type: %v", arg.Table.Type)
	}
	d, err := s.get(reqType, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.GetRibResponse), nil
}

func (s *Server) MonitorRib(arg *api.Table, stream api.GobgpApi_MonitorRibServer) error {
	switch arg.Type {
	case api.Resource_ADJ_IN, api.Resource_GLOBAL:
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Type)
	}

	req := NewGrpcRequest(REQ_MONITOR_RIB, arg.Name, bgp.RouteFamily(arg.Family), arg)
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

func (s *Server) neighbor(reqType int, address string, d interface{}) (interface{}, error) {
	req := NewGrpcRequest(reqType, address, bgp.RouteFamily(0), d)
	s.bgpServerCh <- req
	res := <-req.ResponseCh
	return res.Data, res.Err()
}

func (s *Server) ResetNeighbor(ctx context.Context, arg *api.ResetNeighborRequest) (*api.ResetNeighborResponse, error) {
	d, err := s.neighbor(REQ_NEIGHBOR_RESET, arg.Address, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.ResetNeighborResponse), err
}

func (s *Server) SoftResetNeighbor(ctx context.Context, arg *api.SoftResetNeighborRequest) (*api.SoftResetNeighborResponse, error) {
	op := REQ_NEIGHBOR_SOFT_RESET
	switch arg.Direction {
	case api.SoftResetNeighborRequest_IN:
		op = REQ_NEIGHBOR_SOFT_RESET_IN
	case api.SoftResetNeighborRequest_OUT:
		op = REQ_NEIGHBOR_SOFT_RESET_OUT
	}
	d, err := s.neighbor(op, arg.Address, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.SoftResetNeighborResponse), err
}

func (s *Server) ShutdownNeighbor(ctx context.Context, arg *api.ShutdownNeighborRequest) (*api.ShutdownNeighborResponse, error) {
	d, err := s.neighbor(REQ_NEIGHBOR_SHUTDOWN, arg.Address, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.ShutdownNeighborResponse), err
}

func (s *Server) EnableNeighbor(ctx context.Context, arg *api.EnableNeighborRequest) (*api.EnableNeighborResponse, error) {
	d, err := s.neighbor(REQ_NEIGHBOR_ENABLE, arg.Address, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.EnableNeighborResponse), err
}

func (s *Server) DisableNeighbor(ctx context.Context, arg *api.DisableNeighborRequest) (*api.DisableNeighborResponse, error) {
	d, err := s.neighbor(REQ_NEIGHBOR_DISABLE, arg.Address, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.DisableNeighborResponse), err
}

func (s *Server) AddPath(ctx context.Context, arg *api.AddPathRequest) (*api.AddPathResponse, error) {
	d, err := s.get(REQ_ADD_PATH, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.AddPathResponse), err
}

func (s *Server) DeletePath(ctx context.Context, arg *api.DeletePathRequest) (*api.DeletePathResponse, error) {
	d, err := s.get(REQ_DELETE_PATH, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.DeletePathResponse), err
}

func (s *Server) EnableMrt(ctx context.Context, arg *api.EnableMrtRequest) (*api.EnableMrtResponse, error) {
	d, err := s.get(REQ_ENABLE_MRT, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.EnableMrtResponse), err
}

func (s *Server) DisableMrt(ctx context.Context, arg *api.DisableMrtRequest) (*api.DisableMrtResponse, error) {
	d, err := s.get(REQ_DISABLE_MRT, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.DisableMrtResponse), err
}

func (s *Server) InjectMrt(stream api.GobgpApi_InjectMrtServer) error {
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

		req := NewGrpcRequest(REQ_INJECT_MRT, "", bgp.RouteFamily(0), arg)
		s.bgpServerCh <- req

		res := <-req.ResponseCh
		if err := res.Err(); err != nil {
			log.Debug(err.Error())
			return err
		}
	}
	return stream.SendAndClose(&api.InjectMrtResponse{})
}

func (s *Server) AddBmp(ctx context.Context, arg *api.AddBmpRequest) (*api.AddBmpResponse, error) {
	d, err := s.get(REQ_ADD_BMP, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.AddBmpResponse), err
}

func (s *Server) DeleteBmp(ctx context.Context, arg *api.DeleteBmpRequest) (*api.DeleteBmpResponse, error) {
	d, err := s.get(REQ_DELETE_BMP, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.DeleteBmpResponse), err
}

func (s *Server) ValidateRib(ctx context.Context, arg *api.ValidateRibRequest) (*api.ValidateRibResponse, error) {
	d, err := s.get(REQ_VALIDATE_RIB, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.ValidateRibResponse), err
}

func (s *Server) AddRpki(ctx context.Context, arg *api.AddRpkiRequest) (*api.AddRpkiResponse, error) {
	d, err := s.get(REQ_ADD_RPKI, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.AddRpkiResponse), err
}

func (s *Server) DeleteRpki(ctx context.Context, arg *api.DeleteRpkiRequest) (*api.DeleteRpkiResponse, error) {
	d, err := s.get(REQ_DELETE_RPKI, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.DeleteRpkiResponse), err
}

func (s *Server) EnableRpki(ctx context.Context, arg *api.EnableRpkiRequest) (*api.EnableRpkiResponse, error) {
	d, err := s.get(REQ_ENABLE_RPKI, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.EnableRpkiResponse), err
}

func (s *Server) DisableRpki(ctx context.Context, arg *api.DisableRpkiRequest) (*api.DisableRpkiResponse, error) {
	d, err := s.get(REQ_DISABLE_RPKI, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.DisableRpkiResponse), err
}

func (s *Server) ResetRpki(ctx context.Context, arg *api.ResetRpkiRequest) (*api.ResetRpkiResponse, error) {
	d, err := s.get(REQ_RESET_RPKI, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.ResetRpkiResponse), err
}

func (s *Server) SoftResetRpki(ctx context.Context, arg *api.SoftResetRpkiRequest) (*api.SoftResetRpkiResponse, error) {
	d, err := s.get(REQ_SOFT_RESET_RPKI, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.SoftResetRpkiResponse), err
}

func (s *Server) GetRpki(ctx context.Context, arg *api.GetRpkiRequest) (*api.GetRpkiResponse, error) {
	req := NewGrpcRequest(REQ_GET_RPKI, "", bgp.RouteFamily(arg.Family), nil)
	s.bgpServerCh <- req
	res := <-req.ResponseCh
	if res.Err() != nil {
		return nil, res.Err()
	}
	return res.Data.(*api.GetRpkiResponse), res.Err()
}

func (s *Server) GetRoa(ctx context.Context, arg *api.GetRoaRequest) (*api.GetRoaResponse, error) {
	req := NewGrpcRequest(REQ_ROA, "", bgp.RouteFamily(arg.Family), nil)
	s.bgpServerCh <- req
	res := <-req.ResponseCh
	if res.Err() != nil {
		return nil, res.Err()
	}
	return res.Data.(*api.GetRoaResponse), res.Err()
}

func (s *Server) GetVrf(ctx context.Context, arg *api.GetVrfRequest) (*api.GetVrfResponse, error) {
	req := NewGrpcRequest(REQ_GET_VRF, "", bgp.RouteFamily(0), nil)
	s.bgpServerCh <- req
	res := <-req.ResponseCh
	if res.Err() != nil {
		return nil, res.Err()
	}
	return res.Data.(*api.GetVrfResponse), res.Err()
}

func (s *Server) get(typ int, d interface{}) (interface{}, error) {
	req := NewGrpcRequest(typ, "", bgp.RouteFamily(0), d)
	s.bgpServerCh <- req
	res := <-req.ResponseCh
	return res.Data, res.Err()
}

func (s *Server) AddVrf(ctx context.Context, arg *api.AddVrfRequest) (*api.AddVrfResponse, error) {
	d, err := s.get(REQ_ADD_VRF, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.AddVrfResponse), err
}

func (s *Server) DeleteVrf(ctx context.Context, arg *api.DeleteVrfRequest) (*api.DeleteVrfResponse, error) {
	d, err := s.get(REQ_DELETE_VRF, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.DeleteVrfResponse), err
}

func (s *Server) AddNeighbor(ctx context.Context, arg *api.AddNeighborRequest) (*api.AddNeighborResponse, error) {
	d, err := s.get(REQ_GRPC_ADD_NEIGHBOR, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.AddNeighborResponse), err
}

func (s *Server) DeleteNeighbor(ctx context.Context, arg *api.DeleteNeighborRequest) (*api.DeleteNeighborResponse, error) {
	d, err := s.get(REQ_GRPC_DELETE_NEIGHBOR, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.DeleteNeighborResponse), err
}

func (s *Server) GetDefinedSet(ctx context.Context, arg *api.GetDefinedSetRequest) (*api.GetDefinedSetResponse, error) {
	d, err := s.get(REQ_GET_DEFINED_SET, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.GetDefinedSetResponse), err
}

func (s *Server) AddDefinedSet(ctx context.Context, arg *api.AddDefinedSetRequest) (*api.AddDefinedSetResponse, error) {
	d, err := s.get(REQ_ADD_DEFINED_SET, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.AddDefinedSetResponse), err
}

func (s *Server) DeleteDefinedSet(ctx context.Context, arg *api.DeleteDefinedSetRequest) (*api.DeleteDefinedSetResponse, error) {
	d, err := s.get(REQ_DELETE_DEFINED_SET, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.DeleteDefinedSetResponse), err
}

func (s *Server) ReplaceDefinedSet(ctx context.Context, arg *api.ReplaceDefinedSetRequest) (*api.ReplaceDefinedSetResponse, error) {
	d, err := s.get(REQ_REPLACE_DEFINED_SET, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.ReplaceDefinedSetResponse), err
}

func (s *Server) GetStatement(ctx context.Context, arg *api.GetStatementRequest) (*api.GetStatementResponse, error) {
	d, err := s.get(REQ_GET_STATEMENT, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.GetStatementResponse), err
}

func (s *Server) AddStatement(ctx context.Context, arg *api.AddStatementRequest) (*api.AddStatementResponse, error) {
	d, err := s.get(REQ_ADD_STATEMENT, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.AddStatementResponse), err
}

func (s *Server) DeleteStatement(ctx context.Context, arg *api.DeleteStatementRequest) (*api.DeleteStatementResponse, error) {
	d, err := s.get(REQ_DELETE_STATEMENT, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.DeleteStatementResponse), err
}

func (s *Server) ReplaceStatement(ctx context.Context, arg *api.ReplaceStatementRequest) (*api.ReplaceStatementResponse, error) {
	d, err := s.get(REQ_REPLACE_STATEMENT, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.ReplaceStatementResponse), err
}

func (s *Server) GetPolicy(ctx context.Context, arg *api.GetPolicyRequest) (*api.GetPolicyResponse, error) {
	d, err := s.get(REQ_GET_POLICY, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.GetPolicyResponse), err
}

func (s *Server) AddPolicy(ctx context.Context, arg *api.AddPolicyRequest) (*api.AddPolicyResponse, error) {
	d, err := s.get(REQ_ADD_POLICY, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.AddPolicyResponse), err
}

func (s *Server) DeletePolicy(ctx context.Context, arg *api.DeletePolicyRequest) (*api.DeletePolicyResponse, error) {
	d, err := s.get(REQ_DELETE_POLICY, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.DeletePolicyResponse), err
}

func (s *Server) ReplacePolicy(ctx context.Context, arg *api.ReplacePolicyRequest) (*api.ReplacePolicyResponse, error) {
	d, err := s.get(REQ_REPLACE_POLICY, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.ReplacePolicyResponse), err
}

func (s *Server) GetPolicyAssignment(ctx context.Context, arg *api.GetPolicyAssignmentRequest) (*api.GetPolicyAssignmentResponse, error) {
	d, err := s.get(REQ_GET_POLICY_ASSIGNMENT, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.GetPolicyAssignmentResponse), err
}

func (s *Server) AddPolicyAssignment(ctx context.Context, arg *api.AddPolicyAssignmentRequest) (*api.AddPolicyAssignmentResponse, error) {
	d, err := s.get(REQ_ADD_POLICY_ASSIGNMENT, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.AddPolicyAssignmentResponse), err
}

func (s *Server) DeletePolicyAssignment(ctx context.Context, arg *api.DeletePolicyAssignmentRequest) (*api.DeletePolicyAssignmentResponse, error) {
	d, err := s.get(REQ_DELETE_POLICY_ASSIGNMENT, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.DeletePolicyAssignmentResponse), err
}

func (s *Server) ReplacePolicyAssignment(ctx context.Context, arg *api.ReplacePolicyAssignmentRequest) (*api.ReplacePolicyAssignmentResponse, error) {
	d, err := s.get(REQ_REPLACE_POLICY_ASSIGNMENT, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.ReplacePolicyAssignmentResponse), err
}

func (s *Server) GetServer(ctx context.Context, arg *api.GetServerRequest) (*api.GetServerResponse, error) {
	d, err := s.get(REQ_GET_SERVER, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.GetServerResponse), err
}

func (s *Server) StartServer(ctx context.Context, arg *api.StartServerRequest) (*api.StartServerResponse, error) {
	d, err := s.get(REQ_START_SERVER, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.StartServerResponse), err
}

func (s *Server) StopServer(ctx context.Context, arg *api.StopServerRequest) (*api.StopServerResponse, error) {
	d, err := s.get(REQ_STOP_SERVER, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.StopServerResponse), err
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

func NewGrpcServer(hosts string, bgpServerCh chan *GrpcRequest) *Server {
	grpc.EnableTracing = false
	grpcServer := grpc.NewServer()
	server := &Server{
		grpcServer:  grpcServer,
		bgpServerCh: bgpServerCh,
		hosts:       hosts,
	}
	api.RegisterGobgpApiServer(grpcServer, server)
	return server
}
