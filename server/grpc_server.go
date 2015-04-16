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
	REQ_GLOBAL_RIB
	REQ_GLOBAL_ADD
	REQ_GLOBAL_DELETE
	REQ_MONITOR_BEST_CHANGED
)

const GRPC_PORT = 8080

func convertAf2Rf(af *api.AddressFamily) (bgp.RouteFamily, error) {
	if af.Equal(api.AF_IPV4_UC) {
		return bgp.RF_IPv4_UC, nil
	} else if af.Equal(api.AF_IPV6_UC) {
		return bgp.RF_IPv6_UC, nil
	} else if af.Equal(api.AF_EVPN) {
		return bgp.RF_EVPN, nil
	} else if af.Equal(api.AF_ENCAP) {
		return bgp.RF_ENCAP, nil
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
	rf, err := convertAf2Rf(arg.Af)
	if err != nil {
		return err
	}

	req := NewGrpcRequest(REQ_MONITOR_BEST_CHANGED, arg.RouterId, rf, nil)
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
			return nil
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

		err = stream.Send(&api.Error{
			Code: api.Error_SUCCESS,
		})

		if err != nil {
			return err
		}
	}
}

type GrpcRequest struct {
	RequestType int
	RemoteAddr  string
	RouteFamily bgp.RouteFamily
	ResponseCh  chan *GrpcResponse
	Err         error
	Data        interface{}
}

func NewGrpcRequest(reqType int, remoteAddr string, rf bgp.RouteFamily, d interface{}) *GrpcRequest {
	r := &GrpcRequest{
		RequestType: reqType,
		RouteFamily: rf,
		RemoteAddr:  remoteAddr,
		ResponseCh:  make(chan *GrpcResponse),
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
