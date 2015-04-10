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
	"fmt"
	log "github.com/Sirupsen/logrus"
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

func (s *Server) GetNeighbor(ctx context.Context, arg *Arguments) (*Peer, error) {
	var rf bgp.RouteFamily
	req := NewGrpcRequest(REQ_NEIGHBOR, arg.RouterId, rf, nil)
	s.bgpServerCh <- req

	res := <-req.ResponseCh
	if err := res.Err(); err != nil {
		log.Debug(err.Error())
		return nil, err
	}

	return res.Data.(*Peer), nil
}

func (s *Server) GetNeighbors(_ *Arguments, stream Grpc_GetNeighborsServer) error {
	var rf bgp.RouteFamily
	req := NewGrpcRequest(REQ_NEIGHBORS, "", rf, nil)
	s.bgpServerCh <- req

	for res := range req.ResponseCh {
		if err := res.Err(); err != nil {
			log.Debug(err.Error())
			return err
		}
		if err := stream.Send(res.Data.(*Peer)); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) GetAdjRib(arg *Arguments, stream Grpc_GetAdjRibServer) error {
	var reqType int
	switch arg.Resource {
	case Resource_ADJ_IN:
		reqType = REQ_ADJ_RIB_IN
	case Resource_ADJ_OUT:
		reqType = REQ_ADJ_RIB_OUT
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}

	var rf bgp.RouteFamily
	switch arg.Af {
	case AddressFamily_IPV4:
		rf = bgp.RF_IPv4_UC
	case AddressFamily_IPV6:
		rf = bgp.RF_IPv6_UC
	case AddressFamily_EVPN:
		rf = bgp.RF_EVPN
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Af)
	}

	req := NewGrpcRequest(reqType, arg.RouterId, rf, nil)
	s.bgpServerCh <- req

	for res := range req.ResponseCh {
		if err := res.Err(); err != nil {
			log.Debug(err.Error())
			return err
		}
		if err := stream.Send(res.Data.(*Path)); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) GetRib(arg *Arguments, stream Grpc_GetRibServer) error {
	var reqType int
	switch arg.Resource {
	case Resource_LOCAL:
		reqType = REQ_LOCAL_RIB
	case Resource_GLOBAL:
		reqType = REQ_GLOBAL_RIB
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}

	var rf bgp.RouteFamily
	switch arg.Af {
	case AddressFamily_IPV4:
		rf = bgp.RF_IPv4_UC
	case AddressFamily_IPV6:
		rf = bgp.RF_IPv6_UC
	case AddressFamily_EVPN:
		rf = bgp.RF_EVPN
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Af)
	}

	req := NewGrpcRequest(reqType, arg.RouterId, rf, nil)
	s.bgpServerCh <- req

	for res := range req.ResponseCh {
		if err := res.Err(); err != nil {
			log.Debug(err.Error())
			return err
		}
		if err := stream.Send(res.Data.(*Destination)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) neighbor(reqType int, arg *Arguments) (*Error, error) {
	var rf bgp.RouteFamily
	switch arg.Af {
	case AddressFamily_IPV4:
		rf = bgp.RF_IPv4_UC
	case AddressFamily_IPV6:
		rf = bgp.RF_IPv6_UC
	case AddressFamily_EVPN:
		rf = bgp.RF_EVPN
	default:
		return nil, fmt.Errorf("unsupported resource type: %v", arg.Af)
	}

	none := &Error{}
	req := NewGrpcRequest(reqType, arg.RouterId, rf, nil)
	s.bgpServerCh <- req

	res := <-req.ResponseCh
	if err := res.Err(); err != nil {
		log.Debug(err.Error())
		return nil, err
	}
	return none, nil
}

func (s *Server) Reset(ctx context.Context, arg *Arguments) (*Error, error) {
	return s.neighbor(REQ_NEIGHBOR_RESET, arg)
}

func (s *Server) SoftReset(ctx context.Context, arg *Arguments) (*Error, error) {
	return s.neighbor(REQ_NEIGHBOR_SOFT_RESET, arg)
}

func (s *Server) SoftResetIn(ctx context.Context, arg *Arguments) (*Error, error) {
	return s.neighbor(REQ_NEIGHBOR_SOFT_RESET_IN, arg)
}

func (s *Server) SoftResetOut(ctx context.Context, arg *Arguments) (*Error, error) {
	return s.neighbor(REQ_NEIGHBOR_SOFT_RESET_OUT, arg)
}

func (s *Server) Shutdown(ctx context.Context, arg *Arguments) (*Error, error) {
	return s.neighbor(REQ_NEIGHBOR_SHUTDOWN, arg)
}

func (s *Server) Enable(ctx context.Context, arg *Arguments) (*Error, error) {
	return s.neighbor(REQ_NEIGHBOR_ENABLE, arg)
}

func (s *Server) Disable(ctx context.Context, arg *Arguments) (*Error, error) {
	return s.neighbor(REQ_NEIGHBOR_DISABLE, arg)
}

func (s *Server) modPath(reqType int, stream grpc.ServerStream) error {
	for {
		var err error
		var arg *Arguments

		if reqType == REQ_GLOBAL_ADD {
			arg, err = stream.(Grpc_AddPathServer).Recv()
		} else if reqType == REQ_GLOBAL_DELETE {
			arg, err = stream.(Grpc_DeletePathServer).Recv()
		} else {
			return fmt.Errorf("unsupportd req: %d", reqType)
		}

		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}

		if arg.Resource != Resource_GLOBAL {
			return fmt.Errorf("unsupported resource: %s", arg.Resource)
		}
		prefix := make(map[string]interface{}, 1)
		prefix["prefix"] = arg.Prefix

		var rf bgp.RouteFamily
		switch arg.Af {
		case AddressFamily_IPV4:
			rf = bgp.RF_IPv4_UC
		case AddressFamily_IPV6:
			rf = bgp.RF_IPv6_UC
		case AddressFamily_EVPN:
			rf = bgp.RF_EVPN
		default:
			return fmt.Errorf("unsupported resource type: %v", arg.Af)
		}

		req := NewGrpcRequest(reqType, arg.RouterId, rf, prefix)
		s.bgpServerCh <- req

		res := <-req.ResponseCh
		if err := res.Err(); err != nil {
			log.Debug(err.Error())
			return err
		}
	}
}

func (s *Server) AddPath(stream Grpc_AddPathServer) error {
	return s.modPath(REQ_GLOBAL_ADD, stream)
}

func (s *Server) DeletePath(stream Grpc_DeletePathServer) error {
	return s.modPath(REQ_GLOBAL_DELETE, stream)
}

type GrpcRequest struct {
	RequestType int
	RemoteAddr  string
	RouteFamily bgp.RouteFamily
	ResponseCh  chan *GrpcResponse
	Err         error
	Data        map[string]interface{}
}

func NewGrpcRequest(reqType int, remoteAddr string, rf bgp.RouteFamily, d map[string]interface{}) *GrpcRequest {
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
	RegisterGrpcServer(grpcServer, server)
	return server
}
