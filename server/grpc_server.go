// Copyright (C) 2014-2016 Nippon Telegraph and Telephone Corporation.
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
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
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
	REQ_DELETE_NEIGHBOR
	REQ_UPDATE_NEIGHBOR
	REQ_GLOBAL_RIB
	REQ_MONITOR_RIB
	REQ_MONITOR_NEIGHBOR_PEER_STATE
	REQ_ENABLE_MRT
	REQ_DISABLE_MRT
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
	REQ_DEFERRAL_TIMER_EXPIRED
	REQ_RELOAD_POLICY
	REQ_INITIALIZE_ZEBRA
)

type Server struct {
	bgpServer   *BgpServer
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
	toApi := func(pconf *config.Neighbor) *api.Peer {
		prefixLimits := make([]*api.PrefixLimit, 0, len(pconf.AfiSafis))
		for _, family := range pconf.AfiSafis {
			if c := family.PrefixLimit.Config; c.MaxPrefixes > 0 {
				k, _ := bgp.GetRouteFamily(string(family.Config.AfiSafiName))
				prefixLimits = append(prefixLimits, &api.PrefixLimit{
					Family:               uint32(k),
					MaxPrefixes:          c.MaxPrefixes,
					ShutdownThresholdPct: uint32(c.ShutdownThresholdPct),
				})
			}
		}

		timer := pconf.Timers
		s := pconf.State
		return &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress:  pconf.Config.NeighborAddress,
				Id:               s.Description,
				PeerAs:           pconf.Config.PeerAs,
				LocalAs:          pconf.Config.LocalAs,
				PeerType:         uint32(pconf.Config.PeerType.ToInt()),
				AuthPassword:     pconf.Config.AuthPassword,
				RemovePrivateAs:  uint32(pconf.Config.RemovePrivateAs.ToInt()),
				RouteFlapDamping: pconf.Config.RouteFlapDamping,
				SendCommunity:    uint32(pconf.Config.SendCommunity.ToInt()),
				Description:      pconf.Config.Description,
				PeerGroup:        pconf.Config.PeerGroup,
				RemoteCap:        s.Capabilities.RemoteList,
				LocalCap:         s.Capabilities.LocalList,
				PrefixLimits:     prefixLimits,
			},
			Info: &api.PeerState{
				BgpState:   bgp.FSMState(s.SessionState.ToInt()).String(),
				AdminState: s.AdminState,
				Messages: &api.Messages{
					Received: &api.Message{
						NOTIFICATION: s.Messages.Received.Notification,
						UPDATE:       s.Messages.Received.Update,
						OPEN:         s.Messages.Received.Open,
						KEEPALIVE:    s.Messages.Received.Keepalive,
						REFRESH:      s.Messages.Received.Refresh,
						DISCARDED:    s.Messages.Received.Discarded,
						TOTAL:        s.Messages.Received.Total,
					},
					Sent: &api.Message{
						NOTIFICATION: s.Messages.Sent.Notification,
						UPDATE:       s.Messages.Sent.Update,
						OPEN:         s.Messages.Sent.Open,
						KEEPALIVE:    s.Messages.Sent.Keepalive,
						REFRESH:      s.Messages.Sent.Refresh,
						DISCARDED:    s.Messages.Sent.Discarded,
						TOTAL:        s.Messages.Sent.Total,
					},
				},
				Received:   s.AdjTable.Received,
				Accepted:   s.AdjTable.Accepted,
				Advertised: s.AdjTable.Advertised,
			},
			Timers: &api.Timers{
				Config: &api.TimersConfig{
					ConnectRetry:      uint64(timer.Config.ConnectRetry),
					HoldTime:          uint64(timer.Config.HoldTime),
					KeepaliveInterval: uint64(timer.Config.KeepaliveInterval),
				},
				State: &api.TimersState{
					KeepaliveInterval:  uint64(timer.State.KeepaliveInterval),
					NegotiatedHoldTime: uint64(timer.State.NegotiatedHoldTime),
					Uptime:             uint64(timer.State.Uptime),
					Downtime:           uint64(timer.State.Downtime),
				},
			},
			RouteReflector: &api.RouteReflector{
				RouteReflectorClient:    pconf.RouteReflector.Config.RouteReflectorClient,
				RouteReflectorClusterId: string(pconf.RouteReflector.Config.RouteReflectorClusterId),
			},
			RouteServer: &api.RouteServer{
				RouteServerClient: pconf.RouteServer.Config.RouteServerClient,
			},
		}
	}

	p := []*api.Peer{}
	for _, e := range s.bgpServer.GetNeighbor() {
		p = append(p, toApi(e))
	}
	return &api.GetNeighborResponse{Peers: p}, nil
}

func toPathApi(id string, path *table.Path) *api.Path {
	nlri := path.GetNlri()
	n, _ := nlri.Serialize()
	family := uint32(bgp.AfiSafiToRouteFamily(nlri.AFI(), nlri.SAFI()))
	pattrs := func(arg []bgp.PathAttributeInterface) [][]byte {
		ret := make([][]byte, 0, len(arg))
		for _, a := range arg {
			aa, _ := a.Serialize()
			ret = append(ret, aa)
		}
		return ret
	}(path.GetPathAttrs())
	return &api.Path{
		Nlri:           n,
		Pattrs:         pattrs,
		Age:            path.GetTimestamp().Unix(),
		IsWithdraw:     path.IsWithdraw,
		Validation:     int32(path.Validation().ToInt()),
		Filtered:       path.Filtered(id) == table.POLICY_DIRECTION_IN,
		Family:         family,
		SourceAsn:      path.GetSource().AS,
		SourceId:       path.GetSource().ID.String(),
		NeighborIp:     path.GetSource().Address.String(),
		Stale:          path.IsStale(),
		IsFromExternal: path.IsFromExternal(),
	}
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

	switch reqType {
	case REQ_LOCAL_RIB, REQ_GLOBAL_RIB:
		dsts := make([]*api.Destination, 0, len(d.(map[string][]*table.Path)))
		for k, v := range d.(map[string][]*table.Path) {
			dsts = append(dsts, &api.Destination{
				Prefix: k,
				Paths: func(paths []*table.Path) []*api.Path {
					l := make([]*api.Path, 0, len(v))
					for i, p := range paths {
						pp := toPathApi("", p)
						if i == 0 {
							pp.Best = true
						}
						l = append(l, pp)
					}
					return l
				}(v),
			})
		}
		d := &api.Table{
			Type:         arg.Table.Type,
			Family:       arg.Table.Family,
			Destinations: dsts,
		}
		return &api.GetRibResponse{Table: d}, nil
	case REQ_ADJ_RIB_IN, REQ_ADJ_RIB_OUT, REQ_VRF:
		dsts := make([]*api.Destination, 0, len(d.([]*table.Path)))
		var prefix string
		var dst *api.Destination
		for _, path := range d.([]*table.Path) {
			if path.GetNlri().String() != prefix {
				prefix = path.GetNlri().String()
				dst = &api.Destination{
					Prefix: prefix,
					Paths:  []*api.Path{toPathApi(arg.Table.Name, path)},
				}
			} else {
				dst.Paths = append(dst.Paths, toPathApi(arg.Table.Name, path))
			}
			dsts = append(dsts, dst)
		}
		return &api.GetRibResponse{
			Table: &api.Table{
				Type:         arg.Table.Type,
				Family:       arg.Table.Family,
				Destinations: dsts,
			},
		}, nil
	}
	return d.(*api.GetRibResponse), nil
}

func (s *Server) MonitorRib(arg *api.Table, stream api.GobgpApi_MonitorRibServer) error {
	w, err := func() (*Watcher, error) {
		switch arg.Type {
		case api.Resource_GLOBAL:
			return s.bgpServer.Watch(WatchBestPath()), nil
		case api.Resource_ADJ_IN:
			if arg.PostPolicy {
				return s.bgpServer.Watch(WatchPostUpdate(false)), nil
			}
			return s.bgpServer.Watch(WatchUpdate(false)), nil
		default:
			return nil, fmt.Errorf("unsupported resource type: %v", arg.Type)
		}
	}()
	if err != nil {
		return nil
	}

	return func() error {
		defer func() { w.Stop() }()

		sendPath := func(pathList []*table.Path) error {
			dsts := make(map[string]*api.Destination)
			for _, path := range pathList {
				if path == nil {
					continue
				}
				if dst, y := dsts[path.GetNlri().String()]; y {
					dst.Paths = append(dst.Paths, toPathApi(table.GLOBAL_RIB_NAME, path))
				} else {
					dsts[path.GetNlri().String()] = &api.Destination{
						Prefix: path.GetNlri().String(),
						Paths:  []*api.Path{toPathApi(table.GLOBAL_RIB_NAME, path)},
					}
				}
			}
			for _, dst := range dsts {
				if err := stream.Send(dst); err != nil {
					return err
				}
			}
			return nil
		}
		for {
			select {
			case ev := <-w.Event():
				switch msg := ev.(type) {
				case *WatchEventBestPath:
					if err := sendPath(func() []*table.Path {
						if len(msg.MultiPathList) > 0 {
							l := make([]*table.Path, 0)
							for _, p := range msg.MultiPathList {
								l = append(l, p...)
							}
							return l
						} else {
							return msg.PathList
						}
					}()); err != nil {
						return err
					}
				case *WatchEventUpdate:
					if err := sendPath(msg.PathList); err != nil {
						return err
					}
				}
			}
		}
	}()
}

func (s *Server) MonitorPeerState(arg *api.Arguments, stream api.GobgpApi_MonitorPeerStateServer) error {
	return func() error {
		w := s.bgpServer.Watch(WatchPeerState(false))
		defer func() { w.Stop() }()

		for {
			select {
			case ev := <-w.Event():
				switch msg := ev.(type) {
				case *WatchEventPeerState:
					if len(arg.Name) > 0 && arg.Name != msg.PeerAddress.String() {
						continue
					}
					if err := stream.Send(&api.Peer{
						Conf: &api.PeerConf{
							PeerAs:          msg.PeerAS,
							LocalAs:         msg.LocalAS,
							NeighborAddress: msg.PeerAddress.String(),
							Id:              msg.PeerID.String(),
						},
						Info: &api.PeerState{
							PeerAs:          msg.PeerAS,
							LocalAs:         msg.LocalAS,
							NeighborAddress: msg.PeerAddress.String(),
							BgpState:        msg.State.String(),
							AdminState:      msg.AdminState.String(),
						},
						Transport: &api.Transport{
							LocalAddress: msg.LocalAddress.String(),
							LocalPort:    uint32(msg.LocalPort),
							RemotePort:   uint32(msg.PeerPort),
						},
					}); err != nil {
						return err
					}
				}
			}
		}
	}()
}

func (s *Server) neighbor(reqType int, address string, d interface{}) (interface{}, error) {
	req := NewGrpcRequest(reqType, address, bgp.RouteFamily(0), d)
	s.bgpServerCh <- req
	res := <-req.ResponseCh
	return res.Data, res.Err()
}

func (s *Server) ResetNeighbor(ctx context.Context, arg *api.ResetNeighborRequest) (*api.ResetNeighborResponse, error) {
	return &api.ResetNeighborResponse{}, s.bgpServer.ResetNeighbor(arg.Address)
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
	return &api.ShutdownNeighborResponse{}, s.bgpServer.ShutdownNeighbor(arg.Address)
}

func (s *Server) EnableNeighbor(ctx context.Context, arg *api.EnableNeighborRequest) (*api.EnableNeighborResponse, error) {
	return &api.EnableNeighborResponse{}, s.bgpServer.EnableNeighbor(arg.Address)
}

func (s *Server) DisableNeighbor(ctx context.Context, arg *api.DisableNeighborRequest) (*api.DisableNeighborResponse, error) {
	return &api.DisableNeighborResponse{}, s.bgpServer.DisableNeighbor(arg.Address)
}

func (s *Server) api2PathList(resource api.Resource, ApiPathList []*api.Path) ([]*table.Path, error) {
	var nlri bgp.AddrPrefixInterface
	var nexthop string
	var pi *table.PeerInfo

	pathList := make([]*table.Path, 0, len(ApiPathList))
	for _, path := range ApiPathList {
		seen := make(map[bgp.BGPAttrType]bool)

		pattr := make([]bgp.PathAttributeInterface, 0)
		extcomms := make([]bgp.ExtendedCommunityInterface, 0)

		if path.SourceAsn != 0 {
			pi = &table.PeerInfo{
				AS:      path.SourceAsn,
				LocalID: net.ParseIP(path.SourceId),
			}
		}

		if len(path.Nlri) > 0 {
			nlri = &bgp.IPAddrPrefix{}
			err := nlri.DecodeFromBytes(path.Nlri)
			if err != nil {
				return nil, err
			}
		}

		for _, attr := range path.Pattrs {
			p, err := bgp.GetPathAttribute(attr)
			if err != nil {
				return nil, err
			}

			err = p.DecodeFromBytes(attr)
			if err != nil {
				return nil, err
			}

			if _, ok := seen[p.GetType()]; !ok {
				seen[p.GetType()] = true
			} else {
				return nil, fmt.Errorf("the path attribute apears twice. Type : " + strconv.Itoa(int(p.GetType())))
			}
			switch p.GetType() {
			case bgp.BGP_ATTR_TYPE_NEXT_HOP:
				nexthop = p.(*bgp.PathAttributeNextHop).Value.String()
			case bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES:
				value := p.(*bgp.PathAttributeExtendedCommunities).Value
				if len(value) > 0 {
					extcomms = append(extcomms, value...)
				}
			case bgp.BGP_ATTR_TYPE_MP_REACH_NLRI:
				mpreach := p.(*bgp.PathAttributeMpReachNLRI)
				if len(mpreach.Value) != 1 {
					return nil, fmt.Errorf("include only one route in mp_reach_nlri")
				}
				nlri = mpreach.Value[0]
				nexthop = mpreach.Nexthop.String()
			default:
				pattr = append(pattr, p)
			}
		}

		if nlri == nil || nexthop == "" {
			return nil, fmt.Errorf("not found nlri or nexthop")
		}

		rf := bgp.AfiSafiToRouteFamily(nlri.AFI(), nlri.SAFI())

		if resource != api.Resource_VRF && rf == bgp.RF_IPv4_UC {
			pattr = append(pattr, bgp.NewPathAttributeNextHop(nexthop))
		} else {
			pattr = append(pattr, bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}))
		}

		if len(extcomms) > 0 {
			pattr = append(pattr, bgp.NewPathAttributeExtendedCommunities(extcomms))
		}
		newPath := table.NewPath(pi, nlri, path.IsWithdraw, pattr, time.Now(), path.NoImplicitWithdraw)
		newPath.SetIsFromExternal(path.IsFromExternal)
		pathList = append(pathList, newPath)
	}
	return pathList, nil
}

func (s *Server) AddPath(ctx context.Context, arg *api.AddPathRequest) (*api.AddPathResponse, error) {
	pathList, err := s.api2PathList(arg.Resource, []*api.Path{arg.Path})
	var uuid []byte
	if err == nil {
		uuid, err = s.bgpServer.AddPath(arg.VrfId, pathList)
	}
	return &api.AddPathResponse{Uuid: uuid}, err
}

func (s *Server) DeletePath(ctx context.Context, arg *api.DeletePathRequest) (*api.DeletePathResponse, error) {
	pathList, err := func() ([]*table.Path, error) {
		if arg.Path != nil {
			arg.Path.IsWithdraw = true
			return s.api2PathList(arg.Resource, []*api.Path{arg.Path})
		}
		return []*table.Path{}, nil
	}()
	if err != nil {
		return nil, err
	}
	return &api.DeletePathResponse{}, s.bgpServer.DeletePath(arg.Uuid, bgp.RouteFamily(arg.Family), arg.VrfId, pathList)
}

func (s *Server) EnableMrt(ctx context.Context, arg *api.EnableMrtRequest) (*api.EnableMrtResponse, error) {
	return &api.EnableMrtResponse{}, s.bgpServer.EnableMrt(&config.Mrt{
		Interval: arg.Interval,
		DumpType: config.IntToMrtTypeMap[int(arg.DumpType)],
		FileName: arg.Filename,
	})
}

func (s *Server) DisableMrt(ctx context.Context, arg *api.DisableMrtRequest) (*api.DisableMrtResponse, error) {
	return &api.DisableMrtResponse{}, s.bgpServer.DisableMrt()
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

		if pathList, err := s.api2PathList(arg.Resource, arg.Paths); err != nil {
			return err
		} else {
			if _, err = s.bgpServer.AddPath("", pathList); err != nil {
				return err
			}
		}
	}
	return stream.SendAndClose(&api.InjectMrtResponse{})
}

func (s *Server) AddBmp(ctx context.Context, arg *api.AddBmpRequest) (*api.AddBmpResponse, error) {
	return &api.AddBmpResponse{}, s.bgpServer.AddBmp(&config.BmpServerConfig{
		Address: arg.Address,
		Port:    arg.Port,
		RouteMonitoringPolicy: config.BmpRouteMonitoringPolicyType(arg.Type),
	})
}

func (s *Server) DeleteBmp(ctx context.Context, arg *api.DeleteBmpRequest) (*api.DeleteBmpResponse, error) {
	return &api.DeleteBmpResponse{}, s.bgpServer.DeleteBmp(&config.BmpServerConfig{
		Address: arg.Address,
		Port:    arg.Port,
	})
}

func (s *Server) ValidateRib(ctx context.Context, arg *api.ValidateRibRequest) (*api.ValidateRibResponse, error) {
	return &api.ValidateRibResponse{}, s.bgpServer.ValidateRib(arg.Prefix)
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
	d, err := s.get(REQ_GET_RPKI, arg)
	if err != nil {
		return nil, err
	}
	l := make([]*api.Rpki, 0)
	for _, s := range d.([]*config.RpkiServer) {
		received := &s.State.RpkiMessages.RpkiReceived
		sent := &s.State.RpkiMessages.RpkiSent
		rpki := &api.Rpki{
			Conf: &api.RPKIConf{
				Address:    s.Config.Address,
				RemotePort: strconv.Itoa(int(s.Config.Port)),
			},
			State: &api.RPKIState{
				Uptime:        s.State.Uptime,
				Downtime:      s.State.Downtime,
				Up:            s.State.Up,
				RecordIpv4:    s.State.RecordsV4,
				RecordIpv6:    s.State.RecordsV6,
				PrefixIpv4:    s.State.PrefixesV4,
				PrefixIpv6:    s.State.PrefixesV6,
				Serial:        s.State.SerialNumber,
				ReceivedIpv4:  received.Ipv4Prefix,
				ReceivedIpv6:  received.Ipv6Prefix,
				SerialNotify:  received.SerialNotify,
				CacheReset:    received.CacheReset,
				CacheResponse: received.CacheResponse,
				EndOfData:     received.EndOfData,
				Error:         received.Error,
				SerialQuery:   sent.SerialQuery,
				ResetQuery:    sent.ResetQuery,
			},
		}
		l = append(l, rpki)
	}
	return &api.GetRpkiResponse{Servers: l}, nil
}

func (s *Server) GetRoa(ctx context.Context, arg *api.GetRoaRequest) (*api.GetRoaResponse, error) {
	d, err := s.get(REQ_ROA, arg)
	if err != nil {
		return nil, err
	}
	l := make([]*api.Roa, 0, len(d.([]*ROA)))
	for _, r := range d.([]*ROA) {
		host, port, _ := net.SplitHostPort(r.Src)
		l = append(l, &api.Roa{
			As:        r.AS,
			Maxlen:    uint32(r.MaxLen),
			Prefixlen: uint32(r.Prefix.Length),
			Prefix:    r.Prefix.Prefix.String(),
			Conf: &api.RPKIConf{
				Address:    host,
				RemotePort: port,
			},
		})
	}
	return &api.GetRoaResponse{Roas: l}, nil
}

func (s *Server) GetVrf(ctx context.Context, arg *api.GetVrfRequest) (*api.GetVrfResponse, error) {
	toApi := func(v *table.Vrf) *api.Vrf {
		f := func(rts []bgp.ExtendedCommunityInterface) [][]byte {
			ret := make([][]byte, 0, len(rts))
			for _, rt := range rts {
				b, _ := rt.Serialize()
				ret = append(ret, b)
			}
			return ret
		}
		rd, _ := v.Rd.Serialize()
		return &api.Vrf{
			Name:     v.Name,
			Rd:       rd,
			ImportRt: f(v.ImportRt),
			ExportRt: f(v.ExportRt),
		}
	}
	vrfs := s.bgpServer.GetVrf()
	l := make([]*api.Vrf, 0, len(vrfs))
	for _, v := range vrfs {
		l = append(l, toApi(v))
	}
	return &api.GetVrfResponse{Vrfs: l}, nil
}

func (s *Server) get(typ int, d interface{}) (interface{}, error) {
	req := NewGrpcRequest(typ, "", bgp.RouteFamily(0), d)
	s.bgpServerCh <- req
	res := <-req.ResponseCh
	return res.Data, res.Err()
}

func (s *Server) AddVrf(ctx context.Context, arg *api.AddVrfRequest) (r *api.AddVrfResponse, err error) {
	rd := bgp.GetRouteDistinguisher(arg.Vrf.Rd)
	f := func(bufs [][]byte) ([]bgp.ExtendedCommunityInterface, error) {
		ret := make([]bgp.ExtendedCommunityInterface, 0, len(bufs))
		for _, rt := range bufs {
			r, err := bgp.ParseExtended(rt)
			if err != nil {
				return nil, err
			}
			ret = append(ret, r)
		}
		return ret, nil
	}
	im, err := f(arg.Vrf.ImportRt)
	if err != nil {
		return &api.AddVrfResponse{}, err
	}
	ex, err := f(arg.Vrf.ExportRt)
	if err != nil {
		return &api.AddVrfResponse{}, err
	}
	return &api.AddVrfResponse{}, s.bgpServer.AddVrf(arg.Vrf.Name, rd, im, ex)
}

func (s *Server) DeleteVrf(ctx context.Context, arg *api.DeleteVrfRequest) (*api.DeleteVrfResponse, error) {
	return &api.DeleteVrfResponse{}, s.bgpServer.DeleteVrf(arg.Vrf.Name)
}

func (s *Server) AddNeighbor(ctx context.Context, arg *api.AddNeighborRequest) (*api.AddNeighborResponse, error) {
	c, err := func(a *api.Peer) (config.Neighbor, error) {
		pconf := config.Neighbor{}
		if a.Conf != nil {
			pconf.Config.NeighborAddress = a.Conf.NeighborAddress
			pconf.Config.PeerAs = a.Conf.PeerAs
			pconf.Config.LocalAs = a.Conf.LocalAs

			if pconf.Config.PeerAs != pconf.Config.LocalAs {
				pconf.Config.PeerType = config.PEER_TYPE_EXTERNAL
			} else {
				pconf.Config.PeerType = config.PEER_TYPE_INTERNAL
			}
			pconf.Config.AuthPassword = a.Conf.AuthPassword
			pconf.Config.RemovePrivateAs = config.RemovePrivateAsOption(a.Conf.RemovePrivateAs)
			pconf.Config.RouteFlapDamping = a.Conf.RouteFlapDamping
			pconf.Config.SendCommunity = config.CommunityType(a.Conf.SendCommunity)
			pconf.Config.Description = a.Conf.Description
			pconf.Config.PeerGroup = a.Conf.PeerGroup
			pconf.Config.NeighborAddress = a.Conf.NeighborAddress
		}
		if a.Timers != nil {
			if a.Timers.Config != nil {
				pconf.Timers.Config.ConnectRetry = float64(a.Timers.Config.ConnectRetry)
				pconf.Timers.Config.HoldTime = float64(a.Timers.Config.HoldTime)
				pconf.Timers.Config.KeepaliveInterval = float64(a.Timers.Config.KeepaliveInterval)
				pconf.Timers.Config.MinimumAdvertisementInterval = float64(a.Timers.Config.MinimumAdvertisementInterval)
			}
		} else {
			pconf.Timers.Config.ConnectRetry = float64(config.DEFAULT_CONNECT_RETRY)
			pconf.Timers.Config.HoldTime = float64(config.DEFAULT_HOLDTIME)
			pconf.Timers.Config.KeepaliveInterval = float64(config.DEFAULT_HOLDTIME / 3)
		}
		if a.RouteReflector != nil {
			pconf.RouteReflector.Config.RouteReflectorClusterId = config.RrClusterIdType(a.RouteReflector.RouteReflectorClusterId)
			pconf.RouteReflector.Config.RouteReflectorClient = a.RouteReflector.RouteReflectorClient
		}
		if a.RouteServer != nil {
			pconf.RouteServer.Config.RouteServerClient = a.RouteServer.RouteServerClient
		}
		if a.ApplyPolicy != nil {
			if a.ApplyPolicy.ImportPolicy != nil {
				pconf.ApplyPolicy.Config.DefaultImportPolicy = config.DefaultPolicyType(a.ApplyPolicy.ImportPolicy.Default)
				for _, p := range a.ApplyPolicy.ImportPolicy.Policies {
					pconf.ApplyPolicy.Config.ImportPolicyList = append(pconf.ApplyPolicy.Config.ImportPolicyList, p.Name)
				}
			}
			if a.ApplyPolicy.ExportPolicy != nil {
				pconf.ApplyPolicy.Config.DefaultExportPolicy = config.DefaultPolicyType(a.ApplyPolicy.ExportPolicy.Default)
				for _, p := range a.ApplyPolicy.ExportPolicy.Policies {
					pconf.ApplyPolicy.Config.ExportPolicyList = append(pconf.ApplyPolicy.Config.ExportPolicyList, p.Name)
				}
			}
			if a.ApplyPolicy.InPolicy != nil {
				pconf.ApplyPolicy.Config.DefaultInPolicy = config.DefaultPolicyType(a.ApplyPolicy.InPolicy.Default)
				for _, p := range a.ApplyPolicy.InPolicy.Policies {
					pconf.ApplyPolicy.Config.InPolicyList = append(pconf.ApplyPolicy.Config.InPolicyList, p.Name)
				}
			}
		}
		if a.Families != nil {
			for _, family := range a.Families {
				name, ok := bgp.AddressFamilyNameMap[bgp.RouteFamily(family)]
				if !ok {
					return pconf, fmt.Errorf("invalid address family: %d", family)
				}
				cAfiSafi := config.AfiSafi{
					Config: config.AfiSafiConfig{
						AfiSafiName: config.AfiSafiType(name),
					},
				}
				pconf.AfiSafis = append(pconf.AfiSafis, cAfiSafi)
			}
		} else {
			if net.ParseIP(a.Conf.NeighborAddress).To4() != nil {
				pconf.AfiSafis = []config.AfiSafi{
					config.AfiSafi{
						Config: config.AfiSafiConfig{
							AfiSafiName: "ipv4-unicast",
						},
					},
				}
			} else {
				pconf.AfiSafis = []config.AfiSafi{
					config.AfiSafi{
						Config: config.AfiSafiConfig{
							AfiSafiName: "ipv6-unicast",
						},
					},
				}
			}
		}
		if a.Transport != nil {
			pconf.Transport.Config.LocalAddress = a.Transport.LocalAddress
			pconf.Transport.Config.PassiveMode = a.Transport.PassiveMode
		} else {
			if net.ParseIP(a.Conf.NeighborAddress).To4() != nil {
				pconf.Transport.Config.LocalAddress = "0.0.0.0"
			} else {
				pconf.Transport.Config.LocalAddress = "::"
			}
		}
		if a.EbgpMultihop != nil {
			pconf.EbgpMultihop.Config.Enabled = a.EbgpMultihop.Enabled
			pconf.EbgpMultihop.Config.MultihopTtl = uint8(a.EbgpMultihop.MultihopTtl)
		}
		return pconf, nil
	}(arg.Peer)
	if err != nil {
		return nil, err
	}
	return &api.AddNeighborResponse{}, s.bgpServer.AddNeighbor(&c)
}

func (s *Server) DeleteNeighbor(ctx context.Context, arg *api.DeleteNeighborRequest) (*api.DeleteNeighborResponse, error) {
	return &api.DeleteNeighborResponse{}, s.bgpServer.DeleteNeighbor(&config.Neighbor{Config: config.NeighborConfig{
		NeighborAddress: arg.Peer.Conf.NeighborAddress,
	}})
}

func NewPrefixFromApiStruct(a *api.Prefix) (*table.Prefix, error) {
	addr, prefix, err := net.ParseCIDR(a.IpPrefix)
	if err != nil {
		return nil, err
	}
	rf := bgp.RF_IPv4_UC
	if addr.To4() == nil {
		rf = bgp.RF_IPv6_UC
	}
	return &table.Prefix{
		Prefix:             prefix,
		AddressFamily:      rf,
		MasklengthRangeMin: uint8(a.MaskLengthMin),
		MasklengthRangeMax: uint8(a.MaskLengthMax),
	}, nil
}

func NewDefinedSetFromApiStruct(a *api.DefinedSet) (table.DefinedSet, error) {
	if a.Name == "" {
		return nil, fmt.Errorf("empty neighbor set name")
	}
	switch table.DefinedType(a.Type) {
	case table.DEFINED_TYPE_PREFIX:
		prefixes := make([]*table.Prefix, 0, len(a.Prefixes))
		for _, p := range a.Prefixes {
			prefix, err := NewPrefixFromApiStruct(p)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, prefix)
		}
		return table.NewPrefixSetFromApiStruct(a.Name, prefixes)
	case table.DEFINED_TYPE_NEIGHBOR:
		list := make([]net.IP, 0, len(a.List))
		for _, x := range a.List {
			addr := net.ParseIP(x)
			if addr == nil {
				return nil, fmt.Errorf("invalid ip address format: %s", x)
			}
			list = append(list, addr)
		}
		return table.NewNeighborSetFromApiStruct(a.Name, list)
	case table.DEFINED_TYPE_AS_PATH:
		return table.NewAsPathSet(config.AsPathSet{
			AsPathSetName: a.Name,
			AsPathList:    a.List,
		})
	case table.DEFINED_TYPE_COMMUNITY:
		return table.NewCommunitySet(config.CommunitySet{
			CommunitySetName: a.Name,
			CommunityList:    a.List,
		})
	case table.DEFINED_TYPE_EXT_COMMUNITY:
		return table.NewExtCommunitySet(config.ExtCommunitySet{
			ExtCommunitySetName: a.Name,
			ExtCommunityList:    a.List,
		})
	default:
		return nil, fmt.Errorf("invalid defined type")
	}
}

func (s *Server) GetDefinedSet(ctx context.Context, arg *api.GetDefinedSetRequest) (*api.GetDefinedSetResponse, error) {
	cd, err := s.bgpServer.GetDefinedSet(table.DefinedType(arg.Type))
	if err != nil {
		return nil, err
	}
	sets := make([]*api.DefinedSet, 0)
	for _, cs := range cd.PrefixSets {
		ad := &api.DefinedSet{
			Type: api.DefinedType_PREFIX,
			Name: cs.PrefixSetName,
			Prefixes: func() []*api.Prefix {
				l := make([]*api.Prefix, 0, len(cs.PrefixList))
				for _, p := range cs.PrefixList {
					exp := regexp.MustCompile("(\\d+)\\.\\.(\\d+)")
					elems := exp.FindStringSubmatch(p.MasklengthRange)
					min, _ := strconv.Atoi(elems[1])
					max, _ := strconv.Atoi(elems[2])

					l = append(l, &api.Prefix{IpPrefix: p.IpPrefix, MaskLengthMin: uint32(min), MaskLengthMax: uint32(max)})
				}
				return l
			}(),
		}
		sets = append(sets, ad)

	}
	for _, cs := range cd.NeighborSets {
		ad := &api.DefinedSet{
			Type: api.DefinedType_NEIGHBOR,
			Name: cs.NeighborSetName,
			List: cs.NeighborInfoList,
		}
		sets = append(sets, ad)
	}
	for _, cs := range cd.BgpDefinedSets.CommunitySets {
		ad := &api.DefinedSet{
			Type: api.DefinedType_COMMUNITY,
			Name: cs.CommunitySetName,
			List: cs.CommunityList,
		}
		sets = append(sets, ad)
	}
	for _, cs := range cd.BgpDefinedSets.ExtCommunitySets {
		ad := &api.DefinedSet{
			Type: api.DefinedType_EXT_COMMUNITY,
			Name: cs.ExtCommunitySetName,
			List: cs.ExtCommunityList,
		}
		sets = append(sets, ad)
	}
	for _, cs := range cd.BgpDefinedSets.AsPathSets {
		ad := &api.DefinedSet{
			Type: api.DefinedType_AS_PATH,
			Name: cs.AsPathSetName,
			List: cs.AsPathList,
		}
		sets = append(sets, ad)
	}

	return &api.GetDefinedSetResponse{Sets: sets}, nil
}

func (s *Server) AddDefinedSet(ctx context.Context, arg *api.AddDefinedSetRequest) (*api.AddDefinedSetResponse, error) {
	set, err := NewDefinedSetFromApiStruct(arg.Set)
	if err != nil {
		return nil, err
	}
	return &api.AddDefinedSetResponse{}, s.bgpServer.AddDefinedSet(set)
}

func (s *Server) DeleteDefinedSet(ctx context.Context, arg *api.DeleteDefinedSetRequest) (*api.DeleteDefinedSetResponse, error) {
	set, err := NewDefinedSetFromApiStruct(arg.Set)
	if err != nil {
		return nil, err
	}
	return &api.DeleteDefinedSetResponse{}, s.bgpServer.DeleteDefinedSet(set, arg.All)
}

func (s *Server) ReplaceDefinedSet(ctx context.Context, arg *api.ReplaceDefinedSetRequest) (*api.ReplaceDefinedSetResponse, error) {
	set, err := NewDefinedSetFromApiStruct(arg.Set)
	if err != nil {
		return nil, err
	}
	return &api.ReplaceDefinedSetResponse{}, s.bgpServer.ReplaceDefinedSet(set)
}

func toStatementApi(s *config.Statement) *api.Statement {
	cs := &api.Conditions{}
	if s.Conditions.MatchPrefixSet.PrefixSet != "" {
		cs.PrefixSet = &api.MatchSet{
			Type: api.MatchType(s.Conditions.MatchPrefixSet.MatchSetOptions.ToInt()),
			Name: s.Conditions.MatchPrefixSet.PrefixSet,
		}
	}
	if s.Conditions.MatchNeighborSet.NeighborSet != "" {
		cs.NeighborSet = &api.MatchSet{
			Type: api.MatchType(s.Conditions.MatchNeighborSet.MatchSetOptions.ToInt()),
			Name: s.Conditions.MatchNeighborSet.NeighborSet,
		}
	}
	if s.Conditions.BgpConditions.AsPathLength.Operator != "" {
		cs.AsPathLength = &api.AsPathLength{
			Length: s.Conditions.BgpConditions.AsPathLength.Value,
			Type:   api.AsPathLengthType(s.Conditions.BgpConditions.AsPathLength.Operator.ToInt()),
		}
	}
	if s.Conditions.BgpConditions.MatchAsPathSet.AsPathSet != "" {
		cs.AsPathSet = &api.MatchSet{
			Type: api.MatchType(s.Conditions.BgpConditions.MatchAsPathSet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchAsPathSet.AsPathSet,
		}
	}
	if s.Conditions.BgpConditions.MatchCommunitySet.CommunitySet != "" {
		cs.CommunitySet = &api.MatchSet{
			Type: api.MatchType(s.Conditions.BgpConditions.MatchCommunitySet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchCommunitySet.CommunitySet,
		}
	}
	if s.Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet != "" {
		cs.CommunitySet = &api.MatchSet{
			Type: api.MatchType(s.Conditions.BgpConditions.MatchExtCommunitySet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet,
		}
	}
	cs.RpkiResult = int32(s.Conditions.BgpConditions.RpkiValidationResult.ToInt())
	as := &api.Actions{
		RouteAction: func() api.RouteAction {
			if s.Actions.RouteDisposition.AcceptRoute {
				return api.RouteAction_ACCEPT
			}
			return api.RouteAction_REJECT
		}(),
		Community: func() *api.CommunityAction {
			if len(s.Actions.BgpActions.SetCommunity.SetCommunityMethod.CommunitiesList) == 0 {
				return nil
			}
			return &api.CommunityAction{
				Type:        api.CommunityActionType(config.BgpSetCommunityOptionTypeToIntMap[config.BgpSetCommunityOptionType(s.Actions.BgpActions.SetCommunity.Options)]),
				Communities: s.Actions.BgpActions.SetCommunity.SetCommunityMethod.CommunitiesList}
		}(),
		Med: func() *api.MedAction {
			if len(string(s.Actions.BgpActions.SetMed)) == 0 {
				return nil
			}
			exp := regexp.MustCompile("^(\\+|\\-)?(\\d+)$")
			elems := exp.FindStringSubmatch(string(s.Actions.BgpActions.SetMed))
			action := api.MedActionType_MED_REPLACE
			switch elems[1] {
			case "+", "-":
				action = api.MedActionType_MED_MOD
			}
			value, _ := strconv.Atoi(string(s.Actions.BgpActions.SetMed))
			return &api.MedAction{
				Value: int64(value),
				Type:  action,
			}
		}(),
		AsPrepend: func() *api.AsPrependAction {
			if len(s.Actions.BgpActions.SetAsPathPrepend.As) == 0 {
				return nil
			}
			asn := 0
			useleft := false
			if s.Actions.BgpActions.SetAsPathPrepend.As != "last-as" {
				asn, _ = strconv.Atoi(s.Actions.BgpActions.SetAsPathPrepend.As)
			} else {
				useleft = true
			}
			return &api.AsPrependAction{
				Asn:         uint32(asn),
				Repeat:      uint32(s.Actions.BgpActions.SetAsPathPrepend.RepeatN),
				UseLeftMost: useleft,
			}
		}(),
		ExtCommunity: func() *api.CommunityAction {
			if len(s.Actions.BgpActions.SetExtCommunity.SetExtCommunityMethod.CommunitiesList) == 0 {
				return nil
			}
			return &api.CommunityAction{
				Type:        api.CommunityActionType(config.BgpSetCommunityOptionTypeToIntMap[config.BgpSetCommunityOptionType(s.Actions.BgpActions.SetExtCommunity.Options)]),
				Communities: s.Actions.BgpActions.SetExtCommunity.SetExtCommunityMethod.CommunitiesList,
			}
		}(),
		Nexthop: func() *api.NexthopAction {
			if len(string(s.Actions.BgpActions.SetNextHop)) == 0 {
				return nil
			}

			if string(s.Actions.BgpActions.SetNextHop) == "self" {
				return &api.NexthopAction{
					Self: true,
				}
			}
			return &api.NexthopAction{
				Address: string(s.Actions.BgpActions.SetNextHop),
			}
		}(),
		LocalPref: func() *api.LocalPrefAction {
			if s.Actions.BgpActions.SetLocalPref == 0 {
				return nil
			}
			return &api.LocalPrefAction{Value: s.Actions.BgpActions.SetLocalPref}
		}(),
	}
	return &api.Statement{
		Name:       s.Name,
		Conditions: cs,
		Actions:    as,
	}
}

func toConfigMatchSetOption(a api.MatchType) (config.MatchSetOptionsType, error) {
	var typ config.MatchSetOptionsType
	switch a {
	case api.MatchType_ANY:
		typ = config.MATCH_SET_OPTIONS_TYPE_ANY
	case api.MatchType_ALL:
		typ = config.MATCH_SET_OPTIONS_TYPE_ALL
	case api.MatchType_INVERT:
		typ = config.MATCH_SET_OPTIONS_TYPE_INVERT
	default:
		return typ, fmt.Errorf("invalid match type")
	}
	return typ, nil
}

func toConfigMatchSetOptionRestricted(a api.MatchType) (config.MatchSetOptionsRestrictedType, error) {
	var typ config.MatchSetOptionsRestrictedType
	switch a {
	case api.MatchType_ANY:
		typ = config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY
	case api.MatchType_INVERT:
		typ = config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT
	default:
		return typ, fmt.Errorf("invalid match type")
	}
	return typ, nil
}

func NewPrefixConditionFromApiStruct(a *api.MatchSet) (*table.PrefixCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOptionRestricted(a.Type)
	if err != nil {
		return nil, err
	}
	c := config.MatchPrefixSet{
		PrefixSet:       a.Name,
		MatchSetOptions: typ,
	}
	return table.NewPrefixCondition(c)
}

func NewNeighborConditionFromApiStruct(a *api.MatchSet) (*table.NeighborCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOptionRestricted(a.Type)
	if err != nil {
		return nil, err
	}
	c := config.MatchNeighborSet{
		NeighborSet:     a.Name,
		MatchSetOptions: typ,
	}
	return table.NewNeighborCondition(c)
}

func NewAsPathLengthConditionFromApiStruct(a *api.AsPathLength) (*table.AsPathLengthCondition, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewAsPathLengthCondition(config.AsPathLength{
		Operator: config.IntToAttributeComparisonMap[int(a.Type)],
		Value:    a.Length,
	})
}

func NewAsPathConditionFromApiStruct(a *api.MatchSet) (*table.AsPathCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOption(a.Type)
	if err != nil {
		return nil, err
	}
	c := config.MatchAsPathSet{
		AsPathSet:       a.Name,
		MatchSetOptions: typ,
	}
	return table.NewAsPathCondition(c)
}

func NewRpkiValidationConditionFromApiStruct(a int32) (*table.RpkiValidationCondition, error) {
	if a < 1 {
		return nil, nil
	}
	return table.NewRpkiValidationCondition(config.IntToRpkiValidationResultTypeMap[int(a)])
}

func NewCommunityConditionFromApiStruct(a *api.MatchSet) (*table.CommunityCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOption(a.Type)
	if err != nil {
		return nil, err
	}
	c := config.MatchCommunitySet{
		CommunitySet:    a.Name,
		MatchSetOptions: typ,
	}
	return table.NewCommunityCondition(c)
}

func NewExtCommunityConditionFromApiStruct(a *api.MatchSet) (*table.ExtCommunityCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOption(a.Type)
	if err != nil {
		return nil, err
	}
	c := config.MatchExtCommunitySet{
		ExtCommunitySet: a.Name,
		MatchSetOptions: typ,
	}
	return table.NewExtCommunityCondition(c)
}

func NewRoutingActionFromApiStruct(a api.RouteAction) (*table.RoutingAction, error) {
	if a == api.RouteAction_NONE {
		return nil, nil
	}
	accept := false
	if a == api.RouteAction_ACCEPT {
		accept = true
	}
	return &table.RoutingAction{
		AcceptRoute: accept,
	}, nil
}

func NewCommunityActionFromApiStruct(a *api.CommunityAction) (*table.CommunityAction, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewCommunityAction(config.SetCommunity{
		Options: string(config.IntToBgpSetCommunityOptionTypeMap[int(a.Type)]),
		SetCommunityMethod: config.SetCommunityMethod{
			CommunitiesList: a.Communities,
		},
	})
}

func NewExtCommunityActionFromApiStruct(a *api.CommunityAction) (*table.ExtCommunityAction, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewExtCommunityAction(config.SetExtCommunity{
		Options: string(config.IntToBgpSetCommunityOptionTypeMap[int(a.Type)]),
		SetExtCommunityMethod: config.SetExtCommunityMethod{
			CommunitiesList: a.Communities,
		},
	})
}

func NewMedActionFromApiStruct(a *api.MedAction) (*table.MedAction, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewMedActionFromApiStruct(table.MedActionType(a.Type), int(a.Value)), nil
}

func NewLocalPrefActionFromApiStruct(a *api.LocalPrefAction) (*table.LocalPrefAction, error) {
	if a == nil || a.Value == 0 {
		return nil, nil
	}
	return table.NewLocalPrefAction(a.Value)
}

func NewAsPathPrependActionFromApiStruct(a *api.AsPrependAction) (*table.AsPathPrependAction, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewAsPathPrependAction(config.SetAsPathPrepend{
		RepeatN: uint8(a.Repeat),
		As: func() string {
			if a.UseLeftMost {
				return "last-as"
			}
			return fmt.Sprintf("%d", a.Asn)
		}(),
	})
}

func NewNexthopActionFromApiStruct(a *api.NexthopAction) (*table.NexthopAction, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewNexthopAction(config.BgpNextHopType(
		func() string {
			if a.Self {
				return "self"
			}
			return a.Address
		}(),
	))
}

func NewStatementFromApiStruct(a *api.Statement) (*table.Statement, error) {
	if a.Name == "" {
		return nil, fmt.Errorf("empty statement name")
	}
	var ra table.Action
	var as []table.Action
	var cs []table.Condition
	var err error
	if a.Conditions != nil {
		cfs := []func() (table.Condition, error){
			func() (table.Condition, error) {
				return NewPrefixConditionFromApiStruct(a.Conditions.PrefixSet)
			},
			func() (table.Condition, error) {
				return NewNeighborConditionFromApiStruct(a.Conditions.NeighborSet)
			},
			func() (table.Condition, error) {
				return NewAsPathLengthConditionFromApiStruct(a.Conditions.AsPathLength)
			},
			func() (table.Condition, error) {
				return NewRpkiValidationConditionFromApiStruct(a.Conditions.RpkiResult)
			},
			func() (table.Condition, error) {
				return NewAsPathConditionFromApiStruct(a.Conditions.AsPathSet)
			},
			func() (table.Condition, error) {
				return NewCommunityConditionFromApiStruct(a.Conditions.CommunitySet)
			},
			func() (table.Condition, error) {
				return NewExtCommunityConditionFromApiStruct(a.Conditions.ExtCommunitySet)
			},
		}
		cs = make([]table.Condition, 0, len(cfs))
		for _, f := range cfs {
			c, err := f()
			if err != nil {
				return nil, err
			}
			if !reflect.ValueOf(c).IsNil() {
				cs = append(cs, c)
			}
		}
	}
	if a.Actions != nil {
		ra, err = NewRoutingActionFromApiStruct(a.Actions.RouteAction)
		if err != nil {
			return nil, err
		}
		afs := []func() (table.Action, error){
			func() (table.Action, error) {
				return NewCommunityActionFromApiStruct(a.Actions.Community)
			},
			func() (table.Action, error) {
				return NewExtCommunityActionFromApiStruct(a.Actions.ExtCommunity)
			},
			func() (table.Action, error) {
				return NewMedActionFromApiStruct(a.Actions.Med)
			},
			func() (table.Action, error) {
				return NewLocalPrefActionFromApiStruct(a.Actions.LocalPref)
			},
			func() (table.Action, error) {
				return NewAsPathPrependActionFromApiStruct(a.Actions.AsPrepend)
			},
			func() (table.Action, error) {
				return NewNexthopActionFromApiStruct(a.Actions.Nexthop)
			},
		}
		as = make([]table.Action, 0, len(afs))
		for _, f := range afs {
			a, err := f()
			if err != nil {
				return nil, err
			}
			if !reflect.ValueOf(a).IsNil() {
				as = append(as, a)
			}
		}
	}
	return &table.Statement{
		Name:        a.Name,
		Conditions:  cs,
		RouteAction: ra,
		ModActions:  as,
	}, nil
}

func (s *Server) GetStatement(ctx context.Context, arg *api.GetStatementRequest) (*api.GetStatementResponse, error) {
	l := make([]*api.Statement, 0)
	for _, s := range s.bgpServer.GetStatement() {
		l = append(l, toStatementApi(s))
	}
	return &api.GetStatementResponse{Statements: l}, nil
}

func (s *Server) AddStatement(ctx context.Context, arg *api.AddStatementRequest) (*api.AddStatementResponse, error) {
	st, err := NewStatementFromApiStruct(arg.Statement)
	if err == nil {
		err = s.bgpServer.AddStatement(st)
	}
	return &api.AddStatementResponse{}, err
}

func (s *Server) DeleteStatement(ctx context.Context, arg *api.DeleteStatementRequest) (*api.DeleteStatementResponse, error) {
	st, err := NewStatementFromApiStruct(arg.Statement)
	if err == nil {
		err = s.bgpServer.DeleteStatement(st, arg.All)
	}
	return &api.DeleteStatementResponse{}, err
}

func (s *Server) ReplaceStatement(ctx context.Context, arg *api.ReplaceStatementRequest) (*api.ReplaceStatementResponse, error) {
	st, err := NewStatementFromApiStruct(arg.Statement)
	if err == nil {
		err = s.bgpServer.ReplaceStatement(st)
	}
	return &api.ReplaceStatementResponse{}, err
}

func toPolicyApi(p *config.PolicyDefinition) *api.Policy {
	return &api.Policy{
		Name: p.Name,
		Statements: func() []*api.Statement {
			l := make([]*api.Statement, 0)
			for _, s := range p.Statements {
				l = append(l, toStatementApi(&s))
			}
			return l
		}(),
	}
}

func NewPolicyFromApiStruct(a *api.Policy) (*table.Policy, error) {
	if a.Name == "" {
		return nil, fmt.Errorf("empty policy name")
	}
	stmts := make([]*table.Statement, 0, len(a.Statements))
	for idx, x := range a.Statements {
		if x.Name == "" {
			x.Name = fmt.Sprintf("%s_stmt%d", a.Name, idx)
		}
		y, err := NewStatementFromApiStruct(x)
		if err != nil {
			return nil, err
		}
		stmts = append(stmts, y)
	}
	return &table.Policy{
		Name:       a.Name,
		Statements: stmts,
	}, nil
}

func (s *Server) GetPolicy(ctx context.Context, arg *api.GetPolicyRequest) (*api.GetPolicyResponse, error) {
	l := make([]*api.Policy, 0)
	for _, p := range s.bgpServer.GetPolicy() {
		l = append(l, toPolicyApi(p))
	}
	return &api.GetPolicyResponse{Policies: l}, nil
}

func (s *Server) AddPolicy(ctx context.Context, arg *api.AddPolicyRequest) (*api.AddPolicyResponse, error) {
	x, err := NewPolicyFromApiStruct(arg.Policy)
	if err != nil {
		return nil, err
	}
	return &api.AddPolicyResponse{}, s.bgpServer.AddPolicy(x, arg.ReferExistingStatements)
}

func (s *Server) DeletePolicy(ctx context.Context, arg *api.DeletePolicyRequest) (*api.DeletePolicyResponse, error) {
	x, err := NewPolicyFromApiStruct(arg.Policy)
	if err != nil {
		return nil, err
	}
	return &api.DeletePolicyResponse{}, s.bgpServer.DeletePolicy(x, arg.All, arg.PreserveStatements)
}

func (s *Server) ReplacePolicy(ctx context.Context, arg *api.ReplacePolicyRequest) (*api.ReplacePolicyResponse, error) {
	x, err := NewPolicyFromApiStruct(arg.Policy)
	if err != nil {
		return nil, err
	}
	return &api.ReplacePolicyResponse{}, s.bgpServer.ReplacePolicy(x, arg.ReferExistingStatements, arg.PreserveStatements)
}

func toPolicyAssignmentName(a *api.PolicyAssignment) (string, table.PolicyDirection, error) {
	switch a.Resource {
	case api.Resource_GLOBAL:
		switch a.Type {
		case api.PolicyType_IMPORT:
			return "", table.POLICY_DIRECTION_IMPORT, nil
		case api.PolicyType_EXPORT:
			return "", table.POLICY_DIRECTION_EXPORT, nil
		default:
			return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("invalid policy type")
		}
	case api.Resource_LOCAL:
		switch a.Type {
		case api.PolicyType_IN:
			return a.Name, table.POLICY_DIRECTION_IN, nil
		case api.PolicyType_IMPORT:
			return a.Name, table.POLICY_DIRECTION_IMPORT, nil
		case api.PolicyType_EXPORT:
			return a.Name, table.POLICY_DIRECTION_EXPORT, nil
		default:
			return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("invalid policy type")
		}
	default:
		return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("invalid resource type")
	}

}

func (s *Server) GetPolicyAssignment(ctx context.Context, arg *api.GetPolicyAssignmentRequest) (*api.GetPolicyAssignmentResponse, error) {
	name, dir, err := toPolicyAssignmentName(arg.Assignment)
	if err != nil {
		return nil, err
	}
	d, a, err := s.bgpServer.GetPolicyAssignment(name, dir)
	if err != nil {
		return nil, err
	}
	return &api.GetPolicyAssignmentResponse{
		Assignment: &api.PolicyAssignment{
			Default: func() api.RouteAction {
				switch d {
				case table.ROUTE_TYPE_ACCEPT:
					return api.RouteAction_ACCEPT
				case table.ROUTE_TYPE_REJECT:
					return api.RouteAction_REJECT
				}
				return api.RouteAction_NONE

			}(),
			Policies: func() []*api.Policy {
				l := make([]*api.Policy, 0)
				for _, p := range a {
					l = append(l, toPolicyApi(p))
				}
				return l
			}(),
		},
	}, err
}

func defaultRouteType(d api.RouteAction) table.RouteType {
	switch d {
	case api.RouteAction_ACCEPT:
		return table.ROUTE_TYPE_ACCEPT
	case api.RouteAction_REJECT:
		return table.ROUTE_TYPE_REJECT
	default:
		return table.ROUTE_TYPE_NONE
	}
}

func toPolicyDefinition(policies []*api.Policy) []*config.PolicyDefinition {
	l := make([]*config.PolicyDefinition, 0, len(policies))
	for _, p := range policies {
		l = append(l, &config.PolicyDefinition{Name: p.Name})
	}
	return l
}

func (s *Server) AddPolicyAssignment(ctx context.Context, arg *api.AddPolicyAssignmentRequest) (*api.AddPolicyAssignmentResponse, error) {
	name, dir, err := toPolicyAssignmentName(arg.Assignment)
	if err != nil {
		return nil, err
	}
	return &api.AddPolicyAssignmentResponse{}, s.bgpServer.AddPolicyAssignment(name, dir, toPolicyDefinition(arg.Assignment.Policies), defaultRouteType(arg.Assignment.Default))
}

func (s *Server) DeletePolicyAssignment(ctx context.Context, arg *api.DeletePolicyAssignmentRequest) (*api.DeletePolicyAssignmentResponse, error) {
	name, dir, err := toPolicyAssignmentName(arg.Assignment)
	if err != nil {
		return nil, err
	}
	return &api.DeletePolicyAssignmentResponse{}, s.bgpServer.DeletePolicyAssignment(name, dir, toPolicyDefinition(arg.Assignment.Policies), arg.All)
}

func (s *Server) ReplacePolicyAssignment(ctx context.Context, arg *api.ReplacePolicyAssignmentRequest) (*api.ReplacePolicyAssignmentResponse, error) {
	name, dir, err := toPolicyAssignmentName(arg.Assignment)
	if err != nil {
		return nil, err
	}
	return &api.ReplacePolicyAssignmentResponse{}, s.bgpServer.ReplacePolicyAssignment(name, dir, toPolicyDefinition(arg.Assignment.Policies), defaultRouteType(arg.Assignment.Default))
}

func (s *Server) GetServer(ctx context.Context, arg *api.GetServerRequest) (*api.GetServerResponse, error) {
	g := s.bgpServer.GetServer()
	return &api.GetServerResponse{
		Global: &api.Global{
			As:              g.Config.As,
			RouterId:        g.Config.RouterId,
			ListenPort:      g.Config.Port,
			ListenAddresses: g.Config.LocalAddressList,
			MplsLabelMin:    g.MplsLabelRange.MinLabel,
			MplsLabelMax:    g.MplsLabelRange.MaxLabel,
		},
	}, nil
}

func (s *Server) StartServer(ctx context.Context, arg *api.StartServerRequest) (*api.StartServerResponse, error) {
	g := arg.Global
	if net.ParseIP(g.RouterId) == nil {
		return nil, fmt.Errorf("invalid router-id format: %s", g.RouterId)
	}
	families := make([]config.AfiSafi, 0, len(g.Families))
	for _, f := range g.Families {
		name := config.AfiSafiType(bgp.RouteFamily(f).String())
		families = append(families, config.AfiSafi{
			Config: config.AfiSafiConfig{
				AfiSafiName: name,
				Enabled:     true,
			},
			State: config.AfiSafiState{
				AfiSafiName: name,
			},
		})
	}
	b := &config.BgpConfigSet{
		Global: config.Global{
			Config: config.GlobalConfig{
				As:               g.As,
				RouterId:         g.RouterId,
				Port:             g.ListenPort,
				LocalAddressList: g.ListenAddresses,
			},
			MplsLabelRange: config.MplsLabelRange{
				MinLabel: g.MplsLabelMin,
				MaxLabel: g.MplsLabelMax,
			},
			AfiSafis: families,
		},
	}
	if err := config.SetDefaultConfigValues(nil, b); err != nil {
		return nil, err
	}
	return &api.StartServerResponse{}, s.bgpServer.Start(&b.Global)
}

func (s *Server) StopServer(ctx context.Context, arg *api.StopServerRequest) (*api.StopServerResponse, error) {
	return &api.StopServerResponse{}, s.bgpServer.Stop()
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

func NewGrpcServer(b *BgpServer, hosts string, bgpServerCh chan *GrpcRequest) *Server {
	grpc.EnableTracing = false
	grpcServer := grpc.NewServer()
	server := &Server{
		bgpServer:   b,
		grpcServer:  grpcServer,
		bgpServerCh: bgpServerCh,
		hosts:       hosts,
	}
	api.RegisterGobgpApiServer(grpcServer, server)
	return server
}
