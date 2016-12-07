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

package gobgpapi

import (
	"fmt"
	"io"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/server"
	"github.com/osrg/gobgp/table"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type Server struct {
	bgpServer  *server.BgpServer
	grpcServer *grpc.Server
	hosts      string
}

func NewGrpcServer(b *server.BgpServer, hosts string) *Server {
	return NewServer(b, grpc.NewServer(), hosts)
}

func NewServer(b *server.BgpServer, g *grpc.Server, hosts string) *Server {
	grpc.EnableTracing = false
	server := &Server{
		bgpServer:  b,
		grpcServer: g,
		hosts:      hosts,
	}
	RegisterGobgpApiServer(g, server)
	return server
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

func NewPeerFromConfigStruct(pconf *config.Neighbor) *Peer {
	var families []uint32
	for _, f := range pconf.AfiSafis {
		if family, ok := bgp.AddressFamilyValueMap[string(f.Config.AfiSafiName)]; ok {
			families = append(families, uint32(family))
		}
	}
	applyPolicy := &ApplyPolicy{}
	if len(pconf.ApplyPolicy.Config.ImportPolicyList) != 0 {
		applyPolicy.ImportPolicy = &PolicyAssignment{
			Type: PolicyType_IMPORT,
		}
		for _, pname := range pconf.ApplyPolicy.Config.ImportPolicyList {
			applyPolicy.ImportPolicy.Policies = append(applyPolicy.ImportPolicy.Policies, &Policy{Name: pname})
		}
	}
	if len(pconf.ApplyPolicy.Config.ExportPolicyList) != 0 {
		applyPolicy.ExportPolicy = &PolicyAssignment{
			Type: PolicyType_EXPORT,
		}
		for _, pname := range pconf.ApplyPolicy.Config.ExportPolicyList {
			applyPolicy.ExportPolicy.Policies = append(applyPolicy.ExportPolicy.Policies, &Policy{Name: pname})
		}
	}
	if len(pconf.ApplyPolicy.Config.InPolicyList) != 0 {
		applyPolicy.InPolicy = &PolicyAssignment{
			Type: PolicyType_IN,
		}
		for _, pname := range pconf.ApplyPolicy.Config.InPolicyList {
			applyPolicy.InPolicy.Policies = append(applyPolicy.InPolicy.Policies, &Policy{Name: pname})
		}
	}
	prefixLimits := make([]*PrefixLimit, 0, len(pconf.AfiSafis))
	for _, family := range pconf.AfiSafis {
		if c := family.PrefixLimit.Config; c.MaxPrefixes > 0 {
			k, _ := bgp.GetRouteFamily(string(family.Config.AfiSafiName))
			prefixLimits = append(prefixLimits, &PrefixLimit{
				Family:               uint32(k),
				MaxPrefixes:          c.MaxPrefixes,
				ShutdownThresholdPct: uint32(c.ShutdownThresholdPct),
			})
		}
	}

	timer := pconf.Timers
	s := pconf.State
	localAddress := pconf.Transport.Config.LocalAddress
	if pconf.Transport.State.LocalAddress != "" {
		localAddress = pconf.Transport.State.LocalAddress
	}
	var remoteCap, localCap [][]byte
	for _, cap := range pconf.State.RemoteCapabilityList {
		c, _ := cap.Serialize()
		remoteCap = append(remoteCap, c)
	}
	for _, cap := range pconf.State.LocalCapabilityList {
		c, _ := cap.Serialize()
		localCap = append(localCap, c)
	}
	return &Peer{
		Families:    families,
		ApplyPolicy: applyPolicy,
		Conf: &PeerConf{
			NeighborAddress:   pconf.Config.NeighborAddress,
			Id:                s.RemoteRouterId,
			PeerAs:            pconf.Config.PeerAs,
			LocalAs:           pconf.Config.LocalAs,
			PeerType:          uint32(pconf.Config.PeerType.ToInt()),
			AuthPassword:      pconf.Config.AuthPassword,
			RemovePrivateAs:   uint32(pconf.Config.RemovePrivateAs.ToInt()),
			RouteFlapDamping:  pconf.Config.RouteFlapDamping,
			SendCommunity:     uint32(pconf.Config.SendCommunity.ToInt()),
			Description:       pconf.Config.Description,
			PeerGroup:         pconf.Config.PeerGroup,
			RemoteCap:         remoteCap,
			LocalCap:          localCap,
			PrefixLimits:      prefixLimits,
			LocalAddress:      localAddress,
			NeighborInterface: pconf.Config.NeighborInterface,
			Vrf:               pconf.Config.Vrf,
		},
		Info: &PeerState{
			BgpState:   string(s.SessionState),
			AdminState: PeerState_AdminState(s.AdminState.ToInt()),
			Messages: &Messages{
				Received: &Message{
					NOTIFICATION: s.Messages.Received.Notification,
					UPDATE:       s.Messages.Received.Update,
					OPEN:         s.Messages.Received.Open,
					KEEPALIVE:    s.Messages.Received.Keepalive,
					REFRESH:      s.Messages.Received.Refresh,
					DISCARDED:    s.Messages.Received.Discarded,
					TOTAL:        s.Messages.Received.Total,
				},
				Sent: &Message{
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
		Timers: &Timers{
			Config: &TimersConfig{
				ConnectRetry:      uint64(timer.Config.ConnectRetry),
				HoldTime:          uint64(timer.Config.HoldTime),
				KeepaliveInterval: uint64(timer.Config.KeepaliveInterval),
			},
			State: &TimersState{
				KeepaliveInterval:  uint64(timer.State.KeepaliveInterval),
				NegotiatedHoldTime: uint64(timer.State.NegotiatedHoldTime),
				Uptime:             uint64(timer.State.Uptime),
				Downtime:           uint64(timer.State.Downtime),
			},
		},
		RouteReflector: &RouteReflector{
			RouteReflectorClient:    pconf.RouteReflector.Config.RouteReflectorClient,
			RouteReflectorClusterId: string(pconf.RouteReflector.Config.RouteReflectorClusterId),
		},
		RouteServer: &RouteServer{
			RouteServerClient: pconf.RouteServer.Config.RouteServerClient,
		},
		Transport: &Transport{
			RemotePort:   uint32(pconf.Transport.Config.RemotePort),
			LocalAddress: pconf.Transport.Config.LocalAddress,
		},
	}
}

func (s *Server) GetNeighbor(ctx context.Context, arg *GetNeighborRequest) (*GetNeighborResponse, error) {
	p := []*Peer{}
	for _, e := range s.bgpServer.GetNeighbor(arg.EnableAdvertised) {
		p = append(p, NewPeerFromConfigStruct(e))
	}
	return &GetNeighborResponse{Peers: p}, nil
}

func ToPathApi(path *table.Path) *Path {
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
	p := &Path{
		Nlri:               n,
		Pattrs:             pattrs,
		Age:                path.GetTimestamp().Unix(),
		IsWithdraw:         path.IsWithdraw,
		Validation:         int32(path.Validation().ToInt()),
		Filtered:           path.Filtered("") == table.POLICY_DIRECTION_IN,
		Family:             family,
		Stale:              path.IsStale(),
		IsFromExternal:     path.IsFromExternal(),
		NoImplicitWithdraw: path.NoImplicitWithdraw(),
	}
	if s := path.GetSource(); s != nil {
		p.SourceAsn = s.AS
		p.SourceId = s.ID.String()
		p.NeighborIp = s.Address.String()
	}
	return p
}

func (s *Server) GetRib(ctx context.Context, arg *GetRibRequest) (*GetRibResponse, error) {
	f := func() []*table.LookupPrefix {
		l := make([]*table.LookupPrefix, 0, len(arg.Table.Destinations))
		for _, p := range arg.Table.Destinations {
			l = append(l, &table.LookupPrefix{
				Prefix: p.Prefix,
				LookupOption: func() table.LookupOption {
					if p.LongerPrefixes {
						return table.LOOKUP_LONGER
					} else if p.ShorterPrefixes {
						return table.LOOKUP_SHORTER
					}
					return table.LOOKUP_EXACT
				}(),
			})
		}
		return l
	}

	var in bool
	var err error
	var tbl *table.Table

	family := bgp.RouteFamily(arg.Table.Family)
	switch arg.Table.Type {
	case Resource_LOCAL, Resource_GLOBAL:
		tbl, err = s.bgpServer.GetRib(arg.Table.Name, family, f())
	case Resource_ADJ_IN:
		in = true
		fallthrough
	case Resource_ADJ_OUT:
		tbl, err = s.bgpServer.GetAdjRib(arg.Table.Name, family, in, f())
	case Resource_VRF:
		tbl, err = s.bgpServer.GetVrfRib(arg.Table.Name, family, []*table.LookupPrefix{})
	default:
		return nil, fmt.Errorf("unsupported resource type: %v", arg.Table.Type)
	}

	if err != nil {
		return nil, err
	}

	dsts := []*Destination{}
	for _, dst := range tbl.GetDestinations() {
		dsts = append(dsts, &Destination{
			Prefix: dst.GetNlri().String(),
			Paths: func(paths []*table.Path) []*Path {
				l := make([]*Path, 0, len(paths))
				for i, p := range paths {
					pp := ToPathApi(p)
					switch arg.Table.Type {
					case Resource_LOCAL, Resource_GLOBAL:
						if i == 0 {
							pp.Best = true
						}
					}
					l = append(l, pp)
				}
				return l
			}(dst.GetAllKnownPathList()),
		})
	}

	return &GetRibResponse{Table: &Table{
		Type:         arg.Table.Type,
		Family:       uint32(tbl.GetRoutefamily()),
		Destinations: dsts},
	}, err
}

func (s *Server) MonitorRib(arg *Table, stream GobgpApi_MonitorRibServer) error {
	w, err := func() (*server.Watcher, error) {
		switch arg.Type {
		case Resource_GLOBAL:
			return s.bgpServer.Watch(server.WatchBestPath()), nil
		case Resource_ADJ_IN:
			if arg.PostPolicy {
				return s.bgpServer.Watch(server.WatchPostUpdate(false)), nil
			}
			return s.bgpServer.Watch(server.WatchUpdate(false)), nil
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
			dsts := make(map[string]*Destination)
			for _, path := range pathList {
				if path == nil || (arg.Family != 0 && bgp.RouteFamily(arg.Family) != path.GetRouteFamily()) {
					continue
				}
				if dst, y := dsts[path.GetNlri().String()]; y {
					dst.Paths = append(dst.Paths, ToPathApi(path))
				} else {
					dsts[path.GetNlri().String()] = &Destination{
						Prefix: path.GetNlri().String(),
						Paths:  []*Path{ToPathApi(path)},
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
				case *server.WatchEventBestPath:
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
				case *server.WatchEventUpdate:
					if err := sendPath(msg.PathList); err != nil {
						return err
					}
				}
			}
		}
	}()
}

func (s *Server) MonitorPeerState(arg *Arguments, stream GobgpApi_MonitorPeerStateServer) error {
	return func() error {
		w := s.bgpServer.Watch(server.WatchPeerState(false))
		defer func() { w.Stop() }()

		for {
			select {
			case ev := <-w.Event():
				switch msg := ev.(type) {
				case *server.WatchEventPeerState:
					if len(arg.Name) > 0 && arg.Name != msg.PeerAddress.String() {
						continue
					}
					if err := stream.Send(&Peer{
						Conf: &PeerConf{
							PeerAs:          msg.PeerAS,
							LocalAs:         msg.LocalAS,
							NeighborAddress: msg.PeerAddress.String(),
							Id:              msg.PeerID.String(),
						},
						Info: &PeerState{
							PeerAs:          msg.PeerAS,
							LocalAs:         msg.LocalAS,
							NeighborAddress: msg.PeerAddress.String(),
							BgpState:        msg.State.String(),
							AdminState:      PeerState_AdminState(msg.AdminState),
						},
						Transport: &Transport{
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

func (s *Server) ResetNeighbor(ctx context.Context, arg *ResetNeighborRequest) (*ResetNeighborResponse, error) {
	return &ResetNeighborResponse{}, s.bgpServer.ResetNeighbor(arg.Address)
}

func (s *Server) SoftResetNeighbor(ctx context.Context, arg *SoftResetNeighborRequest) (*SoftResetNeighborResponse, error) {
	var err error
	addr := arg.Address
	if addr == "all" {
		addr = ""
	}
	family := bgp.RouteFamily(0)
	switch arg.Direction {
	case SoftResetNeighborRequest_IN:
		err = s.bgpServer.SoftResetIn(addr, family)
	case SoftResetNeighborRequest_OUT:
		err = s.bgpServer.SoftResetOut(addr, family)
	default:
		err = s.bgpServer.SoftReset(addr, family)
	}
	return &SoftResetNeighborResponse{}, err
}

func (s *Server) ShutdownNeighbor(ctx context.Context, arg *ShutdownNeighborRequest) (*ShutdownNeighborResponse, error) {
	return &ShutdownNeighborResponse{}, s.bgpServer.ShutdownNeighbor(arg.Address)
}

func (s *Server) EnableNeighbor(ctx context.Context, arg *EnableNeighborRequest) (*EnableNeighborResponse, error) {
	return &EnableNeighborResponse{}, s.bgpServer.EnableNeighbor(arg.Address)
}

func (s *Server) DisableNeighbor(ctx context.Context, arg *DisableNeighborRequest) (*DisableNeighborResponse, error) {
	return &DisableNeighborResponse{}, s.bgpServer.DisableNeighbor(arg.Address)
}

func (s *Server) api2PathList(resource Resource, ApiPathList []*Path) ([]*table.Path, error) {
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

		if nlri == nil || (!path.IsWithdraw && nexthop == "") {
			return nil, fmt.Errorf("not found nlri or nexthop")
		}

		rf := bgp.AfiSafiToRouteFamily(nlri.AFI(), nlri.SAFI())

		if resource != Resource_VRF && rf == bgp.RF_IPv4_UC {
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

func (s *Server) AddPath(ctx context.Context, arg *AddPathRequest) (*AddPathResponse, error) {
	pathList, err := s.api2PathList(arg.Resource, []*Path{arg.Path})
	var uuid []byte
	if err == nil {
		uuid, err = s.bgpServer.AddPath(arg.VrfId, pathList)
	}
	return &AddPathResponse{Uuid: uuid}, err
}

func (s *Server) DeletePath(ctx context.Context, arg *DeletePathRequest) (*DeletePathResponse, error) {
	pathList, err := func() ([]*table.Path, error) {
		if arg.Path != nil {
			arg.Path.IsWithdraw = true
			return s.api2PathList(arg.Resource, []*Path{arg.Path})
		}
		return []*table.Path{}, nil
	}()
	if err != nil {
		return nil, err
	}
	return &DeletePathResponse{}, s.bgpServer.DeletePath(arg.Uuid, bgp.RouteFamily(arg.Family), arg.VrfId, pathList)
}

func (s *Server) EnableMrt(ctx context.Context, arg *EnableMrtRequest) (*EnableMrtResponse, error) {
	return &EnableMrtResponse{}, s.bgpServer.EnableMrt(&config.MrtConfig{
		RotationInterval: arg.Interval,
		DumpType:         config.IntToMrtTypeMap[int(arg.DumpType)],
		FileName:         arg.Filename,
	})
}

func (s *Server) DisableMrt(ctx context.Context, arg *DisableMrtRequest) (*DisableMrtResponse, error) {
	return &DisableMrtResponse{}, s.bgpServer.DisableMrt(&config.MrtConfig{})
}

func (s *Server) InjectMrt(stream GobgpApi_InjectMrtServer) error {
	for {
		arg, err := stream.Recv()

		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if arg.Resource != Resource_GLOBAL && arg.Resource != Resource_VRF {
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
	return stream.SendAndClose(&InjectMrtResponse{})
}

func (s *Server) AddBmp(ctx context.Context, arg *AddBmpRequest) (*AddBmpResponse, error) {
	t, ok := config.IntToBmpRouteMonitoringPolicyTypeMap[int(arg.Type)]
	if !ok {
		return nil, fmt.Errorf("invalid bmp route monitoring policy: %d", arg.Type)
	}
	return &AddBmpResponse{}, s.bgpServer.AddBmp(&config.BmpServerConfig{
		Address: arg.Address,
		Port:    arg.Port,
		RouteMonitoringPolicy: t,
	})
}

func (s *Server) DeleteBmp(ctx context.Context, arg *DeleteBmpRequest) (*DeleteBmpResponse, error) {
	return &DeleteBmpResponse{}, s.bgpServer.DeleteBmp(&config.BmpServerConfig{
		Address: arg.Address,
		Port:    arg.Port,
	})
}

func (s *Server) ValidateRib(ctx context.Context, arg *ValidateRibRequest) (*ValidateRibResponse, error) {
	return &ValidateRibResponse{}, s.bgpServer.ValidateRib(arg.Prefix)
}

func (s *Server) AddRpki(ctx context.Context, arg *AddRpkiRequest) (*AddRpkiResponse, error) {
	return &AddRpkiResponse{}, s.bgpServer.AddRpki(&config.RpkiServerConfig{
		Address:        arg.Address,
		Port:           arg.Port,
		RecordLifetime: arg.Lifetime,
	})
}

func (s *Server) DeleteRpki(ctx context.Context, arg *DeleteRpkiRequest) (*DeleteRpkiResponse, error) {
	return &DeleteRpkiResponse{}, s.bgpServer.DeleteRpki(&config.RpkiServerConfig{
		Address: arg.Address,
		Port:    arg.Port,
	})
}

func (s *Server) EnableRpki(ctx context.Context, arg *EnableRpkiRequest) (*EnableRpkiResponse, error) {
	return &EnableRpkiResponse{}, s.bgpServer.EnableRpki(&config.RpkiServerConfig{
		Address: arg.Address,
	})
}

func (s *Server) DisableRpki(ctx context.Context, arg *DisableRpkiRequest) (*DisableRpkiResponse, error) {
	return &DisableRpkiResponse{}, s.bgpServer.DisableRpki(&config.RpkiServerConfig{
		Address: arg.Address,
	})
}

func (s *Server) ResetRpki(ctx context.Context, arg *ResetRpkiRequest) (*ResetRpkiResponse, error) {
	return &ResetRpkiResponse{}, s.bgpServer.ResetRpki(&config.RpkiServerConfig{
		Address: arg.Address,
	})
}

func (s *Server) SoftResetRpki(ctx context.Context, arg *SoftResetRpkiRequest) (*SoftResetRpkiResponse, error) {
	return &SoftResetRpkiResponse{}, s.bgpServer.SoftResetRpki(&config.RpkiServerConfig{
		Address: arg.Address,
	})
}

func (s *Server) GetRpki(ctx context.Context, arg *GetRpkiRequest) (*GetRpkiResponse, error) {
	servers, err := s.bgpServer.GetRpki()
	if err != nil {
		return nil, err
	}
	l := make([]*Rpki, 0, len(servers))
	for _, s := range servers {
		received := &s.State.RpkiMessages.RpkiReceived
		sent := &s.State.RpkiMessages.RpkiSent
		rpki := &Rpki{
			Conf: &RPKIConf{
				Address:    s.Config.Address,
				RemotePort: strconv.Itoa(int(s.Config.Port)),
			},
			State: &RPKIState{
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
	return &GetRpkiResponse{Servers: l}, nil
}

func (s *Server) GetRoa(ctx context.Context, arg *GetRoaRequest) (*GetRoaResponse, error) {
	roas, err := s.bgpServer.GetRoa(bgp.RouteFamily(arg.Family))
	if err != nil {
		return nil, err
	}
	l := make([]*Roa, 0, len(roas))
	for _, r := range roas {
		host, port, _ := net.SplitHostPort(r.Src)
		l = append(l, &Roa{
			As:        r.AS,
			Maxlen:    uint32(r.MaxLen),
			Prefixlen: uint32(r.Prefix.Length),
			Prefix:    r.Prefix.Prefix.String(),
			Conf: &RPKIConf{
				Address:    host,
				RemotePort: port,
			},
		})
	}
	return &GetRoaResponse{Roas: l}, nil
}

func (s *Server) EnableZebra(ctx context.Context, arg *EnableZebraRequest) (*EnableZebraResponse, error) {
	l := []config.InstallProtocolType{}
	for _, p := range arg.RouteTypes {
		if err := config.InstallProtocolType(p).Validate(); err != nil {
			return &EnableZebraResponse{}, err
		} else {
			l = append(l, config.InstallProtocolType(p))
		}
	}
	return &EnableZebraResponse{}, s.bgpServer.StartZebraClient(&config.ZebraConfig{
		Url: arg.Url,
		RedistributeRouteTypeList: l,
		Version:                   uint8(arg.Version),
	})
}

func (s *Server) GetVrf(ctx context.Context, arg *GetVrfRequest) (*GetVrfResponse, error) {
	toApi := func(v *table.Vrf) *Vrf {
		f := func(rts []bgp.ExtendedCommunityInterface) [][]byte {
			ret := make([][]byte, 0, len(rts))
			for _, rt := range rts {
				b, _ := rt.Serialize()
				ret = append(ret, b)
			}
			return ret
		}
		rd, _ := v.Rd.Serialize()
		return &Vrf{
			Name:     v.Name,
			Rd:       rd,
			Id:       v.Id,
			ImportRt: f(v.ImportRt),
			ExportRt: f(v.ExportRt),
		}
	}
	vrfs := s.bgpServer.GetVrf()
	l := make([]*Vrf, 0, len(vrfs))
	for _, v := range vrfs {
		l = append(l, toApi(v))
	}
	return &GetVrfResponse{Vrfs: l}, nil
}

func (s *Server) AddVrf(ctx context.Context, arg *AddVrfRequest) (r *AddVrfResponse, err error) {
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
		return &AddVrfResponse{}, err
	}
	ex, err := f(arg.Vrf.ExportRt)
	if err != nil {
		return &AddVrfResponse{}, err
	}
	return &AddVrfResponse{}, s.bgpServer.AddVrf(arg.Vrf.Name, arg.Vrf.Id, rd, im, ex)
}

func (s *Server) DeleteVrf(ctx context.Context, arg *DeleteVrfRequest) (*DeleteVrfResponse, error) {
	return &DeleteVrfResponse{}, s.bgpServer.DeleteVrf(arg.Vrf.Name)
}

func NewNeighborFromAPIStruct(a *Peer) (*config.Neighbor, error) {
	pconf := &config.Neighbor{}
	if a.Conf != nil {
		pconf.Config.NeighborAddress = a.Conf.NeighborAddress
		pconf.Config.PeerAs = a.Conf.PeerAs
		pconf.Config.LocalAs = a.Conf.LocalAs
		pconf.Config.AuthPassword = a.Conf.AuthPassword
		pconf.Config.RemovePrivateAs = config.RemovePrivateAsOption(a.Conf.RemovePrivateAs)
		pconf.Config.RouteFlapDamping = a.Conf.RouteFlapDamping
		pconf.Config.SendCommunity = config.CommunityType(a.Conf.SendCommunity)
		pconf.Config.Description = a.Conf.Description
		pconf.Config.PeerGroup = a.Conf.PeerGroup
		pconf.Config.NeighborAddress = a.Conf.NeighborAddress
		pconf.Config.NeighborInterface = a.Conf.NeighborInterface
		pconf.Config.Vrf = a.Conf.Vrf

		f := func(bufs [][]byte) ([]bgp.ParameterCapabilityInterface, error) {
			var caps []bgp.ParameterCapabilityInterface
			for _, buf := range bufs {
				cap, err := bgp.DecodeCapability(buf)
				if err != nil {
					return nil, err
				}
				caps = append(caps, cap)
			}
			return caps, nil
		}

		localCaps, err := f(a.Conf.LocalCap)
		if err != nil {
			return nil, err
		}
		remoteCaps, err := f(a.Conf.RemoteCap)
		if err != nil {
			return nil, err
		}
		pconf.State.LocalCapabilityList = localCaps
		pconf.State.RemoteCapabilityList = remoteCaps

		pconf.State.RemoteRouterId = a.Conf.Id

		for _, f := range a.Families {
			family := bgp.RouteFamily(f)
			pconf.AfiSafis = append(pconf.AfiSafis, config.AfiSafi{
				Config: config.AfiSafiConfig{
					AfiSafiName: config.AfiSafiType(family.String()),
					Enabled:     true,
				},
			})
		}

		for _, pl := range a.Conf.PrefixLimits {
			for _, f := range pconf.AfiSafis {
				if f.Config.AfiSafiName == config.AfiSafiType(bgp.RouteFamily(pl.Family).String()) {
					f.PrefixLimit.Config.MaxPrefixes = pl.MaxPrefixes
					f.PrefixLimit.Config.ShutdownThresholdPct = config.Percentage(pl.ShutdownThresholdPct)
				}
			}
		}
	}

	if a.Timers != nil {
		if a.Timers.Config != nil {
			pconf.Timers.Config.ConnectRetry = float64(a.Timers.Config.ConnectRetry)
			pconf.Timers.Config.HoldTime = float64(a.Timers.Config.HoldTime)
			pconf.Timers.Config.KeepaliveInterval = float64(a.Timers.Config.KeepaliveInterval)
			pconf.Timers.Config.MinimumAdvertisementInterval = float64(a.Timers.Config.MinimumAdvertisementInterval)
		}
		if a.Timers.State != nil {
			pconf.Timers.State.KeepaliveInterval = float64(a.Timers.State.KeepaliveInterval)
			pconf.Timers.State.NegotiatedHoldTime = float64(a.Timers.State.NegotiatedHoldTime)
			pconf.Timers.State.Uptime = int64(a.Timers.State.Uptime)
			pconf.Timers.State.Downtime = int64(a.Timers.State.Downtime)
		}
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
	if a.Transport != nil {
		pconf.Transport.Config.LocalAddress = a.Transport.LocalAddress
		pconf.Transport.Config.PassiveMode = a.Transport.PassiveMode
		pconf.Transport.Config.RemotePort = uint16(a.Transport.RemotePort)
	}
	if a.EbgpMultihop != nil {
		pconf.EbgpMultihop.Config.Enabled = a.EbgpMultihop.Enabled
		pconf.EbgpMultihop.Config.MultihopTtl = uint8(a.EbgpMultihop.MultihopTtl)
	}
	if a.Info != nil {
		pconf.State.SessionState = config.SessionState(a.Info.BgpState)
		pconf.State.AdminState = config.IntToAdminStateMap[int(a.Info.AdminState)]

		pconf.State.AdjTable.Received = a.Info.Received
		pconf.State.AdjTable.Accepted = a.Info.Accepted
		pconf.State.AdjTable.Advertised = a.Info.Advertised

		if a.Info.Messages != nil {
			if a.Info.Messages.Sent != nil {
				pconf.State.Messages.Sent.Update = a.Info.Messages.Sent.UPDATE
				pconf.State.Messages.Sent.Notification = a.Info.Messages.Sent.NOTIFICATION
				pconf.State.Messages.Sent.Open = a.Info.Messages.Sent.OPEN
				pconf.State.Messages.Sent.Refresh = a.Info.Messages.Sent.REFRESH
				pconf.State.Messages.Sent.Keepalive = a.Info.Messages.Sent.KEEPALIVE
				pconf.State.Messages.Sent.Discarded = a.Info.Messages.Sent.DISCARDED
				pconf.State.Messages.Sent.Total = a.Info.Messages.Sent.TOTAL
			}
			if a.Info.Messages.Received != nil {
				pconf.State.Messages.Received.Update = a.Info.Messages.Received.UPDATE
				pconf.State.Messages.Received.Open = a.Info.Messages.Received.OPEN
				pconf.State.Messages.Received.Refresh = a.Info.Messages.Received.REFRESH
				pconf.State.Messages.Received.Keepalive = a.Info.Messages.Received.KEEPALIVE
				pconf.State.Messages.Received.Discarded = a.Info.Messages.Received.DISCARDED
				pconf.State.Messages.Received.Total = a.Info.Messages.Received.TOTAL
			}
		}
	}
	return pconf, nil
}

func (s *Server) AddNeighbor(ctx context.Context, arg *AddNeighborRequest) (*AddNeighborResponse, error) {
	c, err := NewNeighborFromAPIStruct(arg.Peer)
	if err != nil {
		return nil, err
	}
	return &AddNeighborResponse{}, s.bgpServer.AddNeighbor(c)
}

func (s *Server) DeleteNeighbor(ctx context.Context, arg *DeleteNeighborRequest) (*DeleteNeighborResponse, error) {
	return &DeleteNeighborResponse{}, s.bgpServer.DeleteNeighbor(&config.Neighbor{Config: config.NeighborConfig{
		NeighborAddress:   arg.Peer.Conf.NeighborAddress,
		NeighborInterface: arg.Peer.Conf.NeighborInterface,
	}})
}

func NewPrefixFromApiStruct(a *Prefix) (*table.Prefix, error) {
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

func NewAPIPrefixFromConfigStruct(c config.Prefix) (*Prefix, error) {
	min, max, err := config.ParseMaskLength(c.IpPrefix, c.MasklengthRange)
	if err != nil {
		return nil, err
	}
	return &Prefix{
		IpPrefix:      c.IpPrefix,
		MaskLengthMin: uint32(min),
		MaskLengthMax: uint32(max),
	}, nil
}

func NewAPIDefinedSetFromTableStruct(t table.DefinedSet) (*DefinedSet, error) {
	a := &DefinedSet{
		Type: DefinedType(t.Type()),
		Name: t.Name(),
	}
	switch t.Type() {
	case table.DEFINED_TYPE_PREFIX:
		s := t.(*table.PrefixSet)
		c := s.ToConfig()
		for _, p := range c.PrefixList {
			ap, err := NewAPIPrefixFromConfigStruct(p)
			if err != nil {
				return nil, err
			}
			a.Prefixes = append(a.Prefixes, ap)
		}
	case table.DEFINED_TYPE_NEIGHBOR:
		s := t.(*table.NeighborSet)
		c := s.ToConfig()
		for _, n := range c.NeighborInfoList {
			a.List = append(a.List, n)
		}
	case table.DEFINED_TYPE_AS_PATH:
		s := t.(*table.AsPathSet)
		c := s.ToConfig()
		for _, n := range c.AsPathList {
			a.List = append(a.List, n)
		}
	case table.DEFINED_TYPE_COMMUNITY:
		s := t.(*table.CommunitySet)
		c := s.ToConfig()
		for _, n := range c.CommunityList {
			a.List = append(a.List, n)
		}
	case table.DEFINED_TYPE_EXT_COMMUNITY:
		s := t.(*table.ExtCommunitySet)
		c := s.ToConfig()
		for _, n := range c.ExtCommunityList {
			a.List = append(a.List, n)
		}
	case table.DEFINED_TYPE_LARGE_COMMUNITY:
		s := t.(*table.LargeCommunitySet)
		c := s.ToConfig()
		for _, n := range c.LargeCommunityList {
			a.List = append(a.List, n)
		}
	default:
		return nil, fmt.Errorf("invalid defined type")
	}
	return a, nil
}

func NewDefinedSetFromApiStruct(a *DefinedSet) (table.DefinedSet, error) {
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
	case table.DEFINED_TYPE_LARGE_COMMUNITY:
		return table.NewLargeCommunitySet(config.LargeCommunitySet{
			LargeCommunitySetName: a.Name,
			LargeCommunityList:    a.List,
		})
	default:
		return nil, fmt.Errorf("invalid defined type")
	}
}

func (s *Server) GetDefinedSet(ctx context.Context, arg *GetDefinedSetRequest) (*GetDefinedSetResponse, error) {
	cd, err := s.bgpServer.GetDefinedSet(table.DefinedType(arg.Type))
	if err != nil {
		return nil, err
	}
	sets := make([]*DefinedSet, 0)
	for _, cs := range cd.PrefixSets {
		ad := &DefinedSet{
			Type: DefinedType_PREFIX,
			Name: cs.PrefixSetName,
			Prefixes: func() []*Prefix {
				l := make([]*Prefix, 0, len(cs.PrefixList))
				for _, p := range cs.PrefixList {
					exp := regexp.MustCompile("(\\d+)\\.\\.(\\d+)")
					elems := exp.FindStringSubmatch(p.MasklengthRange)
					min, _ := strconv.Atoi(elems[1])
					max, _ := strconv.Atoi(elems[2])

					l = append(l, &Prefix{IpPrefix: p.IpPrefix, MaskLengthMin: uint32(min), MaskLengthMax: uint32(max)})
				}
				return l
			}(),
		}
		sets = append(sets, ad)

	}
	for _, cs := range cd.NeighborSets {
		ad := &DefinedSet{
			Type: DefinedType_NEIGHBOR,
			Name: cs.NeighborSetName,
			List: cs.NeighborInfoList,
		}
		sets = append(sets, ad)
	}
	for _, cs := range cd.BgpDefinedSets.CommunitySets {
		ad := &DefinedSet{
			Type: DefinedType_COMMUNITY,
			Name: cs.CommunitySetName,
			List: cs.CommunityList,
		}
		sets = append(sets, ad)
	}
	for _, cs := range cd.BgpDefinedSets.ExtCommunitySets {
		ad := &DefinedSet{
			Type: DefinedType_EXT_COMMUNITY,
			Name: cs.ExtCommunitySetName,
			List: cs.ExtCommunityList,
		}
		sets = append(sets, ad)
	}
	for _, cs := range cd.BgpDefinedSets.LargeCommunitySets {
		ad := &DefinedSet{
			Type: DefinedType_LARGE_COMMUNITY,
			Name: cs.LargeCommunitySetName,
			List: cs.LargeCommunityList,
		}
		sets = append(sets, ad)
	}
	for _, cs := range cd.BgpDefinedSets.AsPathSets {
		ad := &DefinedSet{
			Type: DefinedType_AS_PATH,
			Name: cs.AsPathSetName,
			List: cs.AsPathList,
		}
		sets = append(sets, ad)
	}

	return &GetDefinedSetResponse{Sets: sets}, nil
}

func (s *Server) AddDefinedSet(ctx context.Context, arg *AddDefinedSetRequest) (*AddDefinedSetResponse, error) {
	set, err := NewDefinedSetFromApiStruct(arg.Set)
	if err != nil {
		return nil, err
	}
	return &AddDefinedSetResponse{}, s.bgpServer.AddDefinedSet(set)
}

func (s *Server) DeleteDefinedSet(ctx context.Context, arg *DeleteDefinedSetRequest) (*DeleteDefinedSetResponse, error) {
	set, err := NewDefinedSetFromApiStruct(arg.Set)
	if err != nil {
		return nil, err
	}
	return &DeleteDefinedSetResponse{}, s.bgpServer.DeleteDefinedSet(set, arg.All)
}

func (s *Server) ReplaceDefinedSet(ctx context.Context, arg *ReplaceDefinedSetRequest) (*ReplaceDefinedSetResponse, error) {
	set, err := NewDefinedSetFromApiStruct(arg.Set)
	if err != nil {
		return nil, err
	}
	return &ReplaceDefinedSetResponse{}, s.bgpServer.ReplaceDefinedSet(set)
}

func NewAPIStatementFromTableStruct(t *table.Statement) *Statement {
	return toStatementApi(t.ToConfig())
}

func toStatementApi(s *config.Statement) *Statement {
	cs := &Conditions{}
	if s.Conditions.MatchPrefixSet.PrefixSet != "" {
		cs.PrefixSet = &MatchSet{
			Type: MatchType(s.Conditions.MatchPrefixSet.MatchSetOptions.ToInt()),
			Name: s.Conditions.MatchPrefixSet.PrefixSet,
		}
	}
	if s.Conditions.MatchNeighborSet.NeighborSet != "" {
		cs.NeighborSet = &MatchSet{
			Type: MatchType(s.Conditions.MatchNeighborSet.MatchSetOptions.ToInt()),
			Name: s.Conditions.MatchNeighborSet.NeighborSet,
		}
	}
	if s.Conditions.BgpConditions.AsPathLength.Operator != "" {
		cs.AsPathLength = &AsPathLength{
			Length: s.Conditions.BgpConditions.AsPathLength.Value,
			Type:   AsPathLengthType(s.Conditions.BgpConditions.AsPathLength.Operator.ToInt()),
		}
	}
	if s.Conditions.BgpConditions.MatchAsPathSet.AsPathSet != "" {
		cs.AsPathSet = &MatchSet{
			Type: MatchType(s.Conditions.BgpConditions.MatchAsPathSet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchAsPathSet.AsPathSet,
		}
	}
	if s.Conditions.BgpConditions.MatchCommunitySet.CommunitySet != "" {
		cs.CommunitySet = &MatchSet{
			Type: MatchType(s.Conditions.BgpConditions.MatchCommunitySet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchCommunitySet.CommunitySet,
		}
	}
	if s.Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet != "" {
		cs.ExtCommunitySet = &MatchSet{
			Type: MatchType(s.Conditions.BgpConditions.MatchExtCommunitySet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet,
		}
	}
	if s.Conditions.BgpConditions.MatchLargeCommunitySet.LargeCommunitySet != "" {
		cs.LargeCommunitySet = &MatchSet{
			Type: MatchType(s.Conditions.BgpConditions.MatchLargeCommunitySet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchLargeCommunitySet.LargeCommunitySet,
		}
	}
	if s.Conditions.BgpConditions.RouteType != "" {
		cs.RouteType = Conditions_RouteType(s.Conditions.BgpConditions.RouteType.ToInt())
	}
	cs.RpkiResult = int32(s.Conditions.BgpConditions.RpkiValidationResult.ToInt())
	as := &Actions{
		RouteAction: func() RouteAction {
			switch s.Actions.RouteDisposition {
			case config.ROUTE_DISPOSITION_ACCEPT_ROUTE:
				return RouteAction_ACCEPT
			case config.ROUTE_DISPOSITION_REJECT_ROUTE:
				return RouteAction_REJECT
			}
			return RouteAction_NONE
		}(),
		Community: func() *CommunityAction {
			if len(s.Actions.BgpActions.SetCommunity.SetCommunityMethod.CommunitiesList) == 0 {
				return nil
			}
			return &CommunityAction{
				Type:        CommunityActionType(config.BgpSetCommunityOptionTypeToIntMap[config.BgpSetCommunityOptionType(s.Actions.BgpActions.SetCommunity.Options)]),
				Communities: s.Actions.BgpActions.SetCommunity.SetCommunityMethod.CommunitiesList}
		}(),
		Med: func() *MedAction {
			if len(string(s.Actions.BgpActions.SetMed)) == 0 {
				return nil
			}
			exp := regexp.MustCompile("^(\\+|\\-)?(\\d+)$")
			elems := exp.FindStringSubmatch(string(s.Actions.BgpActions.SetMed))
			action := MedActionType_MED_REPLACE
			switch elems[1] {
			case "+", "-":
				action = MedActionType_MED_MOD
			}
			value, _ := strconv.Atoi(string(s.Actions.BgpActions.SetMed))
			return &MedAction{
				Value: int64(value),
				Type:  action,
			}
		}(),
		AsPrepend: func() *AsPrependAction {
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
			return &AsPrependAction{
				Asn:         uint32(asn),
				Repeat:      uint32(s.Actions.BgpActions.SetAsPathPrepend.RepeatN),
				UseLeftMost: useleft,
			}
		}(),
		ExtCommunity: func() *CommunityAction {
			if len(s.Actions.BgpActions.SetExtCommunity.SetExtCommunityMethod.CommunitiesList) == 0 {
				return nil
			}
			return &CommunityAction{
				Type:        CommunityActionType(config.BgpSetCommunityOptionTypeToIntMap[config.BgpSetCommunityOptionType(s.Actions.BgpActions.SetExtCommunity.Options)]),
				Communities: s.Actions.BgpActions.SetExtCommunity.SetExtCommunityMethod.CommunitiesList,
			}
		}(),
		LargeCommunity: func() *CommunityAction {
			if len(s.Actions.BgpActions.SetLargeCommunity.SetLargeCommunityMethod.CommunitiesList) == 0 {
				return nil
			}
			return &CommunityAction{
				Type:        CommunityActionType(config.BgpSetCommunityOptionTypeToIntMap[config.BgpSetCommunityOptionType(s.Actions.BgpActions.SetLargeCommunity.Options)]),
				Communities: s.Actions.BgpActions.SetLargeCommunity.SetLargeCommunityMethod.CommunitiesList,
			}
		}(),
		Nexthop: func() *NexthopAction {
			if len(string(s.Actions.BgpActions.SetNextHop)) == 0 {
				return nil
			}

			if string(s.Actions.BgpActions.SetNextHop) == "self" {
				return &NexthopAction{
					Self: true,
				}
			}
			return &NexthopAction{
				Address: string(s.Actions.BgpActions.SetNextHop),
			}
		}(),
		LocalPref: func() *LocalPrefAction {
			if s.Actions.BgpActions.SetLocalPref == 0 {
				return nil
			}
			return &LocalPrefAction{Value: s.Actions.BgpActions.SetLocalPref}
		}(),
	}
	return &Statement{
		Name:       s.Name,
		Conditions: cs,
		Actions:    as,
	}
}

func toConfigMatchSetOption(a MatchType) (config.MatchSetOptionsType, error) {
	var typ config.MatchSetOptionsType
	switch a {
	case MatchType_ANY:
		typ = config.MATCH_SET_OPTIONS_TYPE_ANY
	case MatchType_ALL:
		typ = config.MATCH_SET_OPTIONS_TYPE_ALL
	case MatchType_INVERT:
		typ = config.MATCH_SET_OPTIONS_TYPE_INVERT
	default:
		return typ, fmt.Errorf("invalid match type")
	}
	return typ, nil
}

func toConfigMatchSetOptionRestricted(a MatchType) (config.MatchSetOptionsRestrictedType, error) {
	var typ config.MatchSetOptionsRestrictedType
	switch a {
	case MatchType_ANY:
		typ = config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY
	case MatchType_INVERT:
		typ = config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT
	default:
		return typ, fmt.Errorf("invalid match type")
	}
	return typ, nil
}

func NewPrefixConditionFromApiStruct(a *MatchSet) (*table.PrefixCondition, error) {
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

func NewNeighborConditionFromApiStruct(a *MatchSet) (*table.NeighborCondition, error) {
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

func NewAsPathLengthConditionFromApiStruct(a *AsPathLength) (*table.AsPathLengthCondition, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewAsPathLengthCondition(config.AsPathLength{
		Operator: config.IntToAttributeComparisonMap[int(a.Type)],
		Value:    a.Length,
	})
}

func NewAsPathConditionFromApiStruct(a *MatchSet) (*table.AsPathCondition, error) {
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

func NewRouteTypeConditionFromApiStruct(a Conditions_RouteType) (*table.RouteTypeCondition, error) {
	if a == 0 {
		return nil, nil
	}
	typ, ok := config.IntToRouteTypeMap[int(a)]
	if !ok {
		return nil, fmt.Errorf("invalid route type: %d", a)
	}
	return table.NewRouteTypeCondition(typ)
}

func NewCommunityConditionFromApiStruct(a *MatchSet) (*table.CommunityCondition, error) {
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

func NewExtCommunityConditionFromApiStruct(a *MatchSet) (*table.ExtCommunityCondition, error) {
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

func NewLargeCommunityConditionFromApiStruct(a *MatchSet) (*table.LargeCommunityCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOption(a.Type)
	if err != nil {
		return nil, err
	}
	c := config.MatchLargeCommunitySet{
		LargeCommunitySet: a.Name,
		MatchSetOptions:   typ,
	}
	return table.NewLargeCommunityCondition(c)
}

func NewRoutingActionFromApiStruct(a RouteAction) (*table.RoutingAction, error) {
	if a == RouteAction_NONE {
		return nil, nil
	}
	accept := false
	if a == RouteAction_ACCEPT {
		accept = true
	}
	return &table.RoutingAction{
		AcceptRoute: accept,
	}, nil
}

func NewCommunityActionFromApiStruct(a *CommunityAction) (*table.CommunityAction, error) {
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

func NewExtCommunityActionFromApiStruct(a *CommunityAction) (*table.ExtCommunityAction, error) {
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

func NewLargeCommunityActionFromApiStruct(a *CommunityAction) (*table.LargeCommunityAction, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewLargeCommunityAction(config.SetLargeCommunity{
		Options: config.IntToBgpSetCommunityOptionTypeMap[int(a.Type)],
		SetLargeCommunityMethod: config.SetLargeCommunityMethod{
			CommunitiesList: a.Communities,
		},
	})
}

func NewMedActionFromApiStruct(a *MedAction) (*table.MedAction, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewMedActionFromApiStruct(table.MedActionType(a.Type), a.Value), nil
}

func NewLocalPrefActionFromApiStruct(a *LocalPrefAction) (*table.LocalPrefAction, error) {
	if a == nil || a.Value == 0 {
		return nil, nil
	}
	return table.NewLocalPrefAction(a.Value)
}

func NewAsPathPrependActionFromApiStruct(a *AsPrependAction) (*table.AsPathPrependAction, error) {
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

func NewNexthopActionFromApiStruct(a *NexthopAction) (*table.NexthopAction, error) {
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

func NewStatementFromApiStruct(a *Statement) (*table.Statement, error) {
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
				return NewRouteTypeConditionFromApiStruct(a.Conditions.RouteType)
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
			func() (table.Condition, error) {
				return NewLargeCommunityConditionFromApiStruct(a.Conditions.LargeCommunitySet)
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
				return NewLargeCommunityActionFromApiStruct(a.Actions.LargeCommunity)
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

func (s *Server) GetStatement(ctx context.Context, arg *GetStatementRequest) (*GetStatementResponse, error) {
	l := make([]*Statement, 0)
	for _, s := range s.bgpServer.GetStatement() {
		l = append(l, toStatementApi(s))
	}
	return &GetStatementResponse{Statements: l}, nil
}

func (s *Server) AddStatement(ctx context.Context, arg *AddStatementRequest) (*AddStatementResponse, error) {
	st, err := NewStatementFromApiStruct(arg.Statement)
	if err == nil {
		err = s.bgpServer.AddStatement(st)
	}
	return &AddStatementResponse{}, err
}

func (s *Server) DeleteStatement(ctx context.Context, arg *DeleteStatementRequest) (*DeleteStatementResponse, error) {
	st, err := NewStatementFromApiStruct(arg.Statement)
	if err == nil {
		err = s.bgpServer.DeleteStatement(st, arg.All)
	}
	return &DeleteStatementResponse{}, err
}

func (s *Server) ReplaceStatement(ctx context.Context, arg *ReplaceStatementRequest) (*ReplaceStatementResponse, error) {
	st, err := NewStatementFromApiStruct(arg.Statement)
	if err == nil {
		err = s.bgpServer.ReplaceStatement(st)
	}
	return &ReplaceStatementResponse{}, err
}

func NewAPIPolicyFromTableStruct(p *table.Policy) *Policy {
	return toPolicyApi(p.ToConfig())
}

func toPolicyApi(p *config.PolicyDefinition) *Policy {
	return &Policy{
		Name: p.Name,
		Statements: func() []*Statement {
			l := make([]*Statement, 0)
			for _, s := range p.Statements {
				l = append(l, toStatementApi(&s))
			}
			return l
		}(),
	}
}

func NewAPIPolicyAssignmentFromTableStruct(t *table.PolicyAssignment) *PolicyAssignment {
	return &PolicyAssignment{
		Type: func() PolicyType {
			switch t.Type {
			case table.POLICY_DIRECTION_IN:
				return PolicyType_IN
			case table.POLICY_DIRECTION_IMPORT:
				return PolicyType_IMPORT
			case table.POLICY_DIRECTION_EXPORT:
				return PolicyType_EXPORT
			}
			log.Errorf("invalid policy-type: %s", t.Type)
			return PolicyType(-1)
		}(),
		Default: func() RouteAction {
			switch t.Default {
			case table.ROUTE_TYPE_ACCEPT:
				return RouteAction_ACCEPT
			case table.ROUTE_TYPE_REJECT:
				return RouteAction_REJECT
			}
			return RouteAction_NONE
		}(),
		Name: t.Name,
		Resource: func() Resource {
			if t.Name != "" {
				return Resource_LOCAL
			}
			return Resource_GLOBAL
		}(),
		Policies: func() []*Policy {
			l := make([]*Policy, 0)
			for _, p := range t.Policies {
				l = append(l, NewAPIPolicyFromTableStruct(p))
			}
			return l
		}(),
	}
}

func NewPolicyFromApiStruct(a *Policy) (*table.Policy, error) {
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

func (s *Server) GetPolicy(ctx context.Context, arg *GetPolicyRequest) (*GetPolicyResponse, error) {
	l := make([]*Policy, 0)
	for _, p := range s.bgpServer.GetPolicy() {
		l = append(l, toPolicyApi(p))
	}
	return &GetPolicyResponse{Policies: l}, nil
}

func (s *Server) AddPolicy(ctx context.Context, arg *AddPolicyRequest) (*AddPolicyResponse, error) {
	x, err := NewPolicyFromApiStruct(arg.Policy)
	if err != nil {
		return nil, err
	}
	return &AddPolicyResponse{}, s.bgpServer.AddPolicy(x, arg.ReferExistingStatements)
}

func (s *Server) DeletePolicy(ctx context.Context, arg *DeletePolicyRequest) (*DeletePolicyResponse, error) {
	x, err := NewPolicyFromApiStruct(arg.Policy)
	if err != nil {
		return nil, err
	}
	return &DeletePolicyResponse{}, s.bgpServer.DeletePolicy(x, arg.All, arg.PreserveStatements)
}

func (s *Server) ReplacePolicy(ctx context.Context, arg *ReplacePolicyRequest) (*ReplacePolicyResponse, error) {
	x, err := NewPolicyFromApiStruct(arg.Policy)
	if err != nil {
		return nil, err
	}
	return &ReplacePolicyResponse{}, s.bgpServer.ReplacePolicy(x, arg.ReferExistingStatements, arg.PreserveStatements)
}

func toPolicyAssignmentName(a *PolicyAssignment) (string, table.PolicyDirection, error) {
	switch a.Resource {
	case Resource_GLOBAL:
		switch a.Type {
		case PolicyType_IMPORT:
			return "", table.POLICY_DIRECTION_IMPORT, nil
		case PolicyType_EXPORT:
			return "", table.POLICY_DIRECTION_EXPORT, nil
		default:
			return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("invalid policy type")
		}
	case Resource_LOCAL:
		switch a.Type {
		case PolicyType_IN:
			return a.Name, table.POLICY_DIRECTION_IN, nil
		case PolicyType_IMPORT:
			return a.Name, table.POLICY_DIRECTION_IMPORT, nil
		case PolicyType_EXPORT:
			return a.Name, table.POLICY_DIRECTION_EXPORT, nil
		default:
			return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("invalid policy type")
		}
	default:
		return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("invalid resource type")
	}

}

func (s *Server) GetPolicyAssignment(ctx context.Context, arg *GetPolicyAssignmentRequest) (*GetPolicyAssignmentResponse, error) {
	name, dir, err := toPolicyAssignmentName(arg.Assignment)
	if err != nil {
		return nil, err
	}
	def, pols, err := s.bgpServer.GetPolicyAssignment(name, dir)
	if err != nil {
		return nil, err
	}
	policies := make([]*table.Policy, 0, len(pols))
	for _, p := range pols {
		t, err := table.NewPolicy(*p)
		if err != nil {
			return nil, err
		}
		policies = append(policies, t)
	}
	t := &table.PolicyAssignment{
		Name:     name,
		Type:     dir,
		Default:  def,
		Policies: policies,
	}
	return &GetPolicyAssignmentResponse{NewAPIPolicyAssignmentFromTableStruct(t)}, err
}

func defaultRouteType(d RouteAction) table.RouteType {
	switch d {
	case RouteAction_ACCEPT:
		return table.ROUTE_TYPE_ACCEPT
	case RouteAction_REJECT:
		return table.ROUTE_TYPE_REJECT
	default:
		return table.ROUTE_TYPE_NONE
	}
}

func toPolicyDefinition(policies []*Policy) []*config.PolicyDefinition {
	l := make([]*config.PolicyDefinition, 0, len(policies))
	for _, p := range policies {
		l = append(l, &config.PolicyDefinition{Name: p.Name})
	}
	return l
}

func (s *Server) AddPolicyAssignment(ctx context.Context, arg *AddPolicyAssignmentRequest) (*AddPolicyAssignmentResponse, error) {
	name, dir, err := toPolicyAssignmentName(arg.Assignment)
	if err != nil {
		return nil, err
	}
	return &AddPolicyAssignmentResponse{}, s.bgpServer.AddPolicyAssignment(name, dir, toPolicyDefinition(arg.Assignment.Policies), defaultRouteType(arg.Assignment.Default))
}

func (s *Server) DeletePolicyAssignment(ctx context.Context, arg *DeletePolicyAssignmentRequest) (*DeletePolicyAssignmentResponse, error) {
	name, dir, err := toPolicyAssignmentName(arg.Assignment)
	if err != nil {
		return nil, err
	}
	return &DeletePolicyAssignmentResponse{}, s.bgpServer.DeletePolicyAssignment(name, dir, toPolicyDefinition(arg.Assignment.Policies), arg.All)
}

func (s *Server) ReplacePolicyAssignment(ctx context.Context, arg *ReplacePolicyAssignmentRequest) (*ReplacePolicyAssignmentResponse, error) {
	name, dir, err := toPolicyAssignmentName(arg.Assignment)
	if err != nil {
		return nil, err
	}
	return &ReplacePolicyAssignmentResponse{}, s.bgpServer.ReplacePolicyAssignment(name, dir, toPolicyDefinition(arg.Assignment.Policies), defaultRouteType(arg.Assignment.Default))
}

func (s *Server) GetServer(ctx context.Context, arg *GetServerRequest) (*GetServerResponse, error) {
	g := s.bgpServer.GetServer()
	return &GetServerResponse{
		Global: &Global{
			As:               g.Config.As,
			RouterId:         g.Config.RouterId,
			ListenPort:       g.Config.Port,
			ListenAddresses:  g.Config.LocalAddressList,
			UseMultiplePaths: g.UseMultiplePaths.Config.Enabled,
		},
	}, nil
}

func (s *Server) StartServer(ctx context.Context, arg *StartServerRequest) (*StartServerResponse, error) {
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
			AfiSafis: families,
			UseMultiplePaths: config.UseMultiplePaths{
				Config: config.UseMultiplePathsConfig{
					Enabled: g.UseMultiplePaths,
				},
			},
		},
	}
	return &StartServerResponse{}, s.bgpServer.Start(&b.Global)
}

func (s *Server) StopServer(ctx context.Context, arg *StopServerRequest) (*StopServerResponse, error) {
	return &StopServerResponse{}, s.bgpServer.Stop()
}

func (s *Server) GetRibInfo(ctx context.Context, arg *GetRibInfoRequest) (*GetRibInfoResponse, error) {
	family := bgp.RouteFamily(arg.Info.Family)
	var in bool
	var err error
	var info *table.TableInfo
	switch arg.Info.Type {
	case Resource_GLOBAL, Resource_LOCAL:
		info, err = s.bgpServer.GetRibInfo(arg.Info.Name, family)
	case Resource_ADJ_IN:
		in = true
		fallthrough
	case Resource_ADJ_OUT:
		info, err = s.bgpServer.GetAdjRibInfo(arg.Info.Name, family, in)
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", arg.Info.Type)
	}

	if err != nil {
		return nil, err
	}

	return &GetRibInfoResponse{
		Info: &TableInfo{
			Type:           arg.Info.Type,
			Family:         arg.Info.Family,
			Name:           arg.Info.Name,
			NumDestination: uint64(info.NumDestination),
			NumPath:        uint64(info.NumPath),
			NumAccepted:    uint64(info.NumAccepted),
		},
	}, nil

}
