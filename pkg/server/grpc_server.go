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
	"bytes"
	"fmt"
	"io"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	farm "github.com/dgryski/go-farm"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/internal/pkg/apiutil"
	"github.com/osrg/gobgp/internal/pkg/config"
	"github.com/osrg/gobgp/internal/pkg/table"
	"github.com/osrg/gobgp/pkg/packet/bgp"
)

type Server struct {
	bgpServer  *BgpServer
	grpcServer *grpc.Server
	hosts      string
}

func NewGrpcServer(b *BgpServer, hosts string) *Server {
	size := 256 << 20
	return NewServer(b, grpc.NewServer(grpc.MaxRecvMsgSize(size), grpc.MaxSendMsgSize(size)), hosts)
}

func NewServer(b *BgpServer, g *grpc.Server, hosts string) *Server {
	grpc.EnableTracing = false
	s := &Server{
		bgpServer:  b,
		grpcServer: g,
		hosts:      hosts,
	}
	api.RegisterGobgpApiServer(g, s)
	return s
}

func (s *Server) Serve() error {
	var wg sync.WaitGroup
	l := strings.Split(s.hosts, ",")
	wg.Add(len(l))

	serve := func(host string) {
		defer wg.Done()
		lis, err := net.Listen("tcp", host)
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

	for _, host := range l {
		go serve(host)
	}
	wg.Wait()
	return nil
}

func NewMpGracefulRestartFromConfigStruct(c *config.MpGracefulRestart) *api.MpGracefulRestart {
	return &api.MpGracefulRestart{
		Config: &api.MpGracefulRestartConfig{
			Enabled: c.Config.Enabled,
		},
	}
}

func extractFamilyFromConfigAfiSafi(c *config.AfiSafi) uint32 {
	if c == nil {
		return 0
	}
	// If address family value is already stored in AfiSafiState structure,
	// we prefer to use this value.
	if c.State.Family != 0 {
		return uint32(c.State.Family)
	}
	// In case that Neighbor structure came from CLI or gRPC, address family
	// value in AfiSafiState structure can be omitted.
	// Here extracts value from AfiSafiName field in AfiSafiConfig structure.
	if rf, err := bgp.GetRouteFamily(string(c.Config.AfiSafiName)); err == nil {
		return uint32(rf)
	}
	// Ignores invalid address family name
	return 0
}

func NewAfiSafiConfigFromConfigStruct(c *config.AfiSafi) *api.AfiSafiConfig {
	return &api.AfiSafiConfig{
		Family:  extractFamilyFromConfigAfiSafi(c),
		Enabled: c.Config.Enabled,
	}
}

func NewApplyPolicyFromConfigStruct(c *config.ApplyPolicy) *api.ApplyPolicy {
	applyPolicy := &api.ApplyPolicy{
		ImportPolicy: &api.PolicyAssignment{
			Type:    api.PolicyDirection_IMPORT,
			Default: api.RouteAction(c.Config.DefaultImportPolicy.ToInt()),
		},
		ExportPolicy: &api.PolicyAssignment{
			Type:    api.PolicyDirection_EXPORT,
			Default: api.RouteAction(c.Config.DefaultExportPolicy.ToInt()),
		},
	}

	for _, pname := range c.Config.ImportPolicyList {
		applyPolicy.ImportPolicy.Policies = append(applyPolicy.ImportPolicy.Policies, &api.Policy{Name: pname})
	}
	for _, pname := range c.Config.ExportPolicyList {
		applyPolicy.ExportPolicy.Policies = append(applyPolicy.ExportPolicy.Policies, &api.Policy{Name: pname})
	}

	return applyPolicy
}

func NewRouteSelectionOptionsFromConfigStruct(c *config.RouteSelectionOptions) *api.RouteSelectionOptions {
	return &api.RouteSelectionOptions{
		Config: &api.RouteSelectionOptionsConfig{
			AlwaysCompareMed:        c.Config.AlwaysCompareMed,
			IgnoreAsPathLength:      c.Config.IgnoreAsPathLength,
			ExternalCompareRouterId: c.Config.ExternalCompareRouterId,
			AdvertiseInactiveRoutes: c.Config.AdvertiseInactiveRoutes,
			EnableAigp:              c.Config.EnableAigp,
			IgnoreNextHopIgpMetric:  c.Config.IgnoreNextHopIgpMetric,
		},
	}
}

func NewUseMultiplePathsFromConfigStruct(c *config.UseMultiplePaths) *api.UseMultiplePaths {
	return &api.UseMultiplePaths{
		Config: &api.UseMultiplePathsConfig{
			Enabled: c.Config.Enabled,
		},
		Ebgp: &api.Ebgp{
			Config: &api.EbgpConfig{
				AllowMultipleAs: c.Ebgp.Config.AllowMultipleAs,
				MaximumPaths:    c.Ebgp.Config.MaximumPaths,
			},
		},
		Ibgp: &api.Ibgp{
			Config: &api.IbgpConfig{
				MaximumPaths: c.Ibgp.Config.MaximumPaths,
			},
		},
	}
}

func NewPrefixLimitFromConfigStruct(c *config.AfiSafi) *api.PrefixLimit {
	if c.PrefixLimit.Config.MaxPrefixes == 0 {
		return nil
	}

	return &api.PrefixLimit{
		Family:               uint32(c.State.Family),
		MaxPrefixes:          c.PrefixLimit.Config.MaxPrefixes,
		ShutdownThresholdPct: uint32(c.PrefixLimit.Config.ShutdownThresholdPct),
	}
}

func NewRouteTargetMembershipFromConfigStruct(c *config.RouteTargetMembership) *api.RouteTargetMembership {
	return &api.RouteTargetMembership{
		Config: &api.RouteTargetMembershipConfig{
			DeferralTime: uint32(c.Config.DeferralTime),
		},
	}
}

func NewLongLivedGracefulRestartFromConfigStruct(c *config.LongLivedGracefulRestart) *api.LongLivedGracefulRestart {
	return &api.LongLivedGracefulRestart{
		Config: &api.LongLivedGracefulRestartConfig{
			Enabled:     c.Config.Enabled,
			RestartTime: c.Config.RestartTime,
		},
	}
}

func NewAddPathsFromConfigStruct(c *config.AddPaths) *api.AddPaths {
	return &api.AddPaths{
		Config: &api.AddPathsConfig{
			Receive: c.Config.Receive,
			SendMax: uint32(c.Config.SendMax),
		},
	}
}

func NewAfiSafiFromConfigStruct(c *config.AfiSafi) *api.AfiSafi {
	return &api.AfiSafi{
		MpGracefulRestart:        NewMpGracefulRestartFromConfigStruct(&c.MpGracefulRestart),
		Config:                   NewAfiSafiConfigFromConfigStruct(c),
		ApplyPolicy:              NewApplyPolicyFromConfigStruct(&c.ApplyPolicy),
		RouteSelectionOptions:    NewRouteSelectionOptionsFromConfigStruct(&c.RouteSelectionOptions),
		UseMultiplePaths:         NewUseMultiplePathsFromConfigStruct(&c.UseMultiplePaths),
		PrefixLimits:             NewPrefixLimitFromConfigStruct(c),
		RouteTargetMembership:    NewRouteTargetMembershipFromConfigStruct(&c.RouteTargetMembership),
		LongLivedGracefulRestart: NewLongLivedGracefulRestartFromConfigStruct(&c.LongLivedGracefulRestart),
		AddPaths:                 NewAddPathsFromConfigStruct(&c.AddPaths),
	}
}

func NewPeerFromConfigStruct(pconf *config.Neighbor) *api.Peer {
	families := make([]uint32, 0, len(pconf.AfiSafis))
	prefixLimits := make([]*api.PrefixLimit, 0, len(pconf.AfiSafis))
	afiSafis := make([]*api.AfiSafi, 0, len(pconf.AfiSafis))
	for _, f := range pconf.AfiSafis {
		families = append(families, extractFamilyFromConfigAfiSafi(&f))
		if prefixLimit := NewPrefixLimitFromConfigStruct(&f); prefixLimit != nil {
			prefixLimits = append(prefixLimits, prefixLimit)
		}
		if afiSafi := NewAfiSafiFromConfigStruct(&f); afiSafi != nil {
			afiSafis = append(afiSafis, afiSafi)
		}
	}

	timer := pconf.Timers
	s := pconf.State
	localAddress := pconf.Transport.Config.LocalAddress
	if pconf.Transport.State.LocalAddress != "" {
		localAddress = pconf.Transport.State.LocalAddress
	}
	remoteCap, err := apiutil.MarshalCapabilities(pconf.State.RemoteCapabilityList)
	if err != nil {
		return nil
	}
	localCap, err := apiutil.MarshalCapabilities(pconf.State.LocalCapabilityList)
	if err != nil {
		return nil
	}
	var removePrivateAs api.PeerConf_RemovePrivateAs
	switch pconf.Config.RemovePrivateAs {
	case config.REMOVE_PRIVATE_AS_OPTION_ALL:
		removePrivateAs = api.PeerConf_ALL
	case config.REMOVE_PRIVATE_AS_OPTION_REPLACE:
		removePrivateAs = api.PeerConf_REPLACE
	}
	return &api.Peer{
		Families:    families,
		ApplyPolicy: NewApplyPolicyFromConfigStruct(&pconf.ApplyPolicy),
		Conf: &api.PeerConf{
			NeighborAddress:   pconf.Config.NeighborAddress,
			Id:                s.RemoteRouterId,
			PeerAs:            pconf.Config.PeerAs,
			LocalAs:           pconf.Config.LocalAs,
			PeerType:          uint32(pconf.Config.PeerType.ToInt()),
			AuthPassword:      pconf.Config.AuthPassword,
			RouteFlapDamping:  pconf.Config.RouteFlapDamping,
			Description:       pconf.Config.Description,
			PeerGroup:         pconf.Config.PeerGroup,
			RemoteCap:         remoteCap,
			LocalCap:          localCap,
			PrefixLimits:      prefixLimits,
			LocalAddress:      localAddress,
			NeighborInterface: pconf.Config.NeighborInterface,
			Vrf:               pconf.Config.Vrf,
			AllowOwnAs:        uint32(pconf.AsPathOptions.Config.AllowOwnAs),
			RemovePrivateAs:   removePrivateAs,
			ReplacePeerAs:     pconf.AsPathOptions.Config.ReplacePeerAs,
		},
		State: &api.PeerState{
			SessionState: api.PeerState_SessionState(api.PeerState_SessionState_value[strings.ToUpper(string(s.SessionState))]),
			AdminState:   api.PeerState_AdminState(s.AdminState.ToInt()),
			Messages: &api.Messages{
				Received: &api.Message{
					Notification: s.Messages.Received.Notification,
					Update:       s.Messages.Received.Update,
					Open:         s.Messages.Received.Open,
					Keepalive:    s.Messages.Received.Keepalive,
					Refresh:      s.Messages.Received.Refresh,
					Discarded:    s.Messages.Received.Discarded,
					Total:        s.Messages.Received.Total,
				},
				Sent: &api.Message{
					Notification: s.Messages.Sent.Notification,
					Update:       s.Messages.Sent.Update,
					Open:         s.Messages.Sent.Open,
					Keepalive:    s.Messages.Sent.Keepalive,
					Refresh:      s.Messages.Sent.Refresh,
					Discarded:    s.Messages.Sent.Discarded,
					Total:        s.Messages.Sent.Total,
				},
			},
			Received:        s.AdjTable.Received,
			Accepted:        s.AdjTable.Accepted,
			Advertised:      s.AdjTable.Advertised,
			PeerAs:          s.PeerAs,
			PeerType:        uint32(s.PeerType.ToInt()),
			NeighborAddress: pconf.State.NeighborAddress,
			Queues:          &api.Queues{},
		},
		EbgpMultihop: &api.EbgpMultihop{
			Enabled:     pconf.EbgpMultihop.Config.Enabled,
			MultihopTtl: uint32(pconf.EbgpMultihop.Config.MultihopTtl),
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
			RouteReflectorClusterId: string(pconf.RouteReflector.State.RouteReflectorClusterId),
		},
		RouteServer: &api.RouteServer{
			RouteServerClient: pconf.RouteServer.Config.RouteServerClient,
		},
		GracefulRestart: &api.GracefulRestart{
			Enabled:             pconf.GracefulRestart.Config.Enabled,
			RestartTime:         uint32(pconf.GracefulRestart.Config.RestartTime),
			HelperOnly:          pconf.GracefulRestart.Config.HelperOnly,
			DeferralTime:        uint32(pconf.GracefulRestart.Config.DeferralTime),
			NotificationEnabled: pconf.GracefulRestart.Config.NotificationEnabled,
			LonglivedEnabled:    pconf.GracefulRestart.Config.LongLivedEnabled,
			LocalRestarting:     pconf.GracefulRestart.State.LocalRestarting,
		},
		Transport: &api.Transport{
			RemotePort:   uint32(pconf.Transport.Config.RemotePort),
			LocalAddress: pconf.Transport.Config.LocalAddress,
			PassiveMode:  pconf.Transport.Config.PassiveMode,
		},
		AfiSafis: afiSafis,
		AddPaths: NewAddPathsFromConfigStruct(&pconf.AddPaths),
	}
}

func NewPeerGroupFromConfigStruct(pconf *config.PeerGroup) *api.PeerGroup {
	families := make([]uint32, 0, len(pconf.AfiSafis))
	afiSafis := make([]*api.AfiSafi, 0, len(pconf.AfiSafis))
	for _, f := range pconf.AfiSafis {
		families = append(families, extractFamilyFromConfigAfiSafi(&f))
		if afiSafi := NewAfiSafiFromConfigStruct(&f); afiSafi != nil {
			afiSafis = append(afiSafis, afiSafi)
		}
	}

	timer := pconf.Timers
	s := pconf.State
	return &api.PeerGroup{
		Families:    families,
		ApplyPolicy: NewApplyPolicyFromConfigStruct(&pconf.ApplyPolicy),
		Conf: &api.PeerGroupConf{
			PeerAs:           pconf.Config.PeerAs,
			LocalAs:          pconf.Config.LocalAs,
			PeerType:         uint32(pconf.Config.PeerType.ToInt()),
			AuthPassword:     pconf.Config.AuthPassword,
			RouteFlapDamping: pconf.Config.RouteFlapDamping,
			Description:      pconf.Config.Description,
			PeerGroupName:    pconf.Config.PeerGroupName,
		},
		Info: &api.PeerGroupState{
			PeerAs:        s.PeerAs,
			PeerType:      uint32(s.PeerType.ToInt()),
			TotalPaths:    s.TotalPaths,
			TotalPrefixes: s.TotalPrefixes,
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
		GracefulRestart: &api.GracefulRestart{
			Enabled:             pconf.GracefulRestart.Config.Enabled,
			RestartTime:         uint32(pconf.GracefulRestart.Config.RestartTime),
			HelperOnly:          pconf.GracefulRestart.Config.HelperOnly,
			DeferralTime:        uint32(pconf.GracefulRestart.Config.DeferralTime),
			NotificationEnabled: pconf.GracefulRestart.Config.NotificationEnabled,
			LonglivedEnabled:    pconf.GracefulRestart.Config.LongLivedEnabled,
			LocalRestarting:     pconf.GracefulRestart.State.LocalRestarting,
		},
		Transport: &api.Transport{
			RemotePort:   uint32(pconf.Transport.Config.RemotePort),
			LocalAddress: pconf.Transport.Config.LocalAddress,
			PassiveMode:  pconf.Transport.Config.PassiveMode,
		},
		AfiSafis: afiSafis,
		AddPaths: NewAddPathsFromConfigStruct(&pconf.AddPaths),
	}
}

func (s *Server) ListPeer(r *api.ListPeerRequest, stream api.GobgpApi_ListPeerServer) error {
	l, err := s.bgpServer.ListPeer(context.Background(), r)
	for _, e := range l {
		if err := stream.Send(&api.ListPeerResponse{Peer: e}); err != nil {
			return err
		}
	}
	return err
}

func NewValidationFromTableStruct(v *table.Validation) *api.RPKIValidation {
	if v == nil {
		return &api.RPKIValidation{}
	}
	return &api.RPKIValidation{
		Reason:          api.RPKIValidation_Reason(v.Reason.ToInt()),
		Matched:         NewRoaListFromTableStructList(v.Matched),
		UnmatchedAs:     NewRoaListFromTableStructList(v.UnmatchedAs),
		UnmatchedLength: NewRoaListFromTableStructList(v.UnmatchedLength),
	}
}

func toPathAPI(binNlri []byte, binPattrs [][]byte, anyNlri *any.Any, anyPattrs []*any.Any, path *table.Path, v *table.Validation) *api.Path {
	nlri := path.GetNlri()
	family := uint32(path.GetRouteFamily())
	vv := config.RPKI_VALIDATION_RESULT_TYPE_NONE.ToInt()
	if v != nil {
		vv = v.Status.ToInt()
	}
	p := &api.Path{
		Nlri:               binNlri,
		Pattrs:             binPattrs,
		Age:                path.GetTimestamp().Unix(),
		IsWithdraw:         path.IsWithdraw,
		Validation:         int32(vv),
		ValidationDetail:   NewValidationFromTableStruct(v),
		Family:             family,
		Stale:              path.IsStale(),
		IsFromExternal:     path.IsFromExternal(),
		NoImplicitWithdraw: path.NoImplicitWithdraw(),
		IsNexthopInvalid:   path.IsNexthopInvalid,
		Identifier:         nlri.PathIdentifier(),
		LocalIdentifier:    nlri.PathLocalIdentifier(),
		AnyNlri:            anyNlri,
		AnyPattrs:          anyPattrs,
	}
	if s := path.GetSource(); s != nil {
		p.SourceAsn = s.AS
		p.SourceId = s.ID.String()
		p.NeighborIp = s.Address.String()
	}
	return p
}

func ToPathApi(path *table.Path, v *table.Validation) *api.Path {
	nlri := path.GetNlri()
	anyNlri := apiutil.MarshalNLRI(nlri)
	if path.IsWithdraw {
		return toPathAPI(nil, nil, anyNlri, nil, path, v)
	}
	anyPattrs := apiutil.MarshalPathAttributes(path.GetPathAttrs())
	return toPathAPI(nil, nil, anyNlri, anyPattrs, path, v)
}

func getValidation(v []*table.Validation, i int) *table.Validation {
	if v == nil {
		return nil
	} else {
		return v[i]
	}
}

func (s *Server) ListPath(r *api.ListPathRequest, stream api.GobgpApi_ListPathServer) error {
	dsts, err := s.bgpServer.ListPath(context.Background(), r)
	for _, d := range dsts {
		if err := stream.Send(&api.ListPathResponse{Destination: d}); err != nil {
			return err
		}
	}
	return err
}

func (s *Server) MonitorTable(arg *api.MonitorTableRequest, stream api.GobgpApi_MonitorTableServer) error {
	if arg == nil {
		return fmt.Errorf("invalid request")
	}
	w, err := func() (*Watcher, error) {
		switch arg.Type {
		case api.Resource_GLOBAL:
			return s.bgpServer.Watch(WatchBestPath(arg.Current)), nil
		case api.Resource_ADJ_IN:
			if arg.PostPolicy {
				return s.bgpServer.Watch(WatchPostUpdate(arg.Current)), nil
			}
			return s.bgpServer.Watch(WatchUpdate(arg.Current)), nil
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
			for _, path := range pathList {
				if path == nil || (arg.Family != 0 && bgp.RouteFamily(arg.Family) != path.GetRouteFamily()) {
					continue
				}
				if err := stream.Send(&api.MonitorTableResponse{Path: ToPathApi(path, nil)}); err != nil {
					return err
				}
			}
			return nil
		}

		for ev := range w.Event() {
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
		return nil
	}()
}

func (s *Server) MonitorPeer(arg *api.MonitorPeerRequest, stream api.GobgpApi_MonitorPeerServer) error {
	if arg == nil {
		return fmt.Errorf("invalid request")
	}
	return func() error {
		w := s.bgpServer.Watch(WatchPeerState(arg.Current))
		defer func() { w.Stop() }()

		for ev := range w.Event() {
			switch msg := ev.(type) {
			case *WatchEventPeerState:
				if len(arg.Address) > 0 && arg.Address != msg.PeerAddress.String() && arg.Address != msg.PeerInterface {
					continue
				}
				if err := stream.Send(&api.MonitorPeerResponse{
					Peer: &api.Peer{
						Conf: &api.PeerConf{
							PeerAs:            msg.PeerAS,
							LocalAs:           msg.LocalAS,
							NeighborAddress:   msg.PeerAddress.String(),
							Id:                msg.PeerID.String(),
							NeighborInterface: msg.PeerInterface,
						},
						State: &api.PeerState{
							PeerAs:          msg.PeerAS,
							LocalAs:         msg.LocalAS,
							NeighborAddress: msg.PeerAddress.String(),
							SessionState:    api.PeerState_SessionState(int(msg.State) + 1),
							AdminState:      api.PeerState_AdminState(msg.AdminState),
						},
						Transport: &api.Transport{
							LocalAddress: msg.LocalAddress.String(),
							LocalPort:    uint32(msg.LocalPort),
							RemotePort:   uint32(msg.PeerPort),
						},
					}}); err != nil {
					return err
				}
			}
		}
		return nil
	}()
}

func (s *Server) ResetPeer(ctx context.Context, r *api.ResetPeerRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.ResetPeer(ctx, r)
}

func (s *Server) ShutdownPeer(ctx context.Context, r *api.ShutdownPeerRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.ShutdownPeer(ctx, r)
}

func (s *Server) EnablePeer(ctx context.Context, r *api.EnablePeerRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.EnableNeighbor(ctx, r)
}

func (s *Server) DisablePeer(ctx context.Context, r *api.DisablePeerRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.DisableNeighbor(ctx, r)
}

func (s *Server) UpdatePolicy(ctx context.Context, r *api.UpdatePolicyRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.UpdatePolicy(ctx, r)
}

func NewAPIRoutingPolicyFromConfigStruct(c *config.RoutingPolicy) (*api.RoutingPolicy, error) {
	definedSets, err := NewAPIDefinedSetsFromConfigStruct(&c.DefinedSets)
	if err != nil {
		return nil, err
	}
	policies := make([]*api.Policy, 0, len(c.PolicyDefinitions))
	for _, policy := range c.PolicyDefinitions {
		policies = append(policies, toPolicyApi(&policy))
	}

	return &api.RoutingPolicy{
		DefinedSet:       definedSets,
		PolicyDefinition: policies,
	}, nil
}

func NewRoutingPolicyFromApiStruct(arg *api.UpdatePolicyRequest) (*config.RoutingPolicy, error) {
	policyDefinitions := make([]config.PolicyDefinition, 0, len(arg.Policies))
	for _, p := range arg.Policies {
		pd, err := NewConfigPolicyFromApiStruct(p)
		if err != nil {
			return nil, err
		}
		policyDefinitions = append(policyDefinitions, *pd)
	}

	definedSets, err := NewConfigDefinedSetsFromApiStruct(arg.Sets)
	if err != nil {
		return nil, err
	}

	return &config.RoutingPolicy{
		DefinedSets:       *definedSets,
		PolicyDefinitions: policyDefinitions,
	}, nil
}

func api2PathList(resource api.Resource, ApiPathList []*api.Path) ([]*table.Path, error) {
	var pi *table.PeerInfo

	pathList := make([]*table.Path, 0, len(ApiPathList))
	for _, path := range ApiPathList {
		var nlri bgp.AddrPrefixInterface
		var nexthop string

		if path.SourceAsn != 0 {
			pi = &table.PeerInfo{
				AS:      path.SourceAsn,
				LocalID: net.ParseIP(path.SourceId),
			}
		}

		nlri, err := apiutil.GetNativeNlri(path)
		if err != nil {
			return nil, err
		}
		nlri.SetPathIdentifier(path.Identifier)

		attrList, err := apiutil.GetNativePathAttributes(path)
		if err != nil {
			return nil, err
		}

		pattrs := make([]bgp.PathAttributeInterface, 0)
		seen := make(map[bgp.BGPAttrType]struct{})
		for _, attr := range attrList {
			attrType := attr.GetType()
			if _, ok := seen[attrType]; !ok {
				seen[attrType] = struct{}{}
			} else {
				return nil, fmt.Errorf("duplicated path attribute type: %d", attrType)
			}

			switch a := attr.(type) {
			case *bgp.PathAttributeNextHop:
				nexthop = a.Value.String()
			case *bgp.PathAttributeMpReachNLRI:
				nlri = a.Value[0]
				nexthop = a.Nexthop.String()
			default:
				pattrs = append(pattrs, attr)
			}
		}

		if nlri == nil {
			return nil, fmt.Errorf("nlri not found")
		} else if !path.IsWithdraw && nexthop == "" {
			return nil, fmt.Errorf("nexthop not found")
		}

		if resource != api.Resource_VRF && bgp.RouteFamily(path.Family) == bgp.RF_IPv4_UC && net.ParseIP(nexthop).To4() != nil {
			pattrs = append(pattrs, bgp.NewPathAttributeNextHop(nexthop))
		} else {
			pattrs = append(pattrs, bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}))
		}

		newPath := table.NewPath(pi, nlri, path.IsWithdraw, pattrs, time.Now(), path.NoImplicitWithdraw)
		if !path.IsWithdraw {
			total := bytes.NewBuffer(make([]byte, 0))
			for _, a := range newPath.GetPathAttrs() {
				if a.GetType() == bgp.BGP_ATTR_TYPE_MP_REACH_NLRI {
					continue
				}
				b, _ := a.Serialize()
				total.Write(b)
			}
			newPath.SetHash(farm.Hash32(total.Bytes()))
		}
		newPath.SetIsFromExternal(path.IsFromExternal)
		pathList = append(pathList, newPath)
	}
	return pathList, nil
}

func (s *Server) AddPath(ctx context.Context, r *api.AddPathRequest) (*api.AddPathResponse, error) {
	return s.bgpServer.AddPath(ctx, r)
}

func (s *Server) DeletePath(ctx context.Context, r *api.DeletePathRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.DeletePath(ctx, r)
}

func (s *Server) EnableMrt(ctx context.Context, r *api.EnableMrtRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.EnableMrt(ctx, r)
}

func (s *Server) DisableMrt(ctx context.Context, r *api.DisableMrtRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.DisableMrt(ctx, r)
}

func (s *Server) AddPathStream(stream api.GobgpApi_AddPathStreamServer) error {
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
		pathList, err := api2PathList(arg.Resource, arg.Paths)
		if err != nil {
			return err
		}
		err = s.bgpServer.addPathList(arg.VrfId, pathList)
		if err != nil {
			return err
		}
	}
	return stream.SendAndClose(&empty.Empty{})
}

func (s *Server) AddBmp(ctx context.Context, r *api.AddBmpRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.AddBmp(ctx, r)
}

func (s *Server) DeleteBmp(ctx context.Context, r *api.DeleteBmpRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.DeleteBmp(ctx, r)
}

func (s *Server) AddRpki(ctx context.Context, r *api.AddRpkiRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.AddRpki(ctx, r)
}

func (s *Server) DeleteRpki(ctx context.Context, r *api.DeleteRpkiRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.DeleteRpki(ctx, r)
}

func (s *Server) EnableRpki(ctx context.Context, r *api.EnableRpkiRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.EnableRpki(ctx, r)
}

func (s *Server) DisableRpki(ctx context.Context, r *api.DisableRpkiRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.DisableRpki(ctx, r)
}

func (s *Server) ResetRpki(ctx context.Context, r *api.ResetRpkiRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.ResetRpki(ctx, r)
}

func (s *Server) ListRpki(r *api.ListRpkiRequest, stream api.GobgpApi_ListRpkiServer) error {
	servers, err := s.bgpServer.ListRpki(context.Background(), r)
	if err != nil {
		return err
	}
	for _, rpki := range servers {
		if err := stream.Send(&api.ListRpkiResponse{Server: rpki}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) ListRpkiTable(r *api.ListRpkiTableRequest, stream api.GobgpApi_ListRpkiTableServer) error {
	roas, err := s.bgpServer.ListRpkiTable(context.Background(), r)
	if err != nil {
		return err
	}
	for _, roa := range roas {
		if err := stream.Send(&api.ListRpkiTableResponse{Roa: roa}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) EnableZebra(ctx context.Context, r *api.EnableZebraRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.EnableZebra(ctx, r)
}

func (s *Server) ListVrf(r *api.ListVrfRequest, stream api.GobgpApi_ListVrfServer) error {
	for _, v := range s.bgpServer.ListVrf(context.Background(), r) {
		if err := stream.Send(&api.ListVrfResponse{Vrf: v}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) AddVrf(ctx context.Context, r *api.AddVrfRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.AddVrf(ctx, r)
}

func (s *Server) DeleteVrf(ctx context.Context, r *api.DeleteVrfRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.DeleteVrf(ctx, r)
}

func ReadMpGracefulRestartFromAPIStruct(c *config.MpGracefulRestart, a *api.MpGracefulRestart) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.Enabled = a.Config.Enabled
	}
}

func ReadAfiSafiConfigFromAPIStruct(c *config.AfiSafiConfig, a *api.AfiSafiConfig) {
	if c == nil || a == nil {
		return
	}
	c.AfiSafiName = config.AfiSafiType(bgp.RouteFamily(a.Family).String())
	c.Enabled = a.Enabled
}

func ReadAfiSafiStateFromAPIStruct(s *config.AfiSafiState, a *api.AfiSafiConfig) {
	if s == nil || a == nil {
		return
	}
	// Store only address family value for the convenience
	s.Family = bgp.RouteFamily(a.Family)
}

func ReadPrefixLimitFromAPIStruct(c *config.PrefixLimit, a *api.PrefixLimit) {
	if c == nil || a == nil {
		return
	}
	c.Config.MaxPrefixes = a.MaxPrefixes
	c.Config.ShutdownThresholdPct = config.Percentage(a.ShutdownThresholdPct)
}

func ReadApplyPolicyFromAPIStruct(c *config.ApplyPolicy, a *api.ApplyPolicy) {
	if c == nil || a == nil {
		return
	}
	if a.ImportPolicy != nil {
		c.Config.DefaultImportPolicy = config.IntToDefaultPolicyTypeMap[int(a.ImportPolicy.Default)]
		for _, p := range a.ImportPolicy.Policies {
			c.Config.ImportPolicyList = append(c.Config.ImportPolicyList, p.Name)
		}
	}
	if a.ExportPolicy != nil {
		c.Config.DefaultExportPolicy = config.IntToDefaultPolicyTypeMap[int(a.ExportPolicy.Default)]
		for _, p := range a.ExportPolicy.Policies {
			c.Config.ExportPolicyList = append(c.Config.ExportPolicyList, p.Name)
		}
	}
	if a.InPolicy != nil {
		c.Config.DefaultInPolicy = config.IntToDefaultPolicyTypeMap[int(a.InPolicy.Default)]
		for _, p := range a.InPolicy.Policies {
			c.Config.InPolicyList = append(c.Config.InPolicyList, p.Name)
		}
	}
}

func ReadRouteSelectionOptionsFromAPIStruct(c *config.RouteSelectionOptions, a *api.RouteSelectionOptions) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.AlwaysCompareMed = a.Config.AlwaysCompareMed
		c.Config.IgnoreAsPathLength = a.Config.IgnoreAsPathLength
		c.Config.ExternalCompareRouterId = a.Config.ExternalCompareRouterId
		c.Config.AdvertiseInactiveRoutes = a.Config.AdvertiseInactiveRoutes
		c.Config.EnableAigp = a.Config.EnableAigp
		c.Config.IgnoreNextHopIgpMetric = a.Config.IgnoreNextHopIgpMetric
	}
}

func ReadUseMultiplePathsFromAPIStruct(c *config.UseMultiplePaths, a *api.UseMultiplePaths) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.Enabled = a.Config.Enabled
	}
	if a.Ebgp != nil && a.Ebgp.Config != nil {
		c.Ebgp = config.Ebgp{
			Config: config.EbgpConfig{
				AllowMultipleAs: a.Ebgp.Config.AllowMultipleAs,
				MaximumPaths:    a.Ebgp.Config.MaximumPaths,
			},
		}
	}
	if a.Ibgp != nil && a.Ibgp.Config != nil {
		c.Ibgp = config.Ibgp{
			Config: config.IbgpConfig{
				MaximumPaths: a.Ibgp.Config.MaximumPaths,
			},
		}
	}
}

func ReadRouteTargetMembershipFromAPIStruct(c *config.RouteTargetMembership, a *api.RouteTargetMembership) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.DeferralTime = uint16(a.Config.DeferralTime)
	}
}

func ReadLongLivedGracefulRestartFromAPIStruct(c *config.LongLivedGracefulRestart, a *api.LongLivedGracefulRestart) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.Enabled = a.Config.Enabled
		c.Config.RestartTime = a.Config.RestartTime
	}
}

func ReadAddPathsFromAPIStruct(c *config.AddPaths, a *api.AddPaths) {
	if c == nil || a == nil {
		return
	}
	if a.Config != nil {
		c.Config.Receive = a.Config.Receive
		c.Config.SendMax = uint8(a.Config.SendMax)
	}
}

func NewNeighborFromAPIStruct(a *api.Peer) (*config.Neighbor, error) {
	pconf := &config.Neighbor{}
	if a.Conf != nil {
		pconf.Config.PeerAs = a.Conf.PeerAs
		pconf.Config.LocalAs = a.Conf.LocalAs
		pconf.Config.AuthPassword = a.Conf.AuthPassword
		pconf.Config.RouteFlapDamping = a.Conf.RouteFlapDamping
		pconf.Config.Description = a.Conf.Description
		pconf.Config.PeerGroup = a.Conf.PeerGroup
		pconf.Config.PeerType = config.IntToPeerTypeMap[int(a.Conf.PeerType)]
		pconf.Config.NeighborAddress = a.Conf.NeighborAddress
		pconf.Config.NeighborInterface = a.Conf.NeighborInterface
		pconf.Config.Vrf = a.Conf.Vrf
		pconf.AsPathOptions.Config.AllowOwnAs = uint8(a.Conf.AllowOwnAs)
		pconf.AsPathOptions.Config.ReplacePeerAs = a.Conf.ReplacePeerAs

		switch a.Conf.RemovePrivateAs {
		case api.PeerConf_ALL:
			pconf.Config.RemovePrivateAs = config.REMOVE_PRIVATE_AS_OPTION_ALL
		case api.PeerConf_REPLACE:
			pconf.Config.RemovePrivateAs = config.REMOVE_PRIVATE_AS_OPTION_REPLACE
		}

		localCaps, err := apiutil.UnmarshalCapabilities(a.Conf.LocalCap)
		if err != nil {
			return nil, err
		}
		remoteCaps, err := apiutil.UnmarshalCapabilities(a.Conf.RemoteCap)
		if err != nil {
			return nil, err
		}
		pconf.State.LocalCapabilityList = localCaps
		pconf.State.RemoteCapabilityList = remoteCaps

		pconf.State.RemoteRouterId = a.Conf.Id

		for _, af := range a.AfiSafis {
			afiSafi := config.AfiSafi{}
			ReadMpGracefulRestartFromAPIStruct(&afiSafi.MpGracefulRestart, af.MpGracefulRestart)
			ReadAfiSafiConfigFromAPIStruct(&afiSafi.Config, af.Config)
			ReadAfiSafiStateFromAPIStruct(&afiSafi.State, af.Config)
			ReadApplyPolicyFromAPIStruct(&afiSafi.ApplyPolicy, af.ApplyPolicy)
			ReadRouteSelectionOptionsFromAPIStruct(&afiSafi.RouteSelectionOptions, af.RouteSelectionOptions)
			ReadUseMultiplePathsFromAPIStruct(&afiSafi.UseMultiplePaths, af.UseMultiplePaths)
			ReadPrefixLimitFromAPIStruct(&afiSafi.PrefixLimit, af.PrefixLimits)
			ReadRouteTargetMembershipFromAPIStruct(&afiSafi.RouteTargetMembership, af.RouteTargetMembership)
			ReadLongLivedGracefulRestartFromAPIStruct(&afiSafi.LongLivedGracefulRestart, af.LongLivedGracefulRestart)
			ReadAddPathsFromAPIStruct(&afiSafi.AddPaths, af.AddPaths)
			pconf.AfiSafis = append(pconf.AfiSafis, afiSafi)
		}
		// For the backward compatibility, we override AfiSafi configurations
		// with Peer.Families.
		for _, family := range a.Families {
			found := false
			for _, afiSafi := range pconf.AfiSafis {
				if uint32(afiSafi.State.Family) == family {
					// If Peer.Families contains the same address family,
					// we enable this address family.
					afiSafi.Config.Enabled = true
					found = true
				}
			}
			if !found {
				// If Peer.Families does not contain the same address family,
				// we append AfiSafi structure with the default value.
				pconf.AfiSafis = append(pconf.AfiSafis, config.AfiSafi{
					Config: config.AfiSafiConfig{
						AfiSafiName: config.AfiSafiType(bgp.RouteFamily(family).String()),
						Enabled:     true,
					},
				})
			}
		}
		// For the backward compatibility, we override AfiSafi configurations
		// with Peer.Conf.PrefixLimits.
		for _, prefixLimit := range a.Conf.PrefixLimits {
			for _, afiSafi := range pconf.AfiSafis {
				// If Peer.Conf.PrefixLimits contains the configuration for
				// the same address family, we override AfiSafi.PrefixLimit.
				if uint32(afiSafi.State.Family) == prefixLimit.Family {
					ReadPrefixLimitFromAPIStruct(&afiSafi.PrefixLimit, prefixLimit)
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
	if a.GracefulRestart != nil {
		pconf.GracefulRestart.Config.Enabled = a.GracefulRestart.Enabled
		pconf.GracefulRestart.Config.RestartTime = uint16(a.GracefulRestart.RestartTime)
		pconf.GracefulRestart.Config.HelperOnly = a.GracefulRestart.HelperOnly
		pconf.GracefulRestart.Config.DeferralTime = uint16(a.GracefulRestart.DeferralTime)
		pconf.GracefulRestart.Config.NotificationEnabled = a.GracefulRestart.NotificationEnabled
		pconf.GracefulRestart.Config.LongLivedEnabled = a.GracefulRestart.LonglivedEnabled
		pconf.GracefulRestart.State.LocalRestarting = a.GracefulRestart.LocalRestarting
	}
	ReadApplyPolicyFromAPIStruct(&pconf.ApplyPolicy, a.ApplyPolicy)
	if a.Transport != nil {
		pconf.Transport.Config.LocalAddress = a.Transport.LocalAddress
		pconf.Transport.Config.PassiveMode = a.Transport.PassiveMode
		pconf.Transport.Config.RemotePort = uint16(a.Transport.RemotePort)
	}
	if a.EbgpMultihop != nil {
		pconf.EbgpMultihop.Config.Enabled = a.EbgpMultihop.Enabled
		pconf.EbgpMultihop.Config.MultihopTtl = uint8(a.EbgpMultihop.MultihopTtl)
	}
	if a.State != nil {
		pconf.State.SessionState = config.SessionState(strings.ToUpper(string(a.State.SessionState)))
		pconf.State.AdminState = config.IntToAdminStateMap[int(a.State.AdminState)]

		pconf.State.AdjTable.Received = a.State.Received
		pconf.State.AdjTable.Accepted = a.State.Accepted
		pconf.State.AdjTable.Advertised = a.State.Advertised
		pconf.State.PeerAs = a.State.PeerAs
		pconf.State.PeerType = config.IntToPeerTypeMap[int(a.State.PeerType)]
		pconf.State.NeighborAddress = a.State.NeighborAddress

		if a.State.Messages != nil {
			if a.State.Messages.Sent != nil {
				pconf.State.Messages.Sent.Update = a.State.Messages.Sent.Update
				pconf.State.Messages.Sent.Notification = a.State.Messages.Sent.Notification
				pconf.State.Messages.Sent.Open = a.State.Messages.Sent.Open
				pconf.State.Messages.Sent.Refresh = a.State.Messages.Sent.Refresh
				pconf.State.Messages.Sent.Keepalive = a.State.Messages.Sent.Keepalive
				pconf.State.Messages.Sent.Discarded = a.State.Messages.Sent.Discarded
				pconf.State.Messages.Sent.Total = a.State.Messages.Sent.Total
			}
			if a.State.Messages.Received != nil {
				pconf.State.Messages.Received.Update = a.State.Messages.Received.Update
				pconf.State.Messages.Received.Open = a.State.Messages.Received.Open
				pconf.State.Messages.Received.Refresh = a.State.Messages.Received.Refresh
				pconf.State.Messages.Received.Keepalive = a.State.Messages.Received.Keepalive
				pconf.State.Messages.Received.Discarded = a.State.Messages.Received.Discarded
				pconf.State.Messages.Received.Total = a.State.Messages.Received.Total
			}
		}
	}
	ReadAddPathsFromAPIStruct(&pconf.AddPaths, a.AddPaths)
	return pconf, nil
}

func NewPeerGroupFromAPIStruct(a *api.PeerGroup) (*config.PeerGroup, error) {
	pconf := &config.PeerGroup{}
	if a.Conf != nil {
		pconf.Config.PeerAs = a.Conf.PeerAs
		pconf.Config.LocalAs = a.Conf.LocalAs
		pconf.Config.AuthPassword = a.Conf.AuthPassword
		pconf.Config.RouteFlapDamping = a.Conf.RouteFlapDamping
		pconf.Config.Description = a.Conf.Description
		pconf.Config.PeerGroupName = a.Conf.PeerGroupName

		switch a.Conf.RemovePrivateAs {
		case api.PeerGroupConf_ALL:
			pconf.Config.RemovePrivateAs = config.REMOVE_PRIVATE_AS_OPTION_ALL
		case api.PeerGroupConf_REPLACE:
			pconf.Config.RemovePrivateAs = config.REMOVE_PRIVATE_AS_OPTION_REPLACE
		}

		for _, af := range a.AfiSafis {
			afiSafi := config.AfiSafi{}
			ReadMpGracefulRestartFromAPIStruct(&afiSafi.MpGracefulRestart, af.MpGracefulRestart)
			ReadAfiSafiConfigFromAPIStruct(&afiSafi.Config, af.Config)
			ReadAfiSafiStateFromAPIStruct(&afiSafi.State, af.Config)
			ReadApplyPolicyFromAPIStruct(&afiSafi.ApplyPolicy, af.ApplyPolicy)
			ReadRouteSelectionOptionsFromAPIStruct(&afiSafi.RouteSelectionOptions, af.RouteSelectionOptions)
			ReadUseMultiplePathsFromAPIStruct(&afiSafi.UseMultiplePaths, af.UseMultiplePaths)
			ReadPrefixLimitFromAPIStruct(&afiSafi.PrefixLimit, af.PrefixLimits)
			ReadRouteTargetMembershipFromAPIStruct(&afiSafi.RouteTargetMembership, af.RouteTargetMembership)
			ReadLongLivedGracefulRestartFromAPIStruct(&afiSafi.LongLivedGracefulRestart, af.LongLivedGracefulRestart)
			ReadAddPathsFromAPIStruct(&afiSafi.AddPaths, af.AddPaths)
			pconf.AfiSafis = append(pconf.AfiSafis, afiSafi)
		}
		// For the backward compatibility, we override AfiSafi configurations
		// with Peer.Families.
		for _, family := range a.Families {
			found := false
			for _, afiSafi := range pconf.AfiSafis {
				if uint32(afiSafi.State.Family) == family {
					// If Peer.Families contains the same address family,
					// we enable this address family.
					afiSafi.Config.Enabled = true
					found = true
				}
			}
			if !found {
				// If Peer.Families does not contain the same address family,
				// we append AfiSafi structure with the default value.
				pconf.AfiSafis = append(pconf.AfiSafis, config.AfiSafi{
					Config: config.AfiSafiConfig{
						AfiSafiName: config.AfiSafiType(bgp.RouteFamily(family).String()),
						Enabled:     true,
					},
				})
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
	if a.GracefulRestart != nil {
		pconf.GracefulRestart.Config.Enabled = a.GracefulRestart.Enabled
		pconf.GracefulRestart.Config.RestartTime = uint16(a.GracefulRestart.RestartTime)
		pconf.GracefulRestart.Config.HelperOnly = a.GracefulRestart.HelperOnly
		pconf.GracefulRestart.Config.DeferralTime = uint16(a.GracefulRestart.DeferralTime)
		pconf.GracefulRestart.Config.NotificationEnabled = a.GracefulRestart.NotificationEnabled
		pconf.GracefulRestart.Config.LongLivedEnabled = a.GracefulRestart.LonglivedEnabled
		pconf.GracefulRestart.State.LocalRestarting = a.GracefulRestart.LocalRestarting
	}
	ReadApplyPolicyFromAPIStruct(&pconf.ApplyPolicy, a.ApplyPolicy)
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
		pconf.State.TotalPaths = a.Info.TotalPaths
		pconf.State.TotalPrefixes = a.Info.TotalPrefixes
		pconf.State.PeerAs = a.Info.PeerAs
		pconf.State.PeerType = config.IntToPeerTypeMap[int(a.Info.PeerType)]
	}
	ReadAddPathsFromAPIStruct(&pconf.AddPaths, a.AddPaths)
	return pconf, nil
}

func (s *Server) AddPeer(ctx context.Context, r *api.AddPeerRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.AddPeer(ctx, r)
}

func (s *Server) DeletePeer(ctx context.Context, r *api.DeletePeerRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.DeletePeer(ctx, r)
}

func (s *Server) UpdatePeer(ctx context.Context, r *api.UpdatePeerRequest) (*api.UpdatePeerResponse, error) {
	rsp, err := s.bgpServer.UpdateNeighbor(ctx, r)
	if err != nil {
		return nil, err
	}
	if r.DoSoftResetIn && rsp.NeedsSoftResetIn {
		return &api.UpdatePeerResponse{NeedsSoftResetIn: false}, s.bgpServer.ResetPeer(ctx, &api.ResetPeerRequest{
			Soft:      true,
			Direction: api.ResetPeerRequest_IN,
		})
	}
	return rsp, nil
}

func (s *Server) AddPeerGroup(ctx context.Context, r *api.AddPeerGroupRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.AddPeerGroup(ctx, r)
}

func (s *Server) DeletePeerGroup(ctx context.Context, r *api.DeletePeerGroupRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.DeletePeerGroup(ctx, r)
}

func (s *Server) UpdatePeerGroup(ctx context.Context, r *api.UpdatePeerGroupRequest) (*api.UpdatePeerGroupResponse, error) {
	rsp, err := s.bgpServer.UpdatePeerGroup(ctx, r)
	if err != nil {
		return nil, err
	}
	if r.DoSoftResetIn && rsp.NeedsSoftResetIn {
		return &api.UpdatePeerGroupResponse{NeedsSoftResetIn: false}, s.bgpServer.ResetPeer(ctx, &api.ResetPeerRequest{
			Soft:      true,
			Direction: api.ResetPeerRequest_IN,
		})
	}
	return rsp, err
}

func (s *Server) AddDynamicNeighbor(ctx context.Context, r *api.AddDynamicNeighborRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.AddDynamicNeighbor(ctx, r)
}

func NewPrefixFromApiStruct(a *api.Prefix) (*table.Prefix, error) {
	_, prefix, err := net.ParseCIDR(a.IpPrefix)
	if err != nil {
		return nil, err
	}
	rf := bgp.RF_IPv4_UC
	if strings.Contains(a.IpPrefix, ":") {
		rf = bgp.RF_IPv6_UC
	}
	return &table.Prefix{
		Prefix:             prefix,
		AddressFamily:      rf,
		MasklengthRangeMin: uint8(a.MaskLengthMin),
		MasklengthRangeMax: uint8(a.MaskLengthMax),
	}, nil
}

func NewConfigPrefixFromAPIStruct(a *api.Prefix) (*config.Prefix, error) {
	_, prefix, err := net.ParseCIDR(a.IpPrefix)
	if err != nil {
		return nil, err
	}
	return &config.Prefix{
		IpPrefix:        prefix.String(),
		MasklengthRange: fmt.Sprintf("%d..%d", a.MaskLengthMin, a.MaskLengthMax),
	}, nil
}

func NewAPIPrefixFromConfigStruct(c config.Prefix) (*api.Prefix, error) {
	min, max, err := config.ParseMaskLength(c.IpPrefix, c.MasklengthRange)
	if err != nil {
		return nil, err
	}
	return &api.Prefix{
		IpPrefix:      c.IpPrefix,
		MaskLengthMin: uint32(min),
		MaskLengthMax: uint32(max),
	}, nil
}

func NewAPIDefinedSetFromTableStruct(t table.DefinedSet) (*api.DefinedSet, error) {
	a := &api.DefinedSet{
		Type: api.DefinedType(t.Type()),
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
		a.List = append(a.List, c.NeighborInfoList...)
	case table.DEFINED_TYPE_AS_PATH:
		s := t.(*table.AsPathSet)
		c := s.ToConfig()
		a.List = append(a.List, c.AsPathList...)
	case table.DEFINED_TYPE_COMMUNITY:
		s := t.(*table.CommunitySet)
		c := s.ToConfig()
		a.List = append(a.List, c.CommunityList...)
	case table.DEFINED_TYPE_EXT_COMMUNITY:
		s := t.(*table.ExtCommunitySet)
		c := s.ToConfig()
		a.List = append(a.List, c.ExtCommunityList...)
	case table.DEFINED_TYPE_LARGE_COMMUNITY:
		s := t.(*table.LargeCommunitySet)
		c := s.ToConfig()
		a.List = append(a.List, c.LargeCommunityList...)
	default:
		return nil, fmt.Errorf("invalid defined type")
	}
	return a, nil
}

func NewAPIDefinedSetsFromConfigStruct(t *config.DefinedSets) ([]*api.DefinedSet, error) {
	definedSets := make([]*api.DefinedSet, 0)

	for _, ps := range t.PrefixSets {
		prefixes := make([]*api.Prefix, 0)
		for _, p := range ps.PrefixList {
			ap, err := NewAPIPrefixFromConfigStruct(p)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, ap)
		}
		definedSets = append(definedSets, &api.DefinedSet{
			Type:     api.DefinedType_PREFIX,
			Name:     ps.PrefixSetName,
			Prefixes: prefixes,
		})
	}

	for _, ns := range t.NeighborSets {
		definedSets = append(definedSets, &api.DefinedSet{
			Type: api.DefinedType_NEIGHBOR,
			Name: ns.NeighborSetName,
			List: ns.NeighborInfoList,
		})
	}

	bs := t.BgpDefinedSets
	for _, cs := range bs.CommunitySets {
		definedSets = append(definedSets, &api.DefinedSet{
			Type: api.DefinedType_COMMUNITY,
			Name: cs.CommunitySetName,
			List: cs.CommunityList,
		})
	}

	for _, es := range bs.ExtCommunitySets {
		definedSets = append(definedSets, &api.DefinedSet{
			Type: api.DefinedType_EXT_COMMUNITY,
			Name: es.ExtCommunitySetName,
			List: es.ExtCommunityList,
		})
	}

	for _, ls := range bs.LargeCommunitySets {
		definedSets = append(definedSets, &api.DefinedSet{
			Type: api.DefinedType_LARGE_COMMUNITY,
			Name: ls.LargeCommunitySetName,
			List: ls.LargeCommunityList,
		})
	}

	for _, as := range bs.AsPathSets {
		definedSets = append(definedSets, &api.DefinedSet{
			Type: api.DefinedType_AS_PATH,
			Name: as.AsPathSetName,
			List: as.AsPathList,
		})
	}

	return definedSets, nil
}

func NewConfigDefinedSetsFromApiStruct(a []*api.DefinedSet) (*config.DefinedSets, error) {
	ps := make([]config.PrefixSet, 0)
	ns := make([]config.NeighborSet, 0)
	as := make([]config.AsPathSet, 0)
	cs := make([]config.CommunitySet, 0)
	es := make([]config.ExtCommunitySet, 0)
	ls := make([]config.LargeCommunitySet, 0)

	for _, ds := range a {
		if ds.Name == "" {
			return nil, fmt.Errorf("empty neighbor set name")
		}
		switch table.DefinedType(ds.Type) {
		case table.DEFINED_TYPE_PREFIX:
			prefixes := make([]config.Prefix, 0, len(ds.Prefixes))
			for _, p := range ds.Prefixes {
				prefix, err := NewConfigPrefixFromAPIStruct(p)
				if err != nil {
					return nil, err
				}
				prefixes = append(prefixes, *prefix)
			}
			ps = append(ps, config.PrefixSet{
				PrefixSetName: ds.Name,
				PrefixList:    prefixes,
			})
		case table.DEFINED_TYPE_NEIGHBOR:
			ns = append(ns, config.NeighborSet{
				NeighborSetName:  ds.Name,
				NeighborInfoList: ds.List,
			})
		case table.DEFINED_TYPE_AS_PATH:
			as = append(as, config.AsPathSet{
				AsPathSetName: ds.Name,
				AsPathList:    ds.List,
			})
		case table.DEFINED_TYPE_COMMUNITY:
			cs = append(cs, config.CommunitySet{
				CommunitySetName: ds.Name,
				CommunityList:    ds.List,
			})
		case table.DEFINED_TYPE_EXT_COMMUNITY:
			es = append(es, config.ExtCommunitySet{
				ExtCommunitySetName: ds.Name,
				ExtCommunityList:    ds.List,
			})
		case table.DEFINED_TYPE_LARGE_COMMUNITY:
			ls = append(ls, config.LargeCommunitySet{
				LargeCommunitySetName: ds.Name,
				LargeCommunityList:    ds.List,
			})
		default:
			return nil, fmt.Errorf("invalid defined type")
		}
	}

	return &config.DefinedSets{
		PrefixSets:   ps,
		NeighborSets: ns,
		BgpDefinedSets: config.BgpDefinedSets{
			AsPathSets:         as,
			CommunitySets:      cs,
			ExtCommunitySets:   es,
			LargeCommunitySets: ls,
		},
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
		list := make([]net.IPNet, 0, len(a.List))
		for _, x := range a.List {
			_, addr, err := net.ParseCIDR(x)
			if err != nil {
				return nil, fmt.Errorf("invalid address or prefix: %s", x)
			}
			list = append(list, *addr)
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

var _regexpPrefixMaskLengthRange = regexp.MustCompile(`(\d+)\.\.(\d+)`)

func (s *Server) ListDefinedSet(r *api.ListDefinedSetRequest, stream api.GobgpApi_ListDefinedSetServer) error {
	sets, err := s.bgpServer.ListDefinedSet(context.Background(), r)
	if err != nil {
		return err
	}
	for _, set := range sets {
		if err := stream.Send(&api.ListDefinedSetResponse{Set: set}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) AddDefinedSet(ctx context.Context, r *api.AddDefinedSetRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.AddDefinedSet(ctx, r)
}

func (s *Server) DeleteDefinedSet(ctx context.Context, r *api.DeleteDefinedSetRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.DeleteDefinedSet(ctx, r)
}

func (s *Server) ReplaceDefinedSet(ctx context.Context, r *api.ReplaceDefinedSetRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.ReplaceDefinedSet(ctx, r)
}

func NewAPIStatementFromTableStruct(t *table.Statement) *api.Statement {
	return toStatementApi(t.ToConfig())
}

var _regexpMedActionType = regexp.MustCompile(`([+-]?)(\d+)`)

func toStatementApi(s *config.Statement) *api.Statement {
	cs := &api.Conditions{}
	if s.Conditions.MatchPrefixSet.PrefixSet != "" {
		o, _ := table.NewMatchOption(s.Conditions.MatchPrefixSet.MatchSetOptions)
		cs.PrefixSet = &api.MatchSet{
			Type: api.MatchType(o),
			Name: s.Conditions.MatchPrefixSet.PrefixSet,
		}
	}
	if s.Conditions.MatchNeighborSet.NeighborSet != "" {
		o, _ := table.NewMatchOption(s.Conditions.MatchNeighborSet.MatchSetOptions)
		cs.NeighborSet = &api.MatchSet{
			Type: api.MatchType(o),
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
		cs.ExtCommunitySet = &api.MatchSet{
			Type: api.MatchType(s.Conditions.BgpConditions.MatchExtCommunitySet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet,
		}
	}
	if s.Conditions.BgpConditions.MatchLargeCommunitySet.LargeCommunitySet != "" {
		cs.LargeCommunitySet = &api.MatchSet{
			Type: api.MatchType(s.Conditions.BgpConditions.MatchLargeCommunitySet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchLargeCommunitySet.LargeCommunitySet,
		}
	}
	if s.Conditions.BgpConditions.RouteType != "" {
		cs.RouteType = api.Conditions_RouteType(s.Conditions.BgpConditions.RouteType.ToInt())
	}
	if len(s.Conditions.BgpConditions.NextHopInList) > 0 {
		cs.NextHopInList = s.Conditions.BgpConditions.NextHopInList
	}
	if s.Conditions.BgpConditions.AfiSafiInList != nil {
		afiSafiIn := make([]api.Family, 0)
		for _, afiSafiType := range s.Conditions.BgpConditions.AfiSafiInList {
			if mapped, ok := bgp.AddressFamilyValueMap[string(afiSafiType)]; ok {
				afiSafiIn = append(afiSafiIn, api.Family(mapped))
			}
		}
		cs.AfiSafiIn = afiSafiIn
	}
	cs.RpkiResult = int32(s.Conditions.BgpConditions.RpkiValidationResult.ToInt())
	as := &api.Actions{
		RouteAction: func() api.RouteAction {
			switch s.Actions.RouteDisposition {
			case config.ROUTE_DISPOSITION_ACCEPT_ROUTE:
				return api.RouteAction_ACCEPT
			case config.ROUTE_DISPOSITION_REJECT_ROUTE:
				return api.RouteAction_REJECT
			}
			return api.RouteAction_NONE
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
			medStr := strings.TrimSpace(string(s.Actions.BgpActions.SetMed))
			if len(medStr) == 0 {
				return nil
			}
			matches := _regexpMedActionType.FindStringSubmatch(medStr)
			if len(matches) == 0 {
				return nil
			}
			action := api.MedActionType_MED_REPLACE
			switch matches[1] {
			case "+", "-":
				action = api.MedActionType_MED_MOD
			}
			value, err := strconv.ParseInt(matches[1]+matches[2], 10, 64)
			if err != nil {
				return nil
			}
			return &api.MedAction{
				Value: value,
				Type:  action,
			}
		}(),
		AsPrepend: func() *api.AsPrependAction {
			if len(s.Actions.BgpActions.SetAsPathPrepend.As) == 0 {
				return nil
			}
			var asn uint64
			useleft := false
			if s.Actions.BgpActions.SetAsPathPrepend.As != "last-as" {
				asn, _ = strconv.ParseUint(s.Actions.BgpActions.SetAsPathPrepend.As, 10, 32)
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
		LargeCommunity: func() *api.CommunityAction {
			if len(s.Actions.BgpActions.SetLargeCommunity.SetLargeCommunityMethod.CommunitiesList) == 0 {
				return nil
			}
			return &api.CommunityAction{
				Type:        api.CommunityActionType(config.BgpSetCommunityOptionTypeToIntMap[config.BgpSetCommunityOptionType(s.Actions.BgpActions.SetLargeCommunity.Options)]),
				Communities: s.Actions.BgpActions.SetLargeCommunity.SetLargeCommunityMethod.CommunitiesList,
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

func NewRouteTypeConditionFromApiStruct(a api.Conditions_RouteType) (*table.RouteTypeCondition, error) {
	if a == 0 {
		return nil, nil
	}
	typ, ok := config.IntToRouteTypeMap[int(a)]
	if !ok {
		return nil, fmt.Errorf("invalid route type: %d", a)
	}
	return table.NewRouteTypeCondition(typ)
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

func NewLargeCommunityConditionFromApiStruct(a *api.MatchSet) (*table.LargeCommunityCondition, error) {
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

func NewNextHopConditionFromApiStruct(a []string) (*table.NextHopCondition, error) {
	if a == nil {
		return nil, nil
	}

	return table.NewNextHopCondition(a)
}

func NewAfiSafiInConditionFromApiStruct(a []api.Family) (*table.AfiSafiInCondition, error) {
	if a == nil {
		return nil, nil
	}
	afiSafiTypes := make([]config.AfiSafiType, 0, len(a))
	for _, aType := range a {
		if configType, ok := bgp.AddressFamilyNameMap[bgp.RouteFamily(aType)]; ok {
			afiSafiTypes = append(afiSafiTypes, config.AfiSafiType(configType))
		} else {
			return nil, fmt.Errorf("unknown afi-safi-in type value: %d", aType)
		}
	}
	return table.NewAfiSafiInCondition(afiSafiTypes)
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

func NewLargeCommunityActionFromApiStruct(a *api.CommunityAction) (*table.LargeCommunityAction, error) {
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

func NewMedActionFromApiStruct(a *api.MedAction) (*table.MedAction, error) {
	if a == nil {
		return nil, nil
	}
	return table.NewMedActionFromApiStruct(table.MedActionType(a.Type), a.Value), nil
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
			func() (table.Condition, error) {
				return NewNextHopConditionFromApiStruct(a.Conditions.NextHopInList)
			},
			func() (table.Condition, error) {
				return NewAfiSafiInConditionFromApiStruct(a.Conditions.AfiSafiIn)
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

func (s *Server) ListStatement(r *api.ListStatementRequest, stream api.GobgpApi_ListStatementServer) error {
	l, err := s.bgpServer.ListStatement(context.Background(), r)
	if err != nil {
		for _, st := range l {
			err = stream.Send(&api.ListStatementResponse{Statement: st})
			if err != nil {
				return err
			}
		}
	}
	return err
}

func (s *Server) AddStatement(ctx context.Context, r *api.AddStatementRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.AddStatement(ctx, r)
}

func (s *Server) DeleteStatement(ctx context.Context, r *api.DeleteStatementRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.DeleteStatement(ctx, r)
}

func (s *Server) ReplaceStatement(ctx context.Context, r *api.ReplaceStatementRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.ReplaceStatement(ctx, r)
}

func NewAPIPolicyFromTableStruct(p *table.Policy) *api.Policy {
	return toPolicyApi(p.ToConfig())
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

func NewAPIPolicyAssignmentFromTableStruct(t *table.PolicyAssignment) *api.PolicyAssignment {
	return &api.PolicyAssignment{
		Type: func() api.PolicyDirection {
			switch t.Type {
			case table.POLICY_DIRECTION_IMPORT:
				return api.PolicyDirection_IMPORT
			case table.POLICY_DIRECTION_EXPORT:
				return api.PolicyDirection_EXPORT
			}
			log.Errorf("invalid policy-type: %s", t.Type)
			return api.PolicyDirection_UNKNOWN
		}(),
		Default: func() api.RouteAction {
			switch t.Default {
			case table.ROUTE_TYPE_ACCEPT:
				return api.RouteAction_ACCEPT
			case table.ROUTE_TYPE_REJECT:
				return api.RouteAction_REJECT
			}
			return api.RouteAction_NONE
		}(),
		Name: t.Name,
		Resource: func() api.Resource {
			if t.Name != "" {
				return api.Resource_LOCAL
			}
			return api.Resource_GLOBAL
		}(),
		Policies: func() []*api.Policy {
			l := make([]*api.Policy, 0)
			for _, p := range t.Policies {
				l = append(l, NewAPIPolicyFromTableStruct(p))
			}
			return l
		}(),
	}
}

func NewConfigPolicyFromApiStruct(a *api.Policy) (*config.PolicyDefinition, error) {
	if a.Name == "" {
		return nil, fmt.Errorf("empty policy name")
	}
	stmts := make([]config.Statement, 0, len(a.Statements))
	for idx, x := range a.Statements {
		if x.Name == "" {
			x.Name = fmt.Sprintf("%s_stmt%d", a.Name, idx)
		}
		y, err := NewStatementFromApiStruct(x)
		if err != nil {
			return nil, err
		}
		stmt := y.ToConfig()
		stmts = append(stmts, *stmt)
	}
	return &config.PolicyDefinition{
		Name:       a.Name,
		Statements: stmts,
	}, nil
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

func NewRoaListFromTableStructList(origin []*table.ROA) []*api.Roa {
	l := make([]*api.Roa, 0)
	for _, r := range origin {
		host, portStr, _ := net.SplitHostPort(r.Src)
		port, _ := strconv.ParseUint(portStr, 10, 32)
		l = append(l, &api.Roa{
			As:        r.AS,
			Maxlen:    uint32(r.MaxLen),
			Prefixlen: uint32(r.Prefix.Length),
			Prefix:    r.Prefix.Prefix.String(),
			Conf: &api.RPKIConf{
				Address:    host,
				RemotePort: uint32(port),
			},
		})
	}
	return l
}

func (s *Server) ListPolicy(r *api.ListPolicyRequest, stream api.GobgpApi_ListPolicyServer) error {
	l, err := s.bgpServer.ListPolicy(context.Background(), r)
	for _, p := range l {
		if err := stream.Send(&api.ListPolicyResponse{Policy: p}); err != nil {
			return err
		}
	}
	return err
}

func (s *Server) AddPolicy(ctx context.Context, r *api.AddPolicyRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.AddPolicy(ctx, r)
}

func (s *Server) DeletePolicy(ctx context.Context, r *api.DeletePolicyRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.DeletePolicy(ctx, r)
}

func (s *Server) ReplacePolicy(ctx context.Context, r *api.ReplacePolicyRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.ReplacePolicy(ctx, r)
}

func (s *Server) ListPolicyAssignment(r *api.ListPolicyAssignmentRequest, stream api.GobgpApi_ListPolicyAssignmentServer) error {
	l, err := s.bgpServer.ListPolicyAssignment(context.Background(), r)
	if err == nil {
		for _, a := range l {
			if err := stream.Send(&api.ListPolicyAssignmentResponse{Assignment: a}); err != nil {
				return err
			}
		}
	}
	return err
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

func (s *Server) AddPolicyAssignment(ctx context.Context, r *api.AddPolicyAssignmentRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.AddPolicyAssignment(ctx, r)
}

func (s *Server) DeletePolicyAssignment(ctx context.Context, r *api.DeletePolicyAssignmentRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.DeletePolicyAssignment(ctx, r)
}

func (s *Server) ReplacePolicyAssignment(ctx context.Context, r *api.ReplacePolicyAssignmentRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.ReplacePolicyAssignment(ctx, r)
}

func (s *Server) GetBgp(ctx context.Context, r *api.GetBgpRequest) (*api.GetBgpResponse, error) {
	return s.bgpServer.GetBgp(ctx, r)
}

func NewGlobalFromAPIStruct(a *api.Global) *config.Global {
	families := make([]config.AfiSafi, 0, len(a.Families))
	for _, f := range a.Families {
		name := config.IntToAfiSafiTypeMap[int(f)]
		rf, _ := bgp.GetRouteFamily(string(name))
		families = append(families, config.AfiSafi{
			Config: config.AfiSafiConfig{
				AfiSafiName: name,
				Enabled:     true,
			},
			State: config.AfiSafiState{
				AfiSafiName: name,
				Enabled:     true,
				Family:      rf,
			},
		})
	}

	applyPolicy := &config.ApplyPolicy{}
	ReadApplyPolicyFromAPIStruct(applyPolicy, a.ApplyPolicy)

	global := &config.Global{
		Config: config.GlobalConfig{
			As:               a.As,
			RouterId:         a.RouterId,
			Port:             a.ListenPort,
			LocalAddressList: a.ListenAddresses,
		},
		ApplyPolicy: *applyPolicy,
		AfiSafis:    families,
		UseMultiplePaths: config.UseMultiplePaths{
			Config: config.UseMultiplePathsConfig{
				Enabled: a.UseMultiplePaths,
			},
		},
	}
	if a.RouteSelectionOptions != nil {
		global.RouteSelectionOptions = config.RouteSelectionOptions{
			Config: config.RouteSelectionOptionsConfig{
				AlwaysCompareMed:         a.RouteSelectionOptions.AlwaysCompareMed,
				IgnoreAsPathLength:       a.RouteSelectionOptions.IgnoreAsPathLength,
				ExternalCompareRouterId:  a.RouteSelectionOptions.ExternalCompareRouterId,
				AdvertiseInactiveRoutes:  a.RouteSelectionOptions.AdvertiseInactiveRoutes,
				EnableAigp:               a.RouteSelectionOptions.EnableAigp,
				IgnoreNextHopIgpMetric:   a.RouteSelectionOptions.IgnoreNextHopIgpMetric,
				DisableBestPathSelection: a.RouteSelectionOptions.DisableBestPathSelection,
			},
		}
	}
	if a.DefaultRouteDistance != nil {
		global.DefaultRouteDistance = config.DefaultRouteDistance{
			Config: config.DefaultRouteDistanceConfig{
				ExternalRouteDistance: uint8(a.DefaultRouteDistance.ExternalRouteDistance),
				InternalRouteDistance: uint8(a.DefaultRouteDistance.InternalRouteDistance),
			},
		}
	}
	if a.Confederation != nil {
		global.Confederation = config.Confederation{
			Config: config.ConfederationConfig{
				Enabled:      a.Confederation.Enabled,
				Identifier:   a.Confederation.Identifier,
				MemberAsList: a.Confederation.MemberAsList,
			},
		}
	}
	if a.GracefulRestart != nil {
		global.GracefulRestart = config.GracefulRestart{
			Config: config.GracefulRestartConfig{
				Enabled:             a.GracefulRestart.Enabled,
				RestartTime:         uint16(a.GracefulRestart.RestartTime),
				StaleRoutesTime:     float64(a.GracefulRestart.StaleRoutesTime),
				HelperOnly:          a.GracefulRestart.HelperOnly,
				DeferralTime:        uint16(a.GracefulRestart.DeferralTime),
				NotificationEnabled: a.GracefulRestart.NotificationEnabled,
				LongLivedEnabled:    a.GracefulRestart.LonglivedEnabled,
			},
		}
	}
	return global
}

func NewGlobalFromConfigStruct(c *config.Global) *api.Global {
	families := make([]uint32, 0, len(c.AfiSafis))
	for _, f := range c.AfiSafis {
		families = append(families, uint32(config.AfiSafiTypeToIntMap[f.Config.AfiSafiName]))
	}

	applyPolicy := NewApplyPolicyFromConfigStruct(&c.ApplyPolicy)

	return &api.Global{
		As:               c.Config.As,
		RouterId:         c.Config.RouterId,
		ListenPort:       c.Config.Port,
		ListenAddresses:  c.Config.LocalAddressList,
		Families:         families,
		UseMultiplePaths: c.UseMultiplePaths.Config.Enabled,
		RouteSelectionOptions: &api.RouteSelectionOptionsConfig{
			AlwaysCompareMed:         c.RouteSelectionOptions.Config.AlwaysCompareMed,
			IgnoreAsPathLength:       c.RouteSelectionOptions.Config.IgnoreAsPathLength,
			ExternalCompareRouterId:  c.RouteSelectionOptions.Config.ExternalCompareRouterId,
			AdvertiseInactiveRoutes:  c.RouteSelectionOptions.Config.AdvertiseInactiveRoutes,
			EnableAigp:               c.RouteSelectionOptions.Config.EnableAigp,
			IgnoreNextHopIgpMetric:   c.RouteSelectionOptions.Config.IgnoreNextHopIgpMetric,
			DisableBestPathSelection: c.RouteSelectionOptions.Config.DisableBestPathSelection,
		},
		DefaultRouteDistance: &api.DefaultRouteDistance{
			ExternalRouteDistance: uint32(c.DefaultRouteDistance.Config.ExternalRouteDistance),
			InternalRouteDistance: uint32(c.DefaultRouteDistance.Config.InternalRouteDistance),
		},
		Confederation: &api.Confederation{
			Enabled:      c.Confederation.Config.Enabled,
			Identifier:   c.Confederation.Config.Identifier,
			MemberAsList: c.Confederation.Config.MemberAsList,
		},
		GracefulRestart: &api.GracefulRestart{
			Enabled:             c.GracefulRestart.Config.Enabled,
			RestartTime:         uint32(c.GracefulRestart.Config.RestartTime),
			StaleRoutesTime:     uint32(c.GracefulRestart.Config.StaleRoutesTime),
			HelperOnly:          c.GracefulRestart.Config.HelperOnly,
			DeferralTime:        uint32(c.GracefulRestart.Config.DeferralTime),
			NotificationEnabled: c.GracefulRestart.Config.NotificationEnabled,
			LonglivedEnabled:    c.GracefulRestart.Config.LongLivedEnabled,
		},
		ApplyPolicy: applyPolicy,
	}
}

func (s *Server) StartBgp(ctx context.Context, r *api.StartBgpRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.StartBgp(ctx, r)
}

func (s *Server) StopBgp(ctx context.Context, r *api.StopBgpRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.bgpServer.StopBgp(ctx, r)
}

func (s *Server) GetTable(ctx context.Context, r *api.GetTableRequest) (*api.GetTableResponse, error) {
	return s.bgpServer.GetTable(ctx, r)
}
