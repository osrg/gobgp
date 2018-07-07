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
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/internal/pkg/apiutil"
	"github.com/osrg/gobgp/internal/pkg/config"
	"github.com/osrg/gobgp/internal/pkg/table"
	"github.com/osrg/gobgp/internal/pkg/zebra"
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
			Type:    api.PolicyType_IMPORT,
			Default: api.RouteAction(c.Config.DefaultImportPolicy.ToInt()),
		},
		ExportPolicy: &api.PolicyAssignment{
			Type:    api.PolicyType_EXPORT,
			Default: api.RouteAction(c.Config.DefaultExportPolicy.ToInt()),
		},
		InPolicy: &api.PolicyAssignment{
			Type:    api.PolicyType_IN,
			Default: api.RouteAction(c.Config.DefaultInPolicy.ToInt()),
		},
	}

	for _, pname := range c.Config.ImportPolicyList {
		applyPolicy.ImportPolicy.Policies = append(applyPolicy.ImportPolicy.Policies, &api.Policy{Name: pname})
	}
	for _, pname := range c.Config.ExportPolicyList {
		applyPolicy.ExportPolicy.Policies = append(applyPolicy.ExportPolicy.Policies, &api.Policy{Name: pname})
	}
	for _, pname := range c.Config.InPolicyList {
		applyPolicy.InPolicy.Policies = append(applyPolicy.InPolicy.Policies, &api.Policy{Name: pname})
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
		Info: &api.PeerState{
			BgpState:   string(s.SessionState),
			AdminState: api.PeerState_AdminState(s.AdminState.ToInt()),
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
			Received:        s.AdjTable.Received,
			Accepted:        s.AdjTable.Accepted,
			Advertised:      s.AdjTable.Advertised,
			PeerAs:          s.PeerAs,
			PeerType:        uint32(s.PeerType.ToInt()),
			NeighborAddress: pconf.State.NeighborAddress,
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

func (s *Server) GetNeighbor(ctx context.Context, arg *api.GetNeighborRequest) (*api.GetNeighborResponse, error) {
	if arg == nil {
		return nil, fmt.Errorf("invalid request")
	}
	neighbors := s.bgpServer.GetNeighbor(arg.Address, arg.EnableAdvertised)
	peers := make([]*api.Peer, 0, len(neighbors))
	for _, e := range neighbors {
		peers = append(peers, NewPeerFromConfigStruct(e))
	}
	return &api.GetNeighborResponse{Peers: peers}, nil
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

func (s *Server) GetRib(ctx context.Context, arg *api.GetRibRequest) (*api.GetRibResponse, error) {
	if arg == nil || arg.Table == nil {
		return nil, fmt.Errorf("invalid request")
	}
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
	var v []*table.Validation

	family := bgp.RouteFamily(arg.Table.Family)
	switch arg.Table.Type {
	case api.Resource_LOCAL, api.Resource_GLOBAL:
		tbl, v, err = s.bgpServer.GetRib(arg.Table.Name, family, f())
	case api.Resource_ADJ_IN:
		in = true
		fallthrough
	case api.Resource_ADJ_OUT:
		tbl, v, err = s.bgpServer.GetAdjRib(arg.Table.Name, family, in, f())
	case api.Resource_VRF:
		tbl, err = s.bgpServer.GetVrfRib(arg.Table.Name, family, []*table.LookupPrefix{})
	default:
		return nil, fmt.Errorf("unsupported resource type: %v", arg.Table.Type)
	}

	if err != nil {
		return nil, err
	}

	tblDsts := tbl.GetDestinations()
	dsts := make([]*api.Destination, 0, len(tblDsts))
	idx := 0
	for _, dst := range tblDsts {
		dsts = append(dsts, &api.Destination{
			Prefix: dst.GetNlri().String(),
			Paths: func(paths []*table.Path) []*api.Path {
				l := make([]*api.Path, 0, len(paths))
				for i, p := range paths {
					pp := ToPathApi(p, getValidation(v, idx))
					idx++
					switch arg.Table.Type {
					case api.Resource_LOCAL, api.Resource_GLOBAL:
						if i == 0 && !table.SelectionOptions.DisableBestPathSelection {
							pp.Best = true
						}
					}
					l = append(l, pp)
				}
				return l
			}(dst.GetAllKnownPathList()),
		})
	}

	return &api.GetRibResponse{Table: &api.Table{
		Type:         arg.Table.Type,
		Family:       uint32(tbl.GetRoutefamily()),
		Destinations: dsts},
	}, err
}

func (s *Server) GetPath(arg *api.GetPathRequest, stream api.GobgpApi_GetPathServer) error {
	f := func() []*table.LookupPrefix {
		l := make([]*table.LookupPrefix, 0, len(arg.Prefixes))
		for _, p := range arg.Prefixes {
			l = append(l, &table.LookupPrefix{
				Prefix:       p.Prefix,
				LookupOption: table.LookupOption(p.LookupOption),
			})
		}
		return l
	}

	in := false
	family := bgp.RouteFamily(arg.Family)
	var tbl *table.Table
	var err error
	var v []*table.Validation
	switch arg.Type {
	case api.Resource_LOCAL, api.Resource_GLOBAL:
		tbl, v, err = s.bgpServer.GetRib(arg.Name, family, f())
	case api.Resource_ADJ_IN:
		in = true
		fallthrough
	case api.Resource_ADJ_OUT:
		tbl, v, err = s.bgpServer.GetAdjRib(arg.Name, family, in, f())
	case api.Resource_VRF:
		tbl, err = s.bgpServer.GetVrfRib(arg.Name, family, []*table.LookupPrefix{})
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Type)
	}
	if err != nil {
		return err
	}

	idx := 0
	return func() error {
		for _, dst := range tbl.GetDestinations() {
			for i, path := range dst.GetAllKnownPathList() {
				p := ToPathApi(path, getValidation(v, idx))
				idx++
				if i == 0 && !table.SelectionOptions.DisableBestPathSelection {
					switch arg.Type {
					case api.Resource_LOCAL, api.Resource_GLOBAL:
						p.Best = true
					}
				}
				if err := stream.Send(p); err != nil {
					return err
				}
			}
		}
		return nil
	}()
}

func (s *Server) MonitorRib(arg *api.MonitorRibRequest, stream api.GobgpApi_MonitorRibServer) error {
	if arg == nil || arg.Table == nil {
		return fmt.Errorf("invalid request")
	}
	t := arg.Table
	w, err := func() (*Watcher, error) {
		switch t.Type {
		case api.Resource_GLOBAL:
			return s.bgpServer.Watch(WatchBestPath(arg.Current)), nil
		case api.Resource_ADJ_IN:
			if t.PostPolicy {
				return s.bgpServer.Watch(WatchPostUpdate(arg.Current)), nil
			}
			return s.bgpServer.Watch(WatchUpdate(arg.Current)), nil
		default:
			return nil, fmt.Errorf("unsupported resource type: %v", t.Type)
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
				if path == nil || (t.Family != 0 && bgp.RouteFamily(t.Family) != path.GetRouteFamily()) {
					continue
				}
				if dst, y := dsts[path.GetNlri().String()]; y {
					dst.Paths = append(dst.Paths, ToPathApi(path, nil))
				} else {
					dsts[path.GetNlri().String()] = &api.Destination{
						Prefix: path.GetNlri().String(),
						Paths:  []*api.Path{ToPathApi(path, nil)},
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

func (s *Server) MonitorPeerState(arg *api.Arguments, stream api.GobgpApi_MonitorPeerStateServer) error {
	if arg == nil {
		return fmt.Errorf("invalid request")
	}
	return func() error {
		w := s.bgpServer.Watch(WatchPeerState(arg.Current))
		defer func() { w.Stop() }()

		for ev := range w.Event() {
			switch msg := ev.(type) {
			case *WatchEventPeerState:
				if len(arg.Name) > 0 && arg.Name != msg.PeerAddress.String() && arg.Name != msg.PeerInterface {
					continue
				}
				if err := stream.Send(&api.Peer{
					Conf: &api.PeerConf{
						PeerAs:            msg.PeerAS,
						LocalAs:           msg.LocalAS,
						NeighborAddress:   msg.PeerAddress.String(),
						Id:                msg.PeerID.String(),
						NeighborInterface: msg.PeerInterface,
					},
					Info: &api.PeerState{
						PeerAs:          msg.PeerAS,
						LocalAs:         msg.LocalAS,
						NeighborAddress: msg.PeerAddress.String(),
						BgpState:        msg.State.String(),
						AdminState:      api.PeerState_AdminState(msg.AdminState),
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
		return nil
	}()
}

func (s *Server) ResetNeighbor(ctx context.Context, arg *api.ResetNeighborRequest) (*api.ResetNeighborResponse, error) {
	return &api.ResetNeighborResponse{}, s.bgpServer.ResetNeighbor(arg.Address, arg.Communication)
}

func (s *Server) SoftResetNeighbor(ctx context.Context, arg *api.SoftResetNeighborRequest) (*api.SoftResetNeighborResponse, error) {
	var err error
	addr := arg.Address
	if addr == "all" {
		addr = ""
	}
	family := bgp.RouteFamily(0)
	switch arg.Direction {
	case api.SoftResetNeighborRequest_IN:
		err = s.bgpServer.SoftResetIn(addr, family)
	case api.SoftResetNeighborRequest_OUT:
		err = s.bgpServer.SoftResetOut(addr, family)
	default:
		err = s.bgpServer.SoftReset(addr, family)
	}
	return &api.SoftResetNeighborResponse{}, err
}

func (s *Server) ShutdownNeighbor(ctx context.Context, arg *api.ShutdownNeighborRequest) (*api.ShutdownNeighborResponse, error) {
	return &api.ShutdownNeighborResponse{}, s.bgpServer.ShutdownNeighbor(arg.Address, arg.Communication)
}

func (s *Server) EnableNeighbor(ctx context.Context, arg *api.EnableNeighborRequest) (*api.EnableNeighborResponse, error) {
	return &api.EnableNeighborResponse{}, s.bgpServer.EnableNeighbor(arg.Address)
}

func (s *Server) DisableNeighbor(ctx context.Context, arg *api.DisableNeighborRequest) (*api.DisableNeighborResponse, error) {
	return &api.DisableNeighborResponse{}, s.bgpServer.DisableNeighbor(arg.Address, arg.Communication)
}

func (s *Server) UpdatePolicy(ctx context.Context, arg *api.UpdatePolicyRequest) (*api.UpdatePolicyResponse, error) {
	rp, err := NewRoutingPolicyFromApiStruct(arg)
	if err != nil {
		return nil, err
	}
	return &api.UpdatePolicyResponse{}, s.bgpServer.UpdatePolicy(*rp)
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

func (s *Server) api2PathList(resource api.Resource, ApiPathList []*api.Path) ([]*table.Path, error) {
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
	return &api.EnableMrtResponse{}, s.bgpServer.EnableMrt(&config.MrtConfig{
		RotationInterval: arg.Interval,
		DumpType:         config.IntToMrtTypeMap[int(arg.DumpType)],
		FileName:         arg.Filename,
	})
}

func (s *Server) DisableMrt(ctx context.Context, arg *api.DisableMrtRequest) (*api.DisableMrtResponse, error) {
	return &api.DisableMrtResponse{}, s.bgpServer.DisableMrt(&config.MrtConfig{})
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
	t, ok := config.IntToBmpRouteMonitoringPolicyTypeMap[int(arg.Type)]
	if !ok {
		return nil, fmt.Errorf("invalid bmp route monitoring policy: %d", arg.Type)
	}
	return &api.AddBmpResponse{}, s.bgpServer.AddBmp(&config.BmpServerConfig{
		Address: arg.Address,
		Port:    arg.Port,
		RouteMonitoringPolicy: t,
	})
}

func (s *Server) DeleteBmp(ctx context.Context, arg *api.DeleteBmpRequest) (*api.DeleteBmpResponse, error) {
	return &api.DeleteBmpResponse{}, s.bgpServer.DeleteBmp(&config.BmpServerConfig{
		Address: arg.Address,
		Port:    arg.Port,
	})
}

func (s *Server) ValidateRib(ctx context.Context, arg *api.ValidateRibRequest) (*api.ValidateRibResponse, error) {
	return &api.ValidateRibResponse{}, nil
}

func (s *Server) AddRpki(ctx context.Context, arg *api.AddRpkiRequest) (*api.AddRpkiResponse, error) {
	return &api.AddRpkiResponse{}, s.bgpServer.AddRpki(&config.RpkiServerConfig{
		Address:        arg.Address,
		Port:           arg.Port,
		RecordLifetime: arg.Lifetime,
	})
}

func (s *Server) DeleteRpki(ctx context.Context, arg *api.DeleteRpkiRequest) (*api.DeleteRpkiResponse, error) {
	return &api.DeleteRpkiResponse{}, s.bgpServer.DeleteRpki(&config.RpkiServerConfig{
		Address: arg.Address,
		Port:    arg.Port,
	})
}

func (s *Server) EnableRpki(ctx context.Context, arg *api.EnableRpkiRequest) (*api.EnableRpkiResponse, error) {
	return &api.EnableRpkiResponse{}, s.bgpServer.EnableRpki(&config.RpkiServerConfig{
		Address: arg.Address,
	})
}

func (s *Server) DisableRpki(ctx context.Context, arg *api.DisableRpkiRequest) (*api.DisableRpkiResponse, error) {
	return &api.DisableRpkiResponse{}, s.bgpServer.DisableRpki(&config.RpkiServerConfig{
		Address: arg.Address,
	})
}

func (s *Server) ResetRpki(ctx context.Context, arg *api.ResetRpkiRequest) (*api.ResetRpkiResponse, error) {
	return &api.ResetRpkiResponse{}, s.bgpServer.ResetRpki(&config.RpkiServerConfig{
		Address: arg.Address,
	})
}

func (s *Server) SoftResetRpki(ctx context.Context, arg *api.SoftResetRpkiRequest) (*api.SoftResetRpkiResponse, error) {
	return &api.SoftResetRpkiResponse{}, s.bgpServer.SoftResetRpki(&config.RpkiServerConfig{
		Address: arg.Address,
	})
}

func (s *Server) GetRpki(ctx context.Context, arg *api.GetRpkiRequest) (*api.GetRpkiResponse, error) {
	servers, err := s.bgpServer.GetRpki()
	if err != nil {
		return nil, err
	}
	l := make([]*api.Rpki, 0, len(servers))
	for _, s := range servers {
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
	roas, err := s.bgpServer.GetRoa(bgp.RouteFamily(arg.Family))
	if err != nil {
		return nil, err
	}
	return &api.GetRoaResponse{Roas: NewRoaListFromTableStructList(roas)}, nil
}

func (s *Server) EnableZebra(ctx context.Context, arg *api.EnableZebraRequest) (*api.EnableZebraResponse, error) {
	for _, p := range arg.RouteTypes {
		if _, err := zebra.RouteTypeFromString(p); err != nil {
			return &api.EnableZebraResponse{}, err
		}
	}
	return &api.EnableZebraResponse{}, s.bgpServer.StartZebraClient(&config.ZebraConfig{
		Url: arg.Url,
		RedistributeRouteTypeList: arg.RouteTypes,
		Version:                   uint8(arg.Version),
		NexthopTriggerEnable:      arg.NexthopTriggerEnable,
		NexthopTriggerDelay:       uint8(arg.NexthopTriggerDelay),
	})
}

func (s *Server) GetVrf(ctx context.Context, arg *api.GetVrfRequest) (*api.GetVrfResponse, error) {
	toApi := func(v *table.Vrf) *api.Vrf {
		return &api.Vrf{
			Name:     v.Name,
			Rd:       apiutil.MarshalRD(v.Rd),
			Id:       v.Id,
			ImportRt: apiutil.MarshalRTs(v.ImportRt),
			ExportRt: apiutil.MarshalRTs(v.ExportRt),
		}
	}
	vrfs := s.bgpServer.GetVrf()
	l := make([]*api.Vrf, 0, len(vrfs))
	for _, v := range vrfs {
		l = append(l, toApi(v))
	}
	return &api.GetVrfResponse{Vrfs: l}, nil
}

func (s *Server) AddVrf(ctx context.Context, arg *api.AddVrfRequest) (r *api.AddVrfResponse, err error) {
	if arg == nil || arg.Vrf == nil {
		return nil, fmt.Errorf("invalid request")
	}
	rd, err := apiutil.UnmarshalRD(arg.Vrf.Rd)
	if err != nil {
		return nil, err
	}
	im, err := apiutil.UnmarshalRTs(arg.Vrf.ImportRt)
	if err != nil {
		return nil, err
	}
	ex, err := apiutil.UnmarshalRTs(arg.Vrf.ExportRt)
	if err != nil {
		return nil, err
	}
	return &api.AddVrfResponse{}, s.bgpServer.AddVrf(arg.Vrf.Name, arg.Vrf.Id, rd, im, ex)
}

func (s *Server) DeleteVrf(ctx context.Context, arg *api.DeleteVrfRequest) (*api.DeleteVrfResponse, error) {
	if arg == nil || arg.Vrf == nil {
		return nil, fmt.Errorf("invalid request")
	}
	return &api.DeleteVrfResponse{}, s.bgpServer.DeleteVrf(arg.Vrf.Name)
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
	if a.Info != nil {
		pconf.State.SessionState = config.SessionState(a.Info.BgpState)
		pconf.State.AdminState = config.IntToAdminStateMap[int(a.Info.AdminState)]

		pconf.State.AdjTable.Received = a.Info.Received
		pconf.State.AdjTable.Accepted = a.Info.Accepted
		pconf.State.AdjTable.Advertised = a.Info.Advertised
		pconf.State.PeerAs = a.Info.PeerAs
		pconf.State.PeerType = config.IntToPeerTypeMap[int(a.Info.PeerType)]
		pconf.State.NeighborAddress = a.Info.NeighborAddress

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

func (s *Server) AddNeighbor(ctx context.Context, arg *api.AddNeighborRequest) (*api.AddNeighborResponse, error) {
	c, err := NewNeighborFromAPIStruct(arg.Peer)
	if err != nil {
		return nil, err
	}
	return &api.AddNeighborResponse{}, s.bgpServer.AddNeighbor(c)
}

func (s *Server) DeleteNeighbor(ctx context.Context, arg *api.DeleteNeighborRequest) (*api.DeleteNeighborResponse, error) {
	return &api.DeleteNeighborResponse{}, s.bgpServer.DeleteNeighbor(&config.Neighbor{Config: config.NeighborConfig{
		NeighborAddress:   arg.Peer.Conf.NeighborAddress,
		NeighborInterface: arg.Peer.Conf.NeighborInterface,
	}})
}

func (s *Server) UpdateNeighbor(ctx context.Context, arg *api.UpdateNeighborRequest) (*api.UpdateNeighborResponse, error) {
	c, err := NewNeighborFromAPIStruct(arg.Peer)
	if err != nil {
		return nil, err
	}
	needsSoftResetIn, err := s.bgpServer.UpdateNeighbor(c)
	if err != nil {
		return nil, err
	}
	if arg.DoSoftResetIn && needsSoftResetIn {
		return &api.UpdateNeighborResponse{NeedsSoftResetIn: false}, s.bgpServer.SoftResetIn("", bgp.RouteFamily(0))
	}
	return &api.UpdateNeighborResponse{NeedsSoftResetIn: needsSoftResetIn}, nil
}

func (s *Server) AddPeerGroup(ctx context.Context, arg *api.AddPeerGroupRequest) (*api.AddPeerGroupResponse, error) {
	c, err := NewPeerGroupFromAPIStruct(arg.PeerGroup)
	if err != nil {
		return nil, err
	}
	return &api.AddPeerGroupResponse{}, s.bgpServer.AddPeerGroup(c)
}

func (s *Server) DeletePeerGroup(ctx context.Context, arg *api.DeletePeerGroupRequest) (*api.DeletePeerGroupResponse, error) {
	return &api.DeletePeerGroupResponse{}, s.bgpServer.DeletePeerGroup(&config.PeerGroup{Config: config.PeerGroupConfig{
		PeerGroupName: arg.PeerGroup.Conf.PeerGroupName,
	}})
}

func (s *Server) UpdatePeerGroup(ctx context.Context, arg *api.UpdatePeerGroupRequest) (*api.UpdatePeerGroupResponse, error) {
	c, err := NewPeerGroupFromAPIStruct(arg.PeerGroup)
	if err != nil {
		return nil, err
	}
	needsSoftResetIn, err := s.bgpServer.UpdatePeerGroup(c)
	if err != nil {
		return nil, err
	}
	if arg.DoSoftResetIn && needsSoftResetIn {
		return &api.UpdatePeerGroupResponse{NeedsSoftResetIn: false}, s.bgpServer.SoftResetIn("", bgp.RouteFamily(0))
	}
	return &api.UpdatePeerGroupResponse{NeedsSoftResetIn: needsSoftResetIn}, nil
}

func (s *Server) AddDynamicNeighbor(ctx context.Context, arg *api.AddDynamicNeighborRequest) (*api.AddDynamicNeighborResponse, error) {
	return &api.AddDynamicNeighborResponse{}, s.bgpServer.AddDynamicNeighbor(&config.DynamicNeighbor{Config: config.DynamicNeighborConfig{
		Prefix:    arg.DynamicNeighbor.Prefix,
		PeerGroup: arg.DynamicNeighbor.PeerGroup,
	}})
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

func (s *Server) GetDefinedSet(ctx context.Context, arg *api.GetDefinedSetRequest) (*api.GetDefinedSetResponse, error) {
	cd, err := s.bgpServer.GetDefinedSet(table.DefinedType(arg.Type), arg.Name)
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
					elems := _regexpPrefixMaskLengthRange.FindStringSubmatch(p.MasklengthRange)
					min, _ := strconv.ParseUint(elems[1], 10, 32)
					max, _ := strconv.ParseUint(elems[2], 10, 32)

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
	for _, cs := range cd.BgpDefinedSets.LargeCommunitySets {
		ad := &api.DefinedSet{
			Type: api.DefinedType_LARGE_COMMUNITY,
			Name: cs.LargeCommunitySetName,
			List: cs.LargeCommunityList,
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
	if arg == nil || arg.Set == nil {
		return nil, fmt.Errorf("invalid request")
	}
	set, err := NewDefinedSetFromApiStruct(arg.Set)
	if err != nil {
		return nil, err
	}
	return &api.AddDefinedSetResponse{}, s.bgpServer.AddDefinedSet(set)
}

func (s *Server) DeleteDefinedSet(ctx context.Context, arg *api.DeleteDefinedSetRequest) (*api.DeleteDefinedSetResponse, error) {
	if arg == nil || arg.Set == nil {
		return nil, fmt.Errorf("invalid request")
	}
	set, err := NewDefinedSetFromApiStruct(arg.Set)
	if err != nil {
		return nil, err
	}
	return &api.DeleteDefinedSetResponse{}, s.bgpServer.DeleteDefinedSet(set, arg.All)
}

func (s *Server) ReplaceDefinedSet(ctx context.Context, arg *api.ReplaceDefinedSetRequest) (*api.ReplaceDefinedSetResponse, error) {
	if arg == nil || arg.Set == nil {
		return nil, fmt.Errorf("invalid request")
	}
	set, err := NewDefinedSetFromApiStruct(arg.Set)
	if err != nil {
		return nil, err
	}
	return &api.ReplaceDefinedSetResponse{}, s.bgpServer.ReplaceDefinedSet(set)
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

func (s *Server) GetStatement(ctx context.Context, arg *api.GetStatementRequest) (*api.GetStatementResponse, error) {
	l := make([]*api.Statement, 0)
	for _, s := range s.bgpServer.GetStatement() {
		l = append(l, toStatementApi(s))
	}
	return &api.GetStatementResponse{Statements: l}, nil
}

func (s *Server) AddStatement(ctx context.Context, arg *api.AddStatementRequest) (*api.AddStatementResponse, error) {
	if arg == nil || arg.Statement == nil {
		return nil, fmt.Errorf("invalid request")
	}
	st, err := NewStatementFromApiStruct(arg.Statement)
	if err == nil {
		err = s.bgpServer.AddStatement(st)
	}
	return &api.AddStatementResponse{}, err
}

func (s *Server) DeleteStatement(ctx context.Context, arg *api.DeleteStatementRequest) (*api.DeleteStatementResponse, error) {
	if arg == nil || arg.Statement == nil {
		return nil, fmt.Errorf("invalid request")
	}
	st, err := NewStatementFromApiStruct(arg.Statement)
	if err == nil {
		err = s.bgpServer.DeleteStatement(st, arg.All)
	}
	return &api.DeleteStatementResponse{}, err
}

func (s *Server) ReplaceStatement(ctx context.Context, arg *api.ReplaceStatementRequest) (*api.ReplaceStatementResponse, error) {
	if arg == nil || arg.Statement == nil {
		return nil, fmt.Errorf("invalid request")
	}
	st, err := NewStatementFromApiStruct(arg.Statement)
	if err == nil {
		err = s.bgpServer.ReplaceStatement(st)
	}
	return &api.ReplaceStatementResponse{}, err
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
		Type: func() api.PolicyType {
			switch t.Type {
			case table.POLICY_DIRECTION_IMPORT:
				return api.PolicyType_IMPORT
			case table.POLICY_DIRECTION_EXPORT:
				return api.PolicyType_EXPORT
			}
			log.Errorf("invalid policy-type: %s", t.Type)
			return api.PolicyType(-1)
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
	return l
}

func (s *Server) GetPolicy(ctx context.Context, arg *api.GetPolicyRequest) (*api.GetPolicyResponse, error) {
	l := make([]*api.Policy, 0)
	for _, p := range s.bgpServer.GetPolicy() {
		l = append(l, toPolicyApi(p))
	}
	return &api.GetPolicyResponse{Policies: l}, nil
}

func (s *Server) AddPolicy(ctx context.Context, arg *api.AddPolicyRequest) (*api.AddPolicyResponse, error) {
	if arg == nil || arg.Policy == nil {
		return nil, fmt.Errorf("invalid request")
	}
	x, err := NewPolicyFromApiStruct(arg.Policy)
	if err != nil {
		return nil, err
	}
	return &api.AddPolicyResponse{}, s.bgpServer.AddPolicy(x, arg.ReferExistingStatements)
}

func (s *Server) DeletePolicy(ctx context.Context, arg *api.DeletePolicyRequest) (*api.DeletePolicyResponse, error) {
	if arg == nil || arg.Policy == nil {
		return nil, fmt.Errorf("invalid request")
	}
	x, err := NewPolicyFromApiStruct(arg.Policy)
	if err != nil {
		return nil, err
	}
	return &api.DeletePolicyResponse{}, s.bgpServer.DeletePolicy(x, arg.All, arg.PreserveStatements)
}

func (s *Server) ReplacePolicy(ctx context.Context, arg *api.ReplacePolicyRequest) (*api.ReplacePolicyResponse, error) {
	if arg == nil || arg.Policy == nil {
		return nil, fmt.Errorf("invalid request")
	}
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
	if arg == nil || arg.Assignment == nil {
		return nil, fmt.Errorf("invalid request")
	}
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
	return &api.GetPolicyAssignmentResponse{NewAPIPolicyAssignmentFromTableStruct(t)}, err
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
	if arg == nil || arg.Assignment == nil {
		return nil, fmt.Errorf("invalid request")
	}
	name, dir, err := toPolicyAssignmentName(arg.Assignment)
	if err != nil {
		return nil, err
	}
	return &api.AddPolicyAssignmentResponse{}, s.bgpServer.AddPolicyAssignment(name, dir, toPolicyDefinition(arg.Assignment.Policies), defaultRouteType(arg.Assignment.Default))
}

func (s *Server) DeletePolicyAssignment(ctx context.Context, arg *api.DeletePolicyAssignmentRequest) (*api.DeletePolicyAssignmentResponse, error) {
	if arg == nil || arg.Assignment == nil {
		return nil, fmt.Errorf("invalid request")
	}
	name, dir, err := toPolicyAssignmentName(arg.Assignment)
	if err != nil {
		return nil, err
	}
	return &api.DeletePolicyAssignmentResponse{}, s.bgpServer.DeletePolicyAssignment(name, dir, toPolicyDefinition(arg.Assignment.Policies), arg.All)
}

func (s *Server) ReplacePolicyAssignment(ctx context.Context, arg *api.ReplacePolicyAssignmentRequest) (*api.ReplacePolicyAssignmentResponse, error) {
	if arg == nil || arg.Assignment == nil {
		return nil, fmt.Errorf("invalid request")
	}
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
			As:               g.Config.As,
			RouterId:         g.Config.RouterId,
			ListenPort:       g.Config.Port,
			ListenAddresses:  g.Config.LocalAddressList,
			UseMultiplePaths: g.UseMultiplePaths.Config.Enabled,
		},
	}, nil
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

func (s *Server) StartServer(ctx context.Context, arg *api.StartServerRequest) (*api.StartServerResponse, error) {
	if arg == nil || arg.Global == nil {
		return nil, fmt.Errorf("invalid request")
	}
	g := arg.Global
	if net.ParseIP(g.RouterId) == nil {
		return nil, fmt.Errorf("invalid router-id format: %s", g.RouterId)
	}

	global := NewGlobalFromAPIStruct(arg.Global)

	return &api.StartServerResponse{}, s.bgpServer.Start(global)
}

func (s *Server) StopServer(ctx context.Context, arg *api.StopServerRequest) (*api.StopServerResponse, error) {
	return &api.StopServerResponse{}, s.bgpServer.Stop()
}

func (s *Server) GetRibInfo(ctx context.Context, arg *api.GetRibInfoRequest) (*api.GetRibInfoResponse, error) {
	if arg == nil || arg.Info == nil {
		return nil, fmt.Errorf("invalid request")
	}
	family := bgp.RouteFamily(arg.Info.Family)
	var in bool
	var err error
	var info *table.TableInfo
	switch arg.Info.Type {
	case api.Resource_GLOBAL, api.Resource_LOCAL:
		info, err = s.bgpServer.GetRibInfo(arg.Info.Name, family)
	case api.Resource_ADJ_IN:
		in = true
		fallthrough
	case api.Resource_ADJ_OUT:
		info, err = s.bgpServer.GetAdjRibInfo(arg.Info.Name, family, in)
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", arg.Info.Type)
	}

	if err != nil {
		return nil, err
	}

	return &api.GetRibInfoResponse{
		Info: &api.TableInfo{
			Type:           arg.Info.Type,
			Family:         arg.Info.Family,
			Name:           arg.Info.Name,
			NumDestination: uint64(info.NumDestination),
			NumPath:        uint64(info.NumPath),
			NumAccepted:    uint64(info.NumAccepted),
		},
	}, nil
}

func (s *Server) AddCollector(ctx context.Context, arg *api.AddCollectorRequest) (*api.AddCollectorResponse, error) {
	return &api.AddCollectorResponse{}, s.bgpServer.AddCollector(&config.CollectorConfig{
		Url:               arg.Url,
		DbName:            arg.DbName,
		TableDumpInterval: arg.TableDumpInterval,
	})
}

func (s *Server) Shutdown(ctx context.Context, arg *api.ShutdownRequest) (*api.ShutdownResponse, error) {
	s.bgpServer.Shutdown()
	return &api.ShutdownResponse{}, nil
}
