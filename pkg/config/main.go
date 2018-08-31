package config

import (
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"github.com/golang/protobuf/ptypes/any"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/internal/pkg/apiutil"
	"github.com/osrg/gobgp/internal/pkg/config"
	"github.com/osrg/gobgp/internal/pkg/table"
	"github.com/osrg/gobgp/pkg/packet/bgp"
	"github.com/osrg/gobgp/pkg/server"
)

func marshalRouteTargets(l []string) ([]*any.Any, error) {
	rtList := make([]*any.Any, 0, len(l))
	for _, rtString := range l {
		rt, err := bgp.ParseRouteTarget(rtString)
		if err != nil {
			return nil, err
		}
		rtList = append(rtList, apiutil.MarshalRT(rt))
	}
	return rtList, nil
}

func ReadConfigFileOnSighup(configFile, configType string) chan *config.BgpConfigSet {
	ch := make(chan *config.BgpConfigSet)
	go config.ReadConfigfileServe(configFile, configType, ch)
	return ch
}

func ReadConfigFile(configFile, configType string) *config.BgpConfigSet {
	ch := ReadConfigFileOnSighup(configFile, configType)
	c := <-ch
	return c
}

func ApplyInitialConfig(newConfig *config.BgpConfigSet, isGracefulRestart bool, apiServer *server.Server) *config.BgpConfigSet {
	c := newConfig
	if _, err := apiServer.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: server.NewGlobalFromConfigStruct(&c.Global),
	}); err != nil {
		log.Fatalf("failed to set global config: %s", err)
	}

	if newConfig.Zebra.Config.Enabled {
		tps := c.Zebra.Config.RedistributeRouteTypeList
		l := make([]string, 0, len(tps))
		for _, t := range tps {
			l = append(l, string(t))
		}
		if _, err := apiServer.EnableZebra(context.Background(), &api.EnableZebraRequest{
			Url:                  c.Zebra.Config.Url,
			RouteTypes:           l,
			Version:              uint32(c.Zebra.Config.Version),
			NexthopTriggerEnable: c.Zebra.Config.NexthopTriggerEnable,
			NexthopTriggerDelay:  uint32(c.Zebra.Config.NexthopTriggerDelay),
		}); err != nil {
			log.Fatalf("failed to set zebra config: %s", err)
		}
	}

	if len(newConfig.Collector.Config.Url) > 0 {
		log.Fatal("collector feature is not supported")
	}

	for _, c := range newConfig.RpkiServers {
		if _, err := apiServer.AddRpki(context.Background(), &api.AddRpkiRequest{
			Address:  c.Config.Address,
			Port:     c.Config.Port,
			Lifetime: c.Config.RecordLifetime,
		}); err != nil {
			log.Fatalf("failed to set rpki config: %s", err)
		}
	}
	for _, c := range newConfig.BmpServers {
		if _, err := apiServer.AddBmp(context.Background(), &api.AddBmpRequest{
			Address: c.Config.Address,
			Port:    c.Config.Port,
			Type:    api.AddBmpRequest_MonitoringPolicy(c.Config.RouteMonitoringPolicy.ToInt()),
		}); err != nil {
			log.Fatalf("failed to set bmp config: %s", err)
		}
	}
	for _, vrf := range newConfig.Vrfs {
		rd, err := bgp.ParseRouteDistinguisher(vrf.Config.Rd)
		if err != nil {
			log.Fatalf("failed to load vrf rd config: %s", err)
		}

		importRtList, err := marshalRouteTargets(vrf.Config.ImportRtList)
		if err != nil {
			log.Fatalf("failed to load vrf import rt config: %s", err)
		}
		exportRtList, err := marshalRouteTargets(vrf.Config.ExportRtList)
		if err != nil {
			log.Fatalf("failed to load vrf export rt config: %s", err)
		}

		if _, err := apiServer.AddVrf(context.Background(), &api.AddVrfRequest{
			Vrf: &api.Vrf{
				Name:     vrf.Config.Name,
				Rd:       apiutil.MarshalRD(rd),
				Id:       uint32(vrf.Config.Id),
				ImportRt: importRtList,
				ExportRt: exportRtList,
			},
		}); err != nil {
			log.Fatalf("failed to set vrf config: %s", err)
		}
	}
	for _, c := range newConfig.MrtDump {
		if len(c.Config.FileName) == 0 {
			continue
		}
		if _, err := apiServer.EnableMrt(context.Background(), &api.EnableMrtRequest{
			DumpType: int32(c.Config.DumpType.ToInt()),
			Filename: c.Config.FileName,
			Interval: c.Config.DumpInterval,
		}); err != nil {
			log.Fatalf("failed to set mrt config: %s", err)
		}
	}
	p := config.ConfigSetToRoutingPolicy(newConfig)
	rp, err := server.NewAPIRoutingPolicyFromConfigStruct(p)
	if err != nil {
		log.Warn(err)
	} else {
		apiServer.SetPolicies(context.Background(), &api.SetPoliciesRequest{
			DefinedSets: rp.DefinedSets,
			Policies:    rp.Policies,
		})
	}

	added := newConfig.Neighbors
	addedPg := newConfig.PeerGroups
	if isGracefulRestart {
		for i, n := range added {
			if n.GracefulRestart.Config.Enabled {
				added[i].GracefulRestart.State.LocalRestarting = true
			}
		}
	}

	addPeerGroup(apiServer, addedPg)
	addDynamicNeigbors(apiServer, newConfig.DynamicNeighbors)
	addNeighbors(apiServer, added)
	return c
}

func UpdateConfig(c, newConfig *config.BgpConfigSet, apiServer *server.Server) *config.BgpConfigSet {
	addedPg, deletedPg, updatedPg := config.UpdatePeerGroupConfig(c, newConfig)
	added, deleted, updated := config.UpdateNeighborConfig(c, newConfig)
	updatePolicy := config.CheckPolicyDifference(config.ConfigSetToRoutingPolicy(c), config.ConfigSetToRoutingPolicy(newConfig))

	if updatePolicy {
		log.Info("Policy config is updated")
		p := config.ConfigSetToRoutingPolicy(newConfig)
		rp, err := server.NewAPIRoutingPolicyFromConfigStruct(p)
		if err != nil {
			log.Warn(err)
		} else {
			apiServer.SetPolicies(context.Background(), &api.SetPoliciesRequest{
				DefinedSets: rp.DefinedSets,
				Policies:    rp.Policies,
			})
		}
	}
	// global policy update
	if !newConfig.Global.ApplyPolicy.Config.Equal(&c.Global.ApplyPolicy.Config) {
		a := newConfig.Global.ApplyPolicy.Config
		toDefaultTable := func(r config.DefaultPolicyType) table.RouteType {
			var def table.RouteType
			switch r {
			case config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE:
				def = table.ROUTE_TYPE_ACCEPT
			case config.DEFAULT_POLICY_TYPE_REJECT_ROUTE:
				def = table.ROUTE_TYPE_REJECT
			}
			return def
		}
		toPolicies := func(r []string) []*table.Policy {
			p := make([]*table.Policy, 0, len(r))
			for _, n := range r {
				p = append(p, &table.Policy{
					Name: n,
				})
			}
			return p
		}

		def := toDefaultTable(a.DefaultImportPolicy)
		ps := toPolicies(a.ImportPolicyList)
		apiServer.SetPolicyAssignment(context.Background(), &api.SetPolicyAssignmentRequest{
			Assignment: server.NewAPIPolicyAssignmentFromTableStruct(&table.PolicyAssignment{
				Name:     table.GLOBAL_RIB_NAME,
				Type:     table.POLICY_DIRECTION_IMPORT,
				Policies: ps,
				Default:  def,
			}),
		})

		def = toDefaultTable(a.DefaultExportPolicy)
		ps = toPolicies(a.ExportPolicyList)
		apiServer.SetPolicyAssignment(context.Background(), &api.SetPolicyAssignmentRequest{
			Assignment: server.NewAPIPolicyAssignmentFromTableStruct(&table.PolicyAssignment{
				Name:     table.GLOBAL_RIB_NAME,
				Type:     table.POLICY_DIRECTION_EXPORT,
				Policies: ps,
				Default:  def,
			}),
		})

		updatePolicy = true
	}
	c = newConfig
	addPeerGroup(apiServer, addedPg)
	deletePeerGroup(apiServer, deletedPg)
	updatePolicy = updatePolicy || updatePeerGroup(apiServer, updatedPg)
	addDynamicNeigbors(apiServer, newConfig.DynamicNeighbors)
	addNeighbors(apiServer, added)
	deleteNeighbors(apiServer, deleted)
	updatePolicy = updatePolicy || updateNeighbors(apiServer, updated)
	if updatePolicy {
		if _, err := apiServer.ResetPeer(context.Background(), &api.ResetPeerRequest{
			Address:   "",
			Direction: api.ResetPeerRequest_IN,
			Soft:      true,
		}); err != nil {
			log.Warn(err)
		}
	}
	return c
}

func addNeighbors(apiServer *server.Server, added []config.Neighbor) {
	for _, p := range added {
		log.Infof("Peer %v is added", p.State.NeighborAddress)
		if _, err := apiServer.AddPeer(context.Background(), &api.AddPeerRequest{
			Peer: server.NewPeerFromConfigStruct(&p),
		}); err != nil {
			log.Warn(err)
		}
	}
}

func deleteNeighbors(apiServer *server.Server, deleted []config.Neighbor) {
	for _, p := range deleted {
		log.Infof("Peer %v is deleted", p.State.NeighborAddress)
		if _, err := apiServer.DeletePeer(context.Background(), &api.DeletePeerRequest{
			Address: p.State.NeighborAddress,
		}); err != nil {
			log.Warn(err)
		}
	}
}

func updateNeighbors(apiServer *server.Server, updated []config.Neighbor) bool {
	updatePolicy := false
	for _, p := range updated {
		log.Infof("Peer %v is updated", p.State.NeighborAddress)
		if u, err := apiServer.UpdatePeer(context.Background(), &api.UpdatePeerRequest{
			Peer: server.NewPeerFromConfigStruct(&p),
		}); err != nil {
			log.Warn(err)
		} else {
			updatePolicy = updatePolicy || u.NeedsSoftResetIn
		}
	}
	return updatePolicy
}

func addPeerGroup(apiServer *server.Server, added []config.PeerGroup) {
	for _, pg := range added {
		log.Infof("PeerGroup %s is added", pg.Config.PeerGroupName)
		if _, err := apiServer.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{
			PeerGroup: server.NewPeerGroupFromConfigStruct(&pg),
		}); err != nil {
			log.Warn(err)
		}
	}
}

func deletePeerGroup(apiServer *server.Server, deleted []config.PeerGroup) {
	for _, pg := range deleted {
		log.Infof("PeerGroup %s is deleted", pg.Config.PeerGroupName)
		if _, err := apiServer.DeletePeerGroup(context.Background(), &api.DeletePeerGroupRequest{
			Name: pg.Config.PeerGroupName,
		}); err != nil {
			log.Warn(err)
		}
	}
}

func updatePeerGroup(apiServer *server.Server, updated []config.PeerGroup) bool {
	updatePolicy := false
	for _, pg := range updated {
		log.Infof("PeerGroup %v is updated", pg.State.PeerGroupName)
		if u, err := apiServer.UpdatePeerGroup(context.Background(), &api.UpdatePeerGroupRequest{
			PeerGroup: server.NewPeerGroupFromConfigStruct(&pg),
		}); err != nil {
			log.Warn(err)
		} else {
			updatePolicy = updatePolicy || u.NeedsSoftResetIn
		}
	}
	for _, pg := range updated {
		log.Infof("PeerGroup %s is updated", pg.Config.PeerGroupName)
		if _, err := apiServer.UpdatePeerGroup(context.Background(), &api.UpdatePeerGroupRequest{
			PeerGroup: server.NewPeerGroupFromConfigStruct(&pg),
		}); err != nil {
			log.Warn(err)
		}
	}
	return updatePolicy
}

func addDynamicNeigbors(apiServer *server.Server, dynamicNeighbors []config.DynamicNeighbor) {
	for _, dn := range dynamicNeighbors {
		log.Infof("Dynamic Neighbor %s is added to PeerGroup %s", dn.Config.Prefix, dn.Config.PeerGroup)
		if _, err := apiServer.AddDynamicNeighbor(context.Background(), &api.AddDynamicNeighborRequest{
			DynamicNeighbor: &api.DynamicNeighbor{
				Prefix:    dn.Config.Prefix,
				PeerGroup: dn.Config.PeerGroup,
			},
		}); err != nil {
			log.Warn(err)
		}
	}
}
