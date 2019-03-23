//
// Copyright (C) 2014-2017 Nippon Telegraph and Telephone Corporation.
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

package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/coreos/go-systemd/daemon"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/jessevdk/go-flags"
	"github.com/kr/pretty"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/internal/pkg/apiutil"
	"github.com/osrg/gobgp/internal/pkg/config"
	"github.com/osrg/gobgp/internal/pkg/table"
	"github.com/osrg/gobgp/pkg/packet/bgp"
	"github.com/osrg/gobgp/pkg/server"
)

var version = "master"

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

func assignGlobalpolicy(bgpServer *server.BgpServer, a *config.ApplyPolicyConfig) {
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
	bgpServer.SetPolicyAssignment(context.Background(), &api.SetPolicyAssignmentRequest{
		Assignment: table.NewAPIPolicyAssignmentFromTableStruct(&table.PolicyAssignment{
			Name:     table.GLOBAL_RIB_NAME,
			Type:     table.POLICY_DIRECTION_IMPORT,
			Policies: ps,
			Default:  def,
		}),
	})

	def = toDefaultTable(a.DefaultExportPolicy)
	ps = toPolicies(a.ExportPolicyList)
	bgpServer.SetPolicyAssignment(context.Background(), &api.SetPolicyAssignmentRequest{
		Assignment: table.NewAPIPolicyAssignmentFromTableStruct(&table.PolicyAssignment{
			Name:     table.GLOBAL_RIB_NAME,
			Type:     table.POLICY_DIRECTION_EXPORT,
			Policies: ps,
			Default:  def,
		}),
	})

}

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)

	var opts struct {
		ConfigFile      string `short:"f" long:"config-file" description:"specifying a config file"`
		ConfigType      string `short:"t" long:"config-type" description:"specifying config type (toml, yaml, json)" default:"toml"`
		LogLevel        string `short:"l" long:"log-level" description:"specifying log level"`
		LogPlain        bool   `short:"p" long:"log-plain" description:"use plain format for logging (json by default)"`
		UseSyslog       string `short:"s" long:"syslog" description:"use syslogd"`
		Facility        string `long:"syslog-facility" description:"specify syslog facility"`
		DisableStdlog   bool   `long:"disable-stdlog" description:"disable standard logging"`
		CPUs            int    `long:"cpus" description:"specify the number of CPUs to be used"`
		GrpcHosts       string `long:"api-hosts" description:"specify the hosts that gobgpd listens on" default:":50051"`
		GracefulRestart bool   `short:"r" long:"graceful-restart" description:"flag restart-state in graceful-restart capability"`
		Dry             bool   `short:"d" long:"dry-run" description:"check configuration"`
		PProfHost       string `long:"pprof-host" description:"specify the host that gobgpd listens on for pprof" default:"localhost:6060"`
		PProfDisable    bool   `long:"pprof-disable" description:"disable pprof profiling"`
		UseSdNotify     bool   `long:"sdnotify" description:"use sd_notify protocol"`
		TLS             bool   `long:"tls" description:"enable TLS authentication for gRPC API"`
		TLSCertFile     string `long:"tls-cert-file" description:"The TLS cert file"`
		TLSKeyFile      string `long:"tls-key-file" description:"The TLS key file"`
		Version         bool   `long:"version" description:"show version number"`
	}
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	if opts.Version {
		fmt.Println("gobgpd version", version)
		os.Exit(0)
	}

	if opts.CPUs == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	} else {
		if runtime.NumCPU() < opts.CPUs {
			log.Errorf("Only %d CPUs are available but %d is specified", runtime.NumCPU(), opts.CPUs)
			os.Exit(1)
		}
		runtime.GOMAXPROCS(opts.CPUs)
	}

	if !opts.PProfDisable {
		go func() {
			log.Println(http.ListenAndServe(opts.PProfHost, nil))
		}()
	}

	switch opts.LogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	if opts.DisableStdlog {
		log.SetOutput(ioutil.Discard)
	} else {
		log.SetOutput(os.Stdout)
	}

	if opts.UseSyslog != "" {
		if err := addSyslogHook(opts.UseSyslog, opts.Facility); err != nil {
			log.Error("Unable to connect to syslog daemon, ", opts.UseSyslog)
		}
	}

	if opts.LogPlain {
		if opts.DisableStdlog {
			log.SetFormatter(&log.TextFormatter{
				DisableColors: true,
			})
		}
	} else {
		log.SetFormatter(&log.JSONFormatter{})
	}

	configCh := make(chan *config.BgpConfigSet)
	if opts.Dry {
		go config.ReadConfigfileServe(opts.ConfigFile, opts.ConfigType, configCh)
		c := <-configCh
		if opts.LogLevel == "debug" {
			pretty.Println(c)
		}
		os.Exit(0)
	}

	maxSize := 256 << 20
	grpcOpts := []grpc.ServerOption{grpc.MaxRecvMsgSize(maxSize), grpc.MaxSendMsgSize(maxSize)}
	if opts.TLS {
		creds, err := credentials.NewServerTLSFromFile(opts.TLSCertFile, opts.TLSKeyFile)
		if err != nil {
			log.Fatalf("Failed to generate credentials: %v", err)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
	}

	log.Info("gobgpd started")
	bgpServer := server.NewBgpServer(server.GrpcListenAddress(opts.GrpcHosts), server.GrpcOption(grpcOpts))
	go bgpServer.Serve()

	if opts.UseSdNotify {
		if status, err := daemon.SdNotify(false, daemon.SdNotifyReady); !status {
			if err != nil {
				log.Warnf("Failed to send notification via sd_notify(): %s", err)
			} else {
				log.Warnf("The socket sd_notify() isn't available")
			}
		}
	}

	if opts.ConfigFile != "" {
		go config.ReadConfigfileServe(opts.ConfigFile, opts.ConfigType, configCh)
	}

	loop := func() {
		var c *config.BgpConfigSet
		for {
			select {
			case <-sigCh:
				bgpServer.StopBgp(context.Background(), &api.StopBgpRequest{})
				if opts.UseSdNotify {
					daemon.SdNotify(false, daemon.SdNotifyStopping)
				}
				return
			case newConfig := <-configCh:
				var added, deleted, updated []config.Neighbor
				var addedPg, deletedPg, updatedPg []config.PeerGroup
				var updatePolicy bool

				if c == nil {
					c = newConfig
					if err := bgpServer.StartBgp(context.Background(), &api.StartBgpRequest{
						Global: config.NewGlobalFromConfigStruct(&c.Global),
					}); err != nil {
						log.Fatalf("failed to set global config: %s", err)
					}

					if newConfig.Zebra.Config.Enabled {
						tps := c.Zebra.Config.RedistributeRouteTypeList
						l := make([]string, 0, len(tps))
						for _, t := range tps {
							l = append(l, string(t))
						}
						if err := bgpServer.EnableZebra(context.Background(), &api.EnableZebraRequest{
							Url:                  c.Zebra.Config.Url,
							RouteTypes:           l,
							Version:              uint32(c.Zebra.Config.Version),
							NexthopTriggerEnable: c.Zebra.Config.NexthopTriggerEnable,
							NexthopTriggerDelay:  uint32(c.Zebra.Config.NexthopTriggerDelay),
							MplsLabelRangeSize:   uint32(c.Zebra.Config.MplsLabelRangeSize),
						}); err != nil {
							log.Fatalf("failed to set zebra config: %s", err)
						}
					}

					if len(newConfig.Collector.Config.Url) > 0 {
						log.Fatal("collector feature is not supported")
					}

					for _, c := range newConfig.RpkiServers {
						if err := bgpServer.AddRpki(context.Background(), &api.AddRpkiRequest{
							Address:  c.Config.Address,
							Port:     c.Config.Port,
							Lifetime: c.Config.RecordLifetime,
						}); err != nil {
							log.Fatalf("failed to set rpki config: %s", err)
						}
					}
					for _, c := range newConfig.BmpServers {
						if err := bgpServer.AddBmp(context.Background(), &api.AddBmpRequest{
							Address:           c.Config.Address,
							Port:              c.Config.Port,
							SysName:           c.Config.SysName,
							SysDescr:          c.Config.SysDescr,
							Policy:            api.AddBmpRequest_MonitoringPolicy(c.Config.RouteMonitoringPolicy.ToInt()),
							StatisticsTimeout: int32(c.Config.StatisticsTimeout),
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

						if err := bgpServer.AddVrf(context.Background(), &api.AddVrfRequest{
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
						if err := bgpServer.EnableMrt(context.Background(), &api.EnableMrtRequest{
							DumpType:         int32(c.Config.DumpType.ToInt()),
							Filename:         c.Config.FileName,
							DumpInterval:     c.Config.DumpInterval,
							RotationInterval: c.Config.RotationInterval,
						}); err != nil {
							log.Fatalf("failed to set mrt config: %s", err)
						}
					}
					p := config.ConfigSetToRoutingPolicy(newConfig)
					rp, err := table.NewAPIRoutingPolicyFromConfigStruct(p)
					if err != nil {
						log.Warn(err)
					} else {
						bgpServer.SetPolicies(context.Background(), &api.SetPoliciesRequest{
							DefinedSets: rp.DefinedSets,
							Policies:    rp.Policies,
						})
					}

					assignGlobalpolicy(bgpServer, &newConfig.Global.ApplyPolicy.Config)

					added = newConfig.Neighbors
					addedPg = newConfig.PeerGroups
					if opts.GracefulRestart {
						for i, n := range added {
							if n.GracefulRestart.Config.Enabled {
								added[i].GracefulRestart.State.LocalRestarting = true
							}
						}
					}
				} else {
					addedPg, deletedPg, updatedPg = config.UpdatePeerGroupConfig(c, newConfig)
					added, deleted, updated = config.UpdateNeighborConfig(c, newConfig)
					updatePolicy = config.CheckPolicyDifference(config.ConfigSetToRoutingPolicy(c), config.ConfigSetToRoutingPolicy(newConfig))

					if updatePolicy {
						log.Info("Policy config is updated")
						p := config.ConfigSetToRoutingPolicy(newConfig)
						rp, err := table.NewAPIRoutingPolicyFromConfigStruct(p)
						if err != nil {
							log.Warn(err)
						} else {
							bgpServer.SetPolicies(context.Background(), &api.SetPoliciesRequest{
								DefinedSets: rp.DefinedSets,
								Policies:    rp.Policies,
							})
						}
					}
					// global policy update
					if !newConfig.Global.ApplyPolicy.Config.Equal(&c.Global.ApplyPolicy.Config) {
						assignGlobalpolicy(bgpServer, &newConfig.Global.ApplyPolicy.Config)
						updatePolicy = true
					}
					c = newConfig
				}
				for _, pg := range addedPg {
					log.Infof("PeerGroup %s is added", pg.Config.PeerGroupName)
					if err := bgpServer.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{
						PeerGroup: config.NewPeerGroupFromConfigStruct(&pg),
					}); err != nil {
						log.Warn(err)
					}
				}
				for _, pg := range deletedPg {
					log.Infof("PeerGroup %s is deleted", pg.Config.PeerGroupName)
					if err := bgpServer.DeletePeerGroup(context.Background(), &api.DeletePeerGroupRequest{
						Name: pg.Config.PeerGroupName,
					}); err != nil {
						log.Warn(err)
					}
				}
				for _, pg := range updatedPg {
					log.Infof("PeerGroup %v is updated", pg.State.PeerGroupName)
					if u, err := bgpServer.UpdatePeerGroup(context.Background(), &api.UpdatePeerGroupRequest{
						PeerGroup: config.NewPeerGroupFromConfigStruct(&pg),
					}); err != nil {
						log.Warn(err)
					} else {
						updatePolicy = updatePolicy || u.NeedsSoftResetIn
					}
				}
				for _, pg := range updatedPg {
					log.Infof("PeerGroup %s is updated", pg.Config.PeerGroupName)
					if _, err := bgpServer.UpdatePeerGroup(context.Background(), &api.UpdatePeerGroupRequest{
						PeerGroup: config.NewPeerGroupFromConfigStruct(&pg),
					}); err != nil {
						log.Warn(err)
					}
				}
				for _, dn := range newConfig.DynamicNeighbors {
					log.Infof("Dynamic Neighbor %s is added to PeerGroup %s", dn.Config.Prefix, dn.Config.PeerGroup)
					if err := bgpServer.AddDynamicNeighbor(context.Background(), &api.AddDynamicNeighborRequest{
						DynamicNeighbor: &api.DynamicNeighbor{
							Prefix:    dn.Config.Prefix,
							PeerGroup: dn.Config.PeerGroup,
						},
					}); err != nil {
						log.Warn(err)
					}
				}
				for _, p := range added {
					log.Infof("Peer %v is added", p.State.NeighborAddress)
					if err := bgpServer.AddPeer(context.Background(), &api.AddPeerRequest{
						Peer: config.NewPeerFromConfigStruct(&p),
					}); err != nil {
						log.Warn(err)
					}
				}
				for _, p := range deleted {
					log.Infof("Peer %v is deleted", p.State.NeighborAddress)
					if err := bgpServer.DeletePeer(context.Background(), &api.DeletePeerRequest{
						Address: p.State.NeighborAddress,
					}); err != nil {
						log.Warn(err)
					}
				}
				for _, p := range updated {
					log.Infof("Peer %v is updated", p.State.NeighborAddress)
					if u, err := bgpServer.UpdatePeer(context.Background(), &api.UpdatePeerRequest{
						Peer: config.NewPeerFromConfigStruct(&p),
					}); err != nil {
						log.Warn(err)
					} else {
						updatePolicy = updatePolicy || u.NeedsSoftResetIn
					}
				}

				if updatePolicy {
					if err := bgpServer.ResetPeer(context.Background(), &api.ResetPeerRequest{
						Address:   "",
						Direction: api.ResetPeerRequest_IN,
						Soft:      true,
					}); err != nil {
						log.Warn(err)
					}
				}
			}
		}
	}

	loop()
}
