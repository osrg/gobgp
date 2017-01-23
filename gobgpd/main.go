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
	log "github.com/Sirupsen/logrus"
	"github.com/jessevdk/go-flags"
	p "github.com/kr/pretty"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/server"
	"github.com/osrg/gobgp/table"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

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
	}
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
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

	if opts.DisableStdlog == true {
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
			p.Println(c)
		}
		os.Exit(0)
	}

	log.Info("gobgpd started")
	bgpServer := server.NewBgpServer()
	go bgpServer.Serve()

	// start grpc Server
	grpcServer := api.NewGrpcServer(bgpServer, opts.GrpcHosts)
	go func() {
		if err := grpcServer.Serve(); err != nil {
			log.Fatalf("failed to listen grpc port: %s", err)
		}
	}()

	if opts.ConfigFile != "" {
		go config.ReadConfigfileServe(opts.ConfigFile, opts.ConfigType, configCh)
	}

	var c *config.BgpConfigSet = nil
	for {
		select {
		case newConfig := <-configCh:
			var added, deleted, updated []config.Neighbor
			var updatePolicy bool

			if c == nil {
				c = newConfig
				if err := bgpServer.Start(&newConfig.Global); err != nil {
					log.Fatalf("failed to set global config: %s", err)
				}
				if newConfig.Zebra.Config.Enabled {
					if err := bgpServer.StartZebraClient(&newConfig.Zebra.Config); err != nil {
						log.Fatalf("failed to set zebra config: %s", err)
					}
				}
				if len(newConfig.Collector.Config.Url) > 0 {
					if err := bgpServer.StartCollector(&newConfig.Collector.Config); err != nil {
						log.Fatalf("failed to set collector config: %s", err)
					}
				}
				for _, c := range newConfig.RpkiServers {
					if err := bgpServer.AddRpki(&c.Config); err != nil {
						log.Fatalf("failed to set rpki config: %s", err)
					}
				}
				for _, c := range newConfig.BmpServers {
					if err := bgpServer.AddBmp(&c.Config); err != nil {
						log.Fatalf("failed to set bmp config: %s", err)
					}
				}
				for _, c := range newConfig.MrtDump {
					if len(c.Config.FileName) == 0 {
						continue
					}
					if err := bgpServer.EnableMrt(&c.Config); err != nil {
						log.Fatalf("failed to set mrt config: %s", err)
					}
				}
				p := config.ConfigSetToRoutingPolicy(newConfig)
				if err := bgpServer.UpdatePolicy(*p); err != nil {
					log.Fatalf("failed to set routing policy: %s", err)
				}

				added = newConfig.Neighbors
				if opts.GracefulRestart {
					for i, n := range added {
						if n.GracefulRestart.Config.Enabled {
							added[i].GracefulRestart.State.LocalRestarting = true
						}
					}
				}

			} else {
				added, deleted, updated, updatePolicy = config.UpdateConfig(c, newConfig)
				if updatePolicy {
					log.Info("Policy config is updated")
					p := config.ConfigSetToRoutingPolicy(newConfig)
					bgpServer.UpdatePolicy(*p)
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
					toPolicyDefinitions := func(r []string) []*config.PolicyDefinition {
						p := make([]*config.PolicyDefinition, 0, len(r))
						for _, n := range r {
							p = append(p, &config.PolicyDefinition{
								Name: n,
							})
						}
						return p
					}

					def := toDefaultTable(a.DefaultImportPolicy)
					ps := toPolicyDefinitions(a.ImportPolicyList)
					bgpServer.ReplacePolicyAssignment("", table.POLICY_DIRECTION_IMPORT, ps, def)

					def = toDefaultTable(a.DefaultExportPolicy)
					ps = toPolicyDefinitions(a.ExportPolicyList)
					bgpServer.ReplacePolicyAssignment("", table.POLICY_DIRECTION_EXPORT, ps, def)

					updatePolicy = true

				}
				c = newConfig
			}

			for i, p := range added {
				log.Infof("Peer %v is added", p.Config.NeighborAddress)
				if err := bgpServer.AddNeighbor(&added[i]); err != nil {
					log.Warn(err)
				}
			}
			for i, p := range deleted {
				log.Infof("Peer %v is deleted", p.Config.NeighborAddress)
				if err := bgpServer.DeleteNeighbor(&deleted[i]); err != nil {
					log.Warn(err)
				}
			}
			for i, p := range updated {
				log.Infof("Peer %v is updated", p.Config.NeighborAddress)
				u, err := bgpServer.UpdateNeighbor(&updated[i])
				if err != nil {
					log.Warn(err)
				}
				updatePolicy = updatePolicy || u
			}

			if updatePolicy {
				bgpServer.SoftResetIn("", bgp.RouteFamily(0))
			}
		case <-sigCh:
			bgpServer.Shutdown()
		}
	}
}
