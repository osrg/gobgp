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

package main

import (
	log "github.com/Sirupsen/logrus"
	"github.com/Sirupsen/logrus/hooks/syslog"
	"github.com/jessevdk/go-flags"
	p "github.com/kr/pretty"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/server"
	"io/ioutil"
	"log/syslog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
)

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGUSR1)

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
		dst := strings.SplitN(opts.UseSyslog, ":", 2)
		network := ""
		addr := ""
		if len(dst) == 2 {
			network = dst[0]
			addr = dst[1]
		}

		facility := syslog.Priority(0)
		switch opts.Facility {
		case "kern":
			facility = syslog.LOG_KERN
		case "user":
			facility = syslog.LOG_USER
		case "mail":
			facility = syslog.LOG_MAIL
		case "daemon":
			facility = syslog.LOG_DAEMON
		case "auth":
			facility = syslog.LOG_AUTH
		case "syslog":
			facility = syslog.LOG_SYSLOG
		case "lpr":
			facility = syslog.LOG_LPR
		case "news":
			facility = syslog.LOG_NEWS
		case "uucp":
			facility = syslog.LOG_UUCP
		case "cron":
			facility = syslog.LOG_CRON
		case "authpriv":
			facility = syslog.LOG_AUTHPRIV
		case "ftp":
			facility = syslog.LOG_FTP
		case "local0":
			facility = syslog.LOG_LOCAL0
		case "local1":
			facility = syslog.LOG_LOCAL1
		case "local2":
			facility = syslog.LOG_LOCAL2
		case "local3":
			facility = syslog.LOG_LOCAL3
		case "local4":
			facility = syslog.LOG_LOCAL4
		case "local5":
			facility = syslog.LOG_LOCAL5
		case "local6":
			facility = syslog.LOG_LOCAL6
		case "local7":
			facility = syslog.LOG_LOCAL7
		}

		hook, err := logrus_syslog.NewSyslogHook(network, addr, syslog.LOG_INFO|facility, "bgpd")
		if err != nil {
			log.Error("Unable to connect to syslog daemon, ", opts.UseSyslog)
			os.Exit(1)
		} else {
			log.AddHook(hook)
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

	count := 0

	for {
		select {
		case new := <-configCh:

			softResetIn := false
			gr := false
			start := false
			if count == 0 && opts.GracefulRestart {
				gr = true
			}

			prev, _ := bgpServer.GetConfig()

			if prev.Global.Config.As == 0 && new.Global.Config.As != 0 {
				bgpServer.Start(&new.Global)
				start = true
			} else if prev.Global.Config.As != 0 && new.Global.Config.As == 0 {
				log.Error("Removing global configuration is not supported. Configuration reload failed")
				continue
			}

			// bgpServer.UpdatePolicy() must be called after bgpServer.Start() and
			// before bgpServer.Update(), bgpServer.AddNeighbor() and bgpServer.UpdateNeighbor()
			if config.CheckPolicyDifference(config.ConfigSetToRoutingPolicy(prev), config.ConfigSetToRoutingPolicy(new)) {
				bgpServer.UpdatePolicy(config.ConfigSetToRoutingPolicy(new))
				softResetIn = true
			}

			if !start {
				g := new.Global
				if !prev.Global.Equal(&g) {
					if err := bgpServer.Update(&g); err != nil {
						log.Errorf("Configuration reload failed: %s", err)
						continue
					}
					if !prev.Global.ApplyPolicy.Equal(&new.Global.ApplyPolicy) {
						softResetIn = true
					}
				}
			}

			inNSlice := func(n config.Neighbor, b []config.Neighbor) int {
				for i, nb := range b {
					if nb.Config.NeighborAddress == n.Config.NeighborAddress {
						return i
					}
				}
				return -1
			}

			for _, n := range new.Neighbors {
				neigh := n
				if idx := inNSlice(neigh, prev.Neighbors); idx < 0 {
					if gr && neigh.GracefulRestart.Config.Enabled {
						neigh.GracefulRestart.State.LocalRestarting = true
					}
					bgpServer.AddNeighbor(&neigh)
				} else if !n.Equal(&prev.Neighbors[idx]) {
					bgpServer.UpdateNeighbor(&neigh)
					if !neigh.ApplyPolicy.Equal(&prev.Neighbors[idx].ApplyPolicy) {
						softResetIn = true
					}
				}
			}
			for _, n := range prev.Neighbors {
				neigh := n
				if inNSlice(neigh, new.Neighbors) < 0 {
					bgpServer.DeleteNeighbor(&neigh)
				}
			}

			if !prev.Zebra.Config.Enabled && new.Zebra.Config.Enabled {
				bgpServer.StartZebraClient(&new.Zebra.Config)
			} else if prev.Zebra.Config.Enabled && !new.Zebra.Config.Enabled {
				log.Error("Removing zebra configuration is not supported. Configuration reload failed")
				continue
			} else if !prev.Zebra.Config.Equal(&new.Zebra.Config) {
				log.Error("Updating zebra configuration is not supported. Configuration reload failed")
				continue
			}

			if prev.Collector.Config.Url == "" && new.Collector.Config.Url != "" {
				bgpServer.StartCollector(&new.Collector.Config)
			} else if prev.Collector.Config.Url != "" && new.Collector.Config.Url == "" {
				log.Error("Removing collector configuration is not supported. Configuration reload failed")
				continue
			} else if !prev.Collector.Config.Equal(&new.Collector.Config) {
				log.Error("Updating collector configuration is not supported. Configuration reload failed")
				continue
			}

			inRPKISlice := func(n config.RpkiServer, b []config.RpkiServer) int {
				for i, nb := range b {
					if nb.Config.Address == n.Config.Address {
						return i
					}
				}
				return -1
			}

			for _, n := range new.RpkiServers {
				rpki := n
				if idx := inRPKISlice(rpki, prev.RpkiServers); idx < 0 {
					bgpServer.AddRpki(&rpki.Config)
				} else if !n.Equal(&prev.RpkiServers[idx]) {
					bgpServer.DeleteRpki(&rpki.Config)
					bgpServer.AddRpki(&rpki.Config)
				}
			}
			for _, n := range prev.RpkiServers {
				rpki := n
				if inRPKISlice(rpki, new.RpkiServers) < 0 {
					bgpServer.DeleteRpki(&rpki.Config)
				}
			}

			inBMPSlice := func(n config.BmpServer, b []config.BmpServer) int {
				for i, nb := range b {
					if nb.Config.Address == n.Config.Address {
						return i
					}
				}
				return -1
			}

			for _, n := range new.BmpServers {
				bmp := n
				if idx := inBMPSlice(bmp, prev.BmpServers); idx < 0 {
					bgpServer.AddBmp(&bmp.Config)
				} else if !n.Equal(&prev.BmpServers[idx]) {
					bgpServer.DeleteBmp(&bmp.Config)
					bgpServer.AddBmp(&bmp.Config)
				}
			}
			for _, n := range prev.BmpServers {
				bmp := n
				if inBMPSlice(bmp, new.BmpServers) < 0 {
					bgpServer.DeleteBmp(&bmp.Config)
				}
			}

			inMRTSlice := func(n config.Mrt, b []config.Mrt) int {
				for i, nb := range b {
					if nb.Config.FileName == n.Config.FileName {
						return i
					}
				}
				return -1
			}

			for _, n := range new.MrtDump {
				mrt := n
				if idx := inMRTSlice(mrt, prev.MrtDump); idx < 0 {
					bgpServer.EnableMrt(&mrt.Config)
				} else if !n.Equal(&prev.MrtDump[idx]) {
					bgpServer.DisableMrt(&mrt.Config)
					bgpServer.EnableMrt(&mrt.Config)
				}
			}
			for _, n := range prev.MrtDump {
				mrt := n
				if inMRTSlice(mrt, new.MrtDump) < 0 {
					bgpServer.DisableMrt(&mrt.Config)
				}
			}

			if softResetIn && count > 0 {
				bgpServer.SoftResetIn("", bgp.RouteFamily(0))
			}

			count += 1
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGKILL, syscall.SIGTERM:
				bgpServer.Shutdown()
			case syscall.SIGUSR1:
				runtime.GC()
				debug.FreeOSMemory()
			}
		}
	}
}
