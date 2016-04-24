// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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
	"github.com/osrg/gobgp/config"
	ops "github.com/osrg/gobgp/openswitch"
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
		Ops             bool   `long:"openswitch" description:"openswitch mode"`
		GrpcHosts       string `long:"api-hosts" description:"specify the hosts that gobgpd listens on" default:":50051"`
		GracefulRestart bool   `short:"r" long:"graceful-restart" description:"flag restart-state in graceful-restart capability"`
		Dry             bool   `short:"d" long:"dry-run" description:"check configuration"`
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

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

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
	grpcServer := server.NewGrpcServer(opts.GrpcHosts, bgpServer.GrpcReqCh)
	go func() {
		if err := grpcServer.Serve(); err != nil {
			log.Fatalf("failed to listen grpc port: %s", err)
		}
	}()

	if opts.Ops {
		m, err := ops.NewOpsManager(bgpServer.GrpcReqCh)
		if err != nil {
			log.Errorf("Failed to start ops config manager: %s", err)
			os.Exit(1)
		}
		log.Info("Coordination with OpenSwitch")
		m.Serve()
	} else if opts.ConfigFile != "" {
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
				if err := bgpServer.SetGlobalType(newConfig.Global); err != nil {
					log.Fatalf("failed to set global config: %s", err)
				}
				if err := bgpServer.SetRpkiConfig(newConfig.RpkiServers); err != nil {
					log.Fatalf("failed to set rpki config: %s", err)
				}
				if err := bgpServer.SetBmpConfig(newConfig.BmpServers); err != nil {
					log.Fatalf("failed to set bmp config: %s", err)
				}
				if err := bgpServer.SetMrtConfig(newConfig.MrtDump); err != nil {
					log.Fatalf("failed to set mrt config: %s", err)
				}
				p := config.ConfigSetToRoutingPolicy(newConfig)
				if err := bgpServer.SetRoutingPolicy(*p); err != nil {
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
				c = newConfig
			}

			for _, p := range added {
				log.Infof("Peer %v is added", p.Config.NeighborAddress)
				bgpServer.PeerAdd(p)
			}
			for _, p := range deleted {
				log.Infof("Peer %v is deleted", p.Config.NeighborAddress)
				bgpServer.PeerDelete(p)
			}
			for _, p := range updated {
				log.Infof("Peer %v is updated", p.Config.NeighborAddress)
				u, _ := bgpServer.PeerUpdate(p)
				updatePolicy = updatePolicy || u
			}

			if updatePolicy {
				// TODO: we want to apply the new policies to the existing
				// routes here. Sending SOFT_RESET_IN to all the peers works
				// for the change of in and import policies. SOFT_RESET_OUT is
				// necessary for the export policy but we can't blindly
				// execute SOFT_RESET_OUT because we unnecessarily advertize
				// the existing routes. Needs to investigate the changes of
				// policies and handle only affected peers.
				ch := make(chan *server.GrpcResponse)
				bgpServer.GrpcReqCh <- &server.GrpcRequest{
					RequestType: server.REQ_NEIGHBOR_SOFT_RESET_IN,
					Name:        "all",
					ResponseCh:  ch,
				}
				<-ch
			}
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
