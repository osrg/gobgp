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
	"github.com/jessevdk/go-flags"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/server"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	var opts struct {
		ConfigFile string `short:"f" long:"config-file" description:"specifying a config file"`
		LogLevel   string `short:"l" long:"log-level" description:"specifying log level"`
	}
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	switch opts.LogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
	log.SetOutput(os.Stderr)
	log.SetFormatter(&log.JSONFormatter{})

	if opts.ConfigFile == "" {
		opts.ConfigFile = "gobgpd.conf"
	}

	configCh := make(chan config.BgpType)
	reloadCh := make(chan bool)
	go config.ReadConfigfileServe(opts.ConfigFile, configCh, reloadCh)
	reloadCh <- true

	bgpServer := server.NewBgpServer(bgp.BGP_PORT)
	go bgpServer.Serve()

	// start Rest Server
	restServer := api.NewRestServer(api.REST_PORT, bgpServer.RestReqCh)
	go restServer.Serve()

	var bgpConfig *config.BgpType = nil
	for {
		select {
		case newConfig := <-configCh:
			var added []config.NeighborType
			var deleted []config.NeighborType

			if bgpConfig == nil {
				bgpServer.SetGlobalType(newConfig.Global)
				bgpConfig = &newConfig
				added = newConfig.NeighborList
				deleted = []config.NeighborType{}
			} else {
				_, added, deleted = config.UpdateConfig(bgpConfig, &newConfig)
			}

			for _, p := range added {
				log.Infof("Peer %v is added", p.NeighborAddress)
				bgpServer.PeerAdd(p)
			}
			for _, p := range deleted {
				log.Infof("Peer %v is deleted", p.NeighborAddress)
				bgpServer.PeerDelete(p)
			}
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				log.Info("relaod the config file")
				reloadCh <- true
			}
		}
	}
}
