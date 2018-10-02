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
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/jessevdk/go-flags"
	"github.com/kr/pretty"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/pkg/config"
	"github.com/osrg/gobgp/pkg/server"
)

var version = "master"

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

	if opts.Dry {
		c := config.ReadConfigFile(opts.ConfigFile, opts.ConfigType)
		if opts.LogLevel == "debug" {
			pretty.Println(c)
		}
		os.Exit(0)
	}

	log.Info("gobgpd started")
	bgpServer := server.NewBgpServer()
	go bgpServer.Serve()

	var grpcOpts []grpc.ServerOption
	if opts.TLS {
		creds, err := credentials.NewServerTLSFromFile(opts.TLSCertFile, opts.TLSKeyFile)
		if err != nil {
			log.Fatalf("Failed to generate credentials: %v", err)
		}
		grpcOpts = []grpc.ServerOption{grpc.Creds(creds)}
	}
	// start grpc Server
	apiServer := server.NewServer(bgpServer, grpc.NewServer(grpcOpts...), opts.GrpcHosts)
	go func() {
		if err := apiServer.Serve(); err != nil {
			log.Fatalf("failed to listen grpc port: %s", err)
		}
	}()

	if opts.ConfigFile == "" {
		<-sigCh
		apiServer.StopBgp(context.Background(), &api.StopBgpRequest{})
		return
	}

	configCh := config.ReadConfigFileOnSighup(opts.ConfigFile, opts.ConfigType)
	initialConfig := <-configCh
	c := config.ApplyInitialConfig(initialConfig, opts.GracefulRestart, apiServer)

	for {
		select {
		case <-sigCh:
			apiServer.StopBgp(context.Background(), &api.StopBgpRequest{})
			return
		case newConfig := <-configCh:
			c = config.UpdateConfig(c, newConfig, apiServer)
		}
	}
}
