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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/getsentry/sentry-go"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/jessevdk/go-flags"
	"github.com/kr/pretty"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/osrg/gobgp/v3/internal/pkg/version"
	"github.com/osrg/gobgp/v3/pkg/config"
	"github.com/osrg/gobgp/v3/pkg/metrics"
	"github.com/osrg/gobgp/v3/pkg/server"
)

var logger = logrus.New()

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	var opts struct {
		ConfigFile        string  `short:"f" long:"config-file" description:"specifying a config file"`
		ConfigType        string  `short:"t" long:"config-type" description:"specifying config type (toml, yaml, json)" default:"toml"`
		ConfigAutoReload  bool    `short:"a" long:"config-auto-reload" description:"activate config auto reload on changes"`
		ConfigStrict      bool    `long:"config-strict" description:"make any config error fatal"`
		LogLevel          string  `short:"l" long:"log-level" description:"specifying log level"`
		LogPlain          bool    `short:"p" long:"log-plain" description:"use plain format for logging (json by default)"`
		UseSyslog         string  `short:"s" long:"syslog" description:"use syslogd"`
		Facility          string  `long:"syslog-facility" description:"specify syslog facility"`
		DisableStdlog     bool    `long:"disable-stdlog" description:"disable standard logging"`
		CPUs              int     `long:"cpus" description:"specify the number of CPUs to be used"`
		GrpcHosts         string  `long:"api-hosts" description:"specify the hosts that gobgpd listens on" default:":50051"`
		GracefulRestart   bool    `short:"r" long:"graceful-restart" description:"flag restart-state in graceful-restart capability"`
		Dry               bool    `short:"d" long:"dry-run" description:"check configuration"`
		PProfHost         string  `long:"pprof-host" description:"specify the host that gobgpd listens on for pprof and metrics" default:"localhost:6060"`
		PProfDisable      bool    `long:"pprof-disable" description:"disable pprof profiling"`
		MetricsPath       string  `long:"metrics-path" description:"specify path for prometheus metrics, empty value disables them" default:"/metrics"`
		UseSdNotify       bool    `long:"sdnotify" description:"use sd_notify protocol"`
		TLS               bool    `long:"tls" description:"enable TLS authentication for gRPC API"`
		TLSCertFile       string  `long:"tls-cert-file" description:"The TLS cert file"`
		TLSKeyFile        string  `long:"tls-key-file" description:"The TLS key file"`
		TLSClientCAFile   string  `long:"tls-client-ca-file" description:"Optional TLS client CA file to authenticate clients against"`
		Version           bool    `long:"version" description:"show version number"`
		SentryDSN         string  `long:"sentry-dsn" description:"Sentry DSN" default:""`
		SentryEnvironment string  `long:"sentry-environment" description:"Sentry environment" default:"development"`
		SentrySampleRate  float64 `long:"sentry-sample-rate" description:"Sentry traces sample rate" default:"1.0"`
		SentryDebug       bool    `long:"sentry-debug" description:"Sentry debug mode"`
	}
	_, err := flags.Parse(&opts)
	if err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	if opts.Version {
		fmt.Println("gobgpd version", version.Version())
		os.Exit(0)
	}

	// if Sentry DSN is provided, initialize Sentry
	// We would like to capture errors and exceptions, but not traces
	if opts.SentryDSN != "" {
		logger.Debugf("Initializing Sentry, Env: %s, Release: %s, SampleRate: %f, Debug: %t",
			opts.SentryEnvironment, version.Version(), opts.SentrySampleRate, opts.SentryDebug)
		err := sentry.Init(sentry.ClientOptions{
			Dsn:         opts.SentryDSN,
			SampleRate:  opts.SentrySampleRate,
			Debug:       opts.SentryDebug,
			Release:     version.Version(),
			Environment: opts.SentryEnvironment,
			// Disable tracing as it's not relevant for now
			EnableTracing:    false,
			TracesSampleRate: 0.0,
		})
		if err != nil {
			logger.Fatalf("sentry.Init: %s", err)
		}
		// Flush buffered events before the program terminates.
		defer sentry.Flush(2 * time.Second)

		if opts.SentryDebug {
			sentry.CaptureMessage("Sentry debug mode enabled on gobgpd")
		}
	}

	if opts.CPUs == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	} else {
		if runtime.NumCPU() < opts.CPUs {
			logger.Errorf("Only %d CPUs are available but %d is specified", runtime.NumCPU(), opts.CPUs)
			os.Exit(1)
		}
		runtime.GOMAXPROCS(opts.CPUs)
	}

	httpMux := http.NewServeMux()
	if !opts.PProfDisable {
		httpMux.HandleFunc("/debug/pprof/", pprof.Index)
		httpMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		httpMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		httpMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		httpMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	if opts.MetricsPath != "" {
		httpMux.Handle(opts.MetricsPath, promhttp.Handler())
	}
	if !opts.PProfDisable || opts.MetricsPath != "" {
		go func() {
			logger.Println(http.ListenAndServe(opts.PProfHost, httpMux))
		}()
	}

	switch opts.LogLevel {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "info":
		logger.SetLevel(logrus.InfoLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	if opts.DisableStdlog {
		logger.SetOutput(io.Discard)
	} else {
		logger.SetOutput(os.Stdout)
	}

	if opts.UseSyslog != "" {
		if err := addSyslogHook(opts.UseSyslog, opts.Facility); err != nil {
			logger.Error("Unable to connect to syslog daemon, ", opts.UseSyslog)
		}
	}

	if opts.LogPlain {
		if opts.DisableStdlog {
			logger.SetFormatter(&logrus.TextFormatter{
				DisableColors: true,
			})
		}
	} else {
		logger.SetFormatter(&logrus.JSONFormatter{})
	}

	if opts.Dry {
		c, err := config.ReadConfigFile(opts.ConfigFile, opts.ConfigType)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"Topic": "Config",
				"Error": err,
			}).Fatalf("Can't read config file %s", opts.ConfigFile)
		}
		logger.WithFields(logrus.Fields{
			"Topic": "Config",
		}).Info("Finished reading the config file")
		if opts.LogLevel == "debug" {
			pretty.Println(c)
		}
		os.Exit(0)
	}

	maxSize := 256 << 20
	grpcOpts := []grpc.ServerOption{grpc.MaxRecvMsgSize(maxSize), grpc.MaxSendMsgSize(maxSize)}
	if opts.TLS {
		// server cert/key
		cert, err := tls.LoadX509KeyPair(opts.TLSCertFile, opts.TLSKeyFile)
		if err != nil {
			logger.Fatalf("Failed to load server certificate/key pair: %v", err)
		}
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

		// client CA
		if len(opts.TLSClientCAFile) != 0 {
			tlsConfig.ClientCAs = x509.NewCertPool()
			pemCerts, err := os.ReadFile(opts.TLSClientCAFile)
			if err != nil {
				logger.Fatalf("Failed to load client CA certificates from %q: %v", opts.TLSClientCAFile, err)
			}
			if ok := tlsConfig.ClientCAs.AppendCertsFromPEM(pemCerts); !ok {
				logger.Fatalf("No valid client CA certificates in %q", opts.TLSClientCAFile)
			}
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		creds := credentials.NewTLS(tlsConfig)
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
	}

	if opts.MetricsPath != "" {
		grpcOpts = append(
			grpcOpts,
			grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
			grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
		)
	}

	logger.Info("gobgpd started")
	bgpLogger := &builtinLogger{logger: logger, cfgStrict: opts.ConfigStrict}
	fsmTimingCollector := metrics.NewFSMTimingsCollector()
	bgpServer := server.NewBgpServer(
		server.GrpcListenAddress(opts.GrpcHosts),
		server.GrpcOption(grpcOpts),
		server.LoggerOption(bgpLogger),
		server.TimingHookOption(fsmTimingCollector))
	prometheus.MustRegister(metrics.NewBgpCollector(bgpServer))
	prometheus.MustRegister(fsmTimingCollector)
	go bgpServer.Serve()

	if opts.UseSdNotify {
		if status, err := daemon.SdNotify(false, daemon.SdNotifyReady); !status {
			if err != nil {
				logger.Warnf("Failed to send notification via sd_notify(): %s", err)
			} else {
				logger.Warnf("The socket sd_notify() isn't available")
			}
		}
	}

	if opts.ConfigFile == "" {
		<-sigCh
		stopServer(bgpServer, opts.UseSdNotify)
		return
	}

	signal.Notify(sigCh, syscall.SIGHUP)

	initialConfig, err := config.ReadConfigFile(opts.ConfigFile, opts.ConfigType)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"Topic": "Config",
			"Error": err,
		}).Fatalf("Can't read config file %s", opts.ConfigFile)
	}
	logger.WithFields(logrus.Fields{
		"Topic": "Config",
	}).Info("Finished reading the config file")

	currentConfig, err := config.InitialConfig(context.Background(), bgpServer, initialConfig, opts.GracefulRestart)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"Topic": "Config",
			"Error": err,
		}).Fatalf("Failed to apply initial configuration %s", opts.ConfigFile)
	}

	if opts.ConfigAutoReload {
		logger.WithFields(logrus.Fields{
			"Topic": "Config",
		}).Info("Watching for config changes to trigger auto-reload")

		// Writing to the config may trigger many events in quick successions
		// To prevent abusive reloads, we ignore any event in a 100ms window
		rateLimiter := rate.Sometimes{Interval: 100 * time.Millisecond}

		config.WatchConfigFile(opts.ConfigFile, opts.ConfigType, func() {
			rateLimiter.Do(func() {
				logger.WithFields(logrus.Fields{
					"Topic": "Config",
				}).Info("Config changes detected, reloading configuration")

				sigCh <- syscall.SIGHUP
			})
		})
	}

	// Avoid crashing gobgpd on reload - it shouldn't flush policy entirely, so it's safe to continue to run
	bgpLogger.cfgStrict = false
	for sig := range sigCh {
		if sig != syscall.SIGHUP {
			stopServer(bgpServer, opts.UseSdNotify)
			return
		}

		logger.WithFields(logrus.Fields{
			"Topic": "Config",
		}).Info("Reload the config file")
		newConfig, err := config.ReadConfigFile(opts.ConfigFile, opts.ConfigType)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"Topic": "Config",
				"Error": err,
			}).Warningf("Can't read config file %s", opts.ConfigFile)
			continue
		}

		currentConfig, err = config.UpdateConfig(context.Background(), bgpServer, currentConfig, newConfig)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Topic": "Config",
				"Error": err,
			}).Warningf("Failed to update config %s", opts.ConfigFile)
			continue
		}
	}
}

func stopServer(bgpServer *server.BgpServer, useSdNotify bool) {
	logger.Info("stopping gobgpd server")

	bgpServer.Stop()
	if useSdNotify {
		daemon.SdNotify(false, daemon.SdNotifyStopping)
	}
}
