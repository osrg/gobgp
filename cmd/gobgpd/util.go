// Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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

//go:build !windows
// +build !windows

package main

import (
	"log/syslog"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/sirupsen/logrus"
	lSyslog "github.com/sirupsen/logrus/hooks/syslog"
)

func init() {
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGUSR1)
		for range sigCh {
			runtime.GC()
			debug.FreeOSMemory()
		}
	}()
}

func addSyslogHook(host, facility string) error {
	dst := strings.SplitN(host, ":", 2)
	network := ""
	addr := ""
	if len(dst) == 2 {
		network = dst[0]
		addr = dst[1]
	}

	priority := syslog.Priority(0)
	switch facility {
	case "kern":
		priority = syslog.LOG_KERN
	case "user":
		priority = syslog.LOG_USER
	case "mail":
		priority = syslog.LOG_MAIL
	case "daemon":
		priority = syslog.LOG_DAEMON
	case "auth":
		priority = syslog.LOG_AUTH
	case "syslog":
		priority = syslog.LOG_SYSLOG
	case "lpr":
		priority = syslog.LOG_LPR
	case "news":
		priority = syslog.LOG_NEWS
	case "uucp":
		priority = syslog.LOG_UUCP
	case "cron":
		priority = syslog.LOG_CRON
	case "authpriv":
		priority = syslog.LOG_AUTHPRIV
	case "ftp":
		priority = syslog.LOG_FTP
	case "local0":
		priority = syslog.LOG_LOCAL0
	case "local1":
		priority = syslog.LOG_LOCAL1
	case "local2":
		priority = syslog.LOG_LOCAL2
	case "local3":
		priority = syslog.LOG_LOCAL3
	case "local4":
		priority = syslog.LOG_LOCAL4
	case "local5":
		priority = syslog.LOG_LOCAL5
	case "local6":
		priority = syslog.LOG_LOCAL6
	case "local7":
		priority = syslog.LOG_LOCAL7
	}

	hook, err := lSyslog.NewSyslogHook(network, addr, syslog.LOG_INFO|priority, "bgpd")
	if err != nil {
		return err
	}
	logger.AddHook(hook)
	return nil
}

type builtinLogger struct {
	logger *logrus.Logger
}

func (l *builtinLogger) Panic(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Panic(msg)
}

func (l *builtinLogger) Fatal(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Fatal(msg)
}

func (l *builtinLogger) Error(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Error(msg)
}

func (l *builtinLogger) Warn(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Warn(msg)
}

func (l *builtinLogger) Info(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Info(msg)
}

func (l *builtinLogger) Debug(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Debug(msg)
}

func (l *builtinLogger) SetLevel(level log.LogLevel) {
	l.logger.SetLevel(logrus.Level(level))
}

func (l *builtinLogger) GetLevel() log.LogLevel {
	return log.LogLevel(l.logger.GetLevel())
}
