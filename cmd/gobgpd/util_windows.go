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
//go:build windows
// +build windows

package main

import (
	"errors"

	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/sirupsen/logrus"
)

func addSyslogHook(_, _ string) error {
	return errors.New("syslog is not supported on this OS")
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
