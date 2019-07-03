// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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

	api "github.com/osrg/gobgp/api"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func modLogLevelServer(cmdType string, args []string) error {
	var level log.Level

	switch cmdType {
	case cmdDebug:
		level = log.DebugLevel
	case cmdError:
		level = log.ErrorLevel
	case cmdFatal:
		level = log.FatalLevel
	case cmdInfo:
		level = log.InfoLevel
	case cmdPanic:
		level = log.PanicLevel
	case cmdWarn:
		level = log.WarnLevel
	default:
		return fmt.Errorf("wrong log level: %s", cmdType)
	}
	_, err := client.SetLogLevel(ctx, &api.SetLogLevelRequest{Level: uint32(level)})
	return err
}

func newLogLevelCmd() *cobra.Command {

	llCmd := &cobra.Command{
		Use: cmdLoglevel,
	}

	for _, w := range []string{cmdDebug, cmdError, cmdFatal, cmdInfo, cmdPanic, cmdWarn} {
		subcmd := &cobra.Command{
			Use: w,
			Run: func(cmd *cobra.Command, args []string) {
				err := modLogLevelServer(cmd.Use, args)
				if err != nil {
					exitWithError(err)
				}
			},
		}
		llCmd.AddCommand(subcmd)
	}

	return llCmd
}
