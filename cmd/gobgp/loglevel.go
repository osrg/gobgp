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

	api "github.com/osrg/gobgp/v3/api"
	"github.com/spf13/cobra"
)

func modLogLevelServer(cmdType string, args []string) error {
	var level api.SetLogLevelRequest_Level

	switch cmdType {
	case cmdPanic:
		level = api.SetLogLevelRequest_PANIC
	case cmdFatal:
		level = api.SetLogLevelRequest_FATAL
	case cmdError:
		level = api.SetLogLevelRequest_ERROR
	case cmdWarn:
		level = api.SetLogLevelRequest_WARN
	case cmdInfo:
		level = api.SetLogLevelRequest_INFO
	case cmdDebug:
		level = api.SetLogLevelRequest_DEBUG
	case cmdTrace:
		level = api.SetLogLevelRequest_TRACE
	default:
		return fmt.Errorf("invalid log level: %s", cmdType)
	}
	_, err := client.SetLogLevel(ctx, &api.SetLogLevelRequest{Level: level})
	return err
}

func newLogLevelCmd() *cobra.Command {
	logLevelCmd := &cobra.Command{
		Use: cmdLogLevel,
	}
	cmds := []string{
		cmdPanic,
		cmdFatal,
		cmdError,
		cmdWarn,
		cmdInfo,
		cmdDebug,
		cmdTrace,
	}

	for _, cmd := range cmds {
		subCmd := &cobra.Command{
			Use: cmd,
			Run: func(cmd *cobra.Command, args []string) {
				if err := modLogLevelServer(cmd.Use, args); err != nil {
					exitWithError(err)
				}
			},
		}
		logLevelCmd.AddCommand(subCmd)
	}
	return logLevelCmd
}
