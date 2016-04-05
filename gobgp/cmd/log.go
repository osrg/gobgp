// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

package cmd

import (
	"fmt"
	api "github.com/osrg/gobgp/api"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"strings"
)

func NewLogCmd() *cobra.Command {
	logCmd := &cobra.Command{
		Use: CMD_LOG,
		Run: func(cmd *cobra.Command, args []string) {
			err := fmt.Errorf("gobgp log { info | debug | warn | error } <message>")
			if len(args) < 2 {
				exitWithError(err)
			}
			lvl, y := api.LogLevel_value[strings.ToUpper(args[0])]
			if !y {
				exitWithError(err)
			}
			_, err = client.Log(context.Background(), &api.LogArguments{
				Level:   api.LogLevel(lvl),
				Message: args[1],
			})
			if err != nil {
				exitWithError(err)
			}
		},
	}
	return logCmd
}
