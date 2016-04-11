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
	"encoding/json"
	"fmt"
	api "github.com/osrg/gobgp/api"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"strings"
)

func NewConfigCmd() *cobra.Command {
	var format string
	configCmd := &cobra.Command{
		Use: CMD_CONFIG,
		Run: func(cmd *cobra.Command, args []string) {
			f, y := api.Config_Format_value[strings.ToUpper(format)]
			if !y {
				exitWithError(fmt.Errorf("unknown format %s", format))
			}
			arg := &api.Config{
				Format: api.Config_Format(f),
			}
			config, e := client.GetRunningConfig(context.Background(), arg)
			if e != nil {
				exitWithError(e)
			}

			if globalOpts.Json {
				j, _ := json.Marshal(config)
				fmt.Println(string(j))
				return
			}
			fmt.Println(string(config.Data))
		},
	}
	configCmd.Flags().StringVarP(&format, "format", "t", "toml", "dump format")
	return configCmd
}
