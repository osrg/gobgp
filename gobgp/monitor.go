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
	"encoding/json"
	"fmt"
	"github.com/osrg/gobgp/api"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"io"
	"net"
	"os"
)

func NewMonitorCmd() *cobra.Command {
	ribCmd := &cobra.Command{
		Use: CMD_RIB,
		Run: func(cmd *cobra.Command, args []string) {
			rt, err := checkAddressFamily(net.IP{})
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			arg := &api.Arguments{
				Resource: api.Resource_GLOBAL,
				Af:       rt,
			}

			stream, err := client.MonitorBestChanged(context.Background(), arg)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			for {
				p, err := stream.Recv()
				if err == io.EOF {
					break
				} else if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				if globalOpts.Json {
					j, _ := json.Marshal(p)
					fmt.Println(string(j))
				} else {
					showRoute([]*api.Path{p}, false, false, true)
				}
			}

		},
	}

	globalCmd := &cobra.Command{
		Use: CMD_GLOBAL,
	}
	globalCmd.AddCommand(ribCmd)

	neighborCmd := &cobra.Command{
		Use: CMD_NEIGHBOR,
		Run: func(cmd *cobra.Command, args []string) {
			var arg *api.Arguments
			if len(args) > 0 {
				arg = &api.Arguments{
					Name: args[0],
				}
			} else {
				arg = &api.Arguments{}
			}

			stream, err := client.MonitorPeerState(context.Background(), arg)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			for {
				s, err := stream.Recv()
				if err == io.EOF {
					break
				} else if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				if globalOpts.Json {
					j, _ := json.Marshal(s)
					fmt.Println(string(j))
				} else {
					fmt.Printf("[NEIGH] %s fsm: %s admin: %s\n", s.Conf.RemoteIp, s.Info.BgpState, s.Info.AdminState)
				}
			}
		},
	}

	monitorCmd := &cobra.Command{
		Use: CMD_MONITOR,
	}
	monitorCmd.AddCommand(globalCmd)
	monitorCmd.AddCommand(neighborCmd)

	return monitorCmd
}
