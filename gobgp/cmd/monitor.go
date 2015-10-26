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

package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"io"
	"os"
)

func NewMonitorCmd() *cobra.Command {
	ribCmd := &cobra.Command{
		Use: CMD_RIB,
		Run: func(cmd *cobra.Command, args []string) {
			rf, err := checkAddressFamily(bgp.RouteFamily(0))
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			arg := &gobgpapi.Arguments{
				Resource: gobgpapi.Resource_GLOBAL,
				Rf:       uint32(rf),
			}

			stream, err := client.MonitorBestChanged(context.Background(), arg)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			for {
				d, err := stream.Recv()
				if err == io.EOF {
					break
				} else if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				p, err := ApiStruct2Path(d.Paths[0])
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}

				if globalOpts.Json {
					j, _ := json.Marshal(p)
					fmt.Println(string(j))
				} else {
					showRoute([]*Path{p}, false, false, false, true, false)
				}
			}

		},
	}
	ribCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")

	globalCmd := &cobra.Command{
		Use: CMD_GLOBAL,
	}
	globalCmd.AddCommand(ribCmd)

	neighborCmd := &cobra.Command{
		Use: CMD_NEIGHBOR,
		Run: func(cmd *cobra.Command, args []string) {
			var arg *gobgpapi.Arguments
			if len(args) > 0 {
				arg = &gobgpapi.Arguments{
					Name: args[0],
				}
			} else {
				arg = &gobgpapi.Arguments{}
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
					fmt.Printf("[NEIGH] %s fsm: %s admin: %s\n", s.Conf.NeighborAddress, s.Info.BgpState, s.Info.AdminState)
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
