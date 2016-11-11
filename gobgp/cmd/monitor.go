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
	"io"
	"net"

	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
	"github.com/spf13/cobra"
)

func NewMonitorCmd() *cobra.Command {

	monitor := func(recver interface {
		Recv() (*table.Destination, error)
	}) {
		for {
			dst, err := recver.Recv()
			if err == io.EOF {
				break
			} else if err != nil {
				exitWithError(err)
			}
			if globalOpts.Json {
				j, _ := json.Marshal(dst.GetAllKnownPathList())
				fmt.Println(string(j))
			} else {
				ShowRoute(dst.GetAllKnownPathList(), false, false, false, true, false)
			}
		}
	}

	ribCmd := &cobra.Command{
		Use: CMD_RIB,
		Run: func(cmd *cobra.Command, args []string) {
			family, err := checkAddressFamily(bgp.RouteFamily(0))
			if err != nil {
				exitWithError(err)
			}
			recver, err := client.MonitorRIB(family)
			if err != nil {
				exitWithError(err)
			}
			monitor(recver)
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
			var names []string
			if len(args) > 0 {
				names = []string{args[0]}
			}
			stream, err := client.MonitorNeighborState(names...)
			if err != nil {
				exitWithError(err)
			}
			for {
				s, err := stream.Recv()
				if err == io.EOF {
					break
				} else if err != nil {
					exitWithError(err)
				}
				if globalOpts.Json {
					j, _ := json.Marshal(s)
					fmt.Println(string(j))
				} else {
					fmt.Printf("[NEIGH] %s fsm: %s admin: %s\n", s.Config.NeighborAddress, s.State.SessionState, s.State.AdminState)
				}
			}
		},
	}

	adjInCmd := &cobra.Command{
		Use: CMD_ADJ_IN,
		Run: func(cmd *cobra.Command, args []string) {
			name := ""
			if len(args) > 0 {
				remoteIP := net.ParseIP(args[0])
				if remoteIP == nil {
					exitWithError(fmt.Errorf("invalid ip address: %s", args[0]))
				}
				name = args[0]
			}
			family, err := checkAddressFamily(bgp.RouteFamily(0))
			if err != nil {
				exitWithError(err)
			}
			recver, err := client.MonitorAdjRIBIn(name, family)
			if err != nil {
				exitWithError(err)
			}
			monitor(recver)
		},
	}
	adjInCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")

	monitorCmd := &cobra.Command{
		Use: CMD_MONITOR,
	}
	monitorCmd.AddCommand(globalCmd)
	monitorCmd.AddCommand(neighborCmd)
	monitorCmd.AddCommand(adjInCmd)

	return monitorCmd
}
