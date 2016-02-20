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
	"net"
	"time"
)

func NewMonitorCmd() *cobra.Command {
	ribCmd := &cobra.Command{
		Use: CMD_RIB,
		Run: func(cmd *cobra.Command, args []string) {
			family, err := checkAddressFamily(bgp.RouteFamily(0))
			if err != nil {
				exitWithError(err)
			}
			arg := &gobgpapi.Arguments{
				Resource: gobgpapi.Resource_GLOBAL,
				Family:   uint32(family),
			}

			stream, err := client.MonitorBestChanged(context.Background(), arg)
			if err != nil {
				exitWithError(err)
			}
			for {
				d, err := stream.Recv()
				if err == io.EOF {
					break
				} else if err != nil {
					exitWithError(err)
				}
				p, err := ApiStruct2Path(d.Paths[0])
				if err != nil {
					exitWithError(err)
				}

				if globalOpts.Json {
					j, _ := json.Marshal(p)
					fmt.Println(string(j))
				} else {
					ShowRoute(p, false, false, false, true, false)
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
					fmt.Printf("[NEIGH] %s fsm: %s admin: %s\n", s.Conf.NeighborAddress, s.Info.BgpState, s.Info.AdminState)
				}
			}
		},
	}

	rpkiCmd := &cobra.Command{
		Use: CMD_RPKI,
		Run: func(cmd *cobra.Command, args []string) {
			stream, err := client.MonitorROAValidation(context.Background(), &gobgpapi.Arguments{})
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
					reason := "Update"
					if s.Reason == gobgpapi.ROAResult_WITHDRAW {
						reason = "Withdraw"
					} else if s.Reason == gobgpapi.ROAResult_PEER_DOWN {
						reason = "PeerDown"
					} else if s.Reason == gobgpapi.ROAResult_REVALIDATE {
						reason = "Revalidate"
					} else {
						reason = "Unknown"
					}
					aspath := &bgp.PathAttributeAsPath{}
					aspath.DecodeFromBytes(s.AspathAttr)
					fmt.Printf("[VALIDATION] Reason: %s, Peer: %s, Timestamp: %s, Prefix:%s, OriginAS:%d, ASPath:%s, Old:%s, New:%s", reason, s.Address, time.Unix(s.Timestamp, 0).String(), s.Prefix, s.OriginAs, aspath.String(), s.OldResult, s.NewResult)
					if len(s.Roas) == 0 {
						fmt.Printf("\n")
					} else {
						fmt.Printf(", ROAs:")
						for i, roa := range s.Roas {
							if i != 0 {
								fmt.Printf(",")
							}
							fmt.Printf(" [Source: %s, AS: %v, Prefix: %s, Prefixlen: %v, Maxlen: %v]", net.JoinHostPort(roa.Conf.Address, roa.Conf.RemotePort), roa.As, roa.Prefix, roa.Prefixlen, roa.Maxlen)
						}
						fmt.Printf("\n")
					}
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
			arg := &gobgpapi.Table{
				Type:   gobgpapi.Resource_ADJ_IN,
				Family: uint32(family),
				Name:   name,
			}

			stream, err := client.MonitorRib(context.Background(), arg)
			if err != nil {
				exitWithError(err)
			}
			for {
				d, err := stream.Recv()
				if err == io.EOF {
					break
				} else if err != nil {
					exitWithError(err)
				}
				p, err := ApiStruct2Path(d.Paths[0])
				if err != nil {
					exitWithError(err)
				}

				if globalOpts.Json {
					j, _ := json.Marshal(p)
					fmt.Println(string(j))
				} else {
					ShowRoute(p, false, false, false, true, false)
				}
			}

		},
	}
	adjInCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")

	monitorCmd := &cobra.Command{
		Use: CMD_MONITOR,
	}
	monitorCmd.AddCommand(globalCmd)
	monitorCmd.AddCommand(neighborCmd)
	monitorCmd.AddCommand(rpkiCmd)
	monitorCmd.AddCommand(adjInCmd)

	return monitorCmd
}
