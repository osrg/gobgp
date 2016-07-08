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
	"fmt"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"net"
	"time"
)

func showRPKIServer(args []string) error {
	rsp, err := client.GetRpki(context.Background(), &api.GetRpkiRequest{})
	if err != nil {
		fmt.Println(err)
		return err
	}
	if len(args) == 0 {
		format := "%-23s %-6s %-10s %s\n"
		fmt.Printf(format, "Session", "State", "Uptime", "#IPv4/IPv6 records")
		for _, r := range rsp.Servers {
			s := "Down"
			uptime := "never"
			if r.State.Up == true {
				s = "Up"
				uptime = fmt.Sprint(formatTimedelta(int64(time.Now().Sub(time.Unix(r.State.Uptime, 0)).Seconds())))
			}

			fmt.Printf(format, net.JoinHostPort(r.Conf.Address, r.Conf.RemotePort), s, uptime, fmt.Sprintf("%d/%d", r.State.RecordIpv4, r.State.RecordIpv6))
		}
	} else {
		for _, r := range rsp.Servers {
			if r.Conf.Address == args[0] {
				up := "Down"
				if r.State.Up == true {
					up = "Up"
				}
				fmt.Printf("Session: %s, State: %s\n", r.Conf.Address, up)
				fmt.Println("  Port:", r.Conf.RemotePort)
				fmt.Println("  Serial:", r.State.Serial)
				fmt.Printf("  Prefix: %d/%d\n", r.State.PrefixIpv4, r.State.PrefixIpv6)
				fmt.Printf("  Record: %d/%d\n", r.State.RecordIpv4, r.State.RecordIpv6)
				fmt.Println("  Message statistics:")
				fmt.Printf("    Receivedv4:    %10d\n", r.State.ReceivedIpv4)
				fmt.Printf("    Receivedv6:    %10d\n", r.State.ReceivedIpv6)
				fmt.Printf("    SerialNotify:  %10d\n", r.State.SerialNotify)
				fmt.Printf("    CacheReset:    %10d\n", r.State.CacheReset)
				fmt.Printf("    CacheResponse: %10d\n", r.State.CacheResponse)
				fmt.Printf("    EndOfData:     %10d\n", r.State.EndOfData)
				fmt.Printf("    Error:         %10d\n", r.State.Error)
				fmt.Printf("    SerialQuery:   %10d\n", r.State.SerialQuery)
				fmt.Printf("    ResetQuery:    %10d\n", r.State.ResetQuery)
			}
		}
	}
	return nil
}

func showRPKITable(args []string) error {
	family, err := checkAddressFamily(bgp.RouteFamily(0))
	if err != nil {
		exitWithError(err)
	}
	arg := &api.GetRoaRequest{
		Family: uint32(family),
	}
	rsp, err := client.GetRoa(context.Background(), arg)
	if err != nil {
		fmt.Println(err)
		return err
	}

	var format string
	afi, _ := bgp.RouteFamilyToAfiSafi(family)
	if afi == bgp.AFI_IP {
		format = "%-18s %-6s %-10s %s\n"
	} else {
		format = "%-42s %-6s %-10s %s\n"
	}
	fmt.Printf(format, "Network", "Maxlen", "AS", "Server")
	for _, r := range rsp.Roas {
		if len(args) > 0 && args[0] != r.Conf.Address {
			continue
		}

		server := net.JoinHostPort(r.Conf.Address, r.Conf.RemotePort)
		fmt.Printf(format, fmt.Sprintf("%s/%d", r.Prefix, r.Prefixlen), fmt.Sprint(r.Maxlen), fmt.Sprint(r.As), server)
	}
	return nil
}

func NewRPKICmd() *cobra.Command {
	rpkiCmd := &cobra.Command{
		Use: CMD_RPKI,
	}

	serverCmd := &cobra.Command{
		Use: CMD_RPKI_SERVER,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 || len(args) == 1 {
				showRPKIServer(args)
				return
			} else if len(args) != 2 {
				exitWithError(fmt.Errorf("usage: gobgp rpki server <ip address> [reset|softreset|enable]"))
			}
			addr := net.ParseIP(args[0])
			if addr == nil {
				exitWithError(fmt.Errorf("invalid ip address: %s", args[0]))
			}
			var err error
			switch args[1] {
			case "add":
				_, err = client.AddRpki(context.Background(), &api.AddRpkiRequest{
					Address: addr.String(),
					Port:    323,
				})
			case "reset":
				_, err = client.ResetRpki(context.Background(), &api.ResetRpkiRequest{
					Address: addr.String(),
				})
			case "softreset":
				_, err = client.SoftResetRpki(context.Background(), &api.SoftResetRpkiRequest{
					Address: addr.String(),
				})
			case "enable":
				_, err = client.EnableRpki(context.Background(), &api.EnableRpkiRequest{
					Address: addr.String(),
				})
			case "disable":
				_, err = client.DisableRpki(context.Background(), &api.DisableRpkiRequest{
					Address: addr.String(),
				})
			default:
				exitWithError(fmt.Errorf("unknown operation: %s", args[1]))
			}
			if err != nil {
				exitWithError(err)
			}
		},
	}
	rpkiCmd.AddCommand(serverCmd)

	tableCmd := &cobra.Command{
		Use: CMD_RPKI_TABLE,
		Run: func(cmd *cobra.Command, args []string) {
			showRPKITable(args)
		},
	}
	tableCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")

	validateCmd := &cobra.Command{
		Use: "validate",
		Run: func(cmd *cobra.Command, args []string) {
			arg := &api.ValidateRibRequest{}
			if len(args) == 1 {
				arg.Prefix = args[0]
			}
			client.ValidateRib(context.Background(), arg)
		},
	}
	rpkiCmd.AddCommand(validateCmd)

	rpkiCmd.AddCommand(tableCmd)
	return rpkiCmd
}
