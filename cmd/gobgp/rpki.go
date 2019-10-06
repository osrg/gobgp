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
	"io"
	"net"
	"strconv"

	"github.com/golang/protobuf/ptypes"
	api "github.com/osrg/gobgp/api"
	"github.com/spf13/cobra"
)

func showRPKIServer(args []string) error {
	servers := make([]*api.Rpki, 0)
	stream, err := client.ListRpki(ctx, &api.ListRpkiRequest{})
	if err != nil {
		fmt.Println(err)
		return err
	}
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		servers = append(servers, r.Server)
	}
	if len(args) == 0 {
		format := "%-23s %-6s %-10s %s\n"
		fmt.Printf(format, "Session", "State", "Uptime", "#IPv4/IPv6 records")
		for _, r := range servers {
			s := "Down"
			uptime := "never"
			if r.State.Up {
				s = "Up"
				t, _ := ptypes.Timestamp(r.State.Uptime)
				uptime = fmt.Sprint(formatTimedelta(t))
			}

			fmt.Printf(format, net.JoinHostPort(r.Conf.Address, fmt.Sprintf("%d", r.Conf.RemotePort)), s, uptime, fmt.Sprintf("%d/%d", r.State.RecordIpv4, r.State.RecordIpv6))
		}
		return nil
	}

	for _, r := range servers {
		if r.Conf.Address == args[0] {
			up := "Down"
			if r.State.Up {
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
	return nil
}

func showRPKITable(args []string) error {
	family, err := checkAddressFamily(ipv4UC)
	if err != nil {
		exitWithError(err)
	}
	stream, err := client.ListRpkiTable(ctx, &api.ListRpkiTableRequest{
		Family: family,
	})
	if err != nil {
		exitWithError(err)
	}
	roas := make([]*api.Roa, 0)
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			exitWithError(err)
		}
		roas = append(roas, r.Roa)
	}

	var format string
	if family.Afi == api.Family_AFI_IP {
		format = "%-18s %-6s %-10s %s\n"
	} else {
		format = "%-42s %-6s %-10s %s\n"
	}
	fmt.Printf(format, "Network", "Maxlen", "AS", "Server")
	for _, r := range roas {
		if len(args) > 0 && args[0] != r.Conf.Address {
			continue
		}
		bits := net.IPv4len * 8
		if family.Afi == api.Family_AFI_IP6 {
			bits = net.IPv6len * 8
		}
		n := net.IPNet{
			IP:   net.ParseIP(r.GetPrefix()),
			Mask: net.CIDRMask(int(r.GetPrefixlen()), bits),
		}
		fmt.Printf(format, n.String(), fmt.Sprint(r.Maxlen), fmt.Sprint(r.As), net.JoinHostPort(r.Conf.Address, strconv.Itoa(int(r.Conf.RemotePort))))
	}
	return nil
}

func newRPKICmd() *cobra.Command {
	rpkiCmd := &cobra.Command{
		Use: cmdRPKI,
	}

	serverCmd := &cobra.Command{
		Use: cmdRPKIServer,
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
				_, err = client.AddRpki(ctx, &api.AddRpkiRequest{
					Address: addr.String(),
					Port:    323,
				})
			case "reset", "softreset":
				_, err = client.ResetRpki(ctx, &api.ResetRpkiRequest{
					Address: addr.String(),
					Soft: func() bool {
						return args[1] != "reset"
					}(),
				})
			case "enable":
				_, err = client.EnableRpki(ctx, &api.EnableRpkiRequest{
					Address: addr.String(),
				})
			case "disable":
				_, err = client.DisableRpki(ctx, &api.DisableRpkiRequest{
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
		Use: cmdRPKITable,
		Run: func(cmd *cobra.Command, args []string) {
			showRPKITable(args)
		},
	}
	tableCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")
	rpkiCmd.AddCommand(tableCmd)
	return rpkiCmd
}
