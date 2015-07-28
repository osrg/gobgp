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
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"io"
	"sort"
	"net"
	"os"
)

func showRPKITable(args []string) error {
	af, err := checkAddressFamily(net.IP{})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	arg := &api.Arguments{
		Af: af,
	}
	stream, err := client.GetRPKI(context.Background(), arg)
	if err != nil {
		fmt.Println(err)
		return err
	}
	l := roas{}
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		l = append(l, r)
	}
	sort.Sort(l)
	var format string
	if af.Afi == bgp.AFI_IP {
		format = "%-18s %-6s %s\n"
	} else {
		format = "%-42s %-6s %s\n"
	}
	fmt.Printf(format, "Network", "Maxlen", "AS")
	for _, r := range l {
		fmt.Printf(format, fmt.Sprintf("%s/%d", r.Prefix, r.Prefixlen), fmt.Sprint(r.Maxlen), fmt.Sprint(r.Maxlen))
	}
	return nil
}

func NewRPKICmd() *cobra.Command {
	rpkiCmd := &cobra.Command{
		Use: CMD_RPKI,
		Run: func(cmd *cobra.Command, args []string) {
			showRPKITable(args)
		},
	}
	rpkiCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")
	return rpkiCmd
}
