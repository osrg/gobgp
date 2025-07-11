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

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
	"github.com/spf13/cobra"
)

func showStations() error {
	stream, err := client.ListBmp(ctx, &api.ListBmpRequest{})
	if err != nil {
		fmt.Println(err)
		return err
	}
	stations := make([]*api.ListBmpResponse_BmpStation, 0)
	for {
		rsp, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		stations = append(stations, rsp.Station)
	}
	format := "%-23s %-6s %-10s\n"
	fmt.Printf(format, "Session", "State", "Uptime")
	for _, r := range stations {
		s := "Down"
		uptime := "Never"
		if r.State.Uptime.AsTime().Unix() != 0 {
			uptime = fmt.Sprint(formatTimedelta(r.State.Uptime.AsTime()))
			if r.State.Uptime.AsTime().After(r.State.Downtime.AsTime()) {
				s = "Up"
			} else {
				uptime = fmt.Sprint(formatTimedelta(r.State.Downtime.AsTime()))
				s = "Down"
			}
		}
		fmt.Printf(format, net.JoinHostPort(r.Conf.Address, fmt.Sprintf("%d", r.Conf.Port)), s, uptime)
	}

	return nil
}

func modBmpServer(cmdType string, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gobgp bmp %s <addr>[:<port>] [{pre|post|both|local-rib|all}]", cmdType)
	}

	var address string
	port := uint32(bmp.BMP_DEFAULT_PORT)
	if host, p, err := net.SplitHostPort(args[0]); err != nil {
		ip := net.ParseIP(args[0])
		if ip == nil {
			return nil
		}
		address = args[0]
	} else {
		address = host
		// Note: BmpServerConfig.Port is uint32 type, but the TCP/UDP port is
		// 16-bit length.
		pn, _ := strconv.ParseUint(p, 10, 16)
		port = uint32(pn)
	}

	var err error
	switch cmdType {
	case cmdAdd:
		statisticsTimeout := 0
		if bmpOpts.StatisticsTimeout >= 0 && bmpOpts.StatisticsTimeout <= 65535 {
			statisticsTimeout = bmpOpts.StatisticsTimeout
		} else {
			return fmt.Errorf("invalid statistics-timeout value. it must be in the range 0-65535. default value is 0 and means disabled")
		}

		policyType := api.AddBmpRequest_MONITORING_POLICY_PRE
		if len(args) > 1 {
			switch args[1] {
			case "pre":
				policyType = api.AddBmpRequest_MONITORING_POLICY_PRE
			case "post":
				policyType = api.AddBmpRequest_MONITORING_POLICY_POST
			case "both":
				policyType = api.AddBmpRequest_MONITORING_POLICY_BOTH
			case "local-rib":
				policyType = api.AddBmpRequest_MONITORING_POLICY_LOCAL
			case "all":
				policyType = api.AddBmpRequest_MONITORING_POLICY_ALL
			default:
				return fmt.Errorf("invalid bmp policy type. valid type is {pre|post|both|local-rib|all}")
			}
		}
		_, err = client.AddBmp(ctx, &api.AddBmpRequest{
			Address:           address,
			Port:              port,
			Policy:            policyType,
			StatisticsTimeout: int32(statisticsTimeout),
		})
	case cmdDel:
		_, err = client.DeleteBmp(ctx, &api.DeleteBmpRequest{
			Address: address,
			Port:    port,
		})
	}
	return err
}

func newBmpCmd() *cobra.Command {
	bmpCmd := &cobra.Command{
		Use: cmdBMP,
		RunE: func(cmd *cobra.Command, args []string) error {
			return showStations()
		},
	}

	for _, w := range []string{cmdAdd, cmdDel} {
		subcmd := &cobra.Command{
			Use: w,
			Run: func(cmd *cobra.Command, args []string) {
				err := modBmpServer(cmd.Use, args)
				if err != nil {
					exitWithError(err)
				}
			},
		}
		if w == cmdAdd {
			subcmd.PersistentFlags().IntVarP(&bmpOpts.StatisticsTimeout, "statistics-timeout", "s", 0, "Timeout of statistics report")
		}
		bmpCmd.AddCommand(subcmd)
	}

	return bmpCmd
}
