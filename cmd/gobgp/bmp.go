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
	"net"
	"strconv"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/pkg/packet/bmp"
	"github.com/spf13/cobra"
)

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

		policyType := api.AddBmpRequest_PRE
		if len(args) > 1 {
			switch args[1] {
			case "post":
				policyType = api.AddBmpRequest_POST
			case "both":
				policyType = api.AddBmpRequest_BOTH
			case "local-rib":
				policyType = api.AddBmpRequest_LOCAL
			case "all":
				policyType = api.AddBmpRequest_ALL
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
