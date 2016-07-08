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
	"github.com/osrg/gobgp/packet/bmp"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"net"
	"strconv"
)

func modBmpServer(cmdType string, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gobgp bmp %s <addr>[:<port>] [{pre|post|both}]", cmdType)
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
		pn, _ := strconv.Atoi(p)
		port = uint32(pn)
	}

	var err error
	switch cmdType {
	case CMD_ADD:
		policyType := api.AddBmpRequest_PRE
		if len(args) > 1 {
			switch args[1] {
			case "pre":
				policyType = api.AddBmpRequest_PRE
			case "post":
				policyType = api.AddBmpRequest_POST
			case "both":
				policyType = api.AddBmpRequest_BOTH
			default:
				return fmt.Errorf("invalid bmp policy type. valid type is {pre|post|both}")
			}
		}
		_, err = client.AddBmp(context.Background(), &api.AddBmpRequest{
			Address: address,
			Port:    port,
			Type:    policyType,
		})
	case CMD_DEL:
		_, err = client.DeleteBmp(context.Background(), &api.DeleteBmpRequest{
			Address: address,
			Port:    port,
		})
	}
	return err
}

func NewBmpCmd() *cobra.Command {

	bmpCmd := &cobra.Command{
		Use: CMD_BMP,
	}

	for _, w := range []string{CMD_ADD, CMD_DEL} {
		subcmd := &cobra.Command{
			Use: w,
			Run: func(cmd *cobra.Command, args []string) {
				err := modBmpServer(cmd.Use, args)
				if err != nil {
					exitWithError(err)
				}
			},
		}
		bmpCmd.AddCommand(subcmd)
	}

	return bmpCmd
}
