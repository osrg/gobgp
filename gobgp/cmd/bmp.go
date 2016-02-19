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
	"github.com/osrg/gobgp/packet"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"net"
	"strconv"
)

func modBmpServer(cmdType string, args []string) error {
	arg := &api.ModBmpArguments{}
	if len(args) < 1 {
		return fmt.Errorf("usage: gobgp bmp %s <addr>[:<port>] [{pre|post|both}]", cmdType)
	}

	host, port, err := net.SplitHostPort(args[0])
	if err != nil {
		ip := net.ParseIP(args[0])
		if ip == nil {
			return nil
		}
		arg.Address = args[0]
		arg.Port = bgp.BMP_DEFAULT_PORT
	} else {
		arg.Address = host
		p, _ := strconv.Atoi(port)
		arg.Port = uint32(p)
	}

	switch cmdType {
	case CMD_ADD:
		arg.Operation = api.Operation_ADD
		if len(args) > 1 {
			switch args[1] {
			case "pre":
				arg.Type = api.ModBmpArguments_PRE
			case "post":
				arg.Type = api.ModBmpArguments_POST
			case "both":
				arg.Type = api.ModBmpArguments_BOTH
			default:
				return fmt.Errorf("invalid bmp policy type. valid type is {pre|post|both}")
			}
		} else {
			arg.Type = api.ModBmpArguments_PRE
		}
	case CMD_DEL:
		arg.Operation = api.Operation_DEL
	}
	_, err = client.ModBmp(context.Background(), arg)
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
