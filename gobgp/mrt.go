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
	"bytes"
	"fmt"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func printMrtMsgs(data []byte) {
	buffer := bytes.NewBuffer(data)

	for buffer.Len() > bgp.MRT_COMMON_HEADER_LEN {
		buf := make([]byte, bgp.MRT_COMMON_HEADER_LEN)
		_, err := buffer.Read(buf)
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println("failed to read:", err)
			os.Exit(1)
		}

		h := &bgp.MRTHeader{}
		err = h.DecodeFromBytes(buf)
		if err != nil {
			fmt.Println("failed to parse")
			os.Exit(1)
		}

		buf = make([]byte, h.Len)
		_, err = buffer.Read(buf)
		if err != nil {
			fmt.Println("failed to read")
			os.Exit(1)
		}

		msg, err := bgp.ParseMRTBody(h, buf)
		if err != nil {
			fmt.Println("failed to parse:", err)
			os.Exit(1)
		}

		fmt.Println(msg)
	}

}

func NewMrtCmd() *cobra.Command {
	mrtCmd := &cobra.Command{
		Use: CMD_MRT,
	}
	mrtCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")

	dumpCmd := &cobra.Command{
		Use: CMD_DUMP,
		Run: func(cmd *cobra.Command, args []string) {
			var interval uint64
			if len(args) > 0 {
				i, err := strconv.Atoi(args[0])
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				interval = uint64(i)
			}
			af, err := checkAddressFamily(net.IP{})
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			arg := &api.MrtArguments{
				Resource: api.Resource_GLOBAL,
				Af:       af,
				Interval: interval,
			}

			stream, err := client.GetMrt(context.Background(), arg)
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

				if globalOpts.Debug {
					printMrtMsgs(s.Data)
				}

				now := time.Now()
				y, m, d := now.Date()
				h, min, sec := now.Clock()
				filename := fmt.Sprintf("%s/rib.%04d%02d%02d.%02d%02d%02d", mrtOpts.OutputDir, y, m, d, h, min, sec)

				err = ioutil.WriteFile(filename, s.Data, 0600)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}

				fmt.Println("mrt dump:", filepath.Clean(filename))
			}
		},
	}
	dumpCmd.Flags().StringVarP(&mrtOpts.OutputDir, "outdir", "o", ".", "output directory")

	mrtCmd.AddCommand(dumpCmd)

	return mrtCmd
}
