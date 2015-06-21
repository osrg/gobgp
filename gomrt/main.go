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
	"github.com/osrg/gobgp/gomrt/packet"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"net"
	"os"
	"time"
)

var globalOpts struct {
	Host  string
	Port  int
	Input string
	Count int
}

var client api.GrpcClient

func connGrpc() *grpc.ClientConn {
	timeout := grpc.WithTimeout(time.Second)

	// determine IP address version
	host := net.ParseIP(globalOpts.Host)
	target := fmt.Sprintf("%s:%d", globalOpts.Host, globalOpts.Port)
	if host.To4() == nil {
		target = fmt.Sprintf("[%s]:%d", globalOpts.Host, globalOpts.Port)
	}

	conn, err := grpc.Dial(target, timeout)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return conn
}

func main() {

	rootCmd := &cobra.Command{
		Use: "gomrt",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			conn := connGrpc()
			client = api.NewGrpcClient(conn)
		},
		Run: func(cmd *cobra.Command, args []string) {
			file, err := os.Open(globalOpts.Input)
			if err != nil {
				fmt.Println("failed to open file")
				os.Exit(1)
			}

			idx := 0

			stream, err := client.ModPath(context.Background())
			if err != nil {
				fmt.Println("failed to modpath:", err)
				os.Exit(1)
			}

			for {
				buf := make([]byte, mrt.COMMON_HEADER_LEN)
				_, err := file.Read(buf)
				if err == io.EOF {
					break
				} else if err != nil {
					fmt.Println("failed to read:", err)
					os.Exit(1)
				}

				h := &mrt.Header{}
				err = h.DecodeFromBytes(buf)
				if err != nil {
					fmt.Println("failed to parse")
					os.Exit(1)
				}

				buf = make([]byte, h.Len)
				_, err = file.Read(buf)
				if err != nil {
					fmt.Println("failed to read")
					os.Exit(1)
				}

				msg, err := mrt.ParseBody(h, buf)
				if err != nil {
					fmt.Println("failed to parse:", err)
					os.Exit(1)
				}

				if msg.Header.Type == mrt.TABLE_DUMPv2 {
					subType := mrt.SubTypeTableDumpv2(msg.Header.SubType)
					var af *api.AddressFamily
					switch subType {
					case mrt.PEER_INDEX_TABLE:
						continue
					case mrt.RIB_IPV4_UNICAST:
						af = api.AF_IPV4_UC
					case mrt.RIB_IPV6_UNICAST:
						af = api.AF_IPV6_UC
					default:
						fmt.Println("unsupported subType:", subType)
						os.Exit(1)
					}
					rib := msg.Body.(*mrt.Rib)
					prefix := rib.Prefix.String()
					path := &api.Path{}
					path.Nlri = &api.Nlri{
						Af:     af,
						Prefix: prefix,
					}

					arg := &api.ModPathArguments{
						Resource: api.Resource_GLOBAL,
						Path:     path,
					}

					err = stream.Send(arg)
					if err != nil {
						fmt.Println("failed to send:", err)
						os.Exit(1)
					}

					res, err := stream.Recv()
					if err != nil {
						fmt.Println("failed to send:", err)
						os.Exit(1)
					}
					if res.Code != api.Error_SUCCESS {
						fmt.Errorf("error: code: %d, msg: %s", res.Code, res.Msg)
						os.Exit(1)
					}
				}

				idx += 1

				if idx == globalOpts.Count {
					break
				}
			}
		},
	}

	rootCmd.PersistentFlags().StringVarP(&globalOpts.Host, "host", "u", "127.0.0.1", "host")
	rootCmd.PersistentFlags().IntVarP(&globalOpts.Port, "port", "p", 8080, "port")
	rootCmd.Flags().StringVarP(&globalOpts.Input, "input", "i", "", "input mrt file")
	rootCmd.Flags().IntVarP(&globalOpts.Count, "count", "c", -1, "how many mrt record you read")
	rootCmd.Execute()

}
