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
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/internal/pkg/apiutil"
	"github.com/osrg/gobgp/pkg/packet/bgp"
	"github.com/osrg/gobgp/pkg/packet/mrt"
)

func injectMrt() error {

	file, err := os.Open(mrtOpts.Filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %s", err)
	}

	if mrtOpts.NextHop != nil && !mrtOpts.SkipV4 && !mrtOpts.SkipV6 {
		fmt.Println("You should probably specify either --no-ipv4 or --no-ipv6 when overwriting nexthop, unless your dump contains only one type of routes")
	}

	var idx int64
	if mrtOpts.QueueSize < 1 {
		return fmt.Errorf("specified queue size is smaller than 1, refusing to run with unbounded memory usage")
	}

	ch := make(chan []*api.Path, mrtOpts.QueueSize)
	go func() {

		var peers []*mrt.Peer
		for {
			buf := make([]byte, mrt.MRT_COMMON_HEADER_LEN)
			_, err := file.Read(buf)
			if err == io.EOF {
				break
			} else if err != nil {
				exitWithError(fmt.Errorf("failed to read: %s", err))
			}

			h := &mrt.MRTHeader{}
			err = h.DecodeFromBytes(buf)
			if err != nil {
				exitWithError(fmt.Errorf("failed to parse"))
			}

			buf = make([]byte, h.Len)
			_, err = file.Read(buf)
			if err != nil {
				exitWithError(fmt.Errorf("failed to read"))
			}

			msg, err := mrt.ParseMRTBody(h, buf)
			if err != nil {
				printError(fmt.Errorf("failed to parse: %s", err))
				continue
			}

			if globalOpts.Debug {
				fmt.Println(msg)
			}

			if msg.Header.Type == mrt.TABLE_DUMPv2 {
				subType := mrt.MRTSubTypeTableDumpv2(msg.Header.SubType)
				switch subType {
				case mrt.PEER_INDEX_TABLE:
					peers = msg.Body.(*mrt.PeerIndexTable).Peers
					continue
				case mrt.RIB_IPV4_UNICAST, mrt.RIB_IPV4_UNICAST_ADDPATH:
					if mrtOpts.SkipV4 {
						continue
					}
				case mrt.RIB_IPV6_UNICAST, mrt.RIB_IPV6_UNICAST_ADDPATH:
					if mrtOpts.SkipV6 {
						continue
					}
				case mrt.GEO_PEER_TABLE:
					fmt.Printf("WARNING: Skipping GEO_PEER_TABLE: %s", msg.Body.(*mrt.GeoPeerTable))
				default:
					exitWithError(fmt.Errorf("unsupported subType: %v", subType))
				}

				if peers == nil {
					exitWithError(fmt.Errorf("not found PEER_INDEX_TABLE"))
				}

				rib := msg.Body.(*mrt.Rib)
				nlri := rib.Prefix

				paths := make([]*api.Path, 0, len(rib.Entries))

				for _, e := range rib.Entries {
					if len(peers) < int(e.PeerIndex) {
						exitWithError(fmt.Errorf("invalid peer index: %d (PEER_INDEX_TABLE has only %d peers)", e.PeerIndex, len(peers)))
					}
					//t := time.Unix(int64(e.OriginatedTime), 0)

					var attrs []bgp.PathAttributeInterface
					switch subType {
					case mrt.RIB_IPV4_UNICAST, mrt.RIB_IPV4_UNICAST_ADDPATH:
						if mrtOpts.NextHop != nil {
							for i, attr := range e.PathAttributes {
								if attr.GetType() == bgp.BGP_ATTR_TYPE_NEXT_HOP {
									e.PathAttributes[i] = bgp.NewPathAttributeNextHop(mrtOpts.NextHop.String())
									break
								}
							}
						}
						attrs = e.PathAttributes
					default:
						attrs = make([]bgp.PathAttributeInterface, 0, len(e.PathAttributes))
						for _, attr := range e.PathAttributes {
							if attr.GetType() != bgp.BGP_ATTR_TYPE_MP_REACH_NLRI {
								attrs = append(attrs, attr)
							} else {
								a := attr.(*bgp.PathAttributeMpReachNLRI)
								nexthop := a.Nexthop.String()
								if mrtOpts.NextHop != nil {
									nexthop = mrtOpts.NextHop.String()
								}
								attrs = append(attrs, bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}))
							}
						}
					}

					path := apiutil.NewPath(nlri, false, attrs, time.Unix(int64(e.OriginatedTime), 0))
					path.SourceAsn = peers[e.PeerIndex].AS
					path.SourceId = peers[e.PeerIndex].BgpId.String()

					// TODO: compare here if mrtOpts.Best is enabled
					paths = append(paths, path)
				}

				// TODO: calculate properly if necessary.
				if mrtOpts.Best {
					paths = []*api.Path{paths[0]}
				}

				if idx >= mrtOpts.RecordSkip {
					ch <- paths
				}

				idx += 1
				if idx == mrtOpts.RecordCount+mrtOpts.RecordSkip {
					break
				}
			}
		}

		close(ch)
	}()

	stream, err := client.AddPathStream(ctx)
	if err != nil {
		return fmt.Errorf("failed to add path: %s", err)
	}

	for paths := range ch {
		err = stream.Send(&api.AddPathStreamRequest{
			TableType: api.TableType_GLOBAL,
			Paths:     paths,
		})
		if err != nil {
			return fmt.Errorf("failed to send: %s", err)
		}
	}
	return nil
}

func newMrtCmd() *cobra.Command {
	globalInjectCmd := &cobra.Command{
		Use: cmdGlobal,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				exitWithError(fmt.Errorf("usage: gobgp mrt inject global <filename> [<count> [<skip>]]"))
			}
			mrtOpts.Filename = args[0]
			if len(args) > 1 {
				var err error
				mrtOpts.RecordCount, err = strconv.ParseInt(args[1], 10, 64)
				if err != nil {
					exitWithError(fmt.Errorf("invalid count value: %s", args[1]))
				}
				if len(args) > 2 {
					mrtOpts.RecordSkip, err = strconv.ParseInt(args[2], 10, 64)
					if err != nil {
						exitWithError(fmt.Errorf("invalid skip value: %s", args[2]))
					}
				}
			} else {
				mrtOpts.RecordCount = -1
				mrtOpts.RecordSkip = 0
			}
			err := injectMrt()
			if err != nil {
				exitWithError(err)
			}
		},
	}

	injectCmd := &cobra.Command{
		Use: cmdInject,
	}
	injectCmd.AddCommand(globalInjectCmd)

	mrtCmd := &cobra.Command{
		Use: cmdMRT,
	}
	mrtCmd.AddCommand(injectCmd)

	mrtCmd.PersistentFlags().BoolVarP(&mrtOpts.Best, "only-best", "", false, "inject only best paths")
	mrtCmd.PersistentFlags().BoolVarP(&mrtOpts.SkipV4, "no-ipv4", "", false, "Do not import IPv4 routes")
	mrtCmd.PersistentFlags().BoolVarP(&mrtOpts.SkipV6, "no-ipv6", "", false, "Do not import IPv6 routes")
	mrtCmd.PersistentFlags().IntVarP(&mrtOpts.QueueSize, "queue-size", "", 1<<10, "Maximum number of updates to keep queued")
	mrtCmd.PersistentFlags().IPVarP(&mrtOpts.NextHop, "nexthop", "", nil, "Overwrite nexthop")
	return mrtCmd
}
