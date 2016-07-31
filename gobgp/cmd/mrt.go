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
	"github.com/osrg/gobgp/packet/mrt"
	"github.com/osrg/gobgp/table"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"io"
	"os"
	"strconv"
	"time"
)

func injectMrt(r string, filename string, count int, skip int, onlyBest bool) error {

	var resource api.Resource
	switch r {
	case CMD_GLOBAL:
		resource = api.Resource_GLOBAL
	default:
		return fmt.Errorf("unknown resource type: %s", r)
	}

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %s", err)
	}

	idx := 0

	ch := make(chan *api.InjectMrtRequest, 1<<20)

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
				var rf bgp.RouteFamily
				switch subType {
				case mrt.PEER_INDEX_TABLE:
					peers = msg.Body.(*mrt.PeerIndexTable).Peers
					continue
				case mrt.RIB_IPV4_UNICAST:
					rf = bgp.RF_IPv4_UC
				case mrt.RIB_IPV6_UNICAST:
					rf = bgp.RF_IPv6_UC
				default:
					exitWithError(fmt.Errorf("unsupported subType: %s", subType))
				}

				if peers == nil {
					exitWithError(fmt.Errorf("not found PEER_INDEX_TABLE"))
				}

				rib := msg.Body.(*mrt.Rib)
				nlri := rib.Prefix

				paths := make([]*api.Path, 0, len(rib.Entries))

				for _, e := range rib.Entries {
					if len(peers) < int(e.PeerIndex) {
						exitWithError(fmt.Errorf("invalid peer index: %d (PEER_INDEX_TABLE has only %d peers)\n", e.PeerIndex, len(peers)))
					}

					if !onlyBest {
						path := &api.Path{
							Pattrs:             make([][]byte, 0),
							NoImplicitWithdraw: true,
							SourceAsn:          peers[e.PeerIndex].AS,
							SourceId:           peers[e.PeerIndex].BgpId.String(),
						}

						if rf == bgp.RF_IPv4_UC {
							path.Nlri, _ = nlri.Serialize()
						}

						for _, p := range e.PathAttributes {
							b, err := p.Serialize()
							if err != nil {
								continue
							}
							path.Pattrs = append(path.Pattrs, b)
						}

						paths = append(paths, path)
					}
				}
				if onlyBest {
					paths = func() []*api.Path {
						dst := table.NewDestination(nlri)
						pathList := make([]*table.Path, 0, len(rib.Entries))
						for _, e := range rib.Entries {
							p := table.NewPath(&table.PeerInfo{AS: peers[e.PeerIndex].AS, ID: peers[e.PeerIndex].BgpId}, nlri, false, e.PathAttributes, time.Unix(int64(e.OriginatedTime), 0), false)
							dst.AddNewPath(p)
							pathList = append(pathList, p)
						}
						best, _, _ := dst.Calculate([]string{table.GLOBAL_RIB_NAME})
						for _, p := range pathList {
							if p == best[table.GLOBAL_RIB_NAME] {
								nb, _ := nlri.Serialize()
								return []*api.Path{&api.Path{
									Nlri:               nb,
									NoImplicitWithdraw: true,
									SourceAsn:          p.GetSource().AS,
									SourceId:           p.GetSource().ID.String(),
									Pattrs: func() [][]byte {
										attrs := make([][]byte, 0)
										for _, a := range p.GetPathAttrs() {
											if b, e := a.Serialize(); e == nil {

												attrs = append(attrs, b)
											}
										}
										return attrs
									}(),
								}}
							}
						}
						exitWithError(fmt.Errorf("Can't find the best %v", nlri))
						return []*api.Path{}
					}()
				}

				if idx >= skip {
					ch <- &api.InjectMrtRequest{
						Resource: resource,
						Paths:    paths,
					}
				}

				idx += 1
				if idx == count+skip {
					break
				}
			}
		}

		close(ch)
	}()

	stream, err := client.InjectMrt(context.Background())
	if err != nil {
		return fmt.Errorf("failed to modpath: %s", err)
	}

	for arg := range ch {
		err = stream.Send(arg)
		if err != nil {
			return fmt.Errorf("failed to send: %s", err)
		}
	}

	_, err = stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("failed to send: %s", err)
	}
	return nil
}

func NewMrtCmd() *cobra.Command {
	globalInjectCmd := &cobra.Command{
		Use: CMD_GLOBAL,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				exitWithError(fmt.Errorf("usage: gobgp mrt inject global <filename> [<count> [<skip>]]"))
			}
			filename := args[0]
			count := -1
			skip := 0
			if len(args) > 1 {
				var err error
				count, err = strconv.Atoi(args[1])
				if err != nil {
					exitWithError(fmt.Errorf("invalid count value: %s", args[1]))
				}
				if len(args) > 2 {
					skip, err = strconv.Atoi(args[2])
					if err != nil {
						exitWithError(fmt.Errorf("invalid skip value: %s", args[2]))
					}
				}
			}
			err := injectMrt(CMD_GLOBAL, filename, count, skip, mrtOpts.Best)
			if err != nil {
				exitWithError(err)
			}
		},
	}

	injectCmd := &cobra.Command{
		Use: CMD_INJECT,
	}
	injectCmd.AddCommand(globalInjectCmd)

	mrtCmd := &cobra.Command{
		Use: CMD_MRT,
	}
	mrtCmd.AddCommand(injectCmd)

	mrtCmd.PersistentFlags().BoolVarP(&mrtOpts.Best, "only-best", "", false, "inject only best paths")
	return mrtCmd
}
