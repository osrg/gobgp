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
	"bytes"
	"fmt"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"text/template"
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
			exitWithError(fmt.Errorf("failed to read: %s", err))
		}

		h := &bgp.MRTHeader{}
		err = h.DecodeFromBytes(buf)
		if err != nil {
			exitWithError(fmt.Errorf("failed to parse"))
		}

		buf = make([]byte, h.Len)
		_, err = buffer.Read(buf)
		if err != nil {
			exitWithError(fmt.Errorf("failed to read"))
		}

		msg, err := bgp.ParseMRTBody(h, buf)
		if err != nil {
			exitWithError(fmt.Errorf("failed to parse: %s", err))
		}

		fmt.Println(msg)
	}

}

func dumpRib(r string, remoteIP net.IP, args []string) error {
	var resource api.Resource
	switch r {
	case CMD_GLOBAL:
		resource = api.Resource_GLOBAL
	case CMD_LOCAL:
		resource = api.Resource_LOCAL
	default:
		return fmt.Errorf("unknown resource type: %s", r)
	}

	family, err := checkAddressFamily(addr2AddressFamily(remoteIP))
	if err != nil {
		return err
	}

	var interval uint64
	if len(args) > 0 {
		i, err := strconv.Atoi(args[0])
		if err != nil {
			return err
		}
		interval = uint64(i)
	}

	arg := &api.MrtArguments{
		Resource:        resource,
		Family:          uint32(family),
		Interval:        interval,
		NeighborAddress: remoteIP.String(),
	}

	afi, _ := bgp.RouteFamilyToAfiSafi(family)
	var af string
	switch afi {
	case bgp.AFI_IP:
		af = "ipv4"
	case bgp.AFI_IP6:
		af = "ipv6"
	case bgp.AFI_L2VPN:
		af = "l2vpn"
	}

	seed := struct {
		Y               string
		M               string
		D               string
		H               string
		Min             string
		Sec             string
		Af              string
		NeighborAddress string
		Resource        string
	}{
		Af:              af,
		NeighborAddress: remoteIP.String(),
		Resource:        r,
	}

	stream, err := client.GetMrt(context.Background(), arg)
	if err != nil {
		exitWithError(err)
	}

	var fileformat string

	if mrtOpts.FileFormat != "" {
		fileformat = mrtOpts.FileFormat
	} else if r == CMD_GLOBAL {
		fileformat = "rib_{{.Af}}_{{.Y}}{{.M}}{{.D}}_{{.H}}{{.Min}}{{.Sec}}"
	} else {
		fileformat = "rib_{{.NeighborAddress}}_{{.Y}}{{.M}}{{.D}}_{{.H}}{{.Min}}{{.Sec}}"
	}

	for {
		s, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			exitWithError(err)
		}

		if globalOpts.Debug {
			printMrtMsgs(s.Data)
		}

		now := time.Now()
		y, m, d := now.Date()
		seed.Y = fmt.Sprintf("%04d", y)
		seed.M = fmt.Sprintf("%02d", int(m))
		seed.D = fmt.Sprintf("%02d", d)
		h, min, sec := now.Clock()
		seed.H = fmt.Sprintf("%02d", h)
		seed.Min = fmt.Sprintf("%02d", min)
		seed.Sec = fmt.Sprintf("%02d", sec)
		t, err := template.New("f").Parse(fileformat)
		if err != nil {
			return err
		}
		buf := bytes.NewBuffer(make([]byte, 0, 32))
		err = t.Execute(buf, seed)
		if err != nil {
			return err
		}
		filename := fmt.Sprintf("%s/%s", mrtOpts.OutputDir, buf.String())

		err = ioutil.WriteFile(filename, s.Data, 0600)
		if err != nil {
			exitWithError(err)
		}

		fmt.Println("mrt dump:", filepath.Clean(filename))
	}
	return nil
}

func injectMrt(r string, filename string, count int, skip int) error {

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

	ch := make(chan *api.ModPathsArguments, 1<<20)

	go func() {

		var peers []*bgp.Peer

		for {
			buf := make([]byte, bgp.MRT_COMMON_HEADER_LEN)
			_, err := file.Read(buf)
			if err == io.EOF {
				break
			} else if err != nil {
				exitWithError(fmt.Errorf("failed to read: %s", err))
			}

			h := &bgp.MRTHeader{}
			err = h.DecodeFromBytes(buf)
			if err != nil {
				exitWithError(fmt.Errorf("failed to parse"))
			}

			buf = make([]byte, h.Len)
			_, err = file.Read(buf)
			if err != nil {
				exitWithError(fmt.Errorf("failed to read"))
			}

			msg, err := bgp.ParseMRTBody(h, buf)
			if err != nil {
				exitWithError(fmt.Errorf("failed to parse: %s", err))
			}

			if globalOpts.Debug {
				fmt.Println(msg)
			}

			if msg.Header.Type == bgp.TABLE_DUMPv2 {
				subType := bgp.MRTSubTypeTableDumpv2(msg.Header.SubType)
				var rf bgp.RouteFamily
				switch subType {
				case bgp.PEER_INDEX_TABLE:
					peers = msg.Body.(*bgp.PeerIndexTable).Peers
					continue
				case bgp.RIB_IPV4_UNICAST:
					rf = bgp.RF_IPv4_UC
				case bgp.RIB_IPV6_UNICAST:
					rf = bgp.RF_IPv6_UC
				default:
					exitWithError(fmt.Errorf("unsupported subType: %s", subType))
				}

				if peers == nil {
					exitWithError(fmt.Errorf("not found PEER_INDEX_TABLE"))
				}

				rib := msg.Body.(*bgp.Rib)
				nlri := rib.Prefix

				paths := make([]*api.Path, 0, len(rib.Entries))

				for _, e := range rib.Entries {
					if len(peers) < int(e.PeerIndex) {
						exitWithError(fmt.Errorf("invalid peer index: %d (PEER_INDEX_TABLE has only %d peers)\n", e.PeerIndex, len(peers)))
					}

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

				if idx >= skip {
					ch <- &api.ModPathsArguments{
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

	stream, err := client.ModPaths(context.Background())
	if err != nil {
		return fmt.Errorf("failed to modpath: %s", err)
	}

	for arg := range ch {
		err = stream.Send(arg)
		if err != nil {
			return fmt.Errorf("failed to send: %s", err)
		}
	}

	res, err := stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("failed to send: %s", err)
	}
	if res.Code != api.Error_SUCCESS {
		return fmt.Errorf("error: code: %d, msg: %s", res.Code, res.Msg)
	}
	return nil
}

func NewMrtCmd() *cobra.Command {

	globalDumpCmd := &cobra.Command{
		Use: CMD_GLOBAL,
		Run: func(cmd *cobra.Command, args []string) {
			err := dumpRib(CMD_GLOBAL, net.IP{}, args)
			if err != nil {
				exitWithError(err)
			}
		},
	}

	neighborCmd := &cobra.Command{
		Use: CMD_NEIGHBOR,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				exitWithError(fmt.Errorf("usage: gobgp mrt dump neighbor <neighbor address> [<interval>]"))
			}
			remoteIP := net.ParseIP(args[0])
			if remoteIP == nil {
				exitWithError(fmt.Errorf("invalid ip address: %s", args[0]))
			}
			err := dumpRib(CMD_LOCAL, remoteIP, args[1:])
			if err != nil {
				exitWithError(err)
			}
		},
	}

	ribCmd := &cobra.Command{
		Use: CMD_RIB,
	}
	ribCmd.AddCommand(globalDumpCmd, neighborCmd)
	ribCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")

	dumpCmd := &cobra.Command{
		Use: CMD_DUMP,
	}
	dumpCmd.AddCommand(ribCmd)
	dumpCmd.PersistentFlags().StringVarP(&mrtOpts.OutputDir, "outdir", "o", ".", "output directory")
	dumpCmd.PersistentFlags().StringVarP(&mrtOpts.FileFormat, "format", "f", "", "file format")

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
			err := injectMrt(CMD_GLOBAL, filename, count, skip)
			if err != nil {
				exitWithError(err)
			}
		},
	}

	injectCmd := &cobra.Command{
		Use: CMD_INJECT,
	}
	injectCmd.AddCommand(globalInjectCmd)

	modMrt := func(op api.Operation, filename string) {
		arg := &api.ModMrtArguments{
			Operation: op,
			Filename:  filename,
		}
		client.ModMrt(context.Background(), arg)
	}

	enableCmd := &cobra.Command{
		Use: CMD_ENABLE,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				exitWithError(fmt.Errorf("usage: gobgp mrt update enable <filename>"))
			}
			modMrt(api.Operation_ADD, args[0])
		},
	}

	disableCmd := &cobra.Command{
		Use: CMD_DISABLE,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 0 {
				exitWithError(fmt.Errorf("usage: gobgp mrt update disable"))
			}
			modMrt(api.Operation_DEL, "")
		},
	}

	rotateCmd := &cobra.Command{
		Use: CMD_ROTATE,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				exitWithError(fmt.Errorf("usage: gobgp mrt update rotate <filename>"))
			}
			modMrt(api.Operation_REPLACE, args[0])
		},
	}

	restartCmd := &cobra.Command{
		Use: CMD_RESET,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				exitWithError(fmt.Errorf("usage: gobgp mrt update reset"))
			}
			modMrt(api.Operation_REPLACE, "")
		},
	}

	updateCmd := &cobra.Command{
		Use: CMD_UPDATE,
	}
	updateCmd.AddCommand(enableCmd, disableCmd, restartCmd, rotateCmd)

	mrtCmd := &cobra.Command{
		Use: CMD_MRT,
	}
	mrtCmd.AddCommand(dumpCmd, injectCmd, updateCmd)

	return mrtCmd
}
