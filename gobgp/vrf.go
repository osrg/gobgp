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
	"encoding/json"
	"fmt"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

func getVrfs() (vrfs, error) {
	arg := &api.Arguments{}
	stream, err := client.GetVrfs(context.Background(), arg)
	if err != nil {
		return nil, err
	}
	vs := make(vrfs, 0)
	for {
		v, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		vs = append(vs, v)
	}

	sort.Sort(vs)

	return vs, nil
}

func showVrfs() error {
	maxLens := []int{20, 20, 20, 20}
	vrfs, err := getVrfs()
	if err != nil {
		return err
	}
	if globalOpts.Json {
		j, _ := json.Marshal(vrfs)
		fmt.Println(string(j))
		return nil
	}
	lines := make([][]string, 0, len(vrfs))
	for _, v := range vrfs {
		name := v.Name
		rd := bgp.GetRouteDistinguisher(v.Rd).String()

		f := func(bufs [][]byte) (string, error) {
			ret := make([]string, 0, len(bufs))
			for _, rt := range bufs {
				r, err := bgp.ParseExtended(rt)
				if err != nil {
					return "", err
				}
				ret = append(ret, r.String())
			}
			return strings.Join(ret, ", "), nil
		}

		importRts, _ := f(v.ImportRt)
		exportRts, _ := f(v.ExportRt)
		lines = append(lines, []string{name, rd, importRts, exportRts})

		for i, v := range []int{len(name), len(rd), len(importRts), len(exportRts)} {
			if v > maxLens[i] {
				maxLens[i] = v + 4
			}
		}

	}
	format := fmt.Sprintf("  %%-%ds %%-%ds %%-%ds %%-%ds\n", maxLens[0], maxLens[1], maxLens[2], maxLens[3])
	fmt.Printf(format, "Name", "RD", "Import RT", "Export RT")
	for _, l := range lines {
		fmt.Printf(format, l[0], l[1], l[2], l[3])
	}
	return nil
}

func showVrf(name string) error {
	return showNeighborRib(CMD_VRF, name, nil)
}

func modVrf(typ string, args []string) error {
	var arg *api.ModVrfArguments
	switch typ {
	case CMD_ADD:
		if len(args) < 6 || args[1] != "rd" || args[3] != "rt" {
			return fmt.Errorf("Usage: gobgp vrf add <vrf name> rd <rd> rt { import | export | both } <rt>...")
		}
		name := args[0]
		rd, err := bgp.ParseRouteDistinguisher(args[2])
		if err != nil {
			return err
		}
		cur := ""
		importRt := make([][]byte, 0)
		exportRt := make([][]byte, 0)
		for _, elem := range args[4:] {
			if elem == "import" || elem == "export" || elem == "both" {
				cur = elem
				continue
			}
			rt, err := bgp.ParseRouteTarget(elem)
			if err != nil {
				return err
			}
			buf, err := rt.Serialize()
			if err != nil {
				return err
			}
			switch cur {
			case "import":
				importRt = append(importRt, buf)
			case "export":
				exportRt = append(importRt, buf)
			case "both":
				importRt = append(importRt, buf)
				exportRt = append(exportRt, buf)
			default:
				return fmt.Errorf("Usage: gobgp vrf add <vrf name> rd <rd> rt { import | export | both } <rt>...")
			}
		}
		buf, _ := rd.Serialize()
		arg = &api.ModVrfArguments{
			Operation: api.Operation_ADD,
			Vrf: &api.Vrf{
				Name:     name,
				Rd:       buf,
				ImportRt: importRt,
				ExportRt: exportRt,
			},
		}
	case CMD_DEL:
		if len(args) != 1 {
			return fmt.Errorf("Usage: gobgp vrf del <vrf name>")
		}
		arg = &api.ModVrfArguments{
			Operation: api.Operation_DEL,
			Vrf: &api.Vrf{
				Name: args[0],
			},
		}
	}

	_, err := client.ModVrf(context.Background(), arg)
	return err
}

func modVrfPath(modtype string, vrf string, args []string) error {
	rf, err := checkAddressFamily(net.IP{})
	if err != nil {
		return err
	}

	var nlri bgp.AddrPrefixInterface
	var nexthop string

	switch rf {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		if len(args) != 1 {
			return fmt.Errorf("usage: vrf %s rib %s <prefix> -a { ipv4 | ipv6 }", vrf, modtype)
		}
		ip, net, _ := net.ParseCIDR(args[0])
		if rf == bgp.RF_IPv4_UC {
			if ip.To4() == nil {
				return fmt.Errorf("invalid ipv4 prefix")
			}
			nexthop = "0.0.0.0"
			ones, _ := net.Mask.Size()
			nlri = bgp.NewNLRInfo(uint8(ones), ip.String())
		} else {
			if ip.To16() == nil {
				return fmt.Errorf("invalid ipv6 prefix")
			}
			nexthop = "::"
			ones, _ := net.Mask.Size()
			nlri = bgp.NewIPv6AddrPrefix(uint8(ones), ip.String())
		}
	case bgp.RF_EVPN:
		if len(args) < 1 {
			return fmt.Errorf("usage: vrf %s rib %s { macadv | multicast } ... -a evpn", vrf, modtype)
		}
		subtype := args[0]
		args = args[1:]

		switch subtype {
		case "macadv":
			if len(args) < 4 {
				return fmt.Errorf("usage: vrf %s rib %s macadv <mac address> <ip address> <etag> <label> -a evpn", vrf, modtype)
			}
			mac, err := net.ParseMAC(args[0])
			if err != nil {
				return fmt.Errorf("invalid mac: %s", args[0])
			}
			var ip net.IP
			iplen := 0
			if args[1] != "0.0.0.0" || args[1] != "::" {
				ip = net.ParseIP(args[1])
				if ip == nil {
					return fmt.Errorf("invalid ip prefix: %s", args[1])
				}
				iplen = net.IPv4len * 8
				if ip.To4() == nil {
					iplen = net.IPv6len * 8
				}
			}
			eTag, err := strconv.Atoi(args[2])
			if err != nil {
				return fmt.Errorf("invalid eTag: %s. err: %s", args[2], err)
			}
			label, err := strconv.Atoi(args[3])
			if err != nil {
				return fmt.Errorf("invalid label: %s. err: %s", args[3], err)
			}
			macIpAdv := &bgp.EVPNMacIPAdvertisementRoute{
				ESI: bgp.EthernetSegmentIdentifier{
					Type: bgp.ESI_ARBITRARY,
				},
				MacAddressLength: 48,
				MacAddress:       mac,
				IPAddressLength:  uint8(iplen),
				IPAddress:        ip,
				Labels:           []uint32{uint32(label)},
				ETag:             uint32(eTag),
			}
			nlri = bgp.NewEVPNNLRI(bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT, 0, macIpAdv)
		case "multicast":
			if len(args) < 2 {
				return fmt.Errorf("usage : vrf %s rib %s multicast <ip address> <etag> -a evpn", vrf, modtype)
			}

			var ip net.IP
			iplen := 0
			if args[0] != "0.0.0.0" || args[0] != "::" {
				ip = net.ParseIP(args[0])
				if ip == nil {
					return fmt.Errorf("invalid ip prefix: %s", args[0])
				}
				iplen = net.IPv4len * 8
				if ip.To4() == nil {
					iplen = net.IPv6len * 8
				}
			}

			eTag, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("invalid eTag: %s. err: %s", args[1], err)
			}

			multicastEtag := &bgp.EVPNMulticastEthernetTagRoute{
				IPAddressLength: uint8(iplen),
				IPAddress:       ip,
				ETag:            uint32(eTag),
			}
			nlri = bgp.NewEVPNNLRI(bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG, 0, multicastEtag)
		default:
			return fmt.Errorf("usage: vrf %s rib %s { macadv | multicast | ... -a evpn", vrf, modtype)
		}
		nexthop = "0.0.0.0"
	default:
		return fmt.Errorf("Unsupported route family: %s", rf)
	}

	arg := &api.ModPathArguments{
		Resource:  api.Resource_VRF,
		Name:      vrf,
		RawPattrs: make([][]byte, 0),
	}

	switch modtype {
	case CMD_ADD:
		arg.IsWithdraw = false
	case CMD_DEL:
		arg.IsWithdraw = true
	}

	if rf == bgp.RF_IPv4_UC {
		arg.RawNlri, _ = nlri.Serialize()
		n, _ := bgp.NewPathAttributeNextHop(nexthop).Serialize()
		arg.RawPattrs = append(arg.RawPattrs, n)
	} else {
		mpreach, _ := bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}).Serialize()
		arg.RawPattrs = append(arg.RawPattrs, mpreach)
	}

	origin, _ := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP).Serialize()
	arg.RawPattrs = append(arg.RawPattrs, origin)

	stream, err := client.ModPath(context.Background())
	if err != nil {
		return err
	}
	err = stream.Send(arg)
	if err != nil {
		return err
	}
	stream.CloseSend()

	res, e := stream.CloseAndRecv()
	if e != nil {
		return e
	}
	if res.Code != api.Error_SUCCESS {
		return fmt.Errorf("error: code: %d, msg: %s", res.Code, res.Msg)
	}
	return nil
}

func NewVrfCmd() *cobra.Command {

	ribCmd := &cobra.Command{
		Use: CMD_RIB,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if len(args) == 1 {
				err = showVrf(args[0])
			} else {
				err = fmt.Errorf("usage: gobgp vrf <vrf-name> rib")
			}
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	for _, v := range []string{CMD_ADD, CMD_DEL} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				err := modVrfPath(cmd.Use, args[len(args)-1], args[:len(args)-1])
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			},
		}
		ribCmd.AddCommand(cmd)
	}

	vrfCmdImpl := &cobra.Command{}
	vrfCmdImpl.AddCommand(ribCmd)

	vrfCmd := &cobra.Command{
		Use: CMD_VRF,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if len(args) == 0 {
				err = showVrfs()
			} else if len(args) == 1 {
			} else {
				args = append(args[1:], args[0])
				vrfCmdImpl.SetArgs(args)
				err = vrfCmdImpl.Execute()
			}
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	for _, v := range []string{CMD_ADD, CMD_DEL} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				err := modVrf(cmd.Use, args)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			},
		}
		vrfCmd.AddCommand(cmd)
	}
	vrfCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")

	return vrfCmd
}
