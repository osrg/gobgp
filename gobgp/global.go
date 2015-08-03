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
	"github.com/osrg/gobgp/packet"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"net"
	"os"
	"strconv"
)

func showGlobalRib(args []string) error {
	bogusIp := net.IP{}
	return showNeighborRib(CMD_GLOBAL, bogusIp, args)
}

func getSerizliedRouteTarget(args []string) ([]byte, error) {
	rts := make([]bgp.ExtendedCommunityInterface, 0, len(args))
	for _, elem := range args {
		rt, err := bgp.ParseRouteTarget(elem)
		if err != nil {
			return nil, err
		}
		rts = append(rts, rt)
	}
	return bgp.NewPathAttributeExtendedCommunities(rts).Serialize()
}

func modPath(modtype string, args []string) error {
	rf, err := checkAddressFamily(net.IP{})
	if err != nil {
		return err
	}

	var nlri bgp.AddrPrefixInterface
	var nexthop string
	var rts []string

	switch rf {
	case api.AF_IPV4_UC, api.AF_IPV6_UC:
		if len(args) != 1 {
			return fmt.Errorf("usage: global rib %s <prefix> -a { ipv4 | ipv6 }", modtype)
		}
		ip, net, _ := net.ParseCIDR(args[0])
		if rf == api.AF_IPV4_UC {
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
	case api.AF_IPV4_VPN, api.AF_IPV6_VPN:
		if len(args) < 3 || args[1] != "rd" || args[3] != "rt" {
			return fmt.Errorf("usage: global rib %s <prefix> rd <rd> rt <rt>... -a { vpn-ipv4 | vpn-ipv6 }", modtype)
		}
		ip, net, _ := net.ParseCIDR(args[0])
		ones, _ := net.Mask.Size()

		rd, err := bgp.ParseRouteDistinguisher(args[2])
		if err != nil {
			return err
		}

		rts = args[4:]

		mpls := bgp.NewMPLSLabelStack()

		if rf == api.AF_IPV4_VPN {
			if ip.To4() == nil {
				return fmt.Errorf("invalid ipv4 prefix")
			}
			nexthop = "0.0.0.0"
			nlri = bgp.NewLabeledVPNIPAddrPrefix(uint8(ones), ip.String(), *mpls, rd)
		} else {
			if ip.To16() == nil {
				return fmt.Errorf("invalid ipv6 prefix")
			}
			nexthop = "::"
			nlri = bgp.NewLabeledVPNIPv6AddrPrefix(uint8(ones), ip.String(), *mpls, rd)
		}

	case api.AF_EVPN:
		if len(args) < 1 {
			return fmt.Errorf("usage: global rib %s { macadv | multicast } ... -a evpn", modtype)
		}
		subtype := args[0]
		args = args[1:]

		switch subtype {
		case "macadv":
			if len(args) < 6 || args[4] != "rd" || args[6] != "rt" {
				return fmt.Errorf("usage: global rib %s macadv <mac address> <ip address> <etag> <label> rd <rd> rt <rt>... -a evpn", modtype)
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
			rd, err := bgp.ParseRouteDistinguisher(args[5])
			if err != nil {
				return err
			}

			rts = args[7:]

			macIpAdv := &bgp.EVPNMacIPAdvertisementRoute{
				RD: rd,
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
			if len(args) < 5 || args[2] != "rd" || args[4] != "rt" {
				return fmt.Errorf("usage : global rib %s multicast <ip address> <etag> rd <rd> rt <rt> -a evpn", modtype)
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

			rd, err := bgp.ParseRouteDistinguisher(args[3])
			if err != nil {
				return err
			}

			rts = args[5:]

			multicastEtag := &bgp.EVPNMulticastEthernetTagRoute{
				RD:              rd,
				IPAddressLength: uint8(iplen),
				IPAddress:       ip,
				ETag:            uint32(eTag),
			}
			nlri = bgp.NewEVPNNLRI(bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG, 0, multicastEtag)
		default:
			return fmt.Errorf("usage: global rib add { macadv | multicast | ... -a evpn")
		}
		nexthop = "0.0.0.0"
	default:
		return fmt.Errorf("Unsupported route family: %s", rf)
	}

	arg := &api.ModPathArguments{
		Resource:  api.Resource_GLOBAL,
		RawPattrs: make([][]byte, 0),
	}

	switch modtype {
	case CMD_ADD:
		arg.IsWithdraw = false
	case CMD_DEL:
		arg.IsWithdraw = true
	}

	if rf == api.AF_IPV4_UC {
		arg.RawNlri, _ = nlri.Serialize()
		n, _ := bgp.NewPathAttributeNextHop(nexthop).Serialize()
		arg.RawPattrs = append(arg.RawPattrs, n)
	} else {
		mpreach, _ := bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}).Serialize()
		arg.RawPattrs = append(arg.RawPattrs, mpreach)
	}

	origin, _ := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP).Serialize()
	arg.RawPattrs = append(arg.RawPattrs, origin)

	if rts != nil && len(rts) > 0 {
		extcomm, err := getSerizliedRouteTarget(rts)
		if err != nil {
			return err
		}
		arg.RawPattrs = append(arg.RawPattrs, extcomm)
	}

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

func NewGlobalCmd() *cobra.Command {
	globalCmd := &cobra.Command{
		Use: CMD_GLOBAL,
	}

	ribCmd := &cobra.Command{
		Use: CMD_RIB,
		Run: func(cmd *cobra.Command, args []string) {
			showGlobalRib(args)
		},
	}

	ribCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")

	addCmd := &cobra.Command{
		Use: CMD_ADD,
		Run: func(cmd *cobra.Command, args []string) {
			err := modPath(CMD_ADD, args)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	delCmd := &cobra.Command{
		Use: CMD_DEL,
		Run: func(cmd *cobra.Command, args []string) {
			err := modPath(CMD_DEL, args)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	ribCmd.AddCommand(addCmd, delCmd)
	globalCmd.AddCommand(ribCmd)
	return globalCmd
}
