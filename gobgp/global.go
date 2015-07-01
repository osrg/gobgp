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

func modPath(modtype string, eArgs []string) error {
	rf, err := checkAddressFamily(net.IP{})
	if err != nil {
		return err
	}

	path := &api.Path{}
	var prefix string
	switch rf {
	case api.AF_IPV4_UC, api.AF_IPV6_UC:
		if len(eArgs) == 1 || len(eArgs) == 3 {
			prefix = eArgs[0]
		} else {
			return fmt.Errorf("usage: global rib %s <prefix> -a { ipv4 | ipv6 }", modtype)
		}
		path.Nlri = &api.Nlri{
			Af:     rf,
			Prefix: prefix,
		}
	case api.AF_EVPN:
		var nlri *api.EVPNNlri

		if len(eArgs) < 1 {
			return fmt.Errorf("usage: global rib %s { macadv | multicast } ... -a evpn", modtype)
		}
		subtype := eArgs[0]

		switch subtype {
		case "macadv":
			if len(eArgs) < 5 {
				return fmt.Errorf("usage: global rib %s macadv <mac address> <ip address> <etag> <label> -a evpn", modtype)
			}
			macAddr := eArgs[1]
			ipAddr := eArgs[2]
			eTag, err := strconv.Atoi(eArgs[3])
			if err != nil {
				return fmt.Errorf("invalid eTag: %s. err: %s", eArgs[3], err)
			}
			label, err := strconv.Atoi(eArgs[4])
			if err != nil {
				return fmt.Errorf("invalid label: %s. err: %s", eArgs[4], err)
			}
			nlri = &api.EVPNNlri{
				Type: api.EVPN_TYPE_ROUTE_TYPE_MAC_IP_ADVERTISEMENT,
				MacIpAdv: &api.EvpnMacIpAdvertisement{
					MacAddr: macAddr,
					IpAddr:  ipAddr,
					Etag:    uint32(eTag),
					Labels:  []uint32{uint32(label)},
				},
			}
		case "multicast":
			if len(eArgs) < 3 {
				return fmt.Errorf("usage : global rib %s multicast <etag> <label> -a evpn", modtype)
			}
			eTag, err := strconv.Atoi(eArgs[1])
			if err != nil {
				return fmt.Errorf("invalid eTag: %s. err: %s", eArgs[1], err)
			}
			label, err := strconv.Atoi(eArgs[2])
			if err != nil {
				return fmt.Errorf("invalid label: %s. err: %s", eArgs[2], err)
			}
			nlri = &api.EVPNNlri{
				Type: api.EVPN_TYPE_INCLUSIVE_MULTICAST_ETHERNET_TAG,
				MulticastEtag: &api.EvpnInclusiveMulticastEthernetTag{
					Etag: uint32(eTag),
				},
			}

			attr := &api.PathAttr{
				Type: api.BGP_ATTR_TYPE_PMSI_TUNNEL,
				PmsiTunnel: &api.PmsiTunnel{
					Type:  api.PMSI_TUNNEL_TYPE_INGRESS_REPL,
					Label: uint32(label),
				},
			}

			path.Attrs = append(path.Attrs, attr)
		default:
			return fmt.Errorf("usage: global rib add { macadv | multicast | ... -a evpn")
		}
		path.Nlri = &api.Nlri{
			Af:       rf,
			EvpnNlri: nlri,
		}
	case api.AF_ENCAP:
		if len(eArgs) < 3 {
			return fmt.Errorf("usage: global rib %s <end point ip address> [<vni>] -a encap", modtype)
		}
		prefix = eArgs[0]

		path.Nlri = &api.Nlri{
			Af:     rf,
			Prefix: prefix,
		}

		if len(eArgs) > 3 {
			vni, err := strconv.Atoi(eArgs[1])
			if err != nil {
				return fmt.Errorf("invalid vni: %s", eArgs[1])
			}
			subTlv := &api.TunnelEncapSubTLV{
				Type:  api.ENCAP_SUBTLV_TYPE_COLOR,
				Color: uint32(vni),
			}
			tlv := &api.TunnelEncapTLV{
				Type:   api.TUNNEL_TYPE_VXLAN,
				SubTlv: []*api.TunnelEncapSubTLV{subTlv},
			}
			attr := &api.PathAttr{
				Type:        api.BGP_ATTR_TYPE_TUNNEL_ENCAP,
				TunnelEncap: []*api.TunnelEncapTLV{tlv},
			}

			path.Attrs = append(path.Attrs, attr)
		}
	case api.AF_RTC:
		if !(len(eArgs) == 3 && eArgs[0] == "default") && len(eArgs) < 4 {
			return fmt.Errorf("usage: global rib add <asn> <local admin> -a rtc")
		}
		var asn, admin int

		if eArgs[0] != "default" {
			asn, err = strconv.Atoi(eArgs[0])
			if err != nil {
				return fmt.Errorf("invalid asn: %s", eArgs[0])
			}
			admin, err = strconv.Atoi(eArgs[1])
			if err != nil {
				return fmt.Errorf("invalid local admin: %s", eArgs[1])
			}
		}
		path.Nlri = &api.Nlri{
			Af: rf,
			RtNlri: &api.RTNlri{
				Target: &api.ExtendedCommunity{
					Type:       api.EXTENDED_COMMUNITIE_TYPE_TWO_OCTET_AS_SPECIFIC,
					Subtype:    api.EXTENDED_COMMUNITIE_SUBTYPE_ROUTE_TARGET,
					Asn:        uint32(asn),
					LocalAdmin: uint32(admin),
				},
			},
		}
	}
	switch modtype {
	case CMD_ADD:
		path.IsWithdraw = false
	case CMD_DEL:
		path.IsWithdraw = true
	}

	arg := &api.ModPathArguments{
		Resource: api.Resource_GLOBAL,
		Path:     path,
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
