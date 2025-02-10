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
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	apb "google.golang.org/protobuf/types/known/anypb"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

func getVrfs() ([]*api.Vrf, error) {
	stream, err := client.ListVrf(ctx, &api.ListVrfRequest{})
	if err != nil {
		return nil, err
	}
	vrfs := make([]*api.Vrf, 0)
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		vrfs = append(vrfs, r.Vrf)
	}
	sort.Slice(vrfs, func(i, j int) bool {
		return vrfs[i].Name < vrfs[j].Name
	})
	return vrfs, nil
}

func showVrfs() error {
	maxLens := []int{20, 20, 20, 20, 20, 5, 20, 5}
	vrfs, err := getVrfs()
	if err != nil {
		return err
	}
	if globalOpts.Json {
		j, _ := json.Marshal(vrfs)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		for _, v := range vrfs {
			fmt.Println(v.Name)
		}
		return nil
	}
	lines := make([][]string, 0, len(vrfs))
	for _, v := range vrfs {
		name := v.Name
		rd, err := apiutil.UnmarshalRD(v.Rd)
		if err != nil {
			return err
		}
		rdStr := rd.String()

		f := func(rts []*apb.Any) (string, error) {
			ret := make([]string, 0, len(rts))
			for _, an := range rts {
				rt, err := apiutil.UnmarshalRT(an)
				if err != nil {
					return "", err
				}
				ret = append(ret, rt.String())
			}
			return strings.Join(ret, ", "), nil
		}

		importRts, err := f(v.ImportRt)
		if err != nil {
			return err
		}
		exportRts, err := f(v.ExportRt)
		if err != nil {
			return err
		}
		lines = append(lines, []string{name, rdStr, importRts, exportRts, v.RoutersMac, fmt.Sprintf("%d", v.Id), fmt.Sprintf("%v", v.ImportAsEvpnIpprefix), fmt.Sprintf("%d", v.EthernetTag)})

		for i, v := range []int{len(name), len(rdStr), len(importRts), len(exportRts), len(v.RoutersMac)} {
			if v > maxLens[i] {
				maxLens[i] = v + 4
			}
		}

	}
	format := fmt.Sprintf("  %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds\n", maxLens[0], maxLens[1], maxLens[2], maxLens[3], maxLens[4], maxLens[5], maxLens[6], maxLens[7])
	fmt.Printf(format, "Name", "RD", "Import RT", "Export RT", "Router's MAC", "ID", "Import as EVPN", "Ethernet Tag")
	for _, l := range lines {
		fmt.Printf(format, l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7])
	}
	return nil
}

func showVrfRib(name string) error {
	return showNeighborRib(cmdVRF, name, nil)
}

func modVrf(typ string, args []string) error {
	switch typ {
	case cmdAdd:
		a, err := extractReserved(args, map[string]int{
			"rd":             paramSingle,
			"rt":             paramList,
			"id":             paramSingle,
			"import-as-evpn": paramFlag,
			"routers-mac":    paramSingle,
			"ethernet-tag":   paramSingle,
		})
		if err != nil || len(a[""]) != 1 || len(a["rd"]) != 1 || len(a["rt"]) < 2 {
			//lint:ignore ST1005 cli example
			return fmt.Errorf("usage: gobgp vrf add <vrf name> [ id <id> ] rd <rd> rt { import | export | both } <rt>...")
		}
		name := a[""][0]
		var rd bgp.RouteDistinguisherInterface
		rd, err = bgp.ParseRouteDistinguisher(a["rd"][0])
		if err != nil {
			return err
		}
		cur := ""
		importRt := make([]bgp.ExtendedCommunityInterface, 0)
		exportRt := make([]bgp.ExtendedCommunityInterface, 0)
		for _, elem := range a["rt"] {
			if elem == "import" || elem == "export" || elem == "both" {
				cur = elem
				continue
			}
			rt, err := bgp.ParseRouteTarget(elem)
			if err != nil {
				return err
			}
			switch cur {
			case "import":
				importRt = append(importRt, rt)
			case "export":
				exportRt = append(exportRt, rt)
			case "both":
				importRt = append(importRt, rt)
				exportRt = append(exportRt, rt)
			default:
				//lint:ignore ST1005 cli example
				return fmt.Errorf("usage: gobgp vrf add <vrf name> [ id <id> ] rd <rd> rt { import | export | both } <rt>...")
			}
		}
		var id uint64
		if len(a["id"]) > 0 {
			id, err = strconv.ParseUint(a["id"][0], 10, 32)
			if err != nil {
				return err
			}
		}
		v, _ := apiutil.MarshalRD(rd)
		irt, _ := apiutil.MarshalRTs(importRt)
		ert, _ := apiutil.MarshalRTs(exportRt)

		var etag uint64
		if len(a["ethernet-tag"]) > 0 {
			etag, err = strconv.ParseUint(a["ethernet-tag"][0], 10, 32)
			if err != nil {
				return err
			}
		}

		importAsEVPN := false
		if _, ok := a["import-as-evpn"]; ok {
			importAsEVPN = true
		}

		routersMac := ""
		if mac, ok := a["routers-mac"]; ok {
			if _, err := net.ParseMAC(mac[0]); err != nil {
				return fmt.Errorf("invalid router's mac: %q", mac[0])
			}
			routersMac = mac[0]
		}

		_, err = client.AddVrf(ctx, &api.AddVrfRequest{
			Vrf: &api.Vrf{
				Name:                 name,
				Rd:                   v,
				ImportRt:             irt,
				ExportRt:             ert,
				Id:                   uint32(id),
				ImportAsEvpnIpprefix: importAsEVPN,
				RoutersMac:           routersMac,
				EthernetTag:          uint32(etag),
			},
		})
		return err
	case cmdDel:
		if len(args) != 1 {
			return fmt.Errorf("usage: gobgp vrf del <vrf name>")
		}
		_, err := client.DeleteVrf(ctx, &api.DeleteVrfRequest{
			Name: args[0],
		})
		return err
	}
	return nil
}

func newVrfCmd() *cobra.Command {
	ribCmd := &cobra.Command{
		Use: cmdRib,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if len(args) == 1 {
				err = showVrfRib(args[0])
			} else {
				err = fmt.Errorf("usage: gobgp vrf <vrf-name> rib")
			}
			if err != nil {
				exitWithError(err)
			}
		},
	}

	for _, v := range []string{cmdAdd, cmdDel} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				err := modPath(cmdVRF, args[len(args)-1], cmd.Use, args[:len(args)-1])
				if err != nil {
					exitWithError(err)
				}
			},
		}
		ribCmd.AddCommand(cmd)
	}

	neighborCmd := &cobra.Command{
		Use: cmdNeighbor,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if len(args) == 1 {
				var vs []*api.Vrf
				vs, err = getVrfs()
				if err != nil {
					exitWithError(err)
				}
				found := false
				for _, v := range vs {
					if v.Name == args[0] {
						found = true
						break
					}
				}
				if !found {
					err = fmt.Errorf("vrf %s not found", args[0])
				} else {
					err = showNeighbors(args[0])
				}
			} else {
				err = fmt.Errorf("usage: gobgp vrf <vrf-name> neighbor")
			}
			if err != nil {
				exitWithError(err)
			}
		},
	}

	vrfCmdImpl := &cobra.Command{}
	vrfCmdImpl.AddCommand(ribCmd, neighborCmd)

	vrfCmd := &cobra.Command{
		Use: cmdVRF,
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
				exitWithError(err)
			}
		},
	}

	for _, v := range []string{cmdAdd, cmdDel} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				err := modVrf(cmd.Use, args)
				if err != nil {
					exitWithError(err)
				}
			},
		}
		vrfCmd.AddCommand(cmd)
	}
	vrfCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")

	summaryCmd := &cobra.Command{
		Use: cmdSummary,
		Run: func(cmd *cobra.Command, args []string) {
			if err := showRibInfo(cmdVRF, args[0]); err != nil {
				exitWithError(err)
			}
		},
	}
	ribCmd.AddCommand(summaryCmd)

	return vrfCmd
}
