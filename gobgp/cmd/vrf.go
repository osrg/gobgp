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
	"encoding/json"
	"fmt"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"io"
	"sort"
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
	if globalOpts.Quiet {
		for _, v := range vrfs {
			fmt.Println(v.Name)
		}
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
				exportRt = append(exportRt, buf)
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
				exitWithError(err)
			}
		},
	}

	for _, v := range []string{CMD_ADD, CMD_DEL} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				err := modPath(api.Resource_VRF, args[len(args)-1], cmd.Use, args[:len(args)-1])
				if err != nil {
					exitWithError(err)
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
				exitWithError(err)
			}
		},
	}

	for _, v := range []string{CMD_ADD, CMD_DEL} {
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

	return vrfCmd
}
