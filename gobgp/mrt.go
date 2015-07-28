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

	af, err := checkAddressFamily(remoteIP)
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
		Af:              af,
		Interval:        interval,
		NeighborAddress: remoteIP.String(),
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
		Af:              af.ShortString(),
		NeighborAddress: remoteIP.String(),
		Resource:        r,
	}

	stream, err := client.GetMrt(context.Background(), arg)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
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
			fmt.Println(err)
			os.Exit(1)
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
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println("mrt dump:", filepath.Clean(filename))
	}
	return nil
}

func NewMrtCmd() *cobra.Command {

	globalCmd := &cobra.Command{
		Use: CMD_GLOBAL,
		Run: func(cmd *cobra.Command, args []string) {
			err := dumpRib(CMD_GLOBAL, net.IP{}, args)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	neighborCmd := &cobra.Command{
		Use: CMD_NEIGHBOR,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				fmt.Println("usage: gobgp mrt dump neighbor <neighbor address> [<interval>]")
				os.Exit(1)
			}
			remoteIP := net.ParseIP(args[0])
			if remoteIP == nil {
				fmt.Println("invalid ip address:", args[0])
				os.Exit(1)
			}
			err := dumpRib(CMD_LOCAL, remoteIP, args[1:])
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	ribCmd := &cobra.Command{
		Use: CMD_RIB,
	}
	ribCmd.AddCommand(globalCmd, neighborCmd)
	ribCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")

	dumpCmd := &cobra.Command{
		Use: CMD_DUMP,
	}
	dumpCmd.AddCommand(ribCmd)
	dumpCmd.PersistentFlags().StringVarP(&mrtOpts.OutputDir, "outdir", "o", ".", "output directory")
	dumpCmd.PersistentFlags().StringVarP(&mrtOpts.FileFormat, "format", "f", "", "file format")

	mrtCmd := &cobra.Command{
		Use: CMD_MRT,
	}
	mrtCmd.AddCommand(dumpCmd)

	return mrtCmd
}
