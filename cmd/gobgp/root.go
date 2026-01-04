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
	"context"
	"net/http"
	_ "net/http/pprof"
	"strconv"

	"github.com/osrg/gobgp/v4/api"
	"github.com/spf13/cobra"
)

var globalOpts struct {
	Host           string
	Port           int
	Target         string
	Debug          bool
	Quiet          bool
	Json           bool
	GenCmpl        bool
	BashCmplFile   string
	PprofPort      int
	TLS            bool
	ClientCertFile string
	ClientKeyFile  string
	CaFile         string
}

var (
	client api.GoBgpServiceClient
	ctx    context.Context
)

func newRootCmd() *cobra.Command {
	cobra.EnablePrefixMatching = true
	cleanup := func() {}

	rootCmd := &cobra.Command{
		Use: "gobgp",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if globalOpts.PprofPort > 0 {
				go func() {
					address := "localhost:" + strconv.Itoa(globalOpts.PprofPort)
					if err := http.ListenAndServe(address, nil); err != nil {
						exitWithError(err)
					}
				}()
			}

			if !globalOpts.GenCmpl {
				conn, err := newConn()
				if err != nil {
					exitWithError(err)
				}
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(context.Background())
				client = api.NewGoBgpServiceClient(conn)
				cleanup = func() {
					conn.Close()
					cancel()
				}
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if globalOpts.GenCmpl {
				return cmd.GenBashCompletionFile(globalOpts.BashCmplFile)
			}
			cmd.HelpFunc()(cmd, args)
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			defer cleanup()
		},
	}

	rootCmd.PersistentFlags().StringVarP(&globalOpts.Host, "host", "u", "127.0.0.1", "host")
	rootCmd.PersistentFlags().IntVarP(&globalOpts.Port, "port", "p", 50051, "port")
	rootCmd.PersistentFlags().StringVarP(&globalOpts.Target, "target", "", "", "alternative to host/port when using UDS. Examples: unix:///var/run/go-bgp.sock (absolute path) or unix:tmp/go-bgp.sock (relative to current directory).")
	rootCmd.PersistentFlags().BoolVarP(&globalOpts.Json, "json", "j", false, "use json format to output format")
	rootCmd.PersistentFlags().BoolVarP(&globalOpts.Debug, "debug", "d", false, "use debug")
	rootCmd.PersistentFlags().BoolVarP(&globalOpts.Quiet, "quiet", "q", false, "use quiet")
	rootCmd.PersistentFlags().BoolVarP(&globalOpts.GenCmpl, "gen-cmpl", "c", false, "generate completion file")
	rootCmd.PersistentFlags().StringVarP(&globalOpts.BashCmplFile, "bash-cmpl-file", "", "gobgp-completion.bash", "bash cmpl filename")
	rootCmd.PersistentFlags().IntVarP(&globalOpts.PprofPort, "pprof-port", "r", 0, "pprof port")
	rootCmd.PersistentFlags().BoolVarP(&globalOpts.TLS, "tls", "", false, "connection uses TLS if true, else plain TCP")
	rootCmd.PersistentFlags().StringVarP(&globalOpts.ClientCertFile, "tls-client-cert-file", "", "", "Optional file path to TLS client certificate")
	rootCmd.PersistentFlags().StringVarP(&globalOpts.ClientKeyFile, "tls-client-key-file", "", "", "Optional file path to TLS client key")
	rootCmd.PersistentFlags().StringVarP(&globalOpts.CaFile, "tls-ca-file", "", "", "The file containing the CA root cert file")

	globalCmd := newGlobalCmd()
	neighborCmd := newNeighborCmd()
	vrfCmd := newVrfCmd()
	policyCmd := newPolicyCmd()
	monitorCmd := newMonitorCmd()
	mrtCmd := newMrtCmd()
	rpkiCmd := newRPKICmd()
	bmpCmd := newBmpCmd()
	logLevelCmd := newLogLevelCmd()
	rootCmd.AddCommand(globalCmd, neighborCmd, vrfCmd, policyCmd, monitorCmd, mrtCmd, rpkiCmd, bmpCmd, logLevelCmd)
	return rootCmd
}
