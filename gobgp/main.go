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
	"github.com/jessevdk/go-flags"
	"os"
)

var globalOpts struct {
	Host  string `short:"u" long:"url" description:"specifying an url" default:"127.0.0.1"`
	Port  int    `short:"p" long:"port" description:"specifying a port" default:"8080"`
	Debug bool   `short:"d" long:"debug" description:"use debug"`
	Quiet bool   `short:"q" long:"quiet" description:"use quiet"`
	Json  bool   `short:"j" long:"json" description:"use json format to output format"`
}

var cmds []string

func main() {
	cmds = []string{CMD_GLOBAL, CMD_NEIGHBOR, CMD_POLICY, CMD_RIB, CMD_ADD, CMD_DEL, CMD_ALL, CMD_LOCAL, CMD_ADJ_IN,
		CMD_ADJ_OUT, CMD_RESET, CMD_SOFT_RESET, CMD_SOFT_RESET_IN, CMD_SOFT_RESET_OUT, CMD_SHUTDOWN, CMD_ENABLE,
		CMD_DISABLE, CMD_PREFIX, CMD_ROUTEPOLICY, CMD_CONDITIONS, CMD_ACTIONS, CMD_IMPORT, CMD_EXPORT}

	eArgs := extractArgs("")
	parser := flags.NewParser(&globalOpts, flags.Default)
	parser.AddCommand(CMD_GLOBAL, "subcommand for global", "", &GlobalCommand{})
	parser.AddCommand(CMD_NEIGHBOR, "subcommand for neighbor", "", &NeighborCommand{})
	parser.AddCommand(CMD_POLICY, "subcommand for policy", "", &PolicyCommand{})
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}

}
