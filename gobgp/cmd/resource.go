// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
)

var resourceFile string

func run(cmd *cobra.Command, args []string) {
	var b []byte
	var err error
	if resourceFile == "-" {
		b, err = ioutil.ReadAll(os.Stdin)
	} else {
		b, err = ioutil.ReadFile(resourceFile)
	}
	if err != nil {
		exitWithError(err)
	}
	switch cmd.Use {
	case "create":
		err = client.Create(b)
	case "delete":
		err = client.Delete(b)
	}
	if err != nil {
		exitWithError(err)
	}
}

func NewCreateCmd() *cobra.Command {
	createCmd := &cobra.Command{
		Use: "create",
		Run: run,
	}
	createCmd.PersistentFlags().StringVarP(&resourceFile, "file", "f", "", "resource file path")
	return createCmd
}

func NewDeleteCmd() *cobra.Command {
	deleteCmd := &cobra.Command{
		Use: "delete",
		Run: run,
	}
	deleteCmd.PersistentFlags().StringVarP(&resourceFile, "file", "f", "", "resource file path")
	return deleteCmd
}
