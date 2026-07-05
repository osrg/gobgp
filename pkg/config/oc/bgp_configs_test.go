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

package oc

import (
	"bufio"
	"net/netip"
	"os"
	"path"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEqual(t *testing.T) {
	assert := assert.New(t)
	p1 := Prefix{
		IpPrefix:        netip.MustParsePrefix("192.168.0.0/24"),
		MasklengthRange: "24..32",
	}
	p2 := Prefix{
		IpPrefix:        netip.MustParsePrefix("192.168.0.0/24"),
		MasklengthRange: "24..32",
	}
	assert.True(p1.Equal(&p2))
	assert.False(p1.Equal(nil))
	var p3 *Prefix
	assert.False(p3.Equal(&p1))
	p3 = &Prefix{
		IpPrefix:        netip.MustParsePrefix("192.168.0.0/24"),
		MasklengthRange: "24..32",
	}
	assert.True(p3.Equal(&p1))
	p3.IpPrefix = netip.MustParsePrefix("10.10.0.0/24")
	assert.False(p3.Equal(&p1))
	ps1 := PrefixSet{
		PrefixSetName: "ps",
		PrefixList:    []Prefix{p1, p2},
	}
	ps2 := PrefixSet{
		PrefixSetName: "ps",
		PrefixList:    []Prefix{p2, p1},
	}
	assert.True(ps1.Equal(&ps2))
	ps2.PrefixSetName = "ps2"
	assert.False(ps1.Equal(&ps2))
}

func extractTomlFromMarkdown(fileMd string) (string, error) {
	fMd, err := os.Open(fileMd)
	if err != nil {
		return "", err
	}
	defer fMd.Close()

	var tomlString strings.Builder

	isBody := false
	scanner := bufio.NewScanner(fMd)

	for scanner.Scan() {
		if curText := scanner.Text(); strings.HasPrefix(curText, "```toml") {
			isBody = true
		} else if strings.HasPrefix(curText, "```") {
			isBody = false
		} else if isBody {
			if _, err := tomlString.WriteString(curText); err != nil {
				return "", err
			}
			if _, err := tomlString.WriteString("\n"); err != nil {
				return "", err
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return tomlString.String(), nil
}

func saveTomlToFile(fileToml string, tomlString string) error {
	fToml, err := os.Create(fileToml)
	if err != nil {
		return err
	}
	defer fToml.Close()

	_, err = fToml.WriteString(tomlString)

	return err
}

func TestConfigExample(t *testing.T) {
	assert := assert.New(t)

	_, f, _, _ := runtime.Caller(0)
	fileMd := path.Join(path.Dir(f), "../../../docs/sources/configuration.md")
	fileToml := "/tmp/gobgpd.example.toml"

	tomlString, err := extractTomlFromMarkdown(fileMd)
	assert.NoError(err)

	assert.NoError(saveTomlToFile(fileToml, tomlString))
	defer os.Remove(fileToml)

	c, err := ReadConfigfile(fileToml, "")
	assert.NoError(err)

	// Test if we can set the parameters for a peer-group
	for _, peerGroup := range c.PeerGroups {
		if peerGroup.Config.PeerGroupName != "my-peer-group" {
			continue
		}

		assert.True(peerGroup.Config.SendSoftwareVersion)
	}

	// Test if the peer-group inheritance works for neighbors
	for _, neighbor := range c.Neighbors {
		if neighbor.Config.PeerGroup != "my-peer-group" {
			continue
		}

		assert.True(neighbor.Config.SendSoftwareVersion)
	}
}

func TestConfigError(t *testing.T) {
	assert := assert.New(t)

	_, f, _, _ := runtime.Caller(0)
	fileMd := path.Join(path.Dir(f), "../../../docs/sources/configuration.md")
	fileToml := "/tmp/gobgpd.example.toml"

	tomlString, err := extractTomlFromMarkdown(fileMd)
	assert.NoError(err)

	invlalidToml := strings.Replace(tomlString, "port = 1790", "port-OOPS = 1790", 1)

	assert.NoError(saveTomlToFile(fileToml, invlalidToml))
	defer os.Remove(fileToml)

	_, err = ReadConfigfile(fileToml, "")
	assert.Error(err)

	expectedErr := "decoding failed due to the following error(s):\n\n'global.config' has invalid keys: port-oops"
	assert.Equal(err.Error(), expectedErr)
}
