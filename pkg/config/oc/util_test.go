// Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectConfigFileType(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("toml", detectConfigFileType("bgpd.conf", "toml"))
	assert.Equal("toml", detectConfigFileType("bgpd.toml", "xxx"))
	assert.Equal("yaml", detectConfigFileType("bgpd.yaml", "xxx"))
	assert.Equal("yaml", detectConfigFileType("bgpd.yml", "xxx"))
	assert.Equal("json", detectConfigFileType("bgpd.json", "xxx"))
}

func TestIsAfiSafiChanged(t *testing.T) {
	v4 := AfiSafi{
		Config: AfiSafiConfig{
			AfiSafiName: AFI_SAFI_TYPE_IPV4_UNICAST,
		},
	}
	v6 := AfiSafi{
		Config: AfiSafiConfig{
			AfiSafiName: AFI_SAFI_TYPE_IPV6_UNICAST,
		},
	}
	old := []AfiSafi{v4}
	new := []AfiSafi{v4}
	assert.False(t, isAfiSafiChanged(old, new))

	new = append(new, v6)
	assert.True(t, isAfiSafiChanged(old, new))

	new = []AfiSafi{v6}
	assert.True(t, isAfiSafiChanged(old, new))
	v4ap := v4
	v4ap.AddPaths.Config.Receive = true
	new = []AfiSafi{v4ap}
	assert.True(t, isAfiSafiChanged(old, new))
}
