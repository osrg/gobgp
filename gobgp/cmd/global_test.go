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
	"fmt"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func Test_ParsePath(t *testing.T) {
	assert := assert.New(t)
	buf := "10.0.0.0/24 rt 100:100 med 10 nexthop 10.0.0.1 aigp metric 10 local-pref 100"

	path, err := ParsePath(bgp.RF_IPv4_UC, strings.Split(buf, " "))
	assert.Nil(err)
	fmt.Println(path)
	i := 0
	for _, a := range path.GetPathAttrs() {
		assert.True(i < int(a.GetType()))
		i = int(a.GetType())
	}
}
