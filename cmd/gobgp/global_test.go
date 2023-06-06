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

package main

import (
	"strings"
	"testing"

	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

func Test_ParsePath(t *testing.T) {
	assert := assert.New(t)
	buf := "10.0.0.0/24 rt 100:100 med 10 nexthop 10.0.0.1 aigp metric 10 local-pref 100"

	path, err := parsePath(bgp.RF_IPv4_UC, strings.Split(buf, " "))
	assert.Nil(err)
	i := 0
	attrs, _ := apiutil.GetNativePathAttributes(path)
	for _, a := range attrs {
		assert.True(i < int(a.GetType()))
		i = int(a.GetType())
	}
}

func Test_ParseEvpnPath(t *testing.T) {
	var tests = []struct {
		name string
		path string
	}{
		{"Ethernet Auto-Discovery", "a-d esi LACP aa:bb:cc:dd:ee:ff 100 etag 200 label 300 rd 1.1.1.1:65000 rt 65000:200 encap vxlan esi-label 400 single-active"},
		{"MAC/IP Advertisement", "macadv aa:bb:cc:dd:ee:ff 10.0.0.1 esi AS 65000 100 etag 200 label 300 rd 1.1.1.1:65000 rt 65000:400 encap vxlan default-gateway"},
		{"I-PMSI", "i-pmsi etag 100 rd 1.1.1.1:65000 rt 65000:200 encap vxlan pmsi ingress-repl 100 1.1.1.1"},
		{"IP Prefix", "prefix 10.0.0.0/24 172.16.0.1 esi MSTP aa:aa:aa:aa:aa:aa 100 etag 200 label 300 rd 1.1.1.1:65000 rt 65000:200 encap vxlan router-mac bb:bb:bb:bb:bb:bb"},
		{"Multicast", "multicast 10.0.0.1 etag 100 rd 1.1.1.1:65000 rt 65000:200 encap vxlan pmsi ingress-repl 100 1.1.1.1"},
		{"Ethernet Segment Identifier", "esi 10.0.0.1 esi MAC aa:bb:cc:dd:ee:ff 100 rd 1.1.1.1:65000 rt 65000:200 encap vxlan"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			path, err := parsePath(bgp.RF_EVPN, strings.Split(tt.path, " "))
			assert.Nil(err)
			i := 0
			attrs, _ := apiutil.GetNativePathAttributes(path)
			for _, a := range attrs {
				assert.True(i < int(a.GetType()))
				i = int(a.GetType())
			}
		})
	}
}
