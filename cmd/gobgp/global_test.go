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
	"net/netip"
	"strings"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

func Test_ParsePath(t *testing.T) {
	assert := assert.New(t)
	buf := "10.0.0.0/24 rt 100:100 med 10 nexthop 10.0.0.1 aigp metric 10 local-pref 100"

	path, err := parsePath(bgp.RF_IPv4_UC, strings.Split(buf, " "))
	assert.NoError(err)
	i := 0
	attrs, _ := apiutil.GetNativePathAttributes(path)
	for _, a := range attrs {
		assert.True(i < int(a.GetType()))
		i = int(a.GetType())
	}
}

func Test_ParseEvpnPath(t *testing.T) {
	tests := []struct {
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
			assert.NoError(err)
			i := 0
			attrs, _ := apiutil.GetNativePathAttributes(path)
			for _, a := range attrs {
				assert.True(i < int(a.GetType()))
				i = int(a.GetType())
			}
		})
	}
}

func Test_ParseFlowSpecPath(t *testing.T) {
	tests := []struct {
		name        string
		rf          bgp.Family
		path        string
		expectedErr bool
	}{
		{"FlowSpec Redirect OK: All SRv6 Policy parameters specified", bgp.RF_FS_IPv6_UC, "match destination 2001:db8::/64 then redirect fd00:1::1:0 color 100 prefix 2001:db8:2:2::/64 locator-node-length 24 function-length 16 behavior END_DT6", false},
		{"FlowSpec Redirect OK: Only color specified", bgp.RF_FS_IPv6_UC, "match destination 2001:db8::/64 then redirect fd00:1::1:0 color 100", false},
		{"FlowSpec Redirect OK: No color specified", bgp.RF_FS_IPv6_UC, "match destination 2001:db8::/64 then redirect fd00:1::1:0", false},
		{"FlowSpec Redirect NG: Missing 'color' of SR Policy", bgp.RF_FS_IPv6_UC, "match destination 2001:db8::/64 then redirect fd00:1::1:0 prefix 2001:db8:2:2::/64 locator-node-length 24 function-length 16 behavior END_DT6", true},
		{"FlowSpec Redirect NG: Missing 'behavior' of SR Policy", bgp.RF_FS_IPv6_UC, "match destination 2001:db8::/64 then redirect fd00:1::1:0 color 100 prefix 2001:db8:2:2::/64 locator-node-length 24 function-length 16", true},
		{"FlowSpec Redirect NG: Wrong action", bgp.RF_FS_IPv6_UC, "match destination 2001:db8::/64 then accept color 100 prefix 2001:db8:2:2::/64 locator-node-length 24 function-length 16 behavior END_DT6", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			path, err := parsePath(tt.rf, strings.Split(tt.path, " "))
			if tt.expectedErr {
				assert.NotNil(err)
			} else {
				assert.NoError(err)
				i := 0
				attrs, _ := apiutil.GetNativePathAttributes(path)
				for _, a := range attrs {
					assert.True(i < int(a.GetType()))
					i = int(a.GetType())
				}
			}
		})
	}
}

func Test_ParseLsLinkPathDelayMetricTLVs(t *testing.T) {
	assert := assert.New(t)

	args := strings.Split("link protocol 1 identifier 1 local-asn 65000 local-bgp-router-id 1.1.1.1 remote-asn 65001 remote-bgp-router-id 2.2.2.2 unidirectional-link-delay 8516 unidirectional-link-delay-anomalous min-unidirectional-link-delay 8511 max-unidirectional-link-delay 8527 min-max-unidirectional-link-delay-anomalous unidirectional-delay-variation 51", " ")
	path, err := parsePath(bgp.RF_LS, args)
	assert.NoError(err)
	assert.NotNil(path)

	attrs, err := apiutil.GetNativePathAttributes(path)
	assert.NoError(err)
	assert.NotEmpty(attrs)

	var lsAttr *bgp.PathAttributeLs
	for _, a := range attrs {
		if v, ok := a.(*bgp.PathAttributeLs); ok {
			lsAttr = v
			break
		}
	}

	if assert.NotNil(lsAttr) {
		extracted := lsAttr.Extract()

		if assert.NotNil(extracted.Link.UnidirectionalLinkDelay) {
			assert.Equal(uint32(8516), extracted.Link.UnidirectionalLinkDelay.Delay)
			assert.True(extracted.Link.UnidirectionalLinkDelay.Flags.Anomalous)
		}

		if assert.NotNil(extracted.Link.MinMaxUnidirectionalLinkDelay) {
			assert.Equal(uint32(8511), extracted.Link.MinMaxUnidirectionalLinkDelay.MinDelay)
			assert.Equal(uint32(8527), extracted.Link.MinMaxUnidirectionalLinkDelay.MaxDelay)
			assert.True(extracted.Link.MinMaxUnidirectionalLinkDelay.Flags.Anomalous)
		}

		if assert.NotNil(extracted.Link.UnidirectionalDelayVariation) {
			assert.Equal(uint32(51), *extracted.Link.UnidirectionalDelayVariation)
		}
	}
}

func Test_ParseLsLinkPathDelayMetricTLVsMinGreaterThanMax(t *testing.T) {
	assert := assert.New(t)

	args := strings.Split("link protocol 1 identifier 1 local-asn 65000 local-bgp-router-id 1.1.1.1 remote-asn 65001 remote-bgp-router-id 2.2.2.2 min-unidirectional-link-delay 8527 max-unidirectional-link-delay 8511", " ")
	path, err := parsePath(bgp.RF_LS, args)
	assert.Error(err)
	assert.Nil(path)
	assert.Contains(err.Error(), "min must be <= max")
}

func Test_mupParser(t *testing.T) {
	ipv4Addr := netip.MustParseAddr("10.0.0.1")
	ipv4DirectExt, _ := bgp.NewMUPIPv4AddressSpecificExtended(bgp.EC_SUBTYPE_MUP_DIRECT_SEG_IPV4, ipv4Addr, 100)
	ipv4InterworkExt, _ := bgp.NewMUPIPv4AddressSpecificExtended(bgp.EC_SUBTYPE_MUP_INTERWORK_SEG_IPV4, ipv4Addr, 100)

	tests := []struct {
		name    string
		args    []string
		want    bgp.ExtendedCommunityInterface
		wantErr bool
	}{
		{"direct 2-octet AS (default keyword)", []string{"mup", "10:10"}, bgp.NewMUPExtended(bgp.EC_SUBTYPE_MUP_DIRECT_SEG, 10, 10), false},
		{"direct 2-octet AS (explicit keyword)", []string{"mup", "direct", "10:20"}, bgp.NewMUPExtended(bgp.EC_SUBTYPE_MUP_DIRECT_SEG, 10, 20), false},
		{"direct IPv4", []string{"mup", "10.0.0.1:100"}, ipv4DirectExt, false},
		{"direct 4-octet AS (plain integer)", []string{"mup", "70000:100"}, bgp.NewMUPFourOctetAsSpecificExtended(bgp.EC_SUBTYPE_MUP_DIRECT_SEG_4_OCTET_AS, 70000, 100), false},
		{"direct 4-octet AS (AS-dot notation)", []string{"mup", "1.100:100"}, bgp.NewMUPFourOctetAsSpecificExtended(bgp.EC_SUBTYPE_MUP_DIRECT_SEG_4_OCTET_AS, 1<<16|100, 100), false},
		{"interwork 2-octet AS", []string{"mup", "interwork", "10:20"}, bgp.NewMUPExtended(bgp.EC_SUBTYPE_MUP_INTERWORK_SEG, 10, 20), false},
		{"interwork IPv4", []string{"mup", "interwork", "10.0.0.1:100"}, ipv4InterworkExt, false},
		{"interwork 4-octet AS", []string{"mup", "interwork", "70000:100"}, bgp.NewMUPFourOctetAsSpecificExtended(bgp.EC_SUBTYPE_MUP_INTERWORK_SEG_4_OCTET_AS, 70000, 100), false},
		{"invalid global admin", []string{"mup", "abc:100"}, nil, true},
		{"local admin overflow (2-octet AS form)", []string{"mup", "10:99999999999"}, nil, true},
		{"local admin overflow (IPv4 form)", []string{"mup", "10.0.0.1:99999"}, nil, true},
		{"invalid segment type keyword", []string{"mup", "badkeyword", "10:10"}, nil, true},
		{"missing colon", []string{"mup", "1000"}, nil, true},
		{"too few args", []string{"mup"}, nil, true},
		{"too many args", []string{"mup", "direct", "10:10", "extra"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			exts, err := mupParser(tt.args)
			if tt.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			if assert.Len(exts, 1) {
				assert.Equal(tt.want, exts[0])
			}
		})
	}
}

func Test_ParseMUPType2SessionTransformedRouteArgsTLVs(t *testing.T) {
	base := []string{"10.0.0.1", "rd", "1.1.1.1:65000", "rt", "65000:1", "endpoint-address-length", "32", "teid", "100", "mup", "10:10"}
	sessionTeid, _ := parseTeid("300")
	interworkAddr := netip.MustParseAddr("10.0.0.2")
	sourceAddr := netip.MustParseAddr("10.0.0.3")

	tests := []struct {
		name      string
		extraArgs []string
		wantErr   bool
		wantTLVs  []bgp.MUPTLVInterface
	}{
		{
			name:      "session-teid and session-qfi",
			extraArgs: []string{"session-teid", "300", "session-qfi", "5"},
			wantTLVs:  []bgp.MUPTLVInterface{bgp.NewMUPSessionParametersTLV(sessionTeid, 5)},
		},
		{
			name:      "interwork-endpoint",
			extraArgs: []string{"interwork-endpoint", "10.0.0.2"},
			wantTLVs:  []bgp.MUPTLVInterface{bgp.NewMUPInterworkEndpointTLV(interworkAddr)},
		},
		{
			name:      "source-address",
			extraArgs: []string{"source-address", "10.0.0.3"},
			wantTLVs:  []bgp.MUPTLVInterface{bgp.NewMUPSourceAddressTLV(sourceAddr)},
		},
		{
			name:      "all three TLVs",
			extraArgs: []string{"session-teid", "300", "session-qfi", "5", "interwork-endpoint", "10.0.0.2", "source-address", "10.0.0.3"},
			wantTLVs: []bgp.MUPTLVInterface{
				bgp.NewMUPSessionParametersTLV(sessionTeid, 5),
				bgp.NewMUPInterworkEndpointTLV(interworkAddr),
				bgp.NewMUPSourceAddressTLV(sourceAddr),
			},
		},
		{
			name:      "session-teid without session-qfi",
			extraArgs: []string{"session-teid", "300"},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			args := append(append([]string{}, base...), tt.extraArgs...)
			nlri, _, _, err := parseMUPType2SessionTransformedRouteArgs(args, bgp.AFI_IP)
			if tt.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			mupNlri, ok := nlri.(*bgp.MUPNLRI)
			if !assert.True(ok) {
				return
			}
			route, ok := mupNlri.RouteTypeData.(*bgp.MUPType2SessionTransformedRoute)
			if !assert.True(ok) {
				return
			}
			assert.Equal(tt.wantTLVs, route.TLVs)
		})
	}
}

func Test_ParseMUPType2SessionTransformedRouteArgsMUPExtcomm(t *testing.T) {
	assert := assert.New(t)
	args := []string{
		"10.0.0.1", "rd", "1.1.1.1:65000", "rt", "65000:1",
		"endpoint-address-length", "32", "teid", "100",
		"mup", "interwork", "10.0.0.2:100",
	}
	_, _, extcomms, err := parseMUPType2SessionTransformedRouteArgs(args, bgp.AFI_IP)
	assert.NoError(err)
	assert.Equal([]string{"rt", "65000:1", "mup", "interwork", "10.0.0.2:100"}, extcomms)

	exts, err := parseExtendedCommunities(extcomms)
	assert.NoError(err)
	want, _ := bgp.NewMUPIPv4AddressSpecificExtended(bgp.EC_SUBTYPE_MUP_INTERWORK_SEG_IPV4, netip.MustParseAddr("10.0.0.2"), 100)
	assert.Contains(exts, bgp.ExtendedCommunityInterface(want))
}
