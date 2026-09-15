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
	"github.com/stretchr/testify/require"
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

func Test_ParseEvpnIPMSIPathRequiresRouteTarget(t *testing.T) {
	assert := assert.New(t)

	path, err := parsePath(
		bgp.RF_EVPN,
		strings.Split("i-pmsi etag 100 rd 1.1.1.1:65000 encap vxlan pmsi ingress-repl 100 1.1.1.1", " "),
	)

	assert.Error(err)
	assert.Nil(path)
	assert.Contains(err.Error(), "specify rt")
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

func Test_ParseRtcArgs(t *testing.T) {
	assert := assert.New(t)
	tests := []struct {
		args   string
		asn    uint32
		str    string
		length uint8
		rtNil  bool
	}{
		{"65000:65000:100", 65000, "65000:65000:100/96", 96, false},
		{"65000:65000:100/96", 65000, "65000:65000:100/96", 96, false},
		{"65000:65000:0/64", 65000, "65000:65000:0/64", 64, false},
		{"65000:1.1.1.1:0/80", 65000, "65000:1.1.1.1:0/80", 80, false},
		{"asn 65000 rt 65000:100", 65000, "65000:65000:100/96", 96, false},
		{"default", 0, "0:0:0/0", 0, true},
		{"0:0:0/0", 0, "0:0:0/0", 0, true},
		{"0:0:0", 0, "0:0:0/96", 96, false},
	}
	for _, tt := range tests {
		t.Run("RtcArgs/"+tt.args, func(t *testing.T) {
			nlri, err := parseRtcArgs(strings.Split(tt.args, " "))
			assert.NoError(err)
			r := nlri.(*bgp.RouteTargetMembershipNLRI)
			assert.Equal(tt.asn, r.AS)
			assert.Equal(tt.str, r.String())
			assert.Equal(tt.length, r.Length)
			assert.Equal(tt.rtNil, r.RouteTarget == nil)
		})
	}
}

func Test_ParseFlowSpecRedirectToIP(t *testing.T) {
	assert := assert.New(t)

	for _, tc := range []struct {
		name string
		args string
		copy bool
		want string
	}{
		{"IPv4", "redirect-to-ip 198.51.100.11", false, "redirect-to-ip: 198.51.100.11"},
		{"IPv4 copy", "redirect-to-ip 198.51.100.11 copy", true, "copy-to-ip: 198.51.100.11"},
		{"IPv6", "redirect-to-ip 2001:db8:1::1", false, "redirect-to-ip: 2001:db8:1::1"},
		{"IPv6 copy", "redirect-to-ip 2001:db8:1::1 copy", true, "copy-to-ip: 2001:db8:1::1"},
		{"IPv4-mapped is an IPv4 target", "redirect-to-ip ::ffff:198.51.100.11", false, "redirect-to-ip: 198.51.100.11"},
	} {
		exts, err := parseExtendedCommunities(strings.Split(tc.args, " "))
		assert.NoError(err, tc.name)
		assert.Len(exts, 1, tc.name)
		switch e := exts[0].(type) {
		case *bgp.FlowSpecRedirectToIPv4Extended:
			assert.Equal(tc.copy, e.IsCopy(), tc.name)
			assert.Equal(tc.want, e.String(), tc.name)
		case *bgp.FlowSpecRedirectToIPv6Extended:
			assert.Equal(tc.copy, e.IsCopy(), tc.name)
			assert.Equal(tc.want, e.String(), tc.name)
		default:
			assert.Fail("unexpected type", "%s: %T", tc.name, exts[0])
		}
	}

	for _, bad := range []string{
		"redirect-to-ip",
		"redirect-to-ip not-an-address",
		"redirect-to-ip 198.51.100.11 mirror",
		"redirect-to-ip 198.51.100.11 copy extra",
	} {
		_, err := parseExtendedCommunities(strings.Split(bad, " "))
		assert.Error(err, bad)
	}

	// "redirect" must keep meaning rt-redirect.
	exts, err := parseExtendedCommunities(strings.Split("redirect 10.0.0.1:100", " "))
	assert.NoError(err)
	assert.Len(exts, 1)
	_, isNew := exts[0].(*bgp.FlowSpecRedirectToIPv4Extended)
	assert.False(isNew, "plain redirect must not produce the redirect-to-ip action")
}

func Test_ParseLsArgsRequiresKeywords(t *testing.T) {
	// Every case gives enough arguments to pass the per-type minimum, so the
	// error must come from the missing keyword and not from the argument count.
	cases := []struct {
		args string
		want string
	}{
		{"node identifier 1 local-asn 65000 local-bgp-ls-id 0", "specify protocol"},
		{"node protocol 2 local-asn 65000 local-bgp-ls-id 0", "specify identifier"},
		{"link identifier 1 local-asn 65000 local-bgp-router-id 1.1.1.1 remote-asn 65001 remote-bgp-router-id 2.2.2.2", "specify protocol"},
		{"link protocol 2 local-asn 65000 local-bgp-router-id 1.1.1.1 remote-asn 65001 remote-bgp-router-id 2.2.2.2", "specify identifier"},
		{"prefixv6 identifier 1 local-asn 65000 local-bgp-ls-id 0 ip-reachability-info fc00::/64", "specify protocol"},
		{"prefixv6 protocol 2 local-asn 65000 local-bgp-ls-id 0 ip-reachability-info fc00::/64", "specify identifier"},
		{"srv6sid identifier 1 local-asn 65000 local-bgp-ls-id 0 local-bgp-router-id 1.1.1.1 sids fd00::1", "specify protocol"},
		{"srv6sid protocol 2 local-asn 65000 local-bgp-ls-id 0 local-bgp-router-id 1.1.1.1 sids fd00::1", "specify identifier"},
		{"srv6sid protocol 2 identifier 1 local-asn 65000 local-bgp-ls-id 0 local-bgp-router-id 1.1.1.1", "specify sids"},
	}
	for _, c := range cases {
		t.Run(c.args, func(t *testing.T) {
			// A panic here would abort the whole test binary, so catch it and
			// fail only this subtest.
			assert.NotPanics(t, func() {
				_, _, err := parseLsArgs(strings.Split(c.args, " "))
				assert.ErrorContains(t, err, c.want)
			})
		})
	}
}

func Test_ParseLsSrv6SIDMultiTopoID(t *testing.T) {
	base := "srv6sid protocol 2 identifier 1 local-asn 65001 local-bgp-ls-id 0 local-bgp-router-id 192.168.1.1 sids fd00::1"
	cases := []struct {
		name    string
		args    string
		present bool
	}{
		{"absent", base, false},
		{"present", base + " multi-topology-id 2", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			nlri, _, err := parseLsArgs(strings.Split(c.args, " "))
			assert.NoError(t, err)

			srv6 := nlri.(*bgp.LsAddrPrefix).NLRI.(*bgp.LsSrv6SIDNLRI)
			// Compare the interface itself. A typed nil pointer stored in it
			// still reads as non-nil, and assert.Nil looks through to the
			// pointer, so it would not catch that.
			assert.Equal(t, c.present, srv6.MultiTopoID != nil)

			// The absent-TLV guards in LsSrv6SIDNLRI dereference the field
			// once the interface is non-nil.
			assert.NotPanics(t, func() {
				_ = nlri.String()
				_, err := nlri.Serialize()
				assert.NoError(t, err)
			})
		})
	}
}

func Test_ParseLsSrPolicyCandidatePath(t *testing.T) {
	assert := assert.New(t)

	args := strings.Split("srpolicy identifier 1 local-router-id 10.0.0.1 local-asn 65001 local-bgp-router-id 1.1.1.1 endpoint 10.0.0.2 color 100 originator-asn 65001 originator-address 1.1.1.1 discriminator 1 policy-name blue cp-name cp1 bsid 24001 specified-bsid 24002 priority 10 preference 200 state-flags AEV segment-list 1:16001,16002 2:fc00::1,fc00::2", " ")
	path, err := parsePath(bgp.RF_LS, args)
	assert.NoError(err)
	assert.NotNil(path)

	nlri, err := apiutil.GetNativeNlri(path)
	assert.NoError(err)
	assert.Equal("NLRI { SRPOLICY_CP { LOCAL_NODE: {ASN: 65001, BGP LS ID: 0, BGP ROUTER ID: 1.1.1.1, IPv4 ROUTER ID: 10.0.0.1} ENDPOINT: 10.0.0.2 COLOR: 100 ORIGIN: 3 ORIGINATOR: 65001/1.1.1.1 DISCRIMINATOR: 1 SR:1 } }", nlri.String())

	attrs, err := apiutil.GetNativePathAttributes(path)
	assert.NoError(err)

	var lsAttr *bgp.PathAttributeLs
	for _, a := range attrs {
		if v, ok := a.(*bgp.PathAttributeLs); ok {
			lsAttr = v
			break
		}
	}
	if !assert.NotNil(lsAttr) {
		return
	}
	sp := lsAttr.Extract().SrPolicy

	if assert.NotNil(sp.BindingSID) {
		assert.EqualValues(24001, sp.BindingSID.Label)
		assert.EqualValues(24002, sp.BindingSID.SpecifiedLabel)
		assert.True(sp.BindingSID.Flags.Allocated)
	}
	if assert.NotNil(sp.State) {
		assert.EqualValues(10, sp.State.Priority)
		assert.EqualValues(200, sp.State.Preference)
		assert.True(sp.State.Flags.Active)
		assert.True(sp.State.Flags.Evaluated)
		assert.True(sp.State.Flags.ValidSIDList)
		assert.False(sp.State.Flags.Backup)
	}
	if assert.NotNil(sp.PolicyName) {
		assert.Equal("blue", *sp.PolicyName)
	}
	if assert.NotNil(sp.CandidatePathName) {
		assert.Equal("cp1", *sp.CandidatePathName)
	}
	if assert.Len(sp.SegmentLists, 2) {
		mpls := sp.SegmentLists[0]
		assert.EqualValues(1, mpls.Weight)
		assert.False(mpls.Flags.SRv6)
		// A clear V or R flag reads as failed verification or resolution
		// (RFC 9857 sections 5.7 and 5.7.1), so injected paths set them.
		assert.True(mpls.Flags.Verified)
		assert.True(mpls.Flags.Resolved)
		if assert.Len(mpls.Segments, 2) {
			assert.Equal(bgp.LS_SR_SEGMENT_TYPE_A_MPLS_LABEL, mpls.Segments[0].SegmentType)
			assert.EqualValues(16001, mpls.Segments[0].Label)
			assert.EqualValues(16002, mpls.Segments[1].Label)
			assert.True(mpls.Segments[0].Flags.Verified)
			assert.True(mpls.Segments[0].Flags.Resolved)
		}
		srv6 := sp.SegmentLists[1]
		assert.EqualValues(2, srv6.Weight)
		assert.True(srv6.Flags.SRv6)
		if assert.Len(srv6.Segments, 2) {
			assert.Equal(bgp.LS_SR_SEGMENT_TYPE_B_SRV6_SID, srv6.Segments[0].SegmentType)
			assert.Equal("fc00::1", srv6.Segments[0].SID.String())
			assert.Equal("fc00::2", srv6.Segments[1].SID.String())
		}
	}
}

func Test_ParseLsSrPolicyCandidatePathConstraints(t *testing.T) {
	assert := assert.New(t)

	base := "srpolicy identifier 1 local-router-id 10.0.0.1 local-asn 65001 local-bgp-router-id 1.1.1.1 endpoint 10.0.0.2 color 100 originator-asn 65001 originator-address 1.1.1.1 discriminator 1 segment-list 1:16001"
	constraintsOf := func(args string) (*bgp.LsSrCandidatePathConstraints, error) {
		path, err := parsePath(bgp.RF_LS, strings.Split(args, " "))
		if err != nil {
			return nil, err
		}
		attrs, err := apiutil.GetNativePathAttributes(path)
		if err != nil {
			return nil, err
		}
		for _, a := range attrs {
			if v, ok := a.(*bgp.PathAttributeLs); ok {
				return v.Extract().SrPolicy.Constraints, nil
			}
		}
		return nil, nil
	}

	c, err := constraintsOf(base + " constraint-flags DAS constraint-mtid 2 constraint-algorithm 128 constraint-exclude-any 0xff constraint-include-any 1,0x80000000 constraint-srlg 10 20 constraint-bandwidth 1e9 constraint-disjoint-group 7:SL:L constraint-bidir-group 9:C constraint-metric 0:O 1:MAB:5:100")
	assert.NoError(err)
	if !assert.NotNil(c) {
		return
	}
	assert.Equal(bgp.LsSrCandidatePathConstraintsFlags{SRv6: true, AlgorithmOnly: true, Strict: true}, c.Flags)
	assert.EqualValues(2, c.MTID)
	assert.EqualValues(128, c.Algorithm)
	assert.Equal(&bgp.LsSrAffinityConstraint{ExcludeAny: []uint32{0xff}, IncludeAny: []uint32{1, 0x80000000}}, c.Affinity)
	assert.Equal([]uint32{10, 20}, c.SRLGs)
	if assert.NotNil(c.Bandwidth) {
		assert.EqualValues(1e9, *c.Bandwidth)
	}
	assert.Equal(&bgp.LsSrDisjointGroupConstraint{
		RequestFlags: bgp.LsSrDisjointGroupRequestFlags{SRLG: true, Link: true},
		StatusFlags:  bgp.LsSrDisjointGroupStatusFlags{Link: true},
		GroupID:      7,
	}, c.DisjointGroup)
	assert.Equal(&bgp.LsSrBidirectionalGroupConstraint{Flags: bgp.LsSrBidirectionalGroupFlags{CoRouted: true}, GroupID: 9}, c.BidirectionalGroup)
	assert.Equal([]bgp.LsSrMetricConstraint{
		{MetricType: 0, Flags: bgp.LsSrMetricConstraintFlags{Optimization: true}},
		{MetricType: 1, Flags: bgp.LsSrMetricConstraintFlags{Margin: true, Absolute: true, Bound: true}, Margin: 5, Bound: 100},
	}, c.Metrics)

	// Without constraint arguments no Constraints TLV is built.
	c, err = constraintsOf(base)
	assert.NoError(err)
	assert.Nil(c)

	for _, tt := range []struct{ name, extra string }{
		{"unknown flag letter", "constraint-flags X"},
		{"protected and unprotected", "constraint-flags PU"},
		{"mtid out of range", "constraint-mtid 70000"},
		{"eag word out of range", "constraint-exclude-any 0x1ffffffff"},
		{"bad srlg", "constraint-srlg x"},
		{"negative bandwidth", "constraint-bandwidth -1"},
		{"bad group flags", "constraint-disjoint-group 1:Q"},
		{"too many group fields", "constraint-bidir-group 1:R:C"},
		{"bad metric flags", "constraint-metric 1:Z"},
		{"metric type only", "constraint-metric 2"},
		{"metric type out of range", "constraint-metric 256"},
		{"too many metric fields", "constraint-metric 1:O:1:2:3"},
		{"duplicate O flag", "constraint-metric 1:O 2:O"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := constraintsOf(base + " " + tt.extra)
			assert.Error(err)
		})
	}
}

func Test_ParseLsSrPolicyCandidatePathErrors(t *testing.T) {
	tests := []struct {
		name string
		args string
		msg  string
	}{
		{"missing endpoint", "srpolicy identifier 1 local-router-id 10.0.0.1 local-asn 65001 local-bgp-router-id 1.1.1.1 color 100 originator-asn 65001 originator-address 1.1.1.1 discriminator 1 policy-name x", "endpoint is required"},
		{"missing headend", "srpolicy identifier 1 local-router-id 10.0.0.1 endpoint 10.0.0.2 color 100 originator-asn 65001 originator-address 1.1.1.1 discriminator 1 policy-name x", "headend producer requires local-asn and local-bgp-router-id"},
		{"mixed segment list", "srpolicy identifier 1 local-router-id 10.0.0.1 local-asn 65001 local-bgp-router-id 1.1.1.1 endpoint 10.0.0.2 color 100 originator-asn 65001 originator-address 1.1.1.1 discriminator 1 segment-list 1:16001,fc00::1", "cannot mix"},
		{"bad state flags", "srpolicy identifier 1 local-router-id 10.0.0.1 local-asn 65001 local-bgp-router-id 1.1.1.1 endpoint 10.0.0.2 color 100 originator-asn 65001 originator-address 1.1.1.1 discriminator 1 state-flags AX", "invalid state-flags"},
		{"specified bsid without bsid", "srpolicy identifier 1 local-router-id 10.0.0.1 local-asn 65001 local-bgp-router-id 1.1.1.1 endpoint 10.0.0.2 color 100 originator-asn 65001 originator-address 1.1.1.1 discriminator 1 specified-bsid 1", "specified-bsid requires"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			path, err := parsePath(bgp.RF_LS, strings.Split(test.args, " "))
			if assert.Error(err) {
				assert.Contains(err.Error(), test.msg)
			}
			assert.Nil(path)
		})
	}
}

func TestParseLsSrPolicyProtocolAndHeadend(t *testing.T) {
	base := "srpolicy identifier 0 local-router-id 10.0.0.1 local-asn 65001 local-bgp-router-id 1.1.1.1 endpoint 10.0.0.2 color 100 originator-asn 65001 originator-address 1.1.1.1 discriminator 1"
	for _, tt := range []struct {
		name       string
		args       string
		wantOrigin uint8
		wantErr    bool
	}{
		{"default configuration origin", base, 3, false},
		{"BGP origin", base + " protocol-origin 2 protocol 9", 2, false},
		{"wrong protocol", base + " protocol 2", 0, true},
		{"missing headend address", strings.Replace(base, "local-router-id 10.0.0.1 ", "", 1), 0, true},
		{"IPv6 BGP ID", strings.Replace(base, "local-bgp-router-id 1.1.1.1", "local-bgp-router-id 2001:db8::1", 1), 0, true},
		{"PCE headend address only", "srpolicy identifier 0 local-router-id 2001:db8::1 endpoint 2001:db8::2 color 100 originator-asn 0 originator-address :: discriminator 1 protocol-origin 30", 30, false},
		{"multiple SRv6 BSIDs", base + " srv6-bsid fc00::1 fc00::2 specified-bsid :: fc00::3", 3, false},
		{"mismatched specified BSIDs", base + " srv6-bsid fc00::1 fc00::2 specified-bsid fc00::3", 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path, err := parsePath(bgp.RF_LS, strings.Fields(tt.args))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			native, err := apiutil.GetNativeNlri(path)
			require.NoError(t, err)
			wire, err := native.Serialize()
			require.NoError(t, err)
			decoded, err := bgp.NLRIFromSlice(bgp.RF_LS, wire)
			require.NoError(t, err)
			cp := decoded.(*bgp.LsAddrPrefix).NLRI.(*bgp.LsSrPolicyCandidatePathNLRI)
			require.EqualValues(t, bgp.LS_PROTOCOL_SEGMENT_ROUTING, cp.ProtocolID)
			require.Equal(t, tt.wantOrigin, cp.CandidatePathDesc.(*bgp.LsTLVSrPolicyCandidatePathDescriptor).ProtocolOrigin)
		})
	}
}
