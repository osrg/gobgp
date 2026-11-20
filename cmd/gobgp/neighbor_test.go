// Copyright (C) 2026 Nippon Telegraph and Telephone Corporation.
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
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testIPv4Path(t *testing.T, prefix string, identifier, localIdentifier uint32) *api.Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	p, err := apiutil.NewPath(bgp.RF_IPv4_UC, nlri, false, nil, time.Time{})
	require.NoError(t, err)
	p.Identifier = identifier
	p.LocalIdentifier = localIdentifier
	return p
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	stdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = stdout }()
	fn()
	require.NoError(t, w.Close())
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
}

func Test_makeShowRouteArgsUndecodableNlri(t *testing.T) {
	assert := assert.New(t)
	// A path whose NLRI cannot be decoded must not panic the CLI formatter.
	p := &api.Path{}
	var args []any
	assert.NotPanics(func() {
		args = makeShowRouteArgs(p, 0, time.Now(), false, true, false, false, false, bgp.BGP_ADD_PATH_NONE)
	})
	assert.Contains(args, "?")
}

func Test_makeShowRouteArgsPathIDs(t *testing.T) {
	now := time.Now()
	// Documentation prefix. identifier=0 must be distinguishable from a
	// received/injected identifier of 7, and local_identifier must not be swapped.
	zero := testIPv4Path(t, "192.0.2.0/24", 0, 3)
	nonzero := testIPv4Path(t, "192.0.2.0/24", 7, 11)

	noneZero := makeShowRouteArgs(zero, 0, now, false, true, false, false, false, bgp.BGP_ADD_PATH_NONE)
	noneNonzero := makeShowRouteArgs(nonzero, 1, now, false, true, false, false, false, bgp.BGP_ADD_PATH_NONE)
	require.Equal(t, noneZero[1], noneNonzero[1], "default output must not include path identifiers")
	require.Equal(t, "192.0.2.0/24", noneZero[1])
	require.NotContains(t, noneZero, "0")
	require.NotContains(t, noneNonzero, "7")
	require.NotContains(t, noneNonzero, "11")

	recvZero := makeShowRouteArgs(zero, 0, now, false, true, false, false, false, bgp.BGP_ADD_PATH_RECEIVE)
	recvNonzero := makeShowRouteArgs(nonzero, 0, now, false, true, false, false, false, bgp.BGP_ADD_PATH_RECEIVE)
	assert.Equal(t, "0", recvZero[1])
	assert.Equal(t, "7", recvNonzero[1])
	assert.Equal(t, "192.0.2.0/24", recvZero[2])
	assert.NotEqual(t, "3", recvZero[1], "adj-in must show identifier, not local_identifier")
	assert.NotEqual(t, "11", recvNonzero[1])

	sendZero := makeShowRouteArgs(zero, 0, now, false, true, false, false, false, bgp.BGP_ADD_PATH_SEND)
	sendNonzero := makeShowRouteArgs(nonzero, 0, now, false, true, false, false, false, bgp.BGP_ADD_PATH_SEND)
	assert.Equal(t, "3", sendZero[1])
	assert.Equal(t, "11", sendNonzero[1])
	assert.NotEqual(t, "0", sendNonzero[1], "adj-out must show local_identifier, not identifier")
	assert.NotEqual(t, "7", sendNonzero[1])

	bothZero := makeShowRouteArgs(zero, 0, now, false, true, false, false, false, bgp.BGP_ADD_PATH_BOTH)
	bothNonzero := makeShowRouteArgs(nonzero, 0, now, false, true, false, false, false, bgp.BGP_ADD_PATH_BOTH)
	assert.Equal(t, []any{"0", "3", "192.0.2.0/24"}, bothZero[1:4])
	assert.Equal(t, []any{"7", "11", "192.0.2.0/24"}, bothNonzero[1:4])
}

func Test_showRoutePathIDsDefaultUnchanged(t *testing.T) {
	p1 := testIPv4Path(t, "192.0.2.0/24", 0, 1)
	p2 := testIPv4Path(t, "192.0.2.0/24", 7, 2)
	dsts := []*api.Destination{{Prefix: "192.0.2.0/24", Paths: []*api.Path{p1, p2}}}

	out := captureStdout(t, func() {
		showRoute(dsts, false, true, false, false, false, bgp.BGP_ADD_PATH_NONE)
	})
	require.Contains(t, out, "Network")
	require.NotContains(t, out, "LocalID")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.GreaterOrEqual(t, len(lines), 3)
	header := lines[0]
	assert.NotRegexp(t, `\bID\b`, header)
	assert.NotContains(t, lines[1], " 0 ")
	assert.NotContains(t, lines[2], " 7 ")
}

func Test_showRoutePathIDsBothColumns(t *testing.T) {
	p1 := testIPv4Path(t, "192.0.2.0/24", 0, 1)
	p2 := testIPv4Path(t, "192.0.2.0/24", 7, 2)
	dsts := []*api.Destination{{Prefix: "192.0.2.0/24", Paths: []*api.Path{p1, p2}}}

	out := captureStdout(t, func() {
		showRoute(dsts, false, true, false, false, false, bgp.BGP_ADD_PATH_BOTH)
	})
	require.Contains(t, out, "ID")
	require.Contains(t, out, "LocalID")
	require.Contains(t, out, "192.0.2.0/24")
	// identifier=0 must be printed, and the two local_identifiers must differ.
	require.Regexp(t, `(?m)^\S*\s+0\s+1\s+192\.0\.2\.0/24\b`, out)
	require.Regexp(t, `(?m)^\S*\s+7\s+2\s+192\.0\.2\.0/24\b`, out)
}
