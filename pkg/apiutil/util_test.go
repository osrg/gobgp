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

package apiutil

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAPIPath(t *testing.T) *api.Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("192.0.2.0/24"))
	require.NoError(t, err)
	p, err := NewPath(bgp.RF_IPv4_UC, nlri, false, nil, time.Now())
	require.NoError(t, err)
	return p
}

func marshalTestDestination(t *testing.T, paths ...*api.Path) []map[string]any {
	t.Helper()
	j, err := json.Marshal(NewDestination(&api.Destination{Prefix: "192.0.2.0/24", Paths: paths}))
	require.NoError(t, err)
	var out []map[string]any
	require.NoError(t, json.Unmarshal(j, &out))
	require.Len(t, out, len(paths))
	return out
}

func TestNewDestinationPathIdentifiers(t *testing.T) {
	p0 := newTestAPIPath(t)
	p0.LocalIdentifier = 1
	p1 := newTestAPIPath(t)
	p1.Identifier = 7
	p1.LocalIdentifier = 11

	out := marshalTestDestination(t, p0, p1)
	assert.EqualValues(t, 0, out[0]["RemoteID"])
	assert.EqualValues(t, 1, out[0]["LocalID"])
	assert.EqualValues(t, 7, out[1]["RemoteID"])
	assert.EqualValues(t, 11, out[1]["LocalID"])
}

func TestNewDestinationOptionalFields(t *testing.T) {
	keys := []string{
		"peer-asn",
		"is-from-external",
		"no-implicit-withdraw",
		"is-nexthop-invalid",
		"filtered",
	}

	// The keys are omitted when the values are not set.
	out := marshalTestDestination(t, newTestAPIPath(t))
	for _, k := range keys {
		assert.NotContains(t, out[0], k)
	}

	p := newTestAPIPath(t)
	p.SourceAsn = 65001
	p.SourceId = "192.0.2.1"
	p.NeighborIp = "192.0.2.2"
	p.IsFromExternal = true
	p.NoImplicitWithdraw = true
	p.IsNexthopInvalid = true
	p.Filtered = true

	out = marshalTestDestination(t, p)
	assert.EqualValues(t, 65001, out[0]["peer-asn"])
	for _, k := range keys[1:] {
		assert.Equal(t, true, out[0][k], k)
	}
}
