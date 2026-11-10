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
	"testing"

	"github.com/osrg/gobgp/v4/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ParseNeighborSet(t *testing.T) {
	ds, err := parseNeighborSet([]string{"ns1", "10.0.0.1", "2001:db8::1", "10.0.0.0/24", "2001:db8::/64"})
	require.NoError(t, err)
	assert.Equal(t, api.DefinedType_DEFINED_TYPE_NEIGHBOR, ds.DefinedType)
	assert.Equal(t, "ns1", ds.Name)
	assert.Equal(t, []string{"10.0.0.1/32", "2001:db8::1/128", "10.0.0.0/24", "2001:db8::/64"}, ds.List)

	_, err = parseNeighborSet([]string{"ns1", "10.0.0.0/33"})
	assert.Error(t, err)

	ds, err = parseNeighborSet([]string{"ns1", "fe80::1%eth0", "fe80::1%eth1/128"})
	require.NoError(t, err)
	assert.Equal(t, []string{"fe80::1%eth0", "fe80::1%eth1/128"}, ds.List)
}
