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
	"time"

	"testing"

	"github.com/osrg/gobgp/v4/api"
	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

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
