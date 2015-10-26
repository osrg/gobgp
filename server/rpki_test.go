// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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

package server

import (
	"github.com/armon/go-radix"
	"github.com/osrg/gobgp/config"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func addROA(tree *radix.Tree, addr string, as uint32, prefixLen, maxLen uint8) {
	a := net.ParseIP(addr)
	b := a.To4()
	if b == nil {
		b = a.To16()
	}
	handleIPPrefix(tree, prefixToKey(net.ParseIP(addr), prefixLen), as, b, prefixLen, maxLen)
}

func TestValidate(t *testing.T) {
	assert := assert.New(t)

	tree := radix.New()
	addROA(tree, "192.168.0.0", 100, 24, 32)
	addROA(tree, "192.168.0.0", 200, 24, 24)

	r1 := validateOne(tree, prefixToKey(net.ParseIP("192.168.0.0"), 24), 24, 100)
	assert.Equal(r1, config.RPKI_VALIDATION_RESULT_TYPE_VALID)

	r2 := validateOne(tree, prefixToKey(net.ParseIP("192.168.0.0"), 24), 24, 200)
	assert.Equal(r2, config.RPKI_VALIDATION_RESULT_TYPE_VALID)

	r3 := validateOne(tree, prefixToKey(net.ParseIP("192.168.0.0"), 24), 24, 300)
	assert.Equal(r3, config.RPKI_VALIDATION_RESULT_TYPE_INVALID)

	r4 := validateOne(tree, prefixToKey(net.ParseIP("192.168.0.0"), 25), 25, 100)
	assert.Equal(r4, config.RPKI_VALIDATION_RESULT_TYPE_VALID)

	r5 := validateOne(tree, prefixToKey(net.ParseIP("192.168.0.0"), 25), 25, 200)
	assert.Equal(r5, config.RPKI_VALIDATION_RESULT_TYPE_INVALID)

	r6 := validateOne(tree, prefixToKey(net.ParseIP("192.168.0.0"), 25), 25, 300)
	assert.Equal(r6, config.RPKI_VALIDATION_RESULT_TYPE_INVALID)
}
