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

package server

import (
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/table"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestModPolicyAssign(t *testing.T) {
	assert := assert.New(t)
	s := NewBgpServer()
	go s.Serve()
	s.Start(&config.Global{
		Config: config.GlobalConfig{
			As:       1,
			RouterId: "1.1.1.1",
		},
	})
	err := s.AddPolicy(&table.Policy{Name: "p1"}, false)
	assert.Nil(err)

	err = s.AddPolicy(&table.Policy{Name: "p2"}, false)
	assert.Nil(err)

	err = s.AddPolicy(&table.Policy{Name: "p3"}, false)
	assert.Nil(err)

	err = s.AddPolicyAssignment("", table.POLICY_DIRECTION_IMPORT,
		[]*config.PolicyDefinition{&config.PolicyDefinition{Name: "p1"}, &config.PolicyDefinition{Name: "p2"}, &config.PolicyDefinition{Name: "p3"}}, table.ROUTE_TYPE_ACCEPT)
	assert.Nil(err)

	err = s.DeletePolicyAssignment("", table.POLICY_DIRECTION_IMPORT,
		[]*config.PolicyDefinition{&config.PolicyDefinition{Name: "p1"}}, false)
	assert.Nil(err)

	_, ps, _ := s.GetPolicyAssignment("", table.POLICY_DIRECTION_IMPORT)
	assert.Equal(len(ps), 2)
}
