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

// Package client provides a wrapper for GoBGP's gRPC API
package client

import (
	"fmt"

	"github.com/ghodss/yaml"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/table"
)

type Resource interface {
	create(*GoBGPClient) error
	delete(*GoBGPClient) error

	// TODO
	// apply(*GoBGPClient) error
	// update(*GoBGPClient) error
	// list(*GoBGPClient) ([]Resource, error)
}

type typeMetadata struct {
	Kind string `json:"kind"`
}

type globalResource struct {
	typeMetadata
	Spec config.Global `json:"spec,omitempty"`
}

func (r *globalResource) create(cli *GoBGPClient) error {
	return cli.StartServer(&r.Spec)
}

func (r *globalResource) delete(cli *GoBGPClient) error {
	return cli.StopServer()
}

type neighborResource struct {
	typeMetadata
	Spec config.Neighbor `json:"spec,omitempty"`
}

func (r *neighborResource) create(cli *GoBGPClient) error {
	return cli.AddNeighbor(&r.Spec)
}

func (r *neighborResource) delete(cli *GoBGPClient) error {
	return cli.DeleteNeighbor(&r.Spec)
}

type policyResource struct {
	typeMetadata
	Spec config.PolicyDefinition `json:"spec,omitempty"`
}

func (r *policyResource) create(cli *GoBGPClient) error {
	p, err := table.NewPolicy(r.Spec)
	if err != nil {
		return err
	}
	return cli.AddPolicy(p, false)
}

func (r *policyResource) delete(cli *GoBGPClient) error {
	p, err := table.NewPolicy(r.Spec)
	if err != nil {
		return err
	}
	return cli.DeletePolicy(p, true, false)
}

type definedSetResource struct {
	typeMetadata
	Spec config.DefinedSets `json:"spec,omitempty"`
}

func (r *definedSetResource) create(cli *GoBGPClient) error {
	d, err := table.NewDefinedSet(r.Spec)
	if err != nil {
		return err
	}
	return cli.AddDefinedSet(d)
}

func (r *definedSetResource) delete(cli *GoBGPClient) error {
	d, err := table.NewDefinedSet(r.Spec)
	if err != nil {
		return err
	}
	return cli.DeleteDefinedSet(d, true)
}

func newResourceFromBytes(b []byte) (Resource, error) {
	m := &typeMetadata{}
	err := yaml.Unmarshal(b, m)
	if err != nil {
		return nil, err
	}
	var r Resource
	switch m.Kind {
	case "global":
		r = &globalResource{}
	case "neighbor":
		r = &neighborResource{}
	case "policy":
		r = &policyResource{}
	case "defined-set":
		r = &definedSetResource{}
	default:
		return nil, fmt.Errorf("failed to create resource from bytes: %s", m.Kind)
	}

	if err := yaml.Unmarshal(b, r); err != nil {
		return nil, err
	}
	return r, nil
}
