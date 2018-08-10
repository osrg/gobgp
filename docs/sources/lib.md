# GoBGP as a Go Native BGP library

This page explains how to use GoBGP as a Go Native BGP library.

## Contents

- [Basic Example](#basic-example)

## Basic Example

```go
package main

import (
	"context"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	api "github.com/osrg/gobgp/api"
	gobgp "github.com/osrg/gobgp/pkg/server"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetLevel(log.DebugLevel)
	s := gobgp.NewBgpServer()
	go s.Serve()

	// start grpc api server. this is not mandatory
	// but you will be able to use `gobgp` cmd with this.
	g := gobgp.NewGrpcServer(s, ":50051")
	go g.Serve()

	// global configuration
	if err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			As:         65003,
			RouterId:   "10.0.255.254",
			ListenPort: -1, // gobgp won't listen on tcp:179
		},
	}); err != nil {
		log.Fatal(err)
	}

	// neighbor configuration
	n := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "172.17.0.2",
			PeerAs:          65002,
		},
	}

	if err := s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: n,
	}); err != nil {
		log.Fatal(err)
	}

	// add routes
	nlri, _ := ptypes.MarshalAny(&api.IPAddressPrefix{
		Prefix:    "10.0.0.0",
		PrefixLen: 24,
	})

	a1, _ := ptypes.MarshalAny(&api.OriginAttribute{
		Origin: 0,
	})
	a2, _ := ptypes.MarshalAny(&api.NextHopAttribute{
		NextHop: "10.0.0.1",
	})
	attrs := []*any.Any{a1, a2}

	_, err := s.AddPath(context.Background(), &api.AddPathRequest{
		Path: &api.Path{
			Family:    uint32(api.Family_IPv4),
			AnyNlri:   nlri,
			AnyPattrs: attrs,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// do something useful here instead of exiting
	time.Sleep(time.Minute * 3)
}
```
