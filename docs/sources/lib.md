# GoBGP as a Go Native BGP library

This page explains how to use GoBGP as a Go Native BGP library.

## Contents
- [Basic Example](#basic)

## <a name="basic"> Basic Example

```go
package main

import (
	log "github.com/Sirupsen/logrus"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/gobgp/cmd"
	"github.com/osrg/gobgp/packet/bgp"
	gobgp "github.com/osrg/gobgp/server"
)

func main() {
	log.SetLevel(log.DebugLevel)
	s := gobgp.NewBgpServer()
	go s.Serve()

	// start grpc api server. this is not mandatory
	// but you will be able to use `gobgp` cmd with this.
	g := gobgp.NewGrpcServer(50051, s.GrpcReqCh)
	go g.Serve()

	// global configuration
	req := gobgp.NewGrpcRequest(gobgp.REQ_MOD_GLOBAL_CONFIG, "", bgp.RouteFamily(0), &api.ModGlobalConfigArguments{
		Operation: api.Operation_ADD,
		Global: &api.Global{
			As:         65003,
			RouterId:   "192.168.0.4",
			ListenPort: -1, // gobgp won't listen on tcp:179
		},
	})
	s.GrpcReqCh <- req
	res := <-req.ResponseCh
	if err := res.Err(); err != nil {
		log.Fatal(err)
	}

	// neighbor configuration
	req = gobgp.NewGrpcRequest(gobgp.REQ_MOD_NEIGHBOR, "", bgp.RouteFamily(0), &api.ModNeighborArguments{
		Operation: api.Operation_ADD,
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: "192.168.0.3",
				PeerAs:          65000,
			},
			Transport: &api.Transport{
				LocalAddress: "192.168.0.4",
			},
		},
	})
	s.GrpcReqCh <- req
	res = <-req.ResponseCh
	if err := res.Err(); err != nil {
		log.Fatal(err)
	}

	// add routes
	path, _ := cmd.ParsePath(bgp.RF_IPv4_UC, []string{"10.0.0.0/24", "nexthop", "10.10.10.10"})
	req = gobgp.NewGrpcRequest(gobgp.REQ_MOD_PATHS, "", bgp.RouteFamily(0), &api.ModPathsArguments{
		Resource: api.Resource_GLOBAL,
		Paths:    []*api.Path{path},
	})
	s.GrpcReqCh <- req
	res = <-req.ResponseCh
	if err := res.Err(); err != nil {
		log.Fatal(err)
	}

	// monitor new routes
	req = gobgp.NewGrpcRequest(gobgp.REQ_MONITOR_GLOBAL_BEST_CHANGED, "", bgp.RF_IPv4_UC, nil)
	s.GrpcReqCh <- req
	for res := range req.ResponseCh {
		p, _ := cmd.ApiStruct2Path(res.Data.(*api.Destination).Paths[0])
		cmd.ShowRoute(p, false, false, false, true, false)
	}
}
```
