# Using BGP-LS in GoBGP library mode

This page explains how to use GoBGP for getting BGP-LS prefixes.

## Contents

- [Basic BGP-LS Example](#basic-bgp-ls-example)

## Basic BGP-LS Example

```go
package main

import (
	"context"

	"google.golang.org/protobuf/encoding/protojson"
	api "github.com/osrg/gobgp/v3/api"
	gobgp "github.com/osrg/gobgp/v3/pkg/server"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetLevel(log.DebugLevel)
	s := gobgp.NewBgpServer()
	go s.Serve()

	if err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			As:         64512,
			RouterId:   "10.0.255.254",
			ListenPort: -1, // gobgp won't listen on tcp:179
		},
	}); err != nil {
		log.Fatal(err)
	}

	if err := s.MonitorPeer(context.Background(), &api.MonitorPeerRequest{}, func(p *api.Peer) { log.Info(p) }); err != nil {
		log.Fatal(err)
	}

	// neighbor configuration
	n := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "172.17.0.2",
			PeerAs:          65002,
		},
		ApplyPolicy: &api.ApplyPolicy{
			ImportPolicy: &api.PolicyAssignment{
				DefaultAction: api.RouteAction_ACCEPT,
			},
			ExportPolicy: &api.PolicyAssignment{
				DefaultAction: api.RouteAction_REJECT,
			},
		},
		AfiSafis: []*api.AfiSafi{
			{
				Config: &api.AfiSafiConfig{
					Family: &api.Family{
						Afi:  api.Family_AFI_LS,
						Safi: api.Family_SAFI_LS,
					},
					Enabled: true,
				},
			},
		},
	}

	if err := s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: n,
	}); err != nil {
		log.Fatal(err)
	}

	marshaller := protojson.MarshalOptions{
		Indent:   "  ",
		UseProtoNames: true,
	}

	// Display incoming Prefixes in JSON format.
	if err := s.MonitorTable(context.Background(), &api.MonitorTableRequest{
		TableType: api.TableType_GLOBAL,
		Family: &api.Family{
			Afi:  api.Family_AFI_LS,
			Safi: api.Family_SAFI_LS,
		},
	}, func(p *api.Path) {
		// Your application should do something useful with the BGP-LS path here.
		marshaller.Marshal(p)
	}); err != nil {
		log.Fatal(err)
	}

	select {}
}

```
