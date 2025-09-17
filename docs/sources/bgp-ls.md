# BGP-LS

## Contents

- [CLI Syntax](#cli-syntax)
- [Using BGP-LS in GoBGP library mode](#using-bgp-ls-in-gobgp-library-mode)

## CLI Syntax

### Add routes

Currently, gobgp global rib add supports adding only NODE NLRI, LINK NLRI, SRv6 SID NLRI and PREFIXV6 NLRI.

```shell
# NODE NLRI
$ gobgp global rib add -a ls node protocol <protocol> identifier <identifier> [local-asn <local-asn>] [local-bgp-ls-id <local-bgp-ls-id>] [local-bgp-router-id <local-bgp-router-id>] [local-igp-router-id <local-igp-router-id>] [local-bgp-confederation-member <local-bgp-confederation-member>] [node-name <node-name>] [isis-area-id <isis-area-id>] [sr-algorithm <sr-algorithm>...]

# LINK NLRI  
$ gobgp global rib add -a ls link protocol <protocol> identifier <identifier> [local-asn <local-asn>] [local-bgp-ls-id <local-bgp-ls-id>] [local-bgp-router-id <local-bgp-router-id>] [local-igp-router-id <local-igp-router-id>] [local-bgp-confederation-member <local-bgp-confederation-member>] [remote-asn <remote-asn>] [remote-bgp-ls-id <remote-bgp-ls-id>] [remote-bgp-router-id <remote-bgp-router-id>] [remote-igp-router-id <remote-igp-router-id>] [remote-bgp-confederation-member <remote-bgp-confederation-member>] [link-local-id <link-local-id>] [link-remote-id <link-remote-id>] [ipv4-interface-address <ipv4-interface-address>] [ipv4-neighbor-address <ipv4-neighbor-address>] [sid <sid-value>] [sid-type <sid-type>] [v-flag <v-flag>] [l-flag <l-flag>] [b-flag <b-flag>] [p-flag <p-flag>] [weight <weight>] [ipv6-interface-address <ipv6-interface-address>] [ipv6-neighbor-address <ipv6-neighbor-address>] [srv6-endpoint-behavior <endpoint-behavior>] [srv6-sids <srv6-sids>...] [srv6-weight <srv6-weight>] [srv6-flags <srv6-flags>] [srv6-algo <srv6-algo>] [srv6-structure-lb <srv6-structure-lb>] [srv6-structure-ln <srv6-structure-ln>] [srv6-structure-fun <srv6-structure-fun>] [srv6-structure-arg <srv6-structure-arg>] [max-link-bandwidth <max-link-bandwidth>] [te-default-metric <te-default-metric>] [metric <metric>]

# PREFIXv6 NLRI
$ gobgp global rib add -a ls prefixv6 protocol <protocol> identifier <identifier> [local-asn <local-asn>] [local-bgp-ls-id <local-bgp-ls-id>] [local-bgp-router-id <local-bgp-router-id>] [local-igp-router-id <local-igp-router-id>] [local-bgp-confederation-member <local-bgp-confederation-member>] ip-reachability-info <ipv6-prefix>

# SRv6 SID NLRI
$ gobgp global rib add -a ls srv6sid protocol <protocol> identifier <identifier> [local-asn <local-asn>] [local-bgp-ls-id <local-bgp-ls-id>] [local-bgp-router-id <local-bgp-router-id>] [local-igp-router-id <local-igp-router-id>] [local-bgp-confederation-member <local-bgp-confederation-member>] sids <sids>... [multi-topology-id <multi-topology-id>...] [peer-as <peer-as>] [peer-bgp-id <peer-bgp-id>] [flags <flags>] [weight <weight>] [srv6-endpoint-behavior <srv6-endpoint-behavior>] [srv6-flags <srv6-flags>] [srv6-algo <srv6-algo>] [srv6-structure-lb <srv6-structure-lb>] [srv6-structure-ln <srv6-structure-ln>] [srv6-structure-fun <srv6-structure-fun>] [srv6-structure-arg <srv6-structure-arg>]
```

### Show routes

```shell
gobgp global rib -a ls
```

### Example - NODE NLRI

```shell
# Show routes
$gobgp:/# gobgp global rib -a ls
   Network                                                                            Next Hop             AS_PATH              Age        Attrs
*> NLRI { NODE { LOCAL_NODE: {ASN: 65002, BGP LS ID: 0, BGP ROUTER ID: 2.2.2.2}} }    172.100.100.102      65002                00:00:01   [{Origin: i} ]
*  NLRI { NODE { LOCAL_NODE: {ASN: 65002, BGP LS ID: 0, BGP ROUTER ID: 2.2.2.2}} }    172.100.100.101      65001 65002          00:00:01   [{Origin: i} ]
*> NLRI { NODE { LOCAL_NODE: {ASN: 65002, BGP LS ID: 0, BGP ROUTER ID: 1.1.1.1}} }    172.100.100.102      65002                00:00:01   [{Origin: i} ]
*  NLRI { NODE { LOCAL_NODE: {ASN: 65002, BGP LS ID: 0, BGP ROUTER ID: 1.1.1.1}} }    172.100.100.101      65001 65002          00:00:01   [{Origin: i} ]
*> NLRI { NODE { LOCAL_NODE: {ASN: 65001, BGP LS ID: 0, BGP ROUTER ID: 2.2.2.2}} }    172.100.100.101      65001                00:00:01   [{Origin: i} ]
*  NLRI { NODE { LOCAL_NODE: {ASN: 65001, BGP LS ID: 0, BGP ROUTER ID: 2.2.2.2}} }    172.100.100.102      65002 65001          00:00:01   [{Origin: i} ]
*> NLRI { NODE { LOCAL_NODE: {ASN: 65001, BGP LS ID: 0, BGP ROUTER ID: 1.1.1.1}} }    172.100.100.101      65001                00:00:01   [{Origin: i} ]
*  NLRI { NODE { LOCAL_NODE: {ASN: 65001, BGP LS ID: 0, BGP ROUTER ID: 1.1.1.1}} }    172.100.100.102      65002 65001          00:00:01   [{Origin: i} ]
```

```shell
# Add routes
$ gobgp global rib add -a ls node bgp protocol 2 identifier 7 local-asn 65001 local-bgp-ls-id 0 local-igp-router-id 0000.0000.0001 node-name r1 isis-area-id 490001 sr-algorithm 0 1

# Show routes
$ gobgp global rib -a ls
   Network                                                                                                                                            Next Hop             AS_PATH              Age        Attrs
*  NLRI { NODE { AS:65001 BGP-LS ID:0 0000.0000.0001 ISIS-L2:7 } }                                                                                    0.0.0.0                                   00:14:26   [{Origin: ?} {LsAttributes: {Node Name: r1} {ISIS Area ID: [73 0 1]} {SR Algorithms: [0 1]} }]
```

### Example - LINK NLRI

```shell
# Add routes
# IPv4
$ gobgp global rib add -a ls link bgp protocol 2 identifier 0 local-asn 65002 local-bgp-ls-id 0 local-bgp-router-id 2.2.2.2 local-bgp-confederation-member 1 remote-asn 65001 remote-bgp-ls-id 0 remote-bgp-router-id 1.1.1.1 remote-bgp-confederation-member 0 ipv4-interface-address 10.0.0.2 ipv4-neighbor-address 10.0.0.1 sid 1000002 sid-type node v-flag l-flag b-flag p-flag weight 1 ipv6-interface-address fd00::1 ipv6-neighbor-address fd00::2
# IPv6
$ gobgp global rib add -a ls link bgp protocol 2 identifier 7 local-asn 65001 local-bgp-ls-id 0 local-igp-router-id 0000.0000.0001 remote-asn 65002 remote-bgp-ls-id 0 remote-igp-router-id 0000.0000.0002 link-local-id 1 link-remote-id 2 srv6-endpoint-behavior 57 srv6-sids fc00:b100:2:e000:: srv6-weight 0 srv6-flags 0 srv6-algo 0 srv6-structure-lb 32 srv6-structure-ln 16 srv6-structure-fun 16 srv6-structure-arg 64 max-link-bandwidth 1000 te-default-metric 50 metric 10

# Show routes
# IPv4
$ gobgp global rib -a ls
   Network                                                                                                                                              Next Hop             AS_PATH              Age        Attrs
*> NLRI { LINK { LOCAL_NODE: 2.2.2.2 REMOTE_NODE: 1.1.1.1 LINK: 10.0.0.2->10.0.0.1} }    0.0.0.0                                   00:57:59   [{Origin: ?} {LsAttributes: {Peer Node SID: 1000002} }]
# IPv6
   Network                                                                                                                                            Next Hop             AS_PATH              Age        Attrs
*  NLRI { LINK { LOCAL_NODE: 0000.0000.0001 REMOTE_NODE: 0000.0000.0002 LINK: 1->2} }                                                                 0.0.0.0                                   00:09:50   [{Origin: ?} {LsAttributes: {TE Default metric: 50} {IGP metric: 10} {Max Link BW: 1000} {SRv6 End.X SID: EndpointBehavior:57 SIDs: fc00:b100:2:e000::  LocalBlock:32 LocalNode:16 LocalFunc:16 LocalArg:64} }]
```

### Example - SRv6 SID NLRI

```shell
# Add routes
$ gobgp global rib add -a ls srv6sid bgp protocol 2 identifier 1 local-asn 65001 local-bgp-ls-id 0 local-bgp-router-id 192.168.1.1 sids fd00::1 multi-topology-id 2 srv6-endpoint-behavior 30 srv6-flags 0 srv6-algo 0 srv6-structure-lb 48 srv6-structure-ln 16 srv6-structure-fun 16 srv6-structure-arg 0 peer-as 65002 peer-bgp-id 192.168.1.2 flags 0 weight 0

# Show routes
$ gobgp global rib -a ls
   Network                                                                                                                                            Next Hop             AS_PATH              Age        Attrs
*  NLRI { SRv6SID { LOCAL_NODE: {ASN: 65001, BGP LS ID: 0, BGP ROUTER ID: 192.168.1.1} SRv6_SID: {SIDs: fd00::1} MULTI_TOPO_IDs: {MultiTopoIDs: 2}} } 0.0.0.0                                   00:07:20   [{Origin: ?} {LsAttributes: {SRv6 SID Structure: LocalBlock:48 LocalNode:16 LocalFunc:16 LocalArg:0} {SRv6 BGP PeerNode SID: Flags:0 Weight:0 PeerAS:65002 PeerBgpID:192.168.1.2} {SRv6 Endpoint Behavior: EndpointBehavior:30 Flags:0 Algorithm:0} }]
```

### Example - PREFIXv6 NLRI

```shell
# Add routes
$ gobgp global rib add -a ls prefixv6 bgp protocol 2 identifier 7 local-asn 65001 local-bgp-ls-id 0 local-igp-router-id 0000.0000.0001 ip-reachability-info fc00:b100:1::/64

# Show routes
$ gobgp global rib -a ls
   Network                                                                                                                                            Next Hop             AS_PATH              Age        Attrs
*  NLRI { PREFIXv6 { LOCAL_NODE: 0000.0000.0001 PREFIX: [fc00:b100:1::/64] } }                                                                        0.0.0.0                                   00:00:41   [{Origin: ?}]
```

## Using BGP-LS in GoBGP library mode

```go
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/server"
)

func main() {
	log := slog.Default()
	lvl := &slog.LevelVar{}
	lvl.Set(slog.LevelInfo)

	s := server.NewBgpServer(server.LoggerOption(slog.Default(), lvl))
	go s.Serve()

	if err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        64512,
			RouterId:   "10.0.255.254",
			ListenPort: -1, // gobgp won't listen on tcp:179
		},
	}); err != nil {
		log.Error("failed to start BGP", slog.String("Error", err.Error()))
	}

	// the change of the peer state and path
	if err := s.WatchEvent(context.Background(), server.WatchEventMessageCallbacks{
		OnPeerUpdate: func(peer *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
			if peer.Type == apiutil.PEER_EVENT_STATE {
				log.Info("peer state changed", slog.Any("Peer", peer.Peer))
			}
		},
		OnBestPath: func(paths []*apiutil.Path, _ time.Time) {
			// Your application should do something useful with the BGP-LS path here.
			for _, p := range paths {
				_, err := json.Marshal(p)
				if err != nil {
					log.Error("failed to marshal path", slog.String("Error", err.Error()))
				}
			}
		}}); err != nil {
		log.Error("failed to watch BGP events", slog.String("Error", err.Error()))
	}

	// neighbor configuration
	n := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "172.17.0.2",
			PeerAsn:         65002,
		},
		ApplyPolicy: &api.ApplyPolicy{
			ImportPolicy: &api.PolicyAssignment{
				DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
			},
			ExportPolicy: &api.PolicyAssignment{
				DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT,
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
		log.Error("failed to add peer", slog.String("Error", err.Error()))
	}

	select {}
}
```
