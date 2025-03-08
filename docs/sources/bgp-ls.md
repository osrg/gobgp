# BGP-LS

## Contents

- [CLI Syntax](#cli-syntax)
- [Using BGP-LS in GoBGP library mode](#using-bgp-ls-in-gobgp-library-mode)

## CLI Syntax

### Add a route

Currently, gobgp global rib add supports adding only LINK NLRI and SRv6 SID NLRI.

```shell
# LINK NLRI
$ gobgp global rib add -a ls link bgp identifier <bgp-identifier> local-asn <local-asn> local-bgp-ls-id <local-bgp-ls-id> local-bgp-router-id <local-bgp-router-id> [local-bgp-confederation-member <confederation-member>] remote-asn 65001 remote-bgp-ls-id <remote-bgp-ls-id> remote-bgp-router-id <remote-bgp-router-id> remote-bgp-confederation-member <remote-confederation-member> ipv4-interface-address <ipv4-interface-address> ipv4-neighbor-address <ipv4-neighbor-address> sid <sid-value> sid-type <sid-type> v-flag <v-flag> l-flag <l-flag> b-flag <b-flag> p-flag <p-flag> weight <weight> ipv6-interface-address <ipv6-interface-address> ipv6-neighbor-address <ipv6-neighbor-address>

# SRv6 SID NLRI
$ gobgp global rib add -a ls srv6sid bgp identifier <identifier> local-asn <local-asn> local-bgp-ls-id <local-bgp-ls-id> local-bgp-router-id <local-bgp-router-id> [local-bgp-confederation-member <confederation-member>] sids <sids>... [multi-topology-id <multi-topology-id>...]
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

### Example - LINK NLRI

```shell
# Add a routes
# IPv4
$ gobgp global rib add -a ls link bgp identifier 0 local-asn 65002 local-bgp-ls-id 0 local-bgp-router-id 2.2.2.2 local-bgp-confederation-member 1 remote-asn 65001 remote-bgp-ls-id 0 remote-bgp-router-id 1.1.1.1 remote-bgp-confederation-member 0 ipv4-interface-address 10.0.0.2 ipv4-neighbor-address 10.0.0.1 sid 1000002 sid-type node v-flag l-flag b-flag p-flag weight 1 ipv6-interface-address fd00::1 ipv6-neighbor-address fd00::2

# Show routes
$ gobgp global rib -a ls
   Network                                                                                                                                              Next Hop             AS_PATH              Age        Attrs
*> NLRI { LINK { LOCAL_NODE: 2.2.2.2 REMOTE_NODE: 1.1.1.1 LINK: 10.0.0.2->10.0.0.1} }    0.0.0.0                                   00:57:59   [{Origin: ?} {LsAttributes: {Peer Node SID: 1000002} }]
(snip.)
```

### Example - SRv6 SID NLRI

```shell
# Add a routes
$ gobgp global rib add -a ls srv6sid bgp identifier 0 local-asn 65000 local-bgp-ls-id 0 local-bgp-router-id 192.168.255.1 local-bgp-confederation-member 1 sids fd00::1 multi-topology-id 1

# Show routes
$ gobgp global rib -a ls
   Network                                                                                                                                              Next Hop             AS_PATH              Age        Attrs
*> NLRI { SRv6SID { LOCAL_NODE: {ASN: 65000, BGP LS ID: 0, BGP ROUTER ID: 192.168.255.1} SRv6_SID: {SIDs: fd00::1} MULTI_TOPO_IDs: {MultiTopoIDs: 1}} } 0.0.0.0                                   00:00:08   [{Origin: ?}]
```

## Using BGP-LS in GoBGP library mode

```go
package main

import (
	"context"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/osrg/gobgp/v3/pkg/log"
)

func main() {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	s := server.NewBgpServer(server.LoggerOption(&myLogger{logger: log}))
	go s.Serve()

	if err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:         64512,
			RouterId:   "10.0.255.254",
			ListenPort: -1, // gobgp won't listen on tcp:179
		},
	}); err != nil {
		log.Fatal(err)
	}

	marshaller := protojson.MarshalOptions{
		Indent:   "  ",
		UseProtoNames: true,
	}

	// the change of the peer state and path
	if err := s.WatchEvent(context.Background(), &api.WatchEventRequest{
		Peer: &api.WatchEventRequest_Peer{},
		Table: &api.WatchEventRequest_Table{
			Filters: []*api.WatchEventRequest_Table_Filter{
				{
					Type: api.WatchEventRequest_Table_Filter_BEST,
				},
			},
		},}, func(r *api.WatchEventResponse) {
			if p := r.GetPeer(); p != nil && p.Type == api.WatchEventResponse_PeerEvent_STATE {
				log.Info(p)
			} else if t := r.GetTable(); t != nil {
				// Your application should do something useful with the BGP-LS path here.
				for _, p := range t.Paths {
					marshaller.Marshal(p)
				}
			}
		}); err != nil {
		log.Fatal(err)
	}

	// neighbor configuration
	n := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "172.17.0.2",
			PeerAsn:          65002,
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

	select {}
}

// implement github.com/osrg/gobgp/v3/pkg/log/Logger interface
type myLogger struct {
	logger *logrus.Logger
}

func (l *myLogger) Panic(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Panic(msg)
}

func (l *myLogger) Fatal(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Fatal(msg)
}

func (l *myLogger) Error(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Error(msg)
}

func (l *myLogger) Warn(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Warn(msg)
}

func (l *myLogger) Info(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Info(msg)
}

func (l *myLogger) Debug(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Debug(msg)
}

func (l *myLogger) SetLevel(level log.LogLevel) {
	l.logger.SetLevel(logrus.Level(level))
}

func (l *myLogger) GetLevel() log.LogLevel {
	return log.LogLevel(l.logger.GetLevel())
}

```
