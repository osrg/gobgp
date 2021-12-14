# Using BGP-LS in GoBGP library mode

This page explains how to use GoBGP for getting BGP-LS prefixes.

## Contents

- [Basic BGP-LS Example](#basic-bgp-ls-example)

## Basic BGP-LS Example

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
