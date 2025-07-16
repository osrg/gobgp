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

	"github.com/sirupsen/logrus"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

func main() {
	log := logrus.New()

	s := server.NewBgpServer(server.LoggerOption(&myLogger{logger: log}))
	go s.Serve()

	// global configuration
	if err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65003,
			RouterId:   "10.0.255.254",
			ListenPort: -1, // gobgp won't listen on tcp:179
		},
	}); err != nil {
		log.Fatal(err)
	}

	// monitor the change of the peer state
	if err := s.WatchEvent(context.Background(), server.WatchEventMessageCallbacks{
		OnPeerUpdate: func(peer *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
			if peer.Type == apiutil.PEER_EVENT_STATE {
				log.Info(peer.Peer)
			}
		}}); err != nil {
		log.Fatal(err)
	}

	// neighbor configuration
	n := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "172.17.0.2",
			PeerAsn:         65002,
		},
	}

	if err := s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: n,
	}); err != nil {
		log.Fatal(err)
	}

	// add routes
	nlri := bgp.NewIPAddrPrefix(24, "10.0.0.0")
	a1 := bgp.NewPathAttributeOrigin(0)
	a2 := bgp.NewPathAttributeNextHop("10.0.0.1")
	a3 := bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{6762, 39919, 65000, 35753, 65000})})
	attrs := []bgp.PathAttributeInterface{a1, a2, a3}

	_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
		Nlri:  nlri,
		Attrs: attrs,
	}}})
	if err != nil {
		log.Fatal(err)
	}

	// add v6 route
	v6Nlri := bgp.NewIPv6AddrPrefix(64, "2001:db8:1::")
	aMpr := bgp.NewPathAttributeMpReachNLRI("2001:db8::1", v6Nlri)
	aC := bgp.NewPathAttributeCommunities([]uint32{100, 200})
	attrs = []bgp.PathAttributeInterface{aMpr, aC}

	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
		Nlri:  v6Nlri,
		Attrs: attrs,
	}}})
	if err != nil {
		log.Fatal(err)
	}

	s.ListPath(apiutil.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
	}, func(prefix bgp.AddrPrefixInterface, paths []*apiutil.Path) {
		log.Info(prefix.String())
		for _, p := range paths {
			log.WithFields(logrus.Fields{
				"peer_asn":     p.PeerASN,
				"peer_address": p.PeerAddress,
				"age":          p.Age,
				"best":         p.Best,
			}).Info("path")
		}
	})

	// do something useful here instead of exiting
	time.Sleep(time.Minute * 3)
}

// implement github.com/osrg/gobgp/v4/pkg/log/Logger interface
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
