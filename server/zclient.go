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
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
	"github.com/osrg/gobgp/zebra"
	"net"
	"strconv"
	"strings"
	"time"
)

func newIPRouteMessage(dst []*table.Path) *zebra.Message {
	paths := make([]*table.Path, 0, len(dst))
	for _, path := range dst {
		if path == nil || path.IsFromExternal() {
			continue
		}
		paths = append(paths, path)
	}
	if len(paths) == 0 {
		return nil
	}
	path := paths[0]

	l := strings.SplitN(path.GetNlri().String(), "/", 2)
	var command zebra.API_TYPE
	var prefix net.IP
	nexthops := make([]net.IP, 0, len(paths))
	switch path.GetRouteFamily() {
	case bgp.RF_IPv4_UC:
		if path.IsWithdraw == true {
			command = zebra.IPV4_ROUTE_DELETE
		} else {
			command = zebra.IPV4_ROUTE_ADD
		}
		prefix = net.ParseIP(l[0]).To4()
		for _, p := range paths {
			nexthops = append(nexthops, p.GetNexthop().To4())
		}
	case bgp.RF_IPv6_UC:
		if path.IsWithdraw == true {
			command = zebra.IPV6_ROUTE_DELETE
		} else {
			command = zebra.IPV6_ROUTE_ADD
		}
		prefix = net.ParseIP(l[0]).To16()
		for _, p := range paths {
			nexthops = append(nexthops, p.GetNexthop().To16())
		}
	default:
		return nil
	}
	flags := uint8(zebra.MESSAGE_NEXTHOP)
	plen, _ := strconv.Atoi(l[1])
	med, err := path.GetMed()
	if err == nil {
		flags |= zebra.MESSAGE_METRIC
	}
	return &zebra.Message{
		Header: zebra.Header{
			Len:     zebra.HEADER_SIZE,
			Marker:  zebra.HEADER_MARKER,
			Version: zebra.VERSION,
			Command: command,
		},
		Body: &zebra.IPRouteBody{
			Type:         zebra.ROUTE_BGP,
			SAFI:         zebra.SAFI_UNICAST,
			Message:      flags,
			Prefix:       prefix,
			PrefixLength: uint8(plen),
			Nexthops:     nexthops,
			Metric:       med,
		},
	}
}

func createPathFromIPRouteMessage(m *zebra.Message) *table.Path {

	header := m.Header
	body := m.Body.(*zebra.IPRouteBody)
	family := bgp.RF_IPv6_UC
	if header.Command == zebra.IPV4_ROUTE_ADD || header.Command == zebra.IPV4_ROUTE_DELETE {
		family = bgp.RF_IPv4_UC
	}

	var nlri bgp.AddrPrefixInterface
	pattr := make([]bgp.PathAttributeInterface, 0)
	var mpnlri *bgp.PathAttributeMpReachNLRI
	var isWithdraw bool = header.Command == zebra.IPV4_ROUTE_DELETE || header.Command == zebra.IPV6_ROUTE_DELETE

	origin := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP)
	pattr = append(pattr, origin)

	log.WithFields(log.Fields{
		"Topic":        "Zebra",
		"RouteType":    body.Type.String(),
		"Flag":         body.Flags.String(),
		"Message":      body.Message,
		"Prefix":       body.Prefix,
		"PrefixLength": body.PrefixLength,
		"Nexthop":      body.Nexthops,
		"IfIndex":      body.Ifindexs,
		"Metric":       body.Metric,
		"Distance":     body.Distance,
		"api":          header.Command.String(),
	}).Debugf("create path from ip route message.")

	switch family {
	case bgp.RF_IPv4_UC:
		nlri = bgp.NewIPAddrPrefix(body.PrefixLength, body.Prefix.String())
		nexthop := bgp.NewPathAttributeNextHop(body.Nexthops[0].String())
		pattr = append(pattr, nexthop)
	case bgp.RF_IPv6_UC:
		nlri = bgp.NewIPv6AddrPrefix(body.PrefixLength, body.Prefix.String())
		mpnlri = bgp.NewPathAttributeMpReachNLRI(body.Nexthops[0].String(), []bgp.AddrPrefixInterface{nlri})
		pattr = append(pattr, mpnlri)
	default:
		log.WithFields(log.Fields{
			"Topic": "Zebra",
		}).Errorf("unsupport address family: %s", family)
		return nil
	}

	med := bgp.NewPathAttributeMultiExitDisc(body.Metric)
	pattr = append(pattr, med)

	path := table.NewPath(nil, nlri, isWithdraw, pattr, time.Now(), false)
	path.SetIsFromExternal(true)
	return path
}

type zebraClient struct {
	client *zebra.Client
	server *BgpServer
	dead   chan struct{}
}

func (z *zebraClient) stop() {
	close(z.dead)
}

func (z *zebraClient) loop() {
	w := z.server.Watch(WatchBestPath())
	defer func() { w.Stop() }()

	for {
		select {
		case <-z.dead:
			return
		case msg := <-z.client.Receive():
			switch msg.Body.(type) {
			case *zebra.IPRouteBody:
				if p := createPathFromIPRouteMessage(msg); p != nil {
					if _, err := z.server.AddPath("", []*table.Path{p}); err != nil {
						log.Errorf("failed to add path from zebra: %s", p)
					}
				}
			}
		case ev := <-w.Event():
			msg := ev.(*WatchEventBestPath)
			if table.UseMultiplePaths.Enabled {
				for _, dst := range msg.MultiPathList {
					if m := newIPRouteMessage(dst); m != nil {
						z.client.Send(m)
					}
				}
			} else {
				for _, path := range msg.PathList {
					if m := newIPRouteMessage([]*table.Path{path}); m != nil {
						z.client.Send(m)
					}
				}
			}
		}
	}
}

func newZebraClient(s *BgpServer, url string, protos []string) (*zebraClient, error) {
	l := strings.SplitN(url, ":", 2)
	if len(l) != 2 {
		return nil, fmt.Errorf("unsupported url: %s", url)
	}
	cli, err := zebra.NewClient(l[0], l[1], zebra.ROUTE_BGP)
	if err != nil {
		return nil, err
	}
	cli.SendHello()
	cli.SendRouterIDAdd()
	cli.SendInterfaceAdd()
	for _, typ := range protos {
		t, err := zebra.RouteTypeFromString(typ)
		if err != nil {
			return nil, err
		}
		cli.SendRedistribute(t)
	}
	w := &zebraClient{
		dead:   make(chan struct{}),
		client: cli,
		server: s,
	}
	go w.loop()
	return w, nil
}
