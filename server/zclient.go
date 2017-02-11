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
	"syscall"
	"time"
)

type pathList []*table.Path

type registeredNexthopCache []*net.IP

func newRegisteredNexthopCache() *registeredNexthopCache {
	cache := make(registeredNexthopCache, 0)
	return &cache
}

func (c *registeredNexthopCache) isRegistered(nexthop net.IP) bool {
	for _, cached := range *c {
		if cached.Equal(nexthop) {
			return true
		}
	}
	return false
}

func (c *registeredNexthopCache) register(nexthop net.IP) bool {
	cache := *c
	if c.isRegistered(nexthop) {
		return false
	}
	*c = append(cache, &nexthop)
	return true
}

func filterOutNilPath(paths pathList) pathList {
	filteredPaths := make(pathList, 0, len(paths))
	for _, path := range paths {
		if path == nil {
			continue
		}
		filteredPaths = append(filteredPaths, path)
	}
	return filteredPaths
}

func filterOutExternalPath(paths pathList) pathList {
	filteredPaths := make(pathList, 0, len(paths))
	for _, path := range paths {
		if path == nil || path.IsFromExternal() {
			continue
		}
		filteredPaths = append(filteredPaths, path)
	}
	return filteredPaths
}

func newIPRouteMessage(dst pathList, version uint8, vrfId uint16) *zebra.Message {
	paths := filterOutExternalPath(dst)
	if len(paths) == 0 {
		return nil
	}
	path := paths[0]

	l := strings.SplitN(path.GetNlri().String(), "/", 2)
	var command zebra.API_TYPE
	var prefix net.IP
	nexthops := make([]net.IP, 0, len(paths))
	switch path.GetRouteFamily() {
	case bgp.RF_IPv4_UC, bgp.RF_IPv4_VPN:
		if path.IsWithdraw == true {
			command = zebra.IPV4_ROUTE_DELETE
		} else {
			command = zebra.IPV4_ROUTE_ADD
		}
		if path.GetRouteFamily() == bgp.RF_IPv4_UC {
			prefix = path.GetNlri().(*bgp.IPAddrPrefix).IPAddrPrefixDefault.Prefix.To4()
		} else {
			prefix = path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix).IPAddrPrefixDefault.Prefix.To4()
		}
		for _, p := range paths {
			nexthops = append(nexthops, p.GetNexthop().To4())
		}
	case bgp.RF_IPv6_UC, bgp.RF_IPv6_VPN:
		if path.IsWithdraw == true {
			command = zebra.IPV6_ROUTE_DELETE
		} else {
			command = zebra.IPV6_ROUTE_ADD
		}
		if path.GetRouteFamily() == bgp.RF_IPv6_UC {
			prefix = path.GetNlri().(*bgp.IPv6AddrPrefix).IPAddrPrefixDefault.Prefix.To16()
		} else {
			prefix = path.GetNlri().(*bgp.LabeledVPNIPv6AddrPrefix).IPAddrPrefixDefault.Prefix.To16()
		}
		for _, p := range paths {
			nexthops = append(nexthops, p.GetNexthop().To16())
		}
	default:
		return nil
	}
	msgFlags := uint8(zebra.MESSAGE_NEXTHOP)
	plen, _ := strconv.Atoi(l[1])
	med, err := path.GetMed()
	if err == nil {
		msgFlags |= zebra.MESSAGE_METRIC
	}
	var flags zebra.FLAG
	info := path.GetSource()
	if info.AS == info.LocalAS {
		flags = zebra.FLAG_IBGP | zebra.FLAG_INTERNAL
	} else if info.MultihopTtl > 0 {
		flags = zebra.FLAG_INTERNAL
	}
	return &zebra.Message{
		Header: zebra.Header{
			Len:     zebra.HeaderSize(version),
			Marker:  zebra.HEADER_MARKER,
			Version: version,
			Command: command,
			VrfId:   vrfId,
		},
		Body: &zebra.IPRouteBody{
			Type:         zebra.ROUTE_BGP,
			Flags:        flags,
			SAFI:         zebra.SAFI_UNICAST,
			Message:      msgFlags,
			Prefix:       prefix,
			PrefixLength: uint8(plen),
			Nexthops:     nexthops,
			Metric:       med,
		},
	}
}

func newNexthopRegisterMessage(dst pathList, version uint8, vrfId uint16, nexthopCache *registeredNexthopCache) *zebra.Message {
	// Note: NEXTHOP_REGISTER and NEXTHOP_UNREGISTER messages are not
	// supported in Zebra protocol version<3.
	if version < 3 {
		return nil
	}

	paths := filterOutNilPath(dst)
	if len(paths) == 0 {
		return nil
	}

	route_family := paths[0].GetRouteFamily()
	command := zebra.NEXTHOP_REGISTER
	if paths[0].IsWithdraw == true {
		// TODO:
		// Send NEXTHOP_UNREGISTER message if the given nexthop is no longer
		// referred by any path. Currently, do not send NEXTHOP_UNREGISTER
		// message to simplify the implementation.
		//command = zebra.NEXTHOP_UNREGISTER
		return nil
	}

	nexthops := make([]*zebra.RegisteredNexthop, 0, len(paths))
	for _, p := range paths {
		nexthop := p.GetNexthop()
		// Skips to register or unregister the given nexthop
		// when the nexthop is:
		// - already registered
		// - already invalidated
		// - an unspecified address
		if nexthopCache.isRegistered(nexthop) || p.IsNexthopInvalid || nexthop.IsUnspecified() {
			continue
		}

		var nh *zebra.RegisteredNexthop
		switch route_family {
		case bgp.RF_IPv4_UC, bgp.RF_IPv4_VPN:
			nh = &zebra.RegisteredNexthop{
				Family: syscall.AF_INET,
				Prefix: nexthop.To4(),
			}
		case bgp.RF_IPv6_UC, bgp.RF_IPv6_VPN:
			nh = &zebra.RegisteredNexthop{
				Family: syscall.AF_INET6,
				Prefix: nexthop.To16(),
			}
		default:
			return nil
		}
		nexthops = append(nexthops, nh)
		nexthopCache.register(nexthop)
	}

	// If no nexthop needs to be registered or unregistered,
	// skips to send message.
	if len(nexthops) == 0 {
		return nil
	}

	return &zebra.Message{
		Header: zebra.Header{
			Len:     zebra.HeaderSize(version),
			Marker:  zebra.HEADER_MARKER,
			Version: version,
			Command: command,
			VrfId:   vrfId,
		},
		Body: &zebra.NexthopRegisterBody{
			Nexthops: nexthops,
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
		"Mtu":          body.Mtu,
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
	w := z.server.Watch(WatchBestPath(true))
	defer func() { w.Stop() }()

	nexthopCache := newRegisteredNexthopCache()

	for {
		select {
		case <-z.dead:
			return
		case msg := <-z.client.Receive():
			switch msg.Body.(type) {
			case *zebra.IPRouteBody:
				if p := createPathFromIPRouteMessage(msg); p != nil {
					if _, err := z.server.AddPath("", pathList{p}); err != nil {
						log.Errorf("failed to add path from zebra: %s", p)
					}
				}
			}
		case ev := <-w.Event():
			msg := ev.(*WatchEventBestPath)
			if table.UseMultiplePaths.Enabled {
				for _, dst := range msg.MultiPathList {
					if m := newIPRouteMessage(dst, z.client.Version, 0); m != nil {
						z.client.Send(m)
					}
					if m := newNexthopRegisterMessage(dst, z.client.Version, 0, nexthopCache); m != nil {
						z.client.Send(m)
					}
				}
			} else {
				for _, path := range msg.PathList {
					if len(path.VrfIds) == 0 {
						path.VrfIds = []uint16{0}
					}
					for _, i := range path.VrfIds {
						if m := newIPRouteMessage(pathList{path}, z.client.Version, i); m != nil {
							z.client.Send(m)
						}
						if m := newNexthopRegisterMessage(pathList{path}, z.client.Version, i, nexthopCache); m != nil {
							z.client.Send(m)
						}
					}
				}
			}
		}
	}
}

func newZebraClient(s *BgpServer, url string, protos []string, version uint8) (*zebraClient, error) {
	l := strings.SplitN(url, ":", 2)
	if len(l) != 2 {
		return nil, fmt.Errorf("unsupported url: %s", url)
	}
	cli, err := zebra.NewClient(l[0], l[1], zebra.ROUTE_BGP, version)
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
		cli.SendRedistribute(t, zebra.VRF_DEFAULT)
	}
	w := &zebraClient{
		dead:   make(chan struct{}),
		client: cli,
		server: s,
	}
	go w.loop()
	return w, nil
}
