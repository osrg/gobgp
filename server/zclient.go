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

type nexthopTrackingManager struct {
	nexthopCache            []*net.IP
	server                  *BgpServer
	delay                   int
	isScheduled             bool
	scheduledNexthopUpdates []*zebra.NexthopUpdateBody
}

func newNexthopTrackingManager(server *BgpServer, delay int) *nexthopTrackingManager {
	return &nexthopTrackingManager{
		nexthopCache: make([]*net.IP, 0),
		server:       server,
		delay:        delay,
		scheduledNexthopUpdates: make([]*zebra.NexthopUpdateBody, 0),
	}
}

func (m *nexthopTrackingManager) isRegisteredNexthop(nexthop net.IP) bool {
	for _, cached := range m.nexthopCache {
		if cached.Equal(nexthop) {
			return true
		}
	}
	return false
}

func (m *nexthopTrackingManager) registerNexthop(nexthop net.IP) bool {
	if m.isRegisteredNexthop(nexthop) {
		return false
	}
	m.nexthopCache = append(m.nexthopCache, &nexthop)
	return true
}

func (m *nexthopTrackingManager) calculateDelay(penalty int) int {
	if penalty <= 950 {
		return m.delay
	}

	delay := 8
	for penalty > 950 {
		delay += 8
		penalty /= 2
	}
	return delay
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

func newNexthopRegisterMessage(dst pathList, version uint8, vrfId uint16, nhtManager *nexthopTrackingManager) *zebra.Message {
	// Note: NEXTHOP_REGISTER and NEXTHOP_UNREGISTER messages are not
	// supported in Zebra protocol version<3.
	if version < 3 || nhtManager == nil {
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
		if nhtManager.isRegisteredNexthop(nexthop) || p.IsNexthopInvalid || nexthop.IsUnspecified() {
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
		nhtManager.registerNexthop(nexthop)
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
	}).Debug("create path from ip route message.")

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

func createPathListFromNexthopUpdateMessage(body *zebra.NexthopUpdateBody, manager *table.TableManager) ([]*table.Path, error) {
	isNexthopInvalid := len(body.Nexthops) == 0

	var rfList []bgp.RouteFamily
	switch body.Family {
	case uint16(syscall.AF_INET):
		rfList = []bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv4_VPN}
	case uint16(syscall.AF_INET6):
		rfList = []bgp.RouteFamily{bgp.RF_IPv6_UC, bgp.RF_IPv6_VPN}
	default:
		return nil, fmt.Errorf("invalid address family: %d", body.Family)
	}

	paths := manager.GetPathListWithNexthop(table.GLOBAL_RIB_NAME, rfList, body.Prefix)
	updatedPathList := make(pathList, 0, len(paths))
	for _, path := range paths {
		if isNexthopInvalid {
			// If NEXTHOP_UPDATE message does NOT contain any nexthop,
			// invalidates the nexthop reachability.
			path.IsNexthopInvalid = true
		} else {
			// If NEXTHOP_UPDATE message contains valid nexthops,
			// copies Metric into MED.
			path.IsNexthopInvalid = false
			path.SetMed(int64(body.Metric), true)
		}
		updatedPathList = append(updatedPathList, path)
	}

	return updatedPathList, nil
}

type zebraEvent struct {
	nexthopUpdates []*zebra.NexthopUpdateBody
}

type zebraClient struct {
	client     *zebra.Client
	server     *BgpServer
	nhtManager *nexthopTrackingManager
	EventCh    chan *zebraEvent
}

func (z *zebraClient) HandleUpdatedPath(event *zebraEvent) []*table.Path {
	list := make([]*table.Path, 0)
	for _, update := range event.nexthopUpdates {
		if l, err := createPathListFromNexthopUpdateMessage(update, z.server.globalRib); err != nil {
			log.WithFields(log.Fields{
				"Topic": "Zebra",
				"Event": "Nexthop Tracking",
			}).Error("failed to update nexthop reachability")
		} else {
			log.WithFields(log.Fields{
				"Topic": "Zebra",
				"Event": "Nexthop Tracking",
			}).Debugf("update nexthop reachability: %s", l)
			list = append(list, l...)
		}
	}
	return list
}

func (z *zebraClient) loop() {
	w := z.server.Watch(WatchBestPath(true))
	defer w.Stop()
	t := &time.Ticker{}

	if z.nhtManager != nil {
		t = time.NewTicker(8 * time.Second)
		defer t.Stop()
	}

	penalty := 0
	dampeningCh := make(chan struct{})

	for {
		select {
		case <-t.C:
			penalty /= 2
		case <-dampeningCh:
			z.EventCh <- &zebraEvent{nexthopUpdates: z.nhtManager.scheduledNexthopUpdates}
			z.nhtManager.scheduledNexthopUpdates = make([]*zebra.NexthopUpdateBody, 0)
		case msg := <-z.client.Receive():
			switch msg.Body.(type) {
			case *zebra.IPRouteBody:
				if p := createPathFromIPRouteMessage(msg); p != nil {
					if _, err := z.server.AddPath("", pathList{p}); err != nil {
						log.Errorf("failed to add path from zebra: %s", p)
					}
				}
			case *zebra.NexthopUpdateBody:
				if z.nhtManager != nil {
					penalty += 500
					log.WithFields(log.Fields{
						"Topic": "Zebra",
						"Event": "Nexthop Tracking",
					}).Debugf("penalty 500 charged: penalty: %d", penalty)
					body := msg.Body.(*zebra.NexthopUpdateBody)
					if len(z.nhtManager.scheduledNexthopUpdates) != 0 {
						// already scheduled
					} else {
						delay := z.nhtManager.calculateDelay(penalty)
						time.AfterFunc(time.Second*time.Duration(delay), func() { dampeningCh <- struct{}{} })
						log.WithFields(log.Fields{
							"Topic": "Zebra",
							"Event": "Nexthop Tracking",
						}).Debugf("nexthop tracking event scheduled in %d secs", delay)
					}
					z.nhtManager.scheduledNexthopUpdates = append(z.nhtManager.scheduledNexthopUpdates, body)
				}
			}
		case ev := <-w.Event():
			msg := ev.(*WatchEventBestPath)
			if table.UseMultiplePaths.Enabled {
				for _, dst := range msg.MultiPathList {
					if m := newIPRouteMessage(dst, z.client.Version, 0); m != nil {
						z.client.Send(m)
					}
					if m := newNexthopRegisterMessage(dst, z.client.Version, 0, z.nhtManager); m != nil {
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
						if m := newNexthopRegisterMessage(pathList{path}, z.client.Version, i, z.nhtManager); m != nil {
							z.client.Send(m)
						}
					}
				}
			}
		}
	}
}

func (z *zebraClient) Start(url string, protos []string, version uint8, nhtEnable bool, nhtDelay uint8) error {
	if z.client != nil {
		return fmt.Errorf("already started")
	}
	l := strings.SplitN(url, ":", 2)
	if len(l) != 2 {
		return fmt.Errorf("unsupported url: %s", url)
	}
	cli, err := zebra.NewClient(l[0], l[1], zebra.ROUTE_BGP, version)
	if err != nil {
		return err
	}
	cli.SendHello()
	cli.SendRouterIDAdd()
	cli.SendInterfaceAdd()
	for _, typ := range protos {
		t, err := zebra.RouteTypeFromString(typ)
		if err != nil {
			return err
		}
		cli.SendRedistribute(t, zebra.VRF_DEFAULT)
	}
	if nhtEnable {
		z.nhtManager = newNexthopTrackingManager(z.server, int(nhtDelay))
	}
	z.client = cli
	go z.loop()
	return nil
}

func newZebraClient(s *BgpServer) *zebraClient {
	return &zebraClient{
		server:  s,
		EventCh: make(chan *zebraEvent, 16),
	}
}
