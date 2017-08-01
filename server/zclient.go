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
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
	"github.com/osrg/gobgp/zebra"
	log "github.com/sirupsen/logrus"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type pathList []*table.Path

type nexthopTrackingManager struct {
	dead              chan struct{}
	nexthopCache      []*net.IP
	server            *BgpServer
	delay             int
	isScheduled       bool
	scheduledPathList map[string]pathList
	trigger           chan struct{}
	pathListCh        chan pathList
}

func newNexthopTrackingManager(server *BgpServer, delay int) *nexthopTrackingManager {
	return &nexthopTrackingManager{
		dead:              make(chan struct{}),
		nexthopCache:      make([]*net.IP, 0),
		server:            server,
		delay:             delay,
		scheduledPathList: make(map[string]pathList, 0),
		trigger:           make(chan struct{}),
		pathListCh:        make(chan pathList),
	}
}

func (s *nexthopTrackingManager) stop() {
	close(s.pathListCh)
	close(s.trigger)
	close(s.dead)
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

func (m *nexthopTrackingManager) appendPathList(paths pathList) {
	if len(paths) == 0 {
		return
	}
	path := paths[0]

	m.scheduledPathList[path.GetNexthop().String()] = paths
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

func (m *nexthopTrackingManager) triggerUpdatePathAfter(delay int) {
	time.Sleep(time.Duration(delay) * time.Second)

	m.trigger <- struct{}{}
}

func (m *nexthopTrackingManager) loop() {
	t := time.NewTicker(8 * time.Second)
	defer t.Stop()

	penalty := 0

	for {
		select {
		case <-m.dead:
			return

		case <-t.C:
			penalty /= 2

		case paths := <-m.pathListCh:
			penalty += 500
			log.WithFields(log.Fields{
				"Topic": "Zebra",
				"Event": "Nexthop Tracking",
			}).Debug("penalty 500 chrged: penalty: %d", penalty)

			m.appendPathList(paths)

			isScheduled := m.isScheduled
			if isScheduled {
				log.WithFields(log.Fields{
					"Topic": "Zebra",
					"Event": "Nexthop Tracking",
				}).Debug("nexthop tracking event already scheduled")
				continue
			} else {
				m.isScheduled = true
			}

			delay := m.calculateDelay(penalty)
			go m.triggerUpdatePathAfter(delay)
			log.WithFields(log.Fields{
				"Topic": "Zebra",
				"Event": "Nexthop Tracking",
			}).Debug("nexthop tracking event scheduled in %d secs", delay)

		case <-m.trigger:
			paths := make(pathList, 0)
			for _, pList := range m.scheduledPathList {
				for _, p := range pList {
					paths = append(paths, p)
				}
			}
			log.WithFields(log.Fields{
				"Topic": "Zebra",
				"Event": "Nexthop Tracking",
			}).Debug("update nexthop reachability: %s", paths)

			if err := m.server.UpdatePath("", paths); err != nil {
				log.WithFields(log.Fields{
					"Topic": "Zebra",
					"Event": "Nexthop Tracking",
				}).Error("failed to update nexthop reachability")
			}

			m.isScheduled = false
			m.scheduledPathList = make(map[string]pathList, 0)
		}
	}
}

func (m *nexthopTrackingManager) scheduleUpdate(paths pathList) {
	if len(paths) == 0 {
		return
	}
	m.pathListCh <- paths
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
		if len(body.Nexthops) > 0 {
			pattr = append(pattr, bgp.NewPathAttributeNextHop(body.Nexthops[0].String()))
		}
	case bgp.RF_IPv6_UC:
		nlri = bgp.NewIPv6AddrPrefix(body.PrefixLength, body.Prefix.String())
		nexthop := ""
		if len(body.Nexthops) > 0 {
			nexthop = body.Nexthops[0].String()
		}
		pattr = append(pattr, bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}))
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

func createPathListFromNexthopUpdateMessage(m *zebra.Message, manager *table.TableManager) (pathList, error) {
	body := m.Body.(*zebra.NexthopUpdateBody)
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
		newPath := path.Clone(false)
		if isNexthopInvalid {
			// If NEXTHOP_UPDATE message does NOT contain any nexthop,
			// invalidates the nexthop reachability.
			newPath.IsNexthopInvalid = true
		} else {
			// If NEXTHOP_UPDATE message contains valid nexthops,
			// copies Metric into MED.
			newPath.IsNexthopInvalid = false
			newPath.SetMed(int64(body.Metric), true)
		}
		updatedPathList = append(updatedPathList, newPath)
	}

	return updatedPathList, nil
}

type zebraClient struct {
	client     *zebra.Client
	server     *BgpServer
	dead       chan struct{}
	nhtManager *nexthopTrackingManager
}

func (z *zebraClient) stop() {
	close(z.dead)
}

func (z *zebraClient) loop() {
	w := z.server.Watch(WatchBestPath(true))
	defer w.Stop()

	if z.nhtManager != nil {
		go z.nhtManager.loop()
		defer z.nhtManager.stop()
	}

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
			case *zebra.NexthopUpdateBody:
				if z.nhtManager != nil {
					body := msg.Body.(*zebra.NexthopUpdateBody)
					if paths, err := createPathListFromNexthopUpdateMessage(msg, z.server.globalRib); err != nil {
						log.Errorf("failed to create updated path list related to nexthop %s", body.Prefix.String())
					} else {
						z.nhtManager.scheduleUpdate(paths)
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

func newZebraClient(s *BgpServer, url string, protos []string, version uint8, nhtEnable bool, nhtDelay uint8) (*zebraClient, error) {
	l := strings.SplitN(url, ":", 2)
	if len(l) != 2 {
		return nil, fmt.Errorf("unsupported url: %s", url)
	}
	cli, err := zebra.NewClient(l[0], l[1], zebra.ROUTE_BGP, version)
	if err != nil {
		// Retry with another Zebra message version
		var retry_version uint8 = 2
		if version == 2 {
			retry_version = 3
		}
		log.WithFields(log.Fields{
			"Topic": "Zebra",
		}).Warnf("cannot connect to Zebra with message version %d. retry with version %d", version, retry_version)
		cli, err = zebra.NewClient(l[0], l[1], zebra.ROUTE_BGP, retry_version)
		if err != nil {
			return nil, err
		}
	}
	// Note: HELLO/ROUTER_ID_ADD messages are automatically sent to negotiate
	// the Zebra message version in zebra.NewClient().
	// cli.SendHello()
	// cli.SendRouterIDAdd()
	cli.SendInterfaceAdd()
	for _, typ := range protos {
		t, err := zebra.RouteTypeFromString(typ)
		if err != nil {
			return nil, err
		}
		cli.SendRedistribute(t, zebra.VRF_DEFAULT)
	}
	var nhtManager *nexthopTrackingManager = nil
	if nhtEnable {
		nhtManager = newNexthopTrackingManager(s, int(nhtDelay))
	}
	w := &zebraClient{
		dead:       make(chan struct{}),
		client:     cli,
		server:     s,
		nhtManager: nhtManager,
	}
	go w.loop()
	return w, nil
}
