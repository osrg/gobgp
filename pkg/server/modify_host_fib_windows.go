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
//go:build windows
// +build windows

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// newModifyHostFIBClient creates a new modifyHostFIBClient, attaches is to the global
// BgpServer struct and kicks off its main goroutine loop.
func newModifyHostFIBClient(s *BgpServer) (*modifyHostFIBClient, error) {
	// set up a context to be able to stop the loop() goroutine before we clean up the
	// server while stopping, to avoid race conditions
	ctx, cancel := context.WithCancel(context.Background())
	client := &modifyHostFIBClient{
		server:       s,
		stopLoop:     cancel,
		loopFinished: new(sync.WaitGroup),
	}
	// set up a waitgroup so we clean up only after it's fully finished
	client.loopFinished.Add(1)
	go client.loop(ctx, client.loopFinished)
	return client, nil
}

// loop contains the central coordination for modify-host-fib functionality. It watches
// for route changes and calls the appropriate functionality to interact with the host's
// route table.
func (client *modifyHostFIBClient) loop(ctx context.Context, wg *sync.WaitGroup) {
	w := client.server.watch([]watchOption{
		watchBestPath(true),
		watchPostUpdate(true, ""),
	}...)
	defer w.Stop()

	for {
		select {
		case <-ctx.Done():
			wg.Done()
			return
		case ev := <-w.Event():
			switch msg := ev.(type) {
			case *watchEventBestPath:
				// client.server.logger.Info("watchEventBestPath",
				// 	log.Fields{
				// 		"Topic": "ModifyHostFIB",
				// 		"Msg":   msg,
				// 	},
				// )
				for _, path := range msg.PathList {
					if path.GetRouteFamily() != bgp.RF_IPv4_UC {
						continue
					}

					prefix := path.GetNlri().(*bgp.IPAddrPrefix).IPAddrPrefixDefault.Prefix.To4()
					prefixLen := path.GetNlri().(*bgp.IPAddrPrefix).IPAddrPrefixDefault.Length
					nextHop := path.GetNexthop()

					client.server.logger.Info("watchEventBestPath event",
						log.Fields{
							"Topic":   "ModifyHostFIB",
							"Prefix":  fmt.Sprintf("%v/%v", prefix, prefixLen),
							"NextHop": nextHop,
						},
					)

					if path.IsWithdraw {
						_, err := deleteIPv4HostFIBRoutes(prefix, prefixLen)
						if err != nil {
							client.server.logger.Error(
								fmt.Sprintf("failed to delete host route %v/%v", prefix, prefixLen),
								log.Fields{
									"Topic": "ModifyHostFIB",
									"Error": err,
								},
							)
						}
					} else {
						err := client.updateIPv4HostFIBRoute(prefix, prefixLen, nextHop)
						if err != nil {
							client.server.logger.Error(
								fmt.Sprintf("failed to add host route %v/%v", prefix, prefixLen),
								log.Fields{
									"Topic": "ModifyHostFIB",
									"Error": err,
								},
							)
						}
					}
				}
			}
		}
	}
}

// stop should be called to clean up. It removes all BGP routes from the host's routing
// table. These will most likely be from us but could be from another process (e.g.
// native Windows BGP on Windows Server).
func (client *modifyHostFIBClient) stop() error {
	// avoid race conditions with loop recreating routes.
	client.stopLoop()
	client.loopFinished.Wait()

	routingTable, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return err
	}

	for _, route := range routingTable {
		if route.Protocol == winipcfg.RouteProtocolBgp {
			route.Delete()
			client.server.logger.Info(
				fmt.Sprintf("Stopping: deleting route %v", route.DestinationPrefix.Prefix()),
				log.Fields{
					"Topic": "ModifyHostFIB",
				},
			)
		}
	}
	return nil
}

// updateIPv4HostFIBRoute creates a new or updates an existing route for
// prefix/prefixLength to nexthop. An existing route is only updated if it was
// originally received from BGP (most likely from us). A new route is not created if an
// existing non-BGP route exists.
func (client *modifyHostFIBClient) updateIPv4HostFIBRoute(
	prefix net.IP,
	prefixLength uint8,
	nexthop net.IP,
) error {
	// delete any existing BGP routes first because Create() below will error on duplicate routes.
	// this avoids having to recurse or split functions.
	_, err := deleteIPv4HostFIBRoutes(prefix, prefixLength)
	if err != nil {
		return err
	}

	// convert input to required types
	netipPrefix, netipNextHop, err := ipv4RouteNetToNetIP(prefix, prefixLength, nexthop)
	if err != nil {
		return err
	}
	winPrefix := winipcfg.IPAddressPrefix{}
	err = winPrefix.SetPrefix(netipPrefix)
	if err != nil {
		return err
	}
	winNextHop := winipcfg.RawSockaddrInet{}
	err = winNextHop.SetAddr(netipNextHop)
	if err != nil {
		return err
	}

	// try creating a new route
	route := winipcfg.MibIPforwardRow2{}
	route.Init()
	route.DestinationPrefix = winPrefix
	route.NextHop = winNextHop
	route.InterfaceIndex, err = interfaceIndexFromIPv4Addr(winNextHop)
	if err != nil {
		return err
	}
	// mark where it came from so we know if it's safe to delete later
	route.Protocol = winipcfg.RouteProtocolBgp
	err = route.Create()
	if err != nil {
		// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2#return-valuel
		// a route to the destination already exists, even though we deleted all BGP
		// routes to the destination above. This means its a non-BGP route so leave it
		if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			return nil
		} else if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("access denied. Make sure to run gobgpd as administrator")
		} else {
			return err
		}
	}

	return nil
}

// ipv4RouteNetToNetIP converts inputs for other functions from the original golang IP
// format to the new.
func ipv4RouteNetToNetIP(
	prefix net.IP,
	prefixLength uint8,
	nexthop net.IP,
) (netipPrefix netip.Prefix, netipNextHop netip.Addr, err error) {
	netipPrefixAddr, ok := netip.AddrFromSlice(prefix)
	if !ok {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf(
			"`netipPrefix netip.Prefix \"%v\"` didn't parse as a `netip.Addr`", netipPrefix,
		)
	}

	netipPrefix = netip.PrefixFrom(netipPrefixAddr, int(prefixLength))
	if netipPrefix.Bits() == -1 {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf(
			"`netipPrefix netip.Prefix \"%v\"` didn't parse as a `netip.Addr`", netipPrefix,
		)
	}

	netipNextHop, ok = netip.AddrFromSlice(nexthop)
	if !ok {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf(
			"`nextHop net.IP \"%v\"` didn't parse as a `netip.Addr`", nexthop,
		)
	}
	return netipPrefix, netipNextHop, nil
}

// ipv4AddrNetToNetIP converts an IPv4 address for other functions from the original
// golang IP format to the new.
func ipv4AddrNetToNetIP(
	ip net.IP,
) (convertedIP netip.Addr, err error) {
	convertedIP, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf(
			"`ip net.IP \"%v\"` didn't parse as a `netip.Addr`", ip,
		)
	}
	return
}

// ipv4PrefixNetToNetIP converts an IPv4 prefix for other functions from the original golang IP
// format to the new.
func ipv4PrefixNetToNetIP(
	prefix net.IP,
	prefixLength uint8,
) (netipPrefix netip.Prefix, err error) {
	netipPrefixAddr, ok := netip.AddrFromSlice(prefix)
	if !ok {
		return netip.Prefix{}, fmt.Errorf(
			"`netipPrefix netip.Prefix \"%v\"` didn't parse as a `netip.Addr`", netipPrefix,
		)
	}

	netipPrefix = netip.PrefixFrom(netipPrefixAddr, int(prefixLength))
	if netipPrefix.Bits() == -1 {
		return netip.Prefix{}, fmt.Errorf(
			"`netipPrefix netip.Prefix \"%v\"` didn't parse as a `netip.Addr`", netipPrefix,
		)
	}
	return
}

// interfaceIndexFromIPv4Addr returns the index of the outbound interface a route should
// take to reach destinationIP.
func interfaceIndexFromIPv4Addr(destinationIP winipcfg.RawSockaddrInet) (uint32, error) {
	routingTable, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return 0, err
	}
	for _, route := range routingTable {
		if route.DestinationPrefix.Prefix().Contains(destinationIP.Addr()) {
			return route.InterfaceIndex, nil
		}
	}

	return 0, fmt.Errorf("no route found for %v", destinationIP)
}

// deleteIPv4HostFIBRoute deletes all routes to prefix/prefixLength if they've been
// received via BGP. This will most likely be us but could be from another process (e.g.
// native Windows BGP on Windows Server).
//
// err will still be nil even if no routes were deleted.
func deleteIPv4HostFIBRoutes(
	prefix net.IP,
	prefixLength uint8,
) (deletedAny bool, err error) {
	netipPrefix, err := ipv4PrefixNetToNetIP(prefix, prefixLength)
	if err != nil {
		return false, err
	}

	routingTable, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return false, err
	}

	deletedAny = false
	for _, route := range routingTable {
		if route.DestinationPrefix.Prefix() == netipPrefix &&
			route.Protocol == winipcfg.RouteProtocolBgp {
			route.Delete()
			deletedAny = true
		}
	}
	return
}
