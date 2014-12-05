// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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

package table

import (
	"github.com/osrg/gobgp/packet"
	"net"
	"reflect"
)

type Table interface {
	createDest(nlri bgp.AddrPrefixInterface) Destination
	getDestinations() map[string]Destination
	setDestinations(destinations map[string]Destination)
	getDestination(key string) Destination
	setDestination(key string, dest Destination)
	tableKey(nlri bgp.AddrPrefixInterface) net.IP
	validatePath(path Path)
	validateNlri(nlri bgp.AddrPrefixInterface)
}

type TableDefault struct {
	ROUTE_FAMILY RouteFamily
	destinations map[string]Destination
	coreService  *CoreService
	//need SignalBus
}

func NewTableDefault(scope_id, coreService *CoreService) *TableDefault {
	table := &TableDefault{}
	table.ROUTE_FAMILY = RF_IPv4_UC
	table.destinations = make(map[string]Destination)
	table.coreService = coreService
	return table

}

func (td *TableDefault) getRoutefamily() RouteFamily {
	return td.ROUTE_FAMILY
}

func (td *TableDefault) getCoreService() *CoreService {
	return td.coreService
}

//Creates destination
//Implements interface
func (td *TableDefault) createDest(nlri *bgp.NLRInfo) Destination {
	//return NewDestination(td, nlri)
	logger.Error("CreateDest NotImplementedError")
	return nil
}

func insert(table Table, path Path) Destination {
	var dest Destination

	table.validatePath(path)
	table.validateNlri(path.getNlri())
	dest = getOrCreateDest(table, path.getNlri())

	if path.isWithdraw() {
		// withdraw insert
		dest.addWithdraw(path)
	} else {
		// path insert
		dest.addNewPath(path)
	}
	return dest
}
func insertSentRoute(table Table, sentRoute *SentRoute) {
	pd := sentRoute.path.(*PathDefault)
	table.validatePath(pd)
	dest := getOrCreateDest(table, pd.getNlri())
	dest.(*DestinationDefault).addSentRoute(sentRoute)
}

//"Remove old paths from whose source is `peer`
func (td *TableDefault) cleanupPathsForPeer(peer *Peer) {
	for _, dest := range td.destinations {
		dd := dest.(*DestinationDefault)
		pathsDeleted := dd.removeOldPathsFromSource(peer)
		hadSent := dd.removeSentRoute(peer)
		if hadSent {
			logger.Errorf("Cleaning paths from table %s for peer %s.", td, peer)
		}
		if pathsDeleted != nil {
			//need _signal_bus.dest_changed(dest)
		}
	}
}

/*
//Cleans table of any path that do not have any RT in common with interested_rts
// Commented out because it is a VPN-related processing
func (td *TableDefault) cleanUninterestingPaths(interested_rts) int  {
	uninterestingDestCount = 0
	for _, dest := range td.destinations {
		addedWithdraw :=dest.withdrawUnintrestingPaths(interested_rts)
		if addedWithdraw{
			//need _signal_bus.dest_changed(dest)
			uninterestingDestCount += 1
		}
	}
	return uninterestingDestCount
	// need content
}
*/

func deleteDestByNlri(table Table, nlri *bgp.NLRInfo) Destination {
	table.validateNlri(nlri)
	destinations := table.getDestinations()
	dest := destinations[table.tableKey(nlri).String()]
	if dest != nil {
		delete(destinations, table.tableKey(nlri).String())
	}
	return dest
}

func deleteDest(table Table, dest Destination) {
	destinations := table.getDestinations()
	delete(destinations, table.tableKey(dest.getNlri()).String())
}

func (td *TableDefault) validatePath(path Path) {
	if path == nil || path.getRouteFamily() != td.ROUTE_FAMILY {
		logger.Errorf("Invalid path. Expected instance of %s route family path, got %s.", td.ROUTE_FAMILY, path)
	}
}
func (td *TableDefault) validateNlri(nlri bgp.AddrPrefixInterface) {
	if nlri == nil {
		logger.Error("Invalid Vpnv4 prefix given.")
	}
}

func getOrCreateDest(table Table, nlri bgp.AddrPrefixInterface) Destination {
	logger.Debugf("Table type : %s", reflect.TypeOf(table))
	tableKey := table.tableKey(nlri)
	dest := table.getDestination(tableKey.String())
	// If destination for given prefix does not exist we create it.
	if dest == nil {
		logger.Debugf("dest with key %s is not found", tableKey.String())
		dest = table.createDest(nlri)
		table.setDestination(tableKey.String(), dest)
	}
	return dest
}

func (td *TableDefault) getDestinations() map[string]Destination {
	return td.destinations
}
func (td *TableDefault) setDestinations(destinations map[string]Destination) {
	td.destinations = destinations
}
func (td *TableDefault) getDestination(key string) Destination {
	dest, ok := td.destinations[key]
	if ok {
		return dest
	} else {
		return nil
	}
}

func (td *TableDefault) setDestination(key string, dest Destination) {
	td.destinations[key] = dest
}

//Implements interface
func (td *TableDefault) tableKey(nlri bgp.AddrPrefixInterface) net.IP {
	//need Inheritance over ride
	//return &nlri.IPAddrPrefix.IPAddrPrefixDefault.Prefix
	logger.Error("CreateDest NotImplementedError")
	return nil
}

/*
* 	Definition of inherited Table interface
 */

type IPv4Table struct {
	*TableDefault
	//need structure
}

func NewIPv4Table(scope_id, coreService *CoreService) *IPv4Table {
	ipv4Table := &IPv4Table{}
	ipv4Table.TableDefault = NewTableDefault(scope_id, coreService)
	ipv4Table.TableDefault.ROUTE_FAMILY = RF_IPv4_UC
	//need Processing
	return ipv4Table
}

//Creates destination
//Implements interface
func (ipv4t *IPv4Table) createDest(nlri bgp.AddrPrefixInterface) Destination {
	return NewIPv4Destination(nlri)
}

//make tablekey
//Implements interface
func (ipv4t *IPv4Table) tableKey(nlri bgp.AddrPrefixInterface) net.IP {
	//addrPrefix := nlri.(*bgp.IPAddrPrefix)

	var ip net.IP
	switch p := nlri.(type) {
	case *bgp.NLRInfo:
		ip = p.IPAddrPrefix.IPAddrPrefixDefault.Prefix
	case *bgp.WithdrawnRoute:
		ip = p.IPAddrPrefix.IPAddrPrefixDefault.Prefix
	}
	return ip
}

type IPv6Table struct {
	*TableDefault
	//need structure
}

func NewIPv6Table(scope_id, coreService *CoreService) *IPv6Table {
	ipv6Table := &IPv6Table{}
	ipv6Table.TableDefault = NewTableDefault(scope_id, coreService)
	ipv6Table.TableDefault.ROUTE_FAMILY = RF_IPv6_UC
	//need Processing
	return ipv6Table
}

//Creates destination
//Implements interface
func (ipv6t *IPv6Table) createDest(nlri bgp.AddrPrefixInterface) Destination {
	return Destination(NewIPv6Destination(nlri))
}

//make tablekey
//Implements interface
func (ipv6t *IPv6Table) tableKey(nlri bgp.AddrPrefixInterface) net.IP {

	addrPrefix := nlri.(*bgp.IPv6AddrPrefix)
	return addrPrefix.IPAddrPrefixDefault.Prefix

}
