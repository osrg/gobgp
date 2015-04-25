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
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/packet"
	"reflect"
)

type Table interface {
	createDest(nlri bgp.AddrPrefixInterface) Destination
	GetDestinations() map[string]Destination
	setDestinations(destinations map[string]Destination)
	getDestination(key string) Destination
	setDestination(key string, dest Destination)
	tableKey(nlri bgp.AddrPrefixInterface) string
	validatePath(path Path)
	validateNlri(nlri bgp.AddrPrefixInterface)
	DeleteDestByPeer(*PeerInfo) []Destination
}

type TableDefault struct {
	ROUTE_FAMILY bgp.RouteFamily
	destinations map[string]Destination
	//need SignalBus
}

func NewTableDefault(scope_id int) *TableDefault {
	table := &TableDefault{}
	table.ROUTE_FAMILY = bgp.RF_IPv4_UC
	table.destinations = make(map[string]Destination)
	return table

}

func (td *TableDefault) GetRoutefamily() bgp.RouteFamily {
	return td.ROUTE_FAMILY
}

//Creates destination
//Implements interface
func (td *TableDefault) createDest(nlri *bgp.NLRInfo) Destination {
	//return NewDestination(td, nlri)
	log.Error("CreateDest NotImplementedError")
	return nil
}

func insert(table Table, path Path) Destination {
	var dest Destination

	table.validatePath(path)
	table.validateNlri(path.GetNlri())
	dest = getOrCreateDest(table, path.GetNlri())

	if path.IsWithdraw() {
		// withdraw insert
		dest.addWithdraw(path)
	} else {
		// path insert
		dest.addNewPath(path)
	}
	return dest
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

func (td *TableDefault) DeleteDestByPeer(peerInfo *PeerInfo) []Destination {
	changedDests := make([]Destination, 0)
	for _, dest := range td.destinations {
		newKnownPathList := make([]Path, 0)
		for _, p := range dest.getKnownPathList() {
			if p.GetSource() != peerInfo {
				newKnownPathList = append(newKnownPathList, p)
			}
		}
		if len(newKnownPathList) != len(dest.getKnownPathList()) {
			changedDests = append(changedDests, dest)
			dest.setKnownPathList(newKnownPathList)
		}
	}
	return changedDests
}

func deleteDestByNlri(table Table, nlri bgp.AddrPrefixInterface) Destination {
	table.validateNlri(nlri)
	destinations := table.GetDestinations()
	dest := destinations[table.tableKey(nlri)]
	if dest != nil {
		delete(destinations, table.tableKey(nlri))
	}
	return dest
}

func deleteDest(table Table, dest Destination) {
	destinations := table.GetDestinations()
	delete(destinations, table.tableKey(dest.getNlri()))
}

func (td *TableDefault) validatePath(path Path) {
	if path == nil || path.GetRouteFamily() != td.ROUTE_FAMILY {
		if path == nil {
			log.WithFields(log.Fields{
				"Topic": "Table",
				"Key":   td.ROUTE_FAMILY,
			}).Error("path is nil")
		} else if path.GetRouteFamily() != td.ROUTE_FAMILY {
			log.WithFields(log.Fields{
				"Topic":      "Table",
				"Key":        td.ROUTE_FAMILY,
				"Prefix":     path.GetNlri().String(),
				"ReceivedRf": path.GetRouteFamily().String(),
			}).Error("Invalid path. RouteFamily mismatch")
		}
	}
	_, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	if attr != nil {
		pathParam := attr.(*bgp.PathAttributeAsPath).Value
		for _, as := range pathParam {
			_, y := as.(*bgp.As4PathParam)
			if !y {
				log.WithFields(log.Fields{
					"Topic": "Table",
					"Key":   td.ROUTE_FAMILY,
					"As":    as,
				}).Fatal("AsPathParam must be converted to As4PathParam")
			}
		}
	}

	_, attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS4_PATH)
	if attr != nil {
		log.WithFields(log.Fields{
			"Topic": "Table",
			"Key":   td.ROUTE_FAMILY,
		}).Fatal("AS4_PATH must be converted to AS_PATH")
	}
}

func (td *TableDefault) validateNlri(nlri bgp.AddrPrefixInterface) {
	if nlri == nil {
		log.WithFields(log.Fields{
			"Topic": "Table",
			"Key":   td.ROUTE_FAMILY,
			"Nlri":  nlri,
		}).Error("Invalid Vpnv4 prefix given.")

	}
}

func getOrCreateDest(table Table, nlri bgp.AddrPrefixInterface) Destination {
	log.Debugf("getOrCreateDest Table type : %s", reflect.TypeOf(table))
	tableKey := table.tableKey(nlri)
	dest := table.getDestination(tableKey)
	// If destination for given prefix does not exist we create it.
	if dest == nil {
		log.Debugf("getOrCreateDest dest with key %s is not found", tableKey)
		dest = table.createDest(nlri)
		table.setDestination(tableKey, dest)
	}
	return dest
}

func (td *TableDefault) GetDestinations() map[string]Destination {
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
func (td *TableDefault) tableKey(nlri bgp.AddrPrefixInterface) string {
	//need Inheritance over ride
	//return &nlri.IPAddrPrefix.IPAddrPrefixDefault.Prefix
	log.Error("CreateDest NotImplementedError")
	return ""
}

/*
* 	Definition of inherited Table interface
 */

type IPv4Table struct {
	*TableDefault
	//need structure
}

func NewIPv4Table(scope_id int) *IPv4Table {
	ipv4Table := &IPv4Table{}
	ipv4Table.TableDefault = NewTableDefault(scope_id)
	ipv4Table.TableDefault.ROUTE_FAMILY = bgp.RF_IPv4_UC
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
func (ipv4t *IPv4Table) tableKey(nlri bgp.AddrPrefixInterface) string {
	switch p := nlri.(type) {
	case *bgp.NLRInfo:
		return p.IPAddrPrefix.IPAddrPrefixDefault.String()
	case *bgp.WithdrawnRoute:
		return p.IPAddrPrefix.IPAddrPrefixDefault.String()
	}
	log.Fatal()
	return ""
}

type IPv6Table struct {
	*TableDefault
	//need structure
}

func NewIPv6Table(scope_id int) *IPv6Table {
	ipv6Table := &IPv6Table{}
	ipv6Table.TableDefault = NewTableDefault(scope_id)
	ipv6Table.TableDefault.ROUTE_FAMILY = bgp.RF_IPv6_UC
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
func (ipv6t *IPv6Table) tableKey(nlri bgp.AddrPrefixInterface) string {

	addrPrefix := nlri.(*bgp.IPv6AddrPrefix)
	return addrPrefix.IPAddrPrefixDefault.String()

}

type IPv4VPNTable struct {
	*TableDefault
	//need structure
}

func NewIPv4VPNTable(scope_id int) *IPv4VPNTable {
	ipv4VPNTable := &IPv4VPNTable{}
	ipv4VPNTable.TableDefault = NewTableDefault(scope_id)
	ipv4VPNTable.TableDefault.ROUTE_FAMILY = bgp.RF_IPv4_VPN
	//need Processing
	return ipv4VPNTable
}

//Creates destination
//Implements interface
func (ipv4vpnt *IPv4VPNTable) createDest(nlri bgp.AddrPrefixInterface) Destination {
	return Destination(NewIPv4VPNDestination(nlri))
}

//make tablekey
//Implements interface
func (ipv4vpnt *IPv4VPNTable) tableKey(nlri bgp.AddrPrefixInterface) string {

	addrPrefix := nlri.(*bgp.LabelledVPNIPAddrPrefix)
	return addrPrefix.IPAddrPrefixDefault.String()

}

type EVPNTable struct {
	*TableDefault
	//need structure
}

func NewEVPNTable(scope_id int) *EVPNTable {
	EVPNTable := &EVPNTable{}
	EVPNTable.TableDefault = NewTableDefault(scope_id)
	EVPNTable.TableDefault.ROUTE_FAMILY = bgp.RF_EVPN
	//need Processing
	return EVPNTable
}

//Creates destination
//Implements interface
func (ipv4vpnt *EVPNTable) createDest(nlri bgp.AddrPrefixInterface) Destination {
	return Destination(NewEVPNDestination(nlri))
}

//make tablekey
//Implements interface
func (ipv4vpnt *EVPNTable) tableKey(nlri bgp.AddrPrefixInterface) string {

	addrPrefix := nlri.(*bgp.EVPNNLRI)
	return addrPrefix.String()
}

type EncapTable struct {
	*TableDefault
}

func NewEncapTable() *EncapTable {
	EncapTable := &EncapTable{}
	EncapTable.TableDefault = NewTableDefault(0)
	EncapTable.TableDefault.ROUTE_FAMILY = bgp.RF_ENCAP
	return EncapTable
}

func (t *EncapTable) createDest(nlri bgp.AddrPrefixInterface) Destination {
	return Destination(NewEncapDestination(nlri))
}

func (t *EncapTable) tableKey(nlri bgp.AddrPrefixInterface) string {
	return nlri.String()
}
