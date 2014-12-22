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
	"encoding/binary"
	"fmt"
	"github.com/osrg/gobgp/packet"
	"net"
	"reflect"
)

const (
	BPR_UNKNOWN            = "Unknown"
	BPR_ONLY_PATH          = "Only Path"
	BPR_REACHABLE_NEXT_HOP = "Reachable Next Hop"
	BPR_HIGHEST_WEIGHT     = "Highest Weight"
	BPR_LOCAL_PREF         = "Local Pref"
	BPR_LOCAL_ORIGIN       = "Local Origin"
	BPR_ASPATH             = "AS Path"
	BPR_ORIGIN             = "Origin"
	BPR_MED                = "MED"
	BPR_ASN                = "ASN"
	BPR_IGP_COST           = "IGP Cost"
	BPR_ROUTER_ID          = "Router ID"
)

type PeerInfo struct {
	AS         uint32
	ID         net.IP
	VersionNum int
	LocalID    net.IP
}

type Destination interface {
	Calculate(localAsn uint32) (Path, string, error)
	getRouteFamily() RouteFamily
	setRouteFamily(ROUTE_FAMILY RouteFamily)
	getNlri() bgp.AddrPrefixInterface
	setNlri(nlri bgp.AddrPrefixInterface)
	getBestPathReason() string
	setBestPathReason(string)
	getBestPath() Path
	setBestPath(path Path)
	GetOldBestPath() Path
	setOldBestPath(path Path)
	getKnownPathList() []Path
	setKnownPathList([]Path)
	String() string
	addWithdraw(withdraw Path)
	addNewPath(newPath Path)
	constructWithdrawPath() Path
	removeOldPathsFromSource(source *PeerInfo) []Path
}

type DestinationDefault struct {
	ROUTE_FAMILY   RouteFamily
	nlri           bgp.AddrPrefixInterface
	knownPathList  []Path
	withdrawList   []Path
	newPathList    []Path
	bestPath       Path
	bestPathReason string
	oldBestPath    Path
}

func NewDestinationDefault(nlri bgp.AddrPrefixInterface) *DestinationDefault {
	destination := &DestinationDefault{}
	destination.ROUTE_FAMILY = RF_IPv4_UC
	destination.nlri = nlri
	destination.knownPathList = make([]Path, 0)
	destination.withdrawList = make([]Path, 0)
	destination.newPathList = make([]Path, 0)
	destination.bestPath = nil
	destination.bestPathReason = ""
	destination.oldBestPath = nil
	return destination
}

func (dd *DestinationDefault) getRouteFamily() RouteFamily {
	return dd.ROUTE_FAMILY
}

func (dd *DestinationDefault) setRouteFamily(ROUTE_FAMILY RouteFamily) {
	dd.ROUTE_FAMILY = ROUTE_FAMILY
}

func (dd *DestinationDefault) getNlri() bgp.AddrPrefixInterface {
	return dd.nlri
}

func (dd *DestinationDefault) setNlri(nlri bgp.AddrPrefixInterface) {
	dd.nlri = nlri
}

func (dd *DestinationDefault) getBestPathReason() string {
	return dd.bestPathReason
}

func (dd *DestinationDefault) setBestPathReason(reason string) {
	dd.bestPathReason = reason
}

func (dd *DestinationDefault) getBestPath() Path {
	return dd.bestPath
}

func (dd *DestinationDefault) setBestPath(path Path) {
	dd.bestPath = path
}

func (dd *DestinationDefault) GetOldBestPath() Path {
	return dd.oldBestPath
}

func (dd *DestinationDefault) setOldBestPath(path Path) {
	dd.oldBestPath = path
}

func (dd *DestinationDefault) getKnownPathList() []Path {
	return dd.knownPathList
}

func (dd *DestinationDefault) setKnownPathList(List []Path) {
	dd.knownPathList = List
}

func (dd *DestinationDefault) addWithdraw(withdraw Path) {
	dd.validatePath(withdraw)
	dd.withdrawList = append(dd.withdrawList, withdraw)
}

func (dd *DestinationDefault) addNewPath(newPath Path) {
	dd.validatePath(newPath)
	dd.newPathList = append(dd.newPathList, newPath)
}

func (dd *DestinationDefault) removeOldPathsFromSource(source *PeerInfo) []Path {
	removePaths := make([]Path, 0)
	sourceVerNum := source.VersionNum
	tempKnownPathList := make([]Path, 0)

	for _, path := range dd.knownPathList {
		if path.getSource() == source && path.getSourceVerNum() < sourceVerNum {
			removePaths = append(removePaths, path)
		} else {
			tempKnownPathList = append(tempKnownPathList, path)
		}
	}
	dd.knownPathList = tempKnownPathList
	return removePaths
}

func (dd *DestinationDefault) validatePath(path Path) {
	if path == nil || path.getRouteFamily() != dd.ROUTE_FAMILY {
		logger.Error("Invalid path. Expected %s path got %s.", dd.ROUTE_FAMILY, path)
	}
}

// Calculates best-path among known paths for this destination.
//
// Returns: - Best path
//
// Modifies destination's state related to stored paths. Removes withdrawn
// paths from known paths. Also, adds new paths to known paths.
func (dest *DestinationDefault) Calculate(localAsn uint32) (Path, string, error) {

	// First remove the withdrawn paths.
	// Note: If we want to support multiple paths per destination we may
	// have to maintain sent-routes per path.
	dest.removeWithdrawls()

	//	Have to select best-path from available paths and new paths.
	//	If we do not have any paths, then we no longer have best path.
	if len(dest.knownPathList) == 0 && len(dest.newPathList) == 1 {
		// If we do not have any old but one new path
		// it becomes best path.
		dest.knownPathList = append(dest.knownPathList, dest.newPathList[0])
		dest.newPathList, _ = deleteAt(dest.newPathList, 0)
		logger.Debugf("best path : %s, reason=%s", dest.knownPathList[0], BPR_ONLY_PATH)

		return dest.knownPathList[0], BPR_ONLY_PATH, nil
	}

	// If we have a new version of old/known path we use it and delete old
	// one.
	dest.removeOldPaths()
	logger.Debugf("removeOldPaths")
	// Collect all new paths into known paths.
	dest.knownPathList = append(dest.knownPathList, dest.newPathList...)

	// Clear new paths as we copied them.
	dest.newPathList = make([]Path, 0)

	// If we do not have any paths to this destination, then we do not have
	// new best path.
	if len(dest.knownPathList) == 0 {
		return nil, BPR_UNKNOWN, nil
	}

	// Compute new best path
	currentBestPath, reason, e := dest.computeKnownBestPath(localAsn)
	if e != nil {
		logger.Error(e)
	}
	return currentBestPath, reason, e

}

//"""Removes withdrawn paths.
//
//Note:
//We may have disproportionate number of withdraws compared to know paths
//since not all paths get installed into the table due to bgp policy and
//we can receive withdraws for such paths and withdrawals may not be
//stopped by the same policies.
//"""
func (dest *DestinationDefault) removeWithdrawls() {

	logger.Debugf("Removing %d withdrawals", len(dest.withdrawList))

	// If we have no withdrawals, we have nothing to do.
	if len(dest.withdrawList) == 0 {
		return
	}

	// If we have some withdrawals and no know-paths, it means it is safe to
	// delete these withdraws.
	if len(dest.knownPathList) == 0 {
		logger.Debugf("Found %s withdrawals for path(s) that did not get installed", len(dest.withdrawList))
		dest.withdrawList = dest.withdrawList[len(dest.withdrawList):]
	}

	//	If we have some known paths and some withdrawals, we find matches and
	//	delete them first.
	matches := make(map[string]Path)
	wMatches := make(map[string]Path)
	// Match all withdrawals from destination paths.
	for _, withdraw := range dest.withdrawList {
		var isFound bool = false
		for _, path := range dest.knownPathList {
			// We have a match if the source are same.
			// TODO add GetSource to Path interface
			if path.getSource() == withdraw.getSource() {
				isFound = true
				matches[path.String()] = path
				wMatches[withdraw.String()] = withdraw
				// One withdraw can remove only one path.
				break
			}
		}

		// We do no have any match for this withdraw.
		if !isFound {
			logger.Debugf("No matching path for withdraw found, may be path was not installed into table: %s", withdraw.String())
		}
	}

	// If we have partial match.
	if len(matches) != len(dest.withdrawList) {
		logger.Debugf(
			"Did not find match for some withdrawals. Number of matches(%d), number of withdrawals (%d)",
			len(matches), len(dest.withdrawList))
	}

	// Clear matching paths and withdrawals.
	for _, path := range matches {
		var result bool = false
		dest.knownPathList, result = removeWithPath(dest.knownPathList, path)
		if !result {
			logger.Debugf("could not remove path: %s from knownPathList", path.String())
		}
	}
	for _, path := range wMatches {
		var result bool = false
		dest.withdrawList, result = removeWithPath(dest.withdrawList, path)
		if !result {
			logger.Debugf("could not remove path: %s from withdrawList", path.String())
		}
	}
}

func (dest *DestinationDefault) computeKnownBestPath(localAsn uint32) (Path, string, error) {

	//	"""Computes the best path among known paths.
	//
	//	Returns current best path among `knownPaths`.
	if len(dest.knownPathList) == 0 {
		return nil, "", fmt.Errorf("Need at-least one known path to compute best path")
	}

	logger.Debugf("computeKnownBestPath known pathlist: %d", len(dest.knownPathList))

	// We pick the first path as current best path. This helps in breaking
	// tie between two new paths learned in one cycle for which best-path
	// calculation steps lead to tie.
	currentBestPath := dest.knownPathList[0]
	bestPathReason := BPR_ONLY_PATH
	for _, nextPath := range dest.knownPathList[1:] {
		// Compare next path with current best path.
		// TODO make interface to get Local AS number
		newBestPath, reason := computeBestPath(localAsn, currentBestPath, nextPath)
		bestPathReason = reason
		if newBestPath != nil {
			currentBestPath = newBestPath
		}
	}
	return currentBestPath, bestPathReason, nil
}

func (dest *DestinationDefault) removeOldPaths() {
	//	"""Identifies which of known paths are old and removes them.
	//
	//	Known paths will no longer have paths whose new version is present in
	//	new paths.
	//	"""

	newPaths := dest.newPathList
	knownPaths := dest.knownPathList

	for _, newPath := range newPaths {
		oldPaths := make([]Path, 0)
		for _, path := range knownPaths {
			// Here we just check if source is same and not check if path
			// version num. as newPaths are implicit withdrawal of old
			// paths and when doing RouteRefresh (not EnhancedRouteRefresh)
			// we get same paths again.
			if newPath.getSource() == path.getSource() {
				oldPaths = append(oldPaths, path)
				break
			}
		}
		for _, oldPath := range oldPaths {
			match := false
			knownPaths, match = removeWithPath(knownPaths, oldPath)
			if !match {
				logger.Debugf("not exist withdrawal of old path in known paths: %s ", oldPath.String())

			}
			logger.Debugf("Implicit withdrawal of old path, "+
				"since we have learned new path from same source: %s", oldPath.String())
		}
	}
	dest.knownPathList = knownPaths
}

func deleteAt(list []Path, pos int) ([]Path, bool) {
	if list != nil {
		list = append(list[:pos], list[pos+1:]...)
		return list, true
	}
	return nil, false
}

// remove item from slice by object itself
func removeWithPath(list []Path, path Path) ([]Path, bool) {

	for index, p := range list {
		if p == path {
			pathList := append(list[:index], list[index+1:]...)
			return pathList, true
		}
	}
	return list, false
}

func computeBestPath(localAsn uint32, path1, path2 Path) (Path, string) {

	//Compares given paths and returns best path.
	//
	//Parameters:
	//	-`localAsn`: asn of local bgpspeaker
	//	-`path1`: first path to compare
	//	-`path2`: second path to compare
	//
	//	Best path processing will involve following steps:
	//	1.  Select a path with a reachable next hop.
	//	2.  Select the path with the highest weight.
	//	3.  If path weights are the same, select the path with the highest
	//	local preference value.
	//	4.  Prefer locally originated routes (network routes, redistributed
	//	routes, or aggregated routes) over received routes.
	//	5.  Select the route with the shortest AS-path length.
	//	6.  If all paths have the same AS-path length, select the path based
	//	on origin: IGP is preferred over EGP; EGP is preferred over
	//	Incomplete.
	//	7.  If the origins are the same, select the path with lowest MED
	//	value.
	//	8.  If the paths have the same MED values, select the path learned
	//	via EBGP over one learned via IBGP.
	//	9.  Select the route with the lowest IGP cost to the next hop.
	//	10. Select the route received from the peer with the lowest BGP
	//	router ID.
	//
	//	Returns None if best-path among given paths cannot be computed else best
	//	path.
	//	Assumes paths from NC has source equal to None.
	//

	var bestPath Path
	bestPathReason := BPR_UNKNOWN

	// Follow best path calculation algorithm steps.
	// compare by reachability
	if bestPath == nil {
		bestPath = compareByReachableNexthop(path1, path2)
		bestPathReason = BPR_REACHABLE_NEXT_HOP
	}

	if bestPath == nil {
		bestPath = compareByHighestWeight(path1, path2)
		bestPathReason = BPR_HIGHEST_WEIGHT
	}

	if bestPath == nil {
		bestPath = compareByLocalPref(path1, path2)
		bestPathReason = BPR_LOCAL_PREF
	}
	if bestPath == nil {
		bestPath = compareByLocalOrigin(path1, path2)
		bestPathReason = BPR_LOCAL_ORIGIN
	}
	if bestPath == nil {
		bestPath = compareByASPath(path1, path2)
		bestPathReason = BPR_ASPATH
	}
	if bestPath == nil {
		bestPath = compareByOrigin(path1, path2)
		bestPathReason = BPR_ORIGIN
	}
	if bestPath == nil {
		bestPath = compareByMED(path1, path2)
		bestPathReason = BPR_MED
	}
	if bestPath == nil {
		bestPath = compareByASNumber(localAsn, path1, path2)
		bestPathReason = BPR_ASN
	}
	if bestPath == nil {
		bestPath = compareByIGPCost(path1, path2)
		bestPathReason = BPR_IGP_COST
	}
	if bestPath == nil {
		var e error = nil
		bestPath, e = compareByRouterID(localAsn, path1, path2)
		if e != nil {
			logger.Error(e)
		}
		bestPathReason = BPR_ROUTER_ID
	}
	if bestPath == nil {
		bestPathReason = BPR_UNKNOWN
	}

	return bestPath, bestPathReason
}

func compareByReachableNexthop(path1, path2 Path) Path {
	//	Compares given paths and selects best path based on reachable next-hop.
	//
	//	If no path matches this criteria, return None.
	//  However RouteServer doesn't need to check reachability, so return nil.
	logger.Debugf("enter compareByReachableNexthop")
	logger.Debugf("path1: %s, path2: %s", path1, path2)
	return nil
}

func compareByHighestWeight(path1, path2 Path) Path {
	//	Selects a path with highest weight.
	//
	//	Weight is BGPS specific parameter. It is local to the router on which it
	//	is configured.
	//	Return:
	//	nil if best path among given paths cannot be decided, else best path.
	logger.Debugf("enter compareByHighestWeight")
	logger.Debugf("path1: %s, path2: %s", path1, path2)
	return nil
}

func compareByLocalPref(path1, path2 Path) Path {
	//	Selects a path with highest local-preference.
	//
	//	Unlike the weight attribute, which is only relevant to the local
	//	router, local preference is an attribute that routers exchange in the
	//	same AS. Highest local-pref is preferred. If we cannot decide,
	//	we return None.
	//
	//	# Default local-pref values is 100
	logger.Debugf("enter compareByLocalPref")
	_, attribute1 := path1.GetPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)
	_, attribute2 := path2.GetPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)

	if attribute1 == nil || attribute2 == nil {
		return nil
	}

	localPref1 := attribute1.(*bgp.PathAttributeLocalPref).Value
	localPref2 := attribute2.(*bgp.PathAttributeLocalPref).Value

	// Highest local-preference value is preferred.
	if localPref1 > localPref2 {
		return path1
	} else if localPref1 < localPref2 {
		return path2
	} else {
		return nil
	}
}

func compareByLocalOrigin(path1, path2 Path) Path {

	// """Select locally originating path as best path.
	//	Locally originating routes are network routes, redistributed routes,
	//	or aggregated routes.
	//	Returns None if given paths have same source.
	//	"""
	//	# If both paths are from same sources we cannot compare them here.
	logger.Debugf("enter compareByLocalOrigin")
	if path1.getSource() == path2.getSource() {
		return nil
	}

	//	# Here we consider prefix from NC as locally originating static route.
	//	# Hence it is preferred.
	if path1.getSource() == nil {
		return path1
	}

	if path2.getSource() == nil {
		return path2
	}
	return nil
}

func compareByASPath(path1, path2 Path) Path {
	//	Calculated the best-paths by comparing as-path lengths.
	//
	//	Shortest as-path length is preferred. If both path have same lengths,
	//	we return None.
	logger.Debugf("enter compareByASPath")
	_, attribute1 := path1.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	_, attribute2 := path2.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)

	asPath1 := attribute1.(*bgp.PathAttributeAsPath)
	asPath2 := attribute2.(*bgp.PathAttributeAsPath)

	if asPath1 == nil || asPath2 == nil {
		logger.Error("it is not possible to compare asPath are not present")
	}

	var l1, l2 int
	for _, pathParam := range asPath1.Value {
		l1 += pathParam.ASLen()
	}

	for _, pathParam := range asPath2.Value {
		l2 += pathParam.ASLen()
	}

	logger.Debugf("l1: %d, l2: %d", l1, l2)
	logger.Debug(reflect.TypeOf(asPath1.Value))
	logger.Debug(asPath1.Value)
	if l1 > l2 {
		return path2
	} else if l1 < l2 {
		return path1
	} else {
		return nil
	}
}

func compareByOrigin(path1, path2 Path) Path {
	//	Select the best path based on origin attribute.
	//
	//	IGP is preferred over EGP; EGP is preferred over Incomplete.
	//	If both paths have same origin, we return None.
	logger.Debugf("enter compareByOrigin")
	_, attribute1 := path1.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	_, attribute2 := path2.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)

	if attribute1 == nil || attribute2 == nil {
		logger.Error("it is not possible to compare origin are not present")
		return nil
	}

	origin1, n1 := binary.Uvarint(attribute1.(*bgp.PathAttributeOrigin).Value)
	origin2, n2 := binary.Uvarint(attribute2.(*bgp.PathAttributeOrigin).Value)
	logger.Debugf("path1 origin value: %d, %d byte read", origin1, n1)
	logger.Debugf("path2 origin value: %d, %d byte read", origin2, n2)

	// If both paths have same origins
	if origin1 == origin2 {
		return nil
	} else if origin1 < origin2 {
		return path1
	} else {
		return path2
	}
}

func compareByMED(path1, path2 Path) Path {
	//	Select the path based with lowest MED value.
	//
	//	If both paths have same MED, return None.
	//	By default, a route that arrives with no MED value is treated as if it
	//	had a MED of 0, the most preferred value.
	//	RFC says lower MED is preferred over higher MED value.
	//  compare MED among not only same AS path but also all path,
	//  like bgp always-compare-med
	logger.Debugf("enter compareByMED")
	getMed := func(path Path) uint32 {
		_, attribute := path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		if attribute == nil {
			return 0
		}
		med := attribute.(*bgp.PathAttributeMultiExitDisc).Value
		return med
	}

	med1 := getMed(path1)
	med2 := getMed(path2)

	if med1 == med2 {
		return nil
	} else if med1 < med2 {
		return path1
	}
	return path2
}

func compareByASNumber(localAsn uint32, path1, path2 Path) Path {

	//Select the path based on source (iBGP/eBGP) peer.
	//
	//eBGP path is preferred over iBGP. If both paths are from same kind of
	//peers, return None.
	logger.Debugf("enter compareByASNumber")
	getPathSourceAsn := func(path Path) uint32 {
		var asn uint32
		if path.getSource() == nil {
			asn = localAsn
		} else {
			asn = path.getSource().AS
		}
		return asn
	}

	p1Asn := getPathSourceAsn(path1)
	p2Asn := getPathSourceAsn(path2)
	// If path1 is from ibgp peer and path2 is from ebgp peer.
	if (p1Asn == localAsn) && (p2Asn != localAsn) {
		return path2
	}

	// If path2 is from ibgp peer and path1 is from ebgp peer,
	if (p2Asn == localAsn) && (p1Asn != localAsn) {
		return path1
	}

	// If both paths are from ebgp or ibpg peers, we cannot decide.
	return nil
}

func compareByIGPCost(path1, path2 Path) Path {
	//	Select the route with the lowest IGP cost to the next hop.
	//
	//	Return None if igp cost is same.
	// Currently BGPS has no concept of IGP and IGP cost.
	logger.Debugf("enter compareByIGPCost")
	logger.Debugf("path1: %s, path2: %s", path1, path2)
	return nil
}

func compareByRouterID(localAsn uint32, path1, path2 Path) (Path, error) {
	//	Select the route received from the peer with the lowest BGP router ID.
	//
	//	If both paths are eBGP paths, then we do not do any tie breaking, i.e we do
	//	not pick best-path based on this criteria.
	//	RFC: http://tools.ietf.org/html/rfc5004
	//	We pick best path between two iBGP paths as usual.
	logger.Debugf("enter compareByRouterID")
	getAsn := func(pathSource *PeerInfo) uint32 {
		if pathSource == nil {
			return localAsn
		} else {
			return pathSource.AS
		}
	}

	getRouterId := func(pathSource *PeerInfo, localBgpId uint32) uint32 {
		if pathSource == nil {
			return localBgpId
		} else {
			routerId := pathSource.ID
			routerId_u32 := binary.BigEndian.Uint32(routerId)
			return routerId_u32
		}
	}

	pathSource1 := path1.getSource()
	pathSource2 := path2.getSource()

	// If both paths are from NC we have same router Id, hence cannot compare.
	if pathSource1 == nil && pathSource2 == nil {
		return nil, nil
	}

	asn1 := getAsn(pathSource1)
	asn2 := getAsn(pathSource2)

	isEbgp1 := asn1 != localAsn
	isEbgp2 := asn2 != localAsn
	// If both paths are from eBGP peers, then according to RFC we need
	// not tie break using router id.
	if isEbgp1 && isEbgp2 {
		return nil, nil
	}

	if (isEbgp1 == true && isEbgp2 == false) ||
		(isEbgp1 == false && isEbgp2 == true) {
		return nil, fmt.Errorf("This method does not support comparing ebgp with ibgp path")
	}

	// At least one path is not coming from NC, so we get local bgp id.
	var localBgpId_u32 uint32
	if pathSource1 != nil {
		localBgpId := pathSource1.LocalID
		localBgpId_u32 = binary.BigEndian.Uint32(localBgpId)
	} else {
		localBgpId := pathSource2.LocalID
		localBgpId_u32 = binary.BigEndian.Uint32(localBgpId)
	}

	// Get router ids.
	routerId1_u32 := getRouterId(pathSource1, localBgpId_u32)
	routerId2_u32 := getRouterId(pathSource2, localBgpId_u32)

	// If both router ids are same/equal we cannot decide.
	// This case is possible since router ids are arbitrary.
	if routerId1_u32 == routerId2_u32 {
		return nil, nil
	}

	if routerId1_u32 < routerId2_u32 {
		return path1, nil
	} else {
		return path2, nil
	}
}

// return Destination's string representation
func (dest *DestinationDefault) String() string {
	str := fmt.Sprintf("Destination NLRI: %s", dest.getPrefix().String())
	return str
}

func (dest *DestinationDefault) constructWithdrawPath() Path {
	path := &IPv4Path{}
	return path
}

func (dest *DestinationDefault) getPrefix() net.IP {
	var ip net.IP
	switch p := dest.nlri.(type) {
	case *bgp.NLRInfo:
		ip = p.IPAddrPrefix.IPAddrPrefixDefault.Prefix
	case *bgp.WithdrawnRoute:
		ip = p.IPAddrPrefix.IPAddrPrefixDefault.Prefix
	}
	return ip
}

/*
* 	Definition of inherited Destination interface
 */

type IPv4Destination struct {
	*DestinationDefault
	//need structure
}

func NewIPv4Destination(nlri bgp.AddrPrefixInterface) *IPv4Destination {
	ipv4Destination := &IPv4Destination{}
	ipv4Destination.DestinationDefault = NewDestinationDefault(nlri)
	ipv4Destination.DestinationDefault.ROUTE_FAMILY = RF_IPv4_UC
	//need Processing
	return ipv4Destination
}

func (ipv4d *IPv4Destination) String() string {
	str := fmt.Sprintf("Destination NLRI: %s", ipv4d.getPrefix().String())
	return str
}

type IPv6Destination struct {
	*DestinationDefault
	//need structure
}

func NewIPv6Destination(nlri bgp.AddrPrefixInterface) *IPv6Destination {
	ipv6Destination := &IPv6Destination{}
	ipv6Destination.DestinationDefault = NewDestinationDefault(nlri)
	ipv6Destination.DestinationDefault.ROUTE_FAMILY = RF_IPv6_UC
	//need Processing
	return ipv6Destination
}

func (ipv6d *IPv6Destination) String() string {

	str := fmt.Sprintf("Destination NLRI: %s", ipv6d.getPrefix().String())
	return str
}

func (ipv6d *IPv6Destination) getPrefix() net.IP {
	var ip net.IP
	logger.Debugf("type %s", reflect.TypeOf(ipv6d.nlri))
	switch p := ipv6d.nlri.(type) {
	case *bgp.IPv6AddrPrefix:
		ip = p.IPAddrPrefix.IPAddrPrefixDefault.Prefix
	case *bgp.WithdrawnRoute:
		ip = p.IPAddrPrefix.IPAddrPrefixDefault.Prefix
	}
	return ip
}
