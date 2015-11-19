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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"net"
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

func IpToRadixkey(b []byte, max uint8) string {
	var buffer bytes.Buffer
	for i := 0; i < len(b) && i < int(max); i++ {
		buffer.WriteString(fmt.Sprintf("%08b", b[i]))
	}
	return buffer.String()[:max]
}

func CidrToRadixkey(cidr string) string {
	_, n, _ := net.ParseCIDR(cidr)
	ones, _ := n.Mask.Size()
	return IpToRadixkey(n.IP, uint8(ones))
}

type PeerInfo struct {
	AS                      uint32
	ID                      net.IP
	LocalAS                 uint32
	LocalID                 net.IP
	Address                 net.IP
	RouteReflectorClient    bool
	RouteReflectorClusterID net.IP
}

func (lhs *PeerInfo) Equal(rhs *PeerInfo) bool {
	if lhs == rhs {
		return true
	}

	if rhs == nil {
		return false
	}

	if (lhs.AS == rhs.AS) && lhs.ID.Equal(rhs.ID) && lhs.LocalID.Equal(rhs.LocalID) && lhs.Address.Equal(rhs.Address) {
		return true
	}
	return false
}

func (i *PeerInfo) String() string {
	if i.Address == nil {
		return "local"
	}
	s := bytes.NewBuffer(make([]byte, 0, 64))
	s.WriteString(fmt.Sprintf("{ %s | ", i.Address))
	s.WriteString(fmt.Sprintf("as: %d", i.AS))
	s.WriteString(fmt.Sprintf(", id: %s", i.ID))
	if i.RouteReflectorClient {
		s.WriteString(fmt.Sprintf(", cluster-id: %s", i.RouteReflectorClusterID))
	}
	s.WriteString(" }")
	return s.String()
}

func NewPeerInfo(g *config.Global, p *config.Neighbor) *PeerInfo {
	id := net.ParseIP(string(p.RouteReflector.RouteReflectorConfig.RouteReflectorClusterId)).To4()
	return &PeerInfo{
		AS:                      p.NeighborConfig.PeerAs,
		LocalAS:                 g.GlobalConfig.As,
		LocalID:                 g.GlobalConfig.RouterId,
		Address:                 p.NeighborConfig.NeighborAddress,
		RouteReflectorClient:    p.RouteReflector.RouteReflectorConfig.RouteReflectorClient,
		RouteReflectorClusterID: id,
	}
}

type Destination struct {
	routeFamily    bgp.RouteFamily
	nlri           bgp.AddrPrefixInterface
	knownPathList  []*Path
	withdrawList   []*Path
	newPathList    []*Path
	bestPath       *Path
	bestPathReason string
	RadixKey       string
}

func NewDestination(nlri bgp.AddrPrefixInterface) *Destination {
	d := &Destination{
		routeFamily:   bgp.AfiSafiToRouteFamily(nlri.AFI(), nlri.SAFI()),
		nlri:          nlri,
		knownPathList: make([]*Path, 0),
		withdrawList:  make([]*Path, 0),
		newPathList:   make([]*Path, 0),
	}
	switch d.routeFamily {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		d.RadixKey = CidrToRadixkey(nlri.String())
	}
	return d
}

func (dd *Destination) MarshalJSON() ([]byte, error) {
	return json.Marshal(dd.ToApiStruct())
}

func (dd *Destination) ToApiStruct() *api.Destination {
	prefix := dd.GetNlri().String()
	paths := func(arg []*Path) []*api.Path {
		ret := make([]*api.Path, 0, len(arg))
		for _, p := range arg {
			pp := p.ToApiStruct()
			if dd.GetBestPath() == p {
				pp.Best = true
			}
			ret = append(ret, pp)
		}
		return ret
	}(dd.knownPathList)

	return &api.Destination{
		Prefix: prefix,
		Paths:  paths,
	}
}

func (dd *Destination) getRouteFamily() bgp.RouteFamily {
	return dd.routeFamily
}

func (dd *Destination) setRouteFamily(routeFamily bgp.RouteFamily) {
	dd.routeFamily = routeFamily
}

func (dd *Destination) GetNlri() bgp.AddrPrefixInterface {
	return dd.nlri
}

func (dd *Destination) setNlri(nlri bgp.AddrPrefixInterface) {
	dd.nlri = nlri
}

func (dd *Destination) getBestPathReason() string {
	return dd.bestPathReason
}

func (dd *Destination) setBestPathReason(reason string) {
	dd.bestPathReason = reason
}

func (dd *Destination) GetBestPath() *Path {
	return dd.bestPath
}

func (dd *Destination) setBestPath(path *Path) {
	dd.bestPath = path
}

func (dd *Destination) GetKnownPathList() []*Path {
	return dd.knownPathList
}

func (dd *Destination) setKnownPathList(List []*Path) {
	dd.knownPathList = List
}

func (dd *Destination) addWithdraw(withdraw *Path) {
	dd.validatePath(withdraw)
	dd.withdrawList = append(dd.withdrawList, withdraw)
}

func (dd *Destination) addNewPath(newPath *Path) {
	dd.validatePath(newPath)
	dd.newPathList = append(dd.newPathList, newPath)
}

func (dd *Destination) validatePath(path *Path) {
	if path == nil || path.GetRouteFamily() != dd.routeFamily {

		log.WithFields(log.Fields{
			"Topic":      "Table",
			"Key":        dd.GetNlri().String(),
			"Path":       path,
			"ExpectedRF": dd.routeFamily,
		}).Error("path is nil or invalid route family")
	}
}

// Calculates best-path among known paths for this destination.
//
// Returns: - Best path
//
// Modifies destination's state related to stored paths. Removes withdrawn
// paths from known paths. Also, adds new paths to known paths.
func (dest *Destination) Calculate() (*Path, string, error) {

	// First remove the withdrawn paths.
	// Note: If we want to support multiple paths per destination we may
	// have to maintain sent-routes per path.
	dest.removeWithdrawals()

	//	Have to select best-path from available paths and new paths.
	//	If we do not have any paths, then we no longer have best path.
	if len(dest.knownPathList) == 0 && len(dest.newPathList) == 1 {
		// If we do not have any old but one new path
		// it becomes best path.
		dest.knownPathList = append(dest.knownPathList, dest.newPathList[0])
		dest.newPathList, _ = deleteAt(dest.newPathList, 0)
		log.WithFields(log.Fields{
			"Topic":  "Table",
			"Key":    dest.GetNlri().String(),
			"Path":   dest.knownPathList[0],
			"Reason": BPR_ONLY_PATH,
		}).Debug("best path")

		return dest.knownPathList[0], BPR_ONLY_PATH, nil
	}

	// If we have a new version of old/known path we use it and delete old
	// one.
	dest.removeOldPaths()
	log.Debugf("removeOldPaths")
	// Collect all new paths into known paths.
	dest.knownPathList = append(dest.knownPathList, dest.newPathList...)

	// Clear new paths as we copied them.
	dest.newPathList = make([]*Path, 0)

	// If we do not have any paths to this destination, then we do not have
	// new best path.
	if len(dest.knownPathList) == 0 {
		return nil, BPR_UNKNOWN, nil
	}

	// Compute new best path
	currentBestPath, reason, e := dest.computeKnownBestPath()
	if e != nil {
		log.Error(e)
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
func (dest *Destination) removeWithdrawals() {

	// If we have no withdrawals, we have nothing to do.
	if len(dest.withdrawList) == 0 {
		return
	}

	log.WithFields(log.Fields{
		"Topic":  "Table",
		"Key":    dest.GetNlri().String(),
		"Length": len(dest.withdrawList),
	}).Debug("Removing withdrawals")

	// If we have some withdrawals and no know-paths, it means it is safe to
	// delete these withdraws.
	if len(dest.knownPathList) == 0 {
		log.WithFields(log.Fields{
			"Topic":  "Table",
			"Key":    dest.GetNlri().String(),
			"Length": len(dest.withdrawList),
		}).Debug("Found withdrawals for path(s) that did not get installed")

		dest.withdrawList = dest.withdrawList[len(dest.withdrawList):]
	}

	//	If we have some known paths and some withdrawals, we find matches and
	//	delete them first.
	matches := make(map[string]*Path)
	wMatches := make(map[string]*Path)
	// Match all withdrawals from destination paths.
	for _, withdraw := range dest.withdrawList {
		var isFound bool = false
		for _, path := range dest.knownPathList {
			// We have a match if the source are same.
			// TODO add GetSource to Path interface
			if path.GetSource().Equal(withdraw.GetSource()) {
				isFound = true
				matches[path.String()] = path
				wMatches[withdraw.String()] = withdraw
				// One withdraw can remove only one path.
				break
			}
		}

		// We do no have any match for this withdraw.
		if !isFound {
			log.WithFields(log.Fields{
				"Topic": "Table",
				"Key":   dest.GetNlri().String(),
				"Path":  withdraw,
			}).Debug("No matching path for withdraw found, may be path was not installed into table")
		}
	}

	// If we have partial match.
	if len(matches) != len(dest.withdrawList) {
		log.WithFields(log.Fields{
			"Topic":          "Table",
			"Key":            dest.GetNlri().String(),
			"MatchLength":    len(matches),
			"WithdrawLength": len(dest.withdrawList),
		}).Debug("Did not find match for some withdrawals.")
	}

	// Clear matching paths and withdrawals.
	for _, path := range matches {
		var result bool = false
		dest.knownPathList, result = removeWithPath(dest.knownPathList, path)
		if !result {
			log.WithFields(log.Fields{
				"Topic": "Table",
				"Key":   dest.GetNlri().String(),
				"Path":  path,
			}).Debug("could not remove path from knownPathList")
		}
	}
	for _, path := range wMatches {
		var result bool = false
		dest.withdrawList, result = removeWithPath(dest.withdrawList, path)
		if !result {
			log.WithFields(log.Fields{
				"Topic": "Table",
				"Key":   dest.GetNlri().String(),
				"Path":  path,
			}).Debug("could not remove path from withdrawList")
		}
	}
}

func (dest *Destination) computeKnownBestPath() (*Path, string, error) {

	//	"""Computes the best path among known paths.
	//
	//	Returns current best path among `knownPaths`.
	if len(dest.knownPathList) == 0 {
		return nil, "", fmt.Errorf("Need at-least one known path to compute best path")
	}

	log.Debugf("computeKnownBestPath known pathlist: %d", len(dest.knownPathList))

	// We pick the first path as current best path. This helps in breaking
	// tie between two new paths learned in one cycle for which best-path
	// calculation steps lead to tie.
	currentBestPath := dest.knownPathList[0]
	bestPathReason := BPR_ONLY_PATH
	for _, nextPath := range dest.knownPathList[1:] {
		// Compare next path with current best path.
		newBestPath, reason := computeBestPath(currentBestPath, nextPath)
		bestPathReason = reason
		if newBestPath != nil {
			currentBestPath = newBestPath
		}
	}
	return currentBestPath, bestPathReason, nil
}

func (dest *Destination) removeOldPaths() {
	//	"""Identifies which of known paths are old and removes them.
	//
	//	Known paths will no longer have paths whose new version is present in
	//	new paths.
	//	"""

	newPaths := dest.newPathList
	knownPaths := dest.knownPathList

	for _, newPath := range newPaths {
		if newPath.NoImplicitWithdraw {
			continue
		}
		oldPaths := make([]*Path, 0)
		for _, path := range knownPaths {
			// Here we just check if source is same and not check if path
			// version num. as newPaths are implicit withdrawal of old
			// paths and when doing RouteRefresh (not EnhancedRouteRefresh)
			// we get same paths again.
			if newPath.GetSource().Equal(path.GetSource()) {
				oldPaths = append(oldPaths, path)
				break
			}
		}
		for _, oldPath := range oldPaths {
			match := false
			knownPaths, match = removeWithPath(knownPaths, oldPath)
			if !match {
				log.WithFields(log.Fields{
					"Topic": "Table",
					"Key":   dest.GetNlri().String(),
					"Path":  oldPath,
				}).Debug("not matched")

			}
			log.WithFields(log.Fields{
				"Topic": "Table",
				"Key":   dest.GetNlri().String(),
				"Path":  oldPath,
			}).Debug("Implicit withdrawal of old path, since we have learned new path from the same peer")
		}
	}
	dest.knownPathList = knownPaths
}

func deleteAt(list []*Path, pos int) ([]*Path, bool) {
	if list != nil {
		list = append(list[:pos], list[pos+1:]...)
		return list, true
	}
	return nil, false
}

// remove item from slice by object itself
func removeWithPath(list []*Path, path *Path) ([]*Path, bool) {

	for index, p := range list {
		if p == path {
			pathList := append(list[:index], list[index+1:]...)
			return pathList, true
		}
	}
	return list, false
}

func computeBestPath(path1, path2 *Path) (*Path, string) {

	//Compares given paths and returns best path.
	//
	//Parameters:
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

	var bestPath *Path
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
		bestPath = compareByASNumber(path1, path2)
		bestPathReason = BPR_ASN
	}
	if bestPath == nil {
		bestPath = compareByIGPCost(path1, path2)
		bestPathReason = BPR_IGP_COST
	}
	if bestPath == nil {
		var e error = nil
		bestPath, e = compareByRouterID(path1, path2)
		if e != nil {
			log.Error(e)
		}
		bestPathReason = BPR_ROUTER_ID
	}
	if bestPath == nil {
		bestPathReason = BPR_UNKNOWN
	}

	return bestPath, bestPathReason
}

func compareByReachableNexthop(path1, path2 *Path) *Path {
	//	Compares given paths and selects best path based on reachable next-hop.
	//
	//	If no path matches this criteria, return None.
	//  However RouteServer doesn't need to check reachability, so return nil.
	log.Debugf("enter compareByReachableNexthop -- path1: %s, path2: %s", path1, path2)
	return nil
}

func compareByHighestWeight(path1, path2 *Path) *Path {
	//	Selects a path with highest weight.
	//
	//	Weight is BGPS specific parameter. It is local to the router on which it
	//	is configured.
	//	Return:
	//	nil if best path among given paths cannot be decided, else best path.
	log.Debugf("enter compareByHighestWeight -- path1: %s, path2: %s", path1, path2)
	return nil
}

func compareByLocalPref(path1, path2 *Path) *Path {
	//	Selects a path with highest local-preference.
	//
	//	Unlike the weight attribute, which is only relevant to the local
	//	router, local preference is an attribute that routers exchange in the
	//	same AS. Highest local-pref is preferred. If we cannot decide,
	//	we return None.
	//
	//	# Default local-pref values is 100
	log.Debugf("enter compareByLocalPref")
	_, attribute1 := path1.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)
	_, attribute2 := path2.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)

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

func compareByLocalOrigin(path1, path2 *Path) *Path {

	// Select locally originating path as best path.
	// Locally originating routes are network routes, redistributed routes,
	// or aggregated routes.
	// Returns None if given paths have same source.
	//
	// If both paths are from same sources we cannot compare them here.
	log.Debugf("enter compareByLocalOrigin")
	if path1.GetSource().Equal(path2.GetSource()) {
		return nil
	}

	// Here we consider prefix from NC as locally originating static route.
	// Hence it is preferred.
	if path1.IsLocal() {
		return path1
	}

	if path2.IsLocal() {
		return path2
	}
	return nil
}

func compareByASPath(path1, path2 *Path) *Path {
	// Calculated the best-paths by comparing as-path lengths.
	//
	// Shortest as-path length is preferred. If both path have same lengths,
	// we return None.
	log.Debugf("enter compareByASPath")
	_, attribute1 := path1.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	_, attribute2 := path2.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)

	if attribute1 == nil || attribute2 == nil {
		log.WithFields(log.Fields{
			"Topic":   "Table",
			"Key":     "compareByASPath",
			"ASPath1": attribute1,
			"ASPath2": attribute2,
		}).Warn("can't compare ASPath because it's not present")
	}

	l1 := path1.GetAsPathLen()
	l2 := path2.GetAsPathLen()

	log.Debugf("compareByASPath -- l1: %d, l2: %d", l1, l2)
	if l1 > l2 {
		return path2
	} else if l1 < l2 {
		return path1
	} else {
		return nil
	}
}

func compareByOrigin(path1, path2 *Path) *Path {
	//	Select the best path based on origin attribute.
	//
	//	IGP is preferred over EGP; EGP is preferred over Incomplete.
	//	If both paths have same origin, we return None.
	log.Debugf("enter compareByOrigin")
	_, attribute1 := path1.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	_, attribute2 := path2.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)

	if attribute1 == nil || attribute2 == nil {
		log.WithFields(log.Fields{
			"Topic":   "Table",
			"Key":     "compareByOrigin",
			"Origin1": attribute1,
			"Origin2": attribute2,
		}).Error("can't compare origin because it's not present")
		return nil
	}

	origin1, n1 := binary.Uvarint(attribute1.(*bgp.PathAttributeOrigin).Value)
	origin2, n2 := binary.Uvarint(attribute2.(*bgp.PathAttributeOrigin).Value)
	log.Debugf("compareByOrigin -- origin1: %d(%d), origin2: %d(%d)", origin1, n1, origin2, n2)

	// If both paths have same origins
	if origin1 == origin2 {
		return nil
	} else if origin1 < origin2 {
		return path1
	} else {
		return path2
	}
}

func compareByMED(path1, path2 *Path) *Path {
	//	Select the path based with lowest MED value.
	//
	//	If both paths have same MED, return None.
	//	By default, a route that arrives with no MED value is treated as if it
	//	had a MED of 0, the most preferred value.
	//	RFC says lower MED is preferred over higher MED value.
	//  compare MED among not only same AS path but also all path,
	//  like bgp always-compare-med
	log.Debugf("enter compareByMED")
	getMed := func(path *Path) uint32 {
		_, attribute := path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		if attribute == nil {
			return 0
		}
		med := attribute.(*bgp.PathAttributeMultiExitDisc).Value
		return med
	}

	med1 := getMed(path1)
	med2 := getMed(path2)
	log.Debugf("compareByMED -- med1: %d, med2: %d", med1, med2)
	if med1 == med2 {
		return nil
	} else if med1 < med2 {
		return path1
	}
	return path2
}

func compareByASNumber(path1, path2 *Path) *Path {

	//Select the path based on source (iBGP/eBGP) peer.
	//
	//eBGP path is preferred over iBGP. If both paths are from same kind of
	//peers, return None.
	log.Debugf("enter compareByASNumber")

	log.Debugf("compareByASNumber -- p1Asn: %d, p2Asn: %d", path1.source.AS, path2.source.AS)
	// If one path is from ibgp peer and another is from ebgp peer, take the ebgp path
	if path1.IsIBGP() != path2.IsIBGP() {
		if path1.IsIBGP() {
			return path2
		}
		return path1
	}

	// If both paths are from ebgp or ibpg peers, we cannot decide.
	return nil
}

func compareByIGPCost(path1, path2 *Path) *Path {
	//	Select the route with the lowest IGP cost to the next hop.
	//
	//	Return None if igp cost is same.
	// Currently BGPS has no concept of IGP and IGP cost.
	log.Debugf("enter compareByIGPCost -- path1: %v, path2: %v", path1, path2)
	return nil
}

func compareByRouterID(path1, path2 *Path) (*Path, error) {
	//	Select the route received from the peer with the lowest BGP router ID.
	//
	//	If both paths are eBGP paths, then we do not do any tie breaking, i.e we do
	//	not pick best-path based on this criteria.
	//	RFC: http://tools.ietf.org/html/rfc5004
	//	We pick best path between two iBGP paths as usual.
	log.Debugf("enter compareByRouterID")

	// If both paths are from NC we have same router Id, hence cannot compare.
	if path1.IsLocal() && path2.IsLocal() {
		return nil, nil
	}

	// If both paths are from eBGP peers, then according to RFC we need
	// not tie break using router id.
	if !path1.IsIBGP() && !path2.IsIBGP() {
		return nil, nil
	}

	if path1.IsIBGP() != path2.IsIBGP() {
		return nil, fmt.Errorf("This method does not support comparing ebgp with ibgp path")
	}

	// At least one path is not coming from NC, so we get local bgp id.
	id1 := binary.BigEndian.Uint32(path1.source.ID)
	id2 := binary.BigEndian.Uint32(path2.source.ID)

	// If both router ids are same/equal we cannot decide.
	// This case is possible since router ids are arbitrary.
	if id1 == id2 {
		return nil, nil
	} else if id1 < id2 {
		return path1, nil
	} else {
		return path2, nil
	}
}

func (dest *Destination) String() string {
	return fmt.Sprintf("Destination NLRI: %s", dest.nlri.String())
}
