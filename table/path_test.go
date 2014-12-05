// path_test.go
package table

import (
	//"fmt"
	"github.com/osrg/gobgp/packet"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func updateMsg() *bgp.BGPMessage {
	w1 := bgp.WithdrawnRoute{*bgp.NewIPAddrPrefix(23, "121.1.3.2")}
	w2 := bgp.WithdrawnRoute{*bgp.NewIPAddrPrefix(17, "100.33.3.0")}
	w := []bgp.WithdrawnRoute{w1, w2}
	//w := []WithdrawnRoute{}

	aspath1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{1000}),
		bgp.NewAsPathParam(1, []uint16{1001, 1002}),
		bgp.NewAsPathParam(2, []uint16{1003, 1004}),
	}

	aspath2 := []bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(2, []uint32{1000000}),
		bgp.NewAs4PathParam(1, []uint32{1000001, 1002}),
		bgp.NewAs4PathParam(2, []uint32{1003, 100004}),
	}

	aspath3 := []*bgp.As4PathParam{
		bgp.NewAs4PathParam(2, []uint32{1000000}),
		bgp.NewAs4PathParam(1, []uint32{1000001, 1002}),
		bgp.NewAs4PathParam(2, []uint32{1003, 100004}),
	}

	ecommunities := []bgp.ExtendedCommunityInterface{
		&bgp.TwoOctetAsSpecificExtended{SubType: 1, AS: 10003, LocalAdmin: 3 << 20},
		&bgp.FourOctetAsSpecificExtended{SubType: 2, AS: 1 << 20, LocalAdmin: 300},
		&bgp.IPv4AddressSpecificExtended{SubType: 3, IPv4: net.ParseIP("192.2.1.2").To4(), LocalAdmin: 3000},
		&bgp.OpaqueExtended{Value: []byte{0, 1, 2, 3, 4, 5, 6, 7}},
		&bgp.UnknownExtended{Type: 99, Value: []byte{0, 1, 2, 3, 4, 5, 6, 7}},
	}

	mp_nlri := []bgp.AddrPrefixInterface{
		bgp.NewLabelledVPNIPAddrPrefix(20, "192.0.9.0", *bgp.NewLabel(1, 2, 3),
			bgp.NewRouteDistinguisherTwoOctetAS(256, 10000)),
		bgp.NewLabelledVPNIPAddrPrefix(26, "192.10.8.192", *bgp.NewLabel(5, 6, 7, 8),
			bgp.NewRouteDistinguisherIPAddressAS("10.0.1.1", 10001)),
	}

	mp_nlri2 := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(100,
		"fe80:1234:1234:5667:8967:af12:8912:1023")}

	mp_nlri3 := []bgp.AddrPrefixInterface{bgp.NewLabelledVPNIPv6AddrPrefix(100,
		"fe80:1234:1234:5667:8967:af12:1203:33a1", *bgp.NewLabel(5, 6),
		bgp.NewRouteDistinguisherFourOctetAS(5, 6))}

	mp_nlri4 := []bgp.AddrPrefixInterface{bgp.NewLabelledIPAddrPrefix(25, "192.168.0.0",
		*bgp.NewLabel(5, 6, 7))}

	p := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(3),
		bgp.NewPathAttributeAsPath(aspath1),
		bgp.NewPathAttributeAsPath(aspath2),
		bgp.NewPathAttributeNextHop("129.1.1.2"),
		bgp.NewPathAttributeMultiExitDisc(1 << 20),
		bgp.NewPathAttributeLocalPref(1 << 22),
		bgp.NewPathAttributeAtomicAggregate(),
		bgp.NewPathAttributeAggregator(uint16(30002), "129.0.2.99"),
		bgp.NewPathAttributeAggregator(uint32(30002), "129.0.2.99"),
		bgp.NewPathAttributeAggregator(uint32(300020), "129.0.2.99"),
		bgp.NewPathAttributeCommunities([]uint32{1, 3}),
		bgp.NewPathAttributeOriginatorId("10.10.0.1"),
		bgp.NewPathAttributeClusterList([]string{"10.10.0.2", "10.10.0.3"}),
		bgp.NewPathAttributeExtendedCommunities(ecommunities),
		bgp.NewPathAttributeAs4Path(aspath3),
		bgp.NewPathAttributeAs4Aggregator(10000, "112.22.2.1"),
		bgp.NewPathAttributeMpReachNLRI("112.22.2.0", mp_nlri),
		bgp.NewPathAttributeMpReachNLRI("1023::", mp_nlri2),
		bgp.NewPathAttributeMpReachNLRI("fe80::", mp_nlri3),
		bgp.NewPathAttributeMpReachNLRI("129.1.1.1", mp_nlri4),
		bgp.NewPathAttributeMpUnreachNLRI(mp_nlri),
		&bgp.PathAttributeUnknown{
			PathAttribute: bgp.PathAttribute{
				Flags: 1,
				Type:  100,
				Value: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			},
		},
	}
	n := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "13.2.3.1"), *bgp.NewNLRInfo(24, "13.2.3.2")}
	//n := []bgp.NLRInfo{*bgp.NewNLRInfo(100, "fe80:1234:1234:5667:8967:af12:1203:33a1")}
	return bgp.NewBGPUpdateMessage(w, p, n)
}

func initMsg() *ProcessMessage {
	bgpMessage := updateMsg()
	peer := &Peer{}
	peer.VersionNum = 4
	peer.RemoteAs = 65000

	msg := &ProcessMessage{
		innerMessage: bgpMessage,
		fromPeer:     peer,
	}
	return msg
}
func createPathCheck(t *testing.T, msg *ProcessMessage) (Path, string) {
	updateMsg := msg.innerMessage.Body.(*bgp.BGPUpdate)
	nlriList := updateMsg.NLRI
	pathAttributes := updateMsg.PathAttributes
	nlri_info := nlriList[0]
	path := CreatePath(msg.fromPeer, &nlri_info, pathAttributes, false)
	ar := assert.NotNil(t, path, "Path is Nil")
	if !ar {
		return nil, "NG"
	}
	return path, "OK"
}
func getNextHopCheck(t *testing.T, msg *ProcessMessage) string {
	nexthop := "129.1.1.2"
	pAttr := msg.innerMessage.Body.(*bgp.BGPUpdate).PathAttributes
	r_nexthop := getNextHop(pAttr)
	ar := assert.Equal(t, r_nexthop.String(), nexthop, "unmatch nexthop")
	if !ar {
		return "NG"
	}
	return "OK"
}
func getPrefixCheck(t *testing.T, path Path) string {
	prefix := "13.2.3.1"
	//prefix := "fe80:1234:1234:5667:8967:af12:1203:33a1"
	r_prefix := path.getPrefix()
	ar := assert.Equal(t, r_prefix.String(), prefix, "unmatch prefix")
	if !ar {
		return "NG"
	}
	return "OK"
}

func getPathAttributeCheck(t *testing.T, path Path) string {
	nh := "129.1.1.2"
	pa := path.getPathAttribute(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	r_nh := pa.(*bgp.PathAttributeNextHop).Value.String()
	ar := assert.Equal(t, r_nh, nh, "unmatch nexthop")
	if !ar {
		return "NG"
	}
	return "OK"
}

func cloneCheck(t *testing.T, path Path) string {

	prefix := path.getPrefix()
	cl := path.clone(false)
	r_prefix := cl.getPrefix()
	ar := assert.Equal(t, r_prefix, prefix, "unmatch prefix in clone element")
	if !ar {
		return "NG"
	}
	return "OK"
}

//getter&setter test
func pgsTerCheck(t *testing.T) string {
	pd := &PathDefault{}
	//check Route Family
	pd.setRouteFamily(RF_IPv4_UC)
	rf := pd.getRouteFamily()
	ar := assert.Equal(t, rf, RF_IPv4_UC, "unmatch route family")
	if !ar {
		return "NG"
	}

	//check source
	pr := &Peer{
		RemoteAs:   65000,
		VersionNum: 4,
	}
	pd.setSource(pr)
	r_pr := pd.getSource()
	ar = assert.Equal(t, r_pr, pr, "unmatch source")
	if !ar {
		return "NG"
	}
	//check nexthop
	ip := net.ParseIP("192.168.0.1")
	pd.setNexthop(ip)
	nh := pd.getNexthop()
	ar = assert.Equal(t, nh, ip, "unmatch nexthop")
	if !ar {
		return "NG"
	}
	//check source version num
	svn := 4
	pd.setSourceVerNum(svn)
	r_svn := pd.getSourceVerNum()
	ar = assert.Equal(t, r_svn, svn, "unmatch source ver num")
	if !ar {
		return "NG"
	}
	//check wighdrow
	wd := true
	pd.setWithdraw(wd)
	r_wd := pd.isWithdraw()
	ar = assert.Equal(t, r_wd, wd, "unmatch withdrow flg")
	if !ar {
		return "NG"
	}
	//check nlri
	nlri := bgp.NewNLRInfo(24, "13.2.3.1")
	pd.setNlri(nlri)
	r_nlri := pd.getNlri()
	ar = assert.Equal(t, r_nlri, nlri, "unmatch nlri")
	if !ar {
		return "NG"
	}
	//check med set by targetNeighbor
	msbt := true
	pd.setMedSetByTargetNeighbor(msbt)
	r_msbt := pd.getMedSetByTargetNeighbor()
	ar = assert.Equal(t, r_msbt, msbt, "unmatch med flg")
	if !ar {
		return "NG"
	}
	//ipv4 pathDefault
	ipv4 := &IPv4Path{}
	ipv4.setPathDefault(pd)
	r_pd4 := ipv4.getPathDefault()
	ar = assert.Equal(t, r_pd4, pd, "unmatch path default")
	if !ar {
		return "NG"
	}
	//ipv6 pathDefault
	ipv6 := &IPv6Path{}
	ipv6.setPathDefault(pd)
	r_pd6 := ipv6.getPathDefault()
	ar = assert.Equal(t, r_pd6, pd, "unmatch path default")
	if !ar {
		return "NG"
	}
	return "OK"
}
func TestPath(t *testing.T) {
	msg := initMsg()
	t.Log("# CREATE PATH CHECK")
	path, result := createPathCheck(t, msg)
	t.Log("# CHECK END -> [ ", result, " ]")
	t.Log("")
	t.Log("# GET NEXTHOP CHECK")
	result = getNextHopCheck(t, msg)
	t.Log("# CHECK END -> [ ", result, " ]")
	t.Log("")
	t.Log("# GET PREFIX CHECK")
	result = getPrefixCheck(t, path)
	t.Log("# CHECK END -> [ ", result, " ]")
	t.Log("")
	t.Log("# GET PATH ATTRIBUTE CHECK")
	result = getPathAttributeCheck(t, path)
	t.Log("# CHECK END -> [ ", result, " ]")
	t.Log("")
	t.Log("# CLONE CHECK")
	result = cloneCheck(t, path)
	t.Log("# CHECK END -> [ ", result, " ]")
	t.Log("")
	t.Log("# GETTER SETTER CHECK")
	result = pgsTerCheck(t)
	t.Log("# CHECK END -> [ ", result, " ]")
	t.Log("")
}
