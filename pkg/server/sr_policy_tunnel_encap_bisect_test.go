package server

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// TestSRPolicy_TunnelEncap_SubTLVMatrix runs the same two-server SR-
// Policy SAFI round-trip across every relevant combination of inner
// sub-TLVs (Preference, BSID, Candidate-Path-Name, Unknown type 130,
// Segment List). The test asserts that PathAttributeTunnelEncap
// survives the receive WatchEvent callback for each combination.
//
// The shape mirrors RFC 9012 Section 2.4.4 (Tunnel Encapsulation
// sub-TLV layout) plus the IANA "BGP Tunnel Encapsulation Sub-TLVs"
// registry: type 12 (SR Preference), 13 (SR Binding SID), 128 (SR
// Segment List), 129 (SR Candidate Path Name), 130 (SR Policy Name
// / Unknown). Every combination that includes the Candidate Path
// Name sub-TLV in front of another sub-TLV inside the same Tunnel
// Encap attribute reproduces the silent PathAttributeTunnelEncap
// drop on the receive side; combinations without it round-trip
// cleanly.
func TestSRPolicy_TunnelEncap_SubTLVMatrix(t *testing.T) {
	cases := []struct {
		name        string
		withBSID    bool
		withCPName  bool
		withUnk130  bool
		withSegList bool
	}{
		{name: "pref_only", withSegList: false},
		{name: "pref_segList", withSegList: true},
		{name: "pref_bsid_segList", withBSID: true, withSegList: true},
		{name: "pref_cpName_segList", withCPName: true, withSegList: true},
		{name: "pref_unk130_segList", withUnk130: true, withSegList: true},
		{name: "pref_bsid_cpName_segList", withBSID: true, withCPName: true, withSegList: true},
		{name: "pref_bsid_cpName_unk130_segList", withBSID: true, withCPName: true, withUnk130: true, withSegList: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runSRPolicyTunnelEncapRound(t, tc.withBSID, tc.withCPName, tc.withUnk130, tc.withSegList)
		})
	}
}

func runSRPolicyTunnelEncapRound(t *testing.T, withBSID, withCPName, withUnk130, withSegList bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const as = uint32(65000)
	// Pick non-overlapping ports per sub-test so go test -p>1 stays clean.
	senderPort := 11179 + testTunnelEncapCounter()%100
	recvPort := senderPort + 1
	sender := runNewServer(t, as, "10.0.0.1", senderPort)
	defer sender.StopBgp(context.Background(), &api.StopBgpRequest{})
	receiver := runNewServer(t, as, "10.0.0.2", recvPort)
	defer receiver.StopBgp(context.Background(), &api.StopBgpRequest{})

	rrOpt := func(_ *BgpServer, _ *oc.Global, p *oc.Neighbor) {
		p.RouteReflector.Config.RouteReflectorClient = true
		p.RouteReflector.Config.RouteReflectorClusterId = netip.MustParseAddr("10.10.10.1")
	}
	if err := peerServers(t, ctx, []*BgpServer{sender, receiver},
		[]oc.AfiSafiType{oc.AFI_SAFI_TYPE_IPV4_SRPOLICY}, rrOpt); err != nil {
		t.Fatal(err)
	}
	if err := waitEstablished(t, ctx, sender, receiver); err != nil {
		t.Fatal(err)
	}

	endpoint := net.ParseIP("203.0.113.42").To4()
	nlri, err := bgp.NewSRPolicy(bgp.RF_SR_POLICY_IPv4, 96, 1, 11001, endpoint)
	if err != nil {
		t.Fatalf("NewSRPolicy: %v", err)
	}
	nextHop, _ := netip.AddrFromSlice(net.ParseIP("10.0.0.1").To4())
	mpReach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_SR_POLICY_IPv4,
		[]bgp.PathNLRI{{NLRI: nlri}}, nextHop)
	if err != nil {
		t.Fatalf("NewPathAttributeMpReachNLRI: %v", err)
	}

	subTLVs := []bgp.TunnelEncapSubTLVInterface{
		bgp.NewTunnelEncapSubTLVSRPreference(0, 100),
	}
	if withBSID {
		bsidBuf := []byte{0x00, 0x01, 0x88, 0xb4} // 100020
		bsid, err := bgp.NewBSID(bsidBuf)
		if err != nil {
			t.Fatalf("NewBSID: %v", err)
		}
		subTLVs = append(subTLVs, &bgp.TunnelEncapSubTLVSRBSID{
			TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
				Type:   bgp.ENCAP_SUBTLV_TYPE_SRBINDING_SID,
				Length: uint16(2 + len(bsid.Value)),
			},
			BSID: bsid,
		})
	}
	if withCPName {
		subTLVs = append(subTLVs, bgp.NewTunnelEncapSubTLVSRCandidatePathName("cp-bisect"))
	}
	if withUnk130 {
		name := "cp-bisect"
		body := make([]byte, 1+len(name))
		copy(body[1:], name)
		subTLVs = append(subTLVs, bgp.NewTunnelEncapSubTLVUnknown(bgp.EncapSubTLVType(130), body))
	}
	if withSegList {
		innerSeg := &bgp.SegmentTypeA{
			TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
				Type:   bgp.EncapSubTLVType(bgp.TypeA),
				Length: 6,
			},
			Flags: 0x80,
			Label: 100500 << 4,
		}
		segList := &bgp.TunnelEncapSubTLVSRSegmentList{
			TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
				Type:   bgp.ENCAP_SUBTLV_TYPE_SRSEGMENT_LIST,
				Length: 8,
			},
			Weight: &bgp.SegmentListWeight{
				TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
					Type:   bgp.EncapSubTLVType(bgp.SegmentListSubTLVWeight),
					Length: 6,
				},
				Flags:  0,
				Weight: 0,
			},
			Segments: []bgp.TunnelEncapSubTLVInterface{innerSeg},
		}
		subTLVs = append(subTLVs, segList)
	}

	tlv := bgp.NewTunnelEncapTLV(bgp.TUNNEL_TYPE_SR_POLICY, subTLVs)
	tunnelEncap := bgp.NewPathAttributeTunnelEncap([]*bgp.TunnelEncapTLV{tlv})

	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		mpReach,
		tunnelEncap,
	}

	rxPaths := make(chan []*apiutil.Path, 16)
	watchCtx, watchCancel := context.WithCancel(ctx)
	defer watchCancel()
	go func() {
		_ = receiver.WatchEvent(watchCtx, WatchEventMessageCallbacks{
			OnPathUpdate: func(ps []*apiutil.Path, _ time.Time) {
				select {
				case rxPaths <- ps:
				default:
				}
			},
		}, WatchUpdate(true, "", ""))
	}()

	apiutilPath := &apiutil.Path{
		Family:     bgp.RF_SR_POLICY_IPv4,
		Nlri:       nlri,
		Attrs:      attrs,
		Withdrawal: false,
		Age:        time.Now().Unix(),
	}
	if _, err := sender.AddPath(apiutil.AddPathRequest{
		Paths: []*apiutil.Path{apiutilPath},
	}); err != nil {
		t.Fatalf("AddPath: %v", err)
	}

	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("timeout waiting for SR-Policy UPDATE on receiver WatchEvent")
		case ps := <-rxPaths:
			for _, p := range ps {
				if p == nil {
					continue
				}
				if _, ok := p.Nlri.(*bgp.SRPolicyNLRI); !ok {
					continue
				}
				var hasTunnelEncap bool
				var attrTypes []bgp.BGPAttrType
				for _, a := range p.Attrs {
					attrTypes = append(attrTypes, a.GetType())
					if _, ok := a.(*bgp.PathAttributeTunnelEncap); ok {
						hasTunnelEncap = true
					}
				}
				if !hasTunnelEncap {
					t.Fatalf("PathAttributeTunnelEncap stripped on receive; attributes seen: %v", attrTypes)
				}
				return
			}
		}
	}
}

var testTunnelEncapPortCounter atomic.Int32

func testTunnelEncapCounter() int32 {
	return testTunnelEncapPortCounter.Add(1) * 2
}

func waitEstablished(t *testing.T, ctx context.Context, a, b *BgpServer) error {
	t.Helper()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			if peerEstablished(a) && peerEstablished(b) {
				return nil
			}
		}
	}
}

func peerEstablished(s *BgpServer) bool {
	established := false
	_ = s.ListPeer(context.Background(), &api.ListPeerRequest{}, func(p *api.Peer) {
		if p.State != nil && p.State.SessionState == api.PeerState_SESSION_STATE_ESTABLISHED {
			established = true
		}
	})
	return established
}
