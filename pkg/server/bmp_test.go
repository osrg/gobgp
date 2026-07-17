package server

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	packetbmp "github.com/osrg/gobgp/v4/pkg/packet/bmp"
	"github.com/stretchr/testify/require"
)

func makeIPv4Path(t *testing.T, prefix, nexthop, src string, srcAS uint32, remoteID uint32) *table.Path {
	t.Helper()

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)

	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
	require.NoError(t, err)

	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAsPathParam(2, []uint16{uint16(srcAS)}),
		}),
		nh,
	}
	source := &table.PeerInfo{
		AS:      srcAS,
		ID:      netip.MustParseAddr(src),
		Address: netip.MustParseAddr(src),
	}
	return table.NewPath(
		bgp.RF_IPv4_UC,
		source,
		bgp.PathNLRI{NLRI: nlri, ID: remoteID},
		false,
		attrs,
		time.Unix(100, 0),
		false,
	)
}

func TestLocRIBPathsForBMPUsesDeltaListsFirst(t *testing.T) {
	p1 := makeIPv4Path(t, "10.0.0.0/24", "192.0.2.1", "198.51.100.1", 65001, 1)
	p2 := makeIPv4Path(t, "10.0.0.0/24", "192.0.2.2", "198.51.100.2", 65002, 2)
	w := p1.Clone(true)
	paths := locRIBPathsForBMP(&watchEventBestPath{
		UpdatePathList:   []*table.Path{p2},
		WithdrawPathList: []*table.Path{w},
		// These are ignored when delta lists are present.
		PathList:      []*table.Path{p1},
		MultiPathList: [][]*table.Path{{p1, p2}},
	})
	require.Len(t, paths, 2)
	require.True(t, paths[0].IsWithdraw)
	require.False(t, paths[1].IsWithdraw)
}

func TestLocRIBPathsForBMPFallsBackToMultiPathList(t *testing.T) {
	p1 := makeIPv4Path(t, "10.0.1.0/24", "192.0.2.11", "198.51.100.11", 65101, 11)
	p2 := makeIPv4Path(t, "10.0.1.0/24", "192.0.2.12", "198.51.100.12", 65102, 12)

	paths := locRIBPathsForBMP(&watchEventBestPath{
		PathList:      []*table.Path{p1.Clone(true)},
		MultiPathList: [][]*table.Path{{p1, p2}},
	})
	require.Len(t, paths, 2)
}

func TestBMPAddPathMarshallingOptionCarriesPathIDOnWithdraw(t *testing.T) {
	p := makeIPv4Path(t, "10.0.2.0/24", "192.0.2.21", "198.51.100.21", 65201, 0)
	w := p.Clone(true)

	options := bmpAddPathMarshallingOption(w)
	msg := table.CreateUpdateMsgFromPaths([]*table.Path{w}, options)[0]

	payload, err := msg.Serialize(options)
	require.NoError(t, err)

	decoded, err := bgp.ParseBGPMessage(payload, options)
	require.NoError(t, err)

	// BGP header(19) + WithdrawnRoutesLen(2). For IPv4 /24 withdraw:
	// with Add-Path => 4(path-id) + 1(prefix-len) + 3(prefix bytes) = 8.
	require.GreaterOrEqual(t, len(payload), 21)
	require.Equal(t, uint16(8), binary.BigEndian.Uint16(payload[19:21]))

	update := decoded.Body.(*bgp.BGPUpdate)
	require.Len(t, update.WithdrawnRoutes, 1)
	// Loc-RIB sender-assigned path-id can be 0 for paths without local path-id assignment.
	// We only assert Add-Path encoding is in use (checked above by withdrawn length).
	_ = update.WithdrawnRoutes[0].ID
}

const (
	locRIBTestAS       = uint32(65002)
	locRIBTestRouterID = "100.1.1.102"
)

func localRIBPeerUp(t *testing.T) *packetbmp.BMPMessage {
	t.Helper()
	return bmpLocRIBPeerUp(
		locRIBTestAS,
		netip.MustParseAddr(locRIBTestRouterID),
		"global",
		0,
		time.Now().Unix(),
	)
}

func localRIBPeerUpOpen(t *testing.T) *bgp.BGPOpen {
	t.Helper()
	up := localRIBPeerUp(t).Body.(*packetbmp.BMPPeerUpNotification)
	return up.SentOpenMsg.Body.(*bgp.BGPOpen)
}

func findFourOctetASCapability(open *bgp.BGPOpen) *bgp.CapFourOctetASNumber {
	for _, p := range open.OptParams {
		param, ok := p.(*bgp.OptionParameterCapability)
		if !ok {
			continue
		}
		for _, c := range param.Capability {
			if fourOctet, ok := c.(*bgp.CapFourOctetASNumber); ok {
				return fourOctet
			}
		}
	}
	return nil
}

func findAddPathCapability(open *bgp.BGPOpen) *bgp.CapAddPath {
	for _, p := range open.OptParams {
		param, ok := p.(*bgp.OptionParameterCapability)
		if !ok {
			continue
		}
		for _, c := range param.Capability {
			if addPath, ok := c.(*bgp.CapAddPath); ok {
				return addPath
			}
		}
	}
	return nil
}

// A withdraw generated on peer down (DropAll clones the Adj-RIB-In path with
// IsWithdraw=true) must clear the ribout cache so that an identical path sent
// after the session re-establishes is reported to the BMP server again.
func TestRiboutWithdrawAllowsIdenticalResendAfterFlap(t *testing.T) {
	r := newribout()
	p := makeIPv4Path(t, "10.0.3.0/24", "192.0.2.31", "198.51.100.31", 65301, 0)

	// First advertisement is reported.
	require.True(t, r.update(p))
	// Identical re-advertisement while the session is up is suppressed.
	require.False(t, r.update(p))

	// Peer goes down: DropAll yields a withdraw clone sharing the same source.
	w := p.Clone(true)
	require.True(t, w.IsWithdraw)
	require.Equal(t, p.GetSource(), w.GetSource())
	require.True(t, r.update(w))

	// After the flap the identical path must be reported again.
	require.True(t, r.update(p))
}

// A withdraw for one peer must not evict another peer's cached path for the
// same prefix.
func TestRiboutWithdrawKeepsOtherPeersPath(t *testing.T) {
	r := newribout()
	p1 := makeIPv4Path(t, "10.0.4.0/24", "192.0.2.41", "198.51.100.41", 65401, 0)
	p2 := makeIPv4Path(t, "10.0.4.0/24", "192.0.2.42", "198.51.100.42", 65402, 0)

	require.True(t, r.update(p1))
	require.True(t, r.update(p2))

	// Withdraw p1 only.
	require.True(t, r.update(p1.Clone(true)))

	// p2 is still cached (suppressed), p1 can be reported again.
	require.False(t, r.update(p2))
	require.True(t, r.update(p1))
}

// Loc-RIB Route Monitoring messages are always marshalled with add-path (see
// TestBMPAddPathMarshallingOptionCarriesPathIDOnWithdraw), so the fabricated
// OPEN must always advertise the capability. Omitting it left receivers parsing
// the NLRIs 4 octets out of step. RFC 9069 5.2.
func TestBMPLocRIBPeerUpAlwaysCarriesAddPathCapability(t *testing.T) {
	open := localRIBPeerUpOpen(t)
	addPath := findAddPathCapability(open)
	require.NotNil(t, addPath)
	require.Len(t, addPath.Tuples, 2)
	require.Equal(t, bgp.RF_IPv4_UC, addPath.Tuples[0].Family)
	require.Equal(t, bgp.BGP_ADD_PATH_BOTH, addPath.Tuples[0].Mode)
	require.Equal(t, bgp.RF_IPv6_UC, addPath.Tuples[1].Family)
	require.Equal(t, bgp.BGP_ADD_PATH_BOTH, addPath.Tuples[1].Mode)
}

// RFC 9069 5.2: "Capabilities MUST include the 4-octet ASN and all necessary
// capabilities to represent the Loc-RIB Route Monitoring messages."
//
// RFC 6793 3: the capability is advertised whatever the ASN is, and carries the
// real AS number. Only the 2-octet My Autonomous System field changes: it holds
// the AS when it fits, and AS_TRANS (23456) when it does not.
func TestBMPLocRIBPeerUpAlwaysCarriesFourOctetASCapability(t *testing.T) {
	const asTrans = uint16(23456)

	tests := []struct {
		name     string
		localAS  uint32
		wantMyAS uint16
	}{
		{"two-octet AS is carried in My AS", 65002, 65002},
		{"four-octet AS falls back to AS_TRANS in My AS", 4200000000, asTrans},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := bmpLocRIBPeerUp(tt.localAS, netip.MustParseAddr(locRIBTestRouterID), "global", 0, time.Now().Unix())
			open := msg.Body.(*packetbmp.BMPPeerUpNotification).SentOpenMsg.Body.(*bgp.BGPOpen)

			require.Equal(t, tt.wantMyAS, open.MyAS)

			fourOctet := findFourOctetASCapability(open)
			require.NotNil(t, fourOctet, "the capability is advertised whatever the ASN is")
			require.Equal(t, tt.localAS, fourOctet.CapValue, "the capability carries the real AS number")

			// and the per-peer header always carries the real AS, never AS_TRANS
			require.Equal(t, tt.localAS, msg.PeerHeader.PeerAS)
		})
	}
}

// RFC 9069 5.1: only the Peer Address is zero-filled for a Loc-RIB Instance
// Peer. The Peer AS is the router's ASN and the Peer BGP ID is its router-id,
// and both must match the header carried by the Loc-RIB Route Monitoring
// messages, or a receiver cannot correlate the two and loses the capabilities
// negotiated in this Peer Up.
func TestBMPLocRIBPeerUpHeaderIdentifiesTheRouter(t *testing.T) {
	ph := localRIBPeerUp(t).PeerHeader
	require.Equal(t, packetbmp.BMP_PEER_TYPE_LOCAL_RIB, ph.PeerType)
	require.Equal(t, locRIBTestAS, ph.PeerAS)
	require.Equal(t, netip.MustParseAddr(locRIBTestRouterID), ph.PeerBGPID)
	require.False(t, ph.PeerAddress.IsValid(), "peer address must be zero-filled")
}

// bmpLocRIBPeerDown carries the same per-peer header as the Peer Up and the
// Route Monitoring messages, so a receiver can tie the teardown to the instance
// it was told about. RFC 9069 5.1.
func TestBMPLocRIBPeerDownHeaderIdentifiesTheRouter(t *testing.T) {
	msg := bmpLocRIBPeerDown(
		locRIBTestAS,
		netip.MustParseAddr(locRIBTestRouterID),
		"global",
		0,
		time.Now().Unix(),
	)
	ph := msg.PeerHeader
	require.Equal(t, packetbmp.BMP_PEER_TYPE_LOCAL_RIB, ph.PeerType)
	require.Equal(t, locRIBTestAS, ph.PeerAS)
	require.Equal(t, netip.MustParseAddr(locRIBTestRouterID), ph.PeerBGPID)
	require.False(t, ph.PeerAddress.IsValid(), "peer address must be zero-filled")
}
