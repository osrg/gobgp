package server

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
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
			// 4 byte AS_PATH, so that a serialized UPDATE built from
			// this path can be parsed back with the default options.
			bgp.NewAs4PathParam(2, []uint32{srcAS}),
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

	options := bmpAddPathMarshallingOption(w.GetFamily())
	msg := table.CreateUpdateMsgFromPaths([]*table.Path{w}, options...)[0]

	payload, err := msg.Serialize(options...)
	require.NoError(t, err)

	decoded, err := bgp.ParseBGPMessage(payload, options...)
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

func bmpTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// A live update carries the bytes received on the wire. They must be forwarded
// as they are, without being decoded and encoded again.
func TestBMPRouteMonitoringForwardsWirePayload(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	msgs := bmpRouteMonitoring(&watchEventUpdate{
		PeerAddress: netip.MustParseAddr("198.51.100.1"),
		PeerAS:      65001,
		PeerID:      netip.MustParseAddr("198.51.100.1"),
		Payload:     payload,
		Timestamp:   time.Unix(100, 0),
		FourBytesAs: true,
		Neighbor:    &oc.Neighbor{},
	}, bmpTestLogger())

	require.Len(t, msgs, 1)
	body := msgs[0].Body.(*packetbmp.BMPRouteMonitoring)
	require.Equal(t, payload, body.BGPUpdatePayload)
	require.Equal(t, packetbmp.BMP_PEER_TYPE_GLOBAL, msgs[0].PeerHeader.PeerType)
}

// A locally originated route has no source peer, so the post-policy initial
// dump puts it in a group with no neighbor. RFC 9069 section 1 replaced
// RFC 7854 section 8.2, so such a route belongs to the Loc-RIB instance peer.
// Reporting it here would use a per-peer header of all zeros for a peer that
// no Peer Up ever announced.
func TestBMPRouteMonitoringSkipsTheGroupWithNoNeighbor(t *testing.T) {
	p := makeIPv4Path(t, "10.7.0.0/24", "192.0.2.1", "198.51.100.1", 65001, 0)

	require.Empty(t, bmpRouteMonitoring(&watchEventUpdate{
		PostPolicy: true,
		Init:       true,
		PathList:   []*table.Path{p},
	}, bmpTestLogger()))
}

// The same group also sends an End-of-RIB, which carries a payload rather than
// a path. RFC 7854 3.2 pairs an End-of-RIB with a Peer Up, so the one for a
// group that never had a Peer Up must be dropped too.
func TestBMPRouteMonitoringSkipsTheEndOfRibWithNoNeighbor(t *testing.T) {
	eor := bgp.NewEndOfRib(bgp.RF_IPv4_UC)
	payload, err := eor.Serialize()
	require.NoError(t, err)

	require.Empty(t, bmpRouteMonitoring(&watchEventUpdate{
		Message:    eor,
		Payload:    payload,
		PostPolicy: true,
		Init:       true,
		Timestamp:  time.Unix(100, 0),
	}, bmpTestLogger()))
}

// RFC 9069 Loc-RIB Route Monitoring uses Peer Type 3 and is always marshalled
// with Add-Path.
func TestBMPLocRIBRouteMonitoringUsesLocalRIBPeerType(t *testing.T) {
	p := makeIPv4Path(t, "10.1.2.0/24", "192.0.2.1", "198.51.100.1", 65001, 0)
	info := &table.PeerInfo{
		Address: netip.IPv4Unspecified(),
		AS:      locRIBTestAS,
		ID:      netip.MustParseAddr(locRIBTestRouterID),
	}

	msgs := bmpLocRIBRouteMonitoring(&watchEventBestPath{
		PathList: []*table.Path{p},
	}, info, bmpTestLogger())

	require.Len(t, msgs, 1)
	require.Equal(t, packetbmp.BMP_PEER_TYPE_LOCAL_RIB, msgs[0].PeerHeader.PeerType)

	// The payload is a whole BGP UPDATE, and it carries the 4 octet path
	// identifier that the plain encoding leaves out.
	body := msgs[0].Body.(*packetbmp.BMPRouteMonitoring)
	require.Equal(t, len(body.BGPUpdatePayload), int(binary.BigEndian.Uint16(body.BGPUpdatePayload[16:18])))

	plain, err := table.CreateUpdateMsgFromPaths([]*table.Path{p})[0].Serialize()
	require.NoError(t, err)
	require.Equal(t, len(plain)+4, len(body.BGPUpdatePayload))
}

// RFC 7854 4.7 asks for "verbatim duplication of messages as received". An
// UPDATE received from an ADD-PATH peer carries a 4 octet path identifier in
// front of every NLRI. Re-encoding the parsed message drops it, because the
// encoder is not told which families use ADD-PATH, so the mirrored message
// must be the bytes that arrived.
func TestBMPRouteMirroringIsVerbatim(t *testing.T) {
	options := []*bgp.MarshallingOption{{
		AddPath: map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_BOTH},
	}}
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.3.0.0/24"))
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	update := bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nh,
	}, []bgp.PathNLRI{{NLRI: nlri, ID: 7}})

	wire, err := update.Serialize(options...)
	require.NoError(t, err)

	info := &table.PeerInfo{
		Address: netip.MustParseAddr("198.51.100.1"),
		AS:      65001,
		ID:      netip.MustParseAddr("198.51.100.1"),
	}
	buf, err := bmpPeerRouteMirroring(packetbmp.BMP_PEER_TYPE_GLOBAL, 0, info, 100, wire).Serialize()
	require.NoError(t, err)

	// Common header(6) + per-peer header(42) + TLV header(4).
	const tlvValueOffset = 6 + packetbmp.BMP_PEER_HEADER_SIZE + 4
	require.Equal(t, wire, buf[tlvValueOffset:])

	// What gobgp used to send: the parsed message encoded again. It is
	// 4 octets shorter, because the encoder is not given the options, so
	// the path identifier is gone and the receiver reads the NLRI out of
	// step.
	parsed, err := bgp.ParseBGPMessage(wire, options...)
	require.NoError(t, err)
	reencoded, err := parsed.Serialize()
	require.NoError(t, err)
	require.Len(t, reencoded, len(wire)-4)
}

// makeAddPathNeighbor is a peer that negotiated ADD-PATH receive for IPv4
// unicast, as s.toConfig() reports it on a watch event.
func makeAddPathNeighbor(receive bool) *oc.Neighbor {
	return &oc.Neighbor{
		AfiSafis: []oc.AfiSafi{{
			State:    oc.AfiSafiState{Family: bgp.RF_IPv4_UC},
			AddPaths: oc.AddPaths{State: oc.AddPathsState{Receive: receive}},
		}},
	}
}

// The Peer Up message carries the OPEN messages the session exchanged, so a
// receiver decodes Route Monitoring for an ADD-PATH peer expecting a 4 octet
// path identifier. The identifier reported is the one the peer sent
// (RFC 7911 2), not the one gobgp assigns when it re-advertises the path.
func TestBMPRouteMonitoringEncodesTheReceivedPathID(t *testing.T) {
	p := makeIPv4Path(t, "10.4.0.0/24", "192.0.2.1", "198.51.100.1", 65001, 9)
	require.Equal(t, uint32(9), p.RemoteID())
	require.Equal(t, uint32(0), p.LocalID())

	msgs := bmpRouteMonitoring(&watchEventUpdate{
		PeerAddress: netip.MustParseAddr("198.51.100.1"),
		PostPolicy:  true,
		Neighbor:    makeAddPathNeighbor(true),
		PathList:    []*table.Path{p},
	}, bmpTestLogger())
	require.Len(t, msgs, 1)

	payload := msgs[0].Body.(*packetbmp.BMPRouteMonitoring).BGPUpdatePayload
	options := []*bgp.MarshallingOption{{
		AddPath: map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_BOTH},
	}}
	decoded, err := bgp.ParseBGPMessage(payload, options...)
	require.NoError(t, err)
	update := decoded.Body.(*bgp.BGPUpdate)
	require.Len(t, update.NLRI, 1)
	require.Equal(t, uint32(9), update.NLRI[0].ID)
	require.Equal(t, "10.4.0.0/24", update.NLRI[0].NLRI.String())

	// The path in the RIB is untouched: reporting must not hand gobgp's own
	// re-advertisement the peer's identifier.
	require.Equal(t, uint32(0), p.LocalID())
}

// A peer that did not negotiate ADD-PATH gets the plain encoding. Its Peer Up
// says so, and a path identifier would put the receiver out of step.
func TestBMPRouteMonitoringOmitsPathIDWithoutAddPath(t *testing.T) {
	p := makeIPv4Path(t, "10.4.1.0/24", "192.0.2.1", "198.51.100.1", 65001, 9)

	msgs := bmpRouteMonitoring(&watchEventUpdate{
		PeerAddress: netip.MustParseAddr("198.51.100.1"),
		PostPolicy:  true,
		Neighbor:    makeAddPathNeighbor(false),
		PathList:    []*table.Path{p},
	}, bmpTestLogger())
	require.Len(t, msgs, 1)

	payload := msgs[0].Body.(*packetbmp.BMPRouteMonitoring).BGPUpdatePayload
	decoded, err := bgp.ParseBGPMessage(payload)
	require.NoError(t, err)
	update := decoded.Body.(*bgp.BGPUpdate)
	require.Len(t, update.NLRI, 1)
	require.Equal(t, "10.4.1.0/24", update.NLRI[0].NLRI.String())
}

// An ADD-PATH peer that advertises two paths of one prefix has both reported,
// each with the identifier the peer gave it.
func TestBMPRouteMonitoringReportsBothAddPathPaths(t *testing.T) {
	p1 := makeIPv4Path(t, "10.6.0.0/24", "192.0.2.1", "198.51.100.1", 65001, 1)
	p2 := makeIPv4Path(t, "10.6.0.0/24", "192.0.2.2", "198.51.100.1", 65001, 2)
	p2.SetSource(p1.GetSource())

	neighbor := makeAddPathNeighbor(true)
	options := []*bgp.MarshallingOption{{
		AddPath: map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_BOTH},
	}}

	ids := make([]uint32, 0, 2)
	for _, p := range []*table.Path{p1, p2} {
		msgs := bmpRouteMonitoring(&watchEventUpdate{
			PeerAddress: netip.MustParseAddr("198.51.100.1"),
			PostPolicy:  true,
			Neighbor:    neighbor,
			PathList:    []*table.Path{p},
		}, bmpTestLogger())
		require.Len(t, msgs, 1)

		payload := msgs[0].Body.(*packetbmp.BMPRouteMonitoring).BGPUpdatePayload
		decoded, err := bgp.ParseBGPMessage(payload, options...)
		require.NoError(t, err)
		update := decoded.Body.(*bgp.BGPUpdate)
		require.Len(t, update.NLRI, 1)
		require.Equal(t, "10.6.0.0/24", update.NLRI[0].NLRI.String())
		ids = append(ids, update.NLRI[0].ID)
	}
	require.Equal(t, []uint32{1, 2}, ids)
}
