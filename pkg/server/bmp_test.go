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

func localRIBPeerUpOpen(t *testing.T, addPathEnabled bool) *bgp.BGPOpen {
	t.Helper()
	msg := bmpLocRIBPeerUp(
		65002,
		netip.MustParseAddr("100.1.1.102"),
		"global",
		0,
		time.Now().Unix(),
		addPathEnabled,
	)
	up := msg.Body.(*packetbmp.BMPPeerUpNotification)
	return up.SentOpenMsg.Body.(*bgp.BGPOpen)
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

func TestBMPLocRIBPeerUpOmitsAddPathCapabilityWhenDisabled(t *testing.T) {
	open := localRIBPeerUpOpen(t, false)
	require.Nil(t, findAddPathCapability(open))
}

func TestBMPLocRIBPeerUpCarriesAddPathCapabilityWhenEnabled(t *testing.T) {
	open := localRIBPeerUpOpen(t, true)
	addPath := findAddPathCapability(open)
	require.NotNil(t, addPath)
	require.Len(t, addPath.Tuples, 2)
	require.Equal(t, bgp.RF_IPv4_UC, addPath.Tuples[0].Family)
	require.Equal(t, bgp.BGP_ADD_PATH_BOTH, addPath.Tuples[0].Mode)
	require.Equal(t, bgp.RF_IPv6_UC, addPath.Tuples[1].Family)
	require.Equal(t, bgp.BGP_ADD_PATH_BOTH, addPath.Tuples[1].Mode)
}
