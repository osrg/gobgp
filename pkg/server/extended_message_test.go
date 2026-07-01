package server

import (
	"context"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// remoteAdvertisedExtendedMessage walks a peer's remote capability
// list looking for *bgp.CapExtendedMessage. It is the on-wire
// observation of what the peer sent in its OPEN message, which is
// the only signal a test has of the negotiation outcome.
func remoteAdvertisedExtendedMessage(p *api.Peer) bool {
	if p == nil || p.State == nil {
		return false
	}
	for _, c := range p.State.RemoteCap {
		if c == nil {
			continue
		}
		if c.GetExtendedMessage() != nil {
			return true
		}
	}
	return false
}

// localAdvertisedExtendedMessage mirrors remoteAdvertisedExtendedMessage
// on the local capability list, that is, what WE put in the OPEN.
func localAdvertisedExtendedMessage(p *api.Peer) bool {
	if p == nil || p.State == nil {
		return false
	}
	for _, c := range p.State.LocalCap {
		if c == nil {
			continue
		}
		if c.GetExtendedMessage() != nil {
			return true
		}
	}
	return false
}

// TestExtendedMessage_AdvertisedUnconditionally covers RFC 8654
// Section 3 behaviour: each side always advertises the Extended
// Message Capability in its OPEN, and once the peer also advertises
// it the negotiation reaches "both peers carry the capability on
// both their local and remote capability lists".
func TestExtendedMessage_AdvertisedUnconditionally(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s1 := runNewServer(t, 64512, "1.1.1.1", 10179)
	defer s1.StopBgp(ctx, &api.StopBgpRequest{})
	s2 := runNewServer(t, 64512, "2.2.2.2", 20179)
	defer s2.StopBgp(ctx, &api.StopBgpRequest{})

	require.NoError(t, peerServers(t, ctx, []*BgpServer{s1, s2},
		[]oc.AfiSafiType{oc.AFI_SAFI_TYPE_IPV4_UNICAST}))

	newPeerStateWaiter(s1, api.PeerState_SESSION_STATE_ESTABLISHED).Wait(t, 20*time.Second)

	checked := false
	require.NoError(t, s1.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
		checked = true
		assert.True(t, localAdvertisedExtendedMessage(p),
			"s1 must advertise the capability unconditionally")
		assert.True(t, remoteAdvertisedExtendedMessage(p),
			"s2 must advertise the capability back")
	}))
	assert.True(t, checked, "ListPeer must have surfaced an established peer")
}

// TestExtendedMessage_CapMarshalRoundTripsThroughApi covers the
// apiutil glue: a remote capability list containing
// *bgp.CapExtendedMessage must serialise to api.Capability_ExtendedMessage
// and back without losing identity. Without the dispatch case the
// ListPeer plumbing (which is the only way an operator inspects
// negotiated caps over gRPC) would surface the capability as
// CapUnknown.
func TestExtendedMessage_CapMarshalRoundTripsThroughApi(t *testing.T) {
	caps := []bgp.ParameterCapabilityInterface{
		bgp.NewCapExtendedMessage(),
	}

	apiCaps, err := apiutil.MarshalCapabilities(caps)
	require.NoError(t, err)
	require.Len(t, apiCaps, 1)
	require.NotNil(t, apiCaps[0].GetExtendedMessage(),
		"the api.Capability oneof must carry the ExtendedMessage variant")

	roundTripped, err := apiutil.UnmarshalCapabilities(apiCaps)
	require.NoError(t, err)
	require.Len(t, roundTripped, 1)
	_, ok := roundTripped[0].(*bgp.CapExtendedMessage)
	require.True(t, ok, "round-trip must preserve the native cap type")
}
