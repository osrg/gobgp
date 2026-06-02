package bgp

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCapExtendedMessageRoundTrip exercises Serialize -> DecodeFromBytes
// for the empty-TLV BGP Extended Message capability defined by
// RFC 8654. Capability Code 6, Capability Length 0; nothing more on
// the wire.
func TestCapExtendedMessageRoundTrip(t *testing.T) {
	cap := NewCapExtendedMessage()

	buf, err := cap.Serialize()
	require.NoError(t, err)
	require.Equal(t, []byte{byte(BGP_CAP_EXTENDED_MESSAGE), 0x00}, buf,
		"on-wire form is code=6 length=0")

	decoded := &CapExtendedMessage{}
	require.NoError(t, decoded.DecodeFromBytes(buf))
	require.Equal(t, BGP_CAP_EXTENDED_MESSAGE, decoded.Code())
}

// TestDecodeCapabilityDispatchesExtendedMessage verifies that
// DecodeCapability, the entry point the OPEN-message parser walks
// through, returns a *CapExtendedMessage when handed the on-wire
// form. Without the dispatch case a peer's advertisement would land
// as *CapUnknown and the negotiation logic would never set the
// negotiated flag.
func TestDecodeCapabilityDispatchesExtendedMessage(t *testing.T) {
	on := []byte{byte(BGP_CAP_EXTENDED_MESSAGE), 0x00}

	got, err := DecodeCapability(on)
	require.NoError(t, err)
	_, ok := got.(*CapExtendedMessage)
	require.True(t, ok, "expected *CapExtendedMessage, got %T", got)
}

// TestExtendedMessageNameMap pins the rendered name for the cap so
// the gobgp CLI surface stays the same shape "extended-message"
// other open-source implementations use (FRRouting, BIRD).
func TestExtendedMessageNameMap(t *testing.T) {
	require.Equal(t, "extended-message", CapNameMap[BGP_CAP_EXTENDED_MESSAGE])
}

// TestBGPMessageSerializeLengthCap covers the per-message-type
// branching RFC 8654 Section 6 mandates: UPDATE, NOTIFICATION and
// ROUTE-REFRESH may grow to 65535 octets when the negotiation flag
// is on the MarshallingOption; OPEN and KEEPALIVE keep the legacy
// 4096-octet ceiling regardless.
func TestBGPMessageSerializeLengthCap(t *testing.T) {
	// Build a UPDATE whose body is just shy of the extended cap.
	// The body shape does not matter for the size check; we use a
	// single ATTR_TYPE_UNKNOWN with a payload large enough to push
	// the message past BGP_MAX_MESSAGE_LENGTH but still under
	// BGP_MAX_EXTENDED_MESSAGE_LENGTH.
	largePayload := bytes.Repeat([]byte{0xAA}, 5000)

	mkLargeUpdate := func() *BGPMessage {
		attr := &PathAttributeUnknown{
			PathAttribute: PathAttribute{
				Flags: BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_EXTENDED_LENGTH,
				Type:  0xFE, // a free experimental attribute code
			},
			Value: largePayload,
		}
		return NewBGPUpdateMessage(nil, []PathAttributeInterface{attr}, nil)
	}

	t.Run("UPDATE_over_4096_rejected_without_negotiation", func(t *testing.T) {
		m := mkLargeUpdate()
		_, err := m.Serialize()
		require.Error(t, err, "must reject UPDATE > 4096 with no ExtendedMessage option")
	})

	t.Run("UPDATE_over_4096_accepted_with_negotiation", func(t *testing.T) {
		m := mkLargeUpdate()
		buf, err := m.Serialize(&MarshallingOption{ExtendedMessage: true})
		require.NoError(t, err, "must accept UPDATE > 4096 once ExtendedMessage negotiated")
		require.Greater(t, len(buf), BGP_MAX_MESSAGE_LENGTH,
			"the serialised UPDATE actually exceeds the legacy 4096 cap")
	})

	t.Run("NOTIFICATION_uses_extended_cap", func(t *testing.T) {
		// NOTIFICATION carries Code (1 byte) + Subcode (1 byte) +
		// Data. Pad Data large enough to clear 4096 octets.
		body := &BGPNotification{
			ErrorCode:    BGP_ERROR_CEASE,
			ErrorSubcode: 0,
			Data:         bytes.Repeat([]byte{0xCC}, 5000),
		}
		m := &BGPMessage{
			Header: BGPHeader{Type: BGP_MSG_NOTIFICATION},
			Body:   body,
		}
		_, err := m.Serialize()
		require.Error(t, err, "NOTIFICATION > 4096 without negotiation must reject")

		// Reset the cached length the previous call wrote.
		m.Header.Len = 0
		_, err = m.Serialize(&MarshallingOption{ExtendedMessage: true})
		require.NoError(t, err, "NOTIFICATION > 4096 with negotiation must serialise")
	})

	t.Run("OPEN_stays_at_legacy_cap_even_with_negotiation", func(t *testing.T) {
		// OPEN carries an OptParamLen byte that limits OptParams to
		// 255 octets in the non-extended form, so reaching a 4097-
		// octet BGPOpen body requires RFC 9072 extended params or
		// many capabilities. We compose a synthetic body via the
		// BGPMessageHeader.Type case and a large notification-like
		// body for the size check only - the Serialize cap fires on
		// the body length the Body.Serialize call returns, which
		// here we model by sending a BGPNotification body under an
		// OPEN header. RFC 8654 Section 6: OPEN and KEEPALIVE keep
		// the 4096-octet cap regardless of the option.
		body := &BGPNotification{
			ErrorCode:    BGP_ERROR_CEASE,
			ErrorSubcode: 0,
			Data:         bytes.Repeat([]byte{0xCC}, 5000),
		}
		m := &BGPMessage{
			Header: BGPHeader{Type: BGP_MSG_OPEN},
			Body:   body,
		}
		_, err := m.Serialize(&MarshallingOption{ExtendedMessage: true})
		require.Error(t, err,
			"OPEN > 4096 must reject even with ExtendedMessage negotiated")
	})
}

// TestIsExtendedMessageSerialization documents the helper's
// nil-safe walk: nil entries are skipped (so a callsite may pass a
// half-populated option slice without panicking) and a true flag
// anywhere in the slice flips the result.
func TestIsExtendedMessageSerialization(t *testing.T) {
	require.False(t, IsExtendedMessageSerialization(nil))
	require.False(t, IsExtendedMessageSerialization([]*MarshallingOption{nil}))
	require.False(t, IsExtendedMessageSerialization([]*MarshallingOption{{}}))
	require.True(t, IsExtendedMessageSerialization([]*MarshallingOption{nil, {ExtendedMessage: true}}))
	require.True(t, IsExtendedMessageSerialization([]*MarshallingOption{{ExtendedMessage: true}, {}}))
}
