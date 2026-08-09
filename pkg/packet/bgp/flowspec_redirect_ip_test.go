package bgp

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlowSpecRedirectToIPv4Serialize(t *testing.T) {
	ec, err := NewFlowSpecRedirectToIPv4Extended(netip.MustParseAddr("203.0.113.10"), false)
	assert.NoError(t, err)
	buf, err := ec.Serialize()
	assert.NoError(t, err)
	// type 0x01, subtype 0x0c, GA = target, LA = 0 (C flag clear).
	assert.Equal(t, []byte{0x01, 0x0c, 203, 0, 113, 10, 0x00, 0x00}, buf)
	assert.Equal(t, "redirect-to-ip: 203.0.113.10", ec.String())
}

func TestFlowSpecRedirectToIPv4CopyFlag(t *testing.T) {
	ec, err := NewFlowSpecRedirectToIPv4Extended(netip.MustParseAddr("203.0.113.10"), true)
	assert.NoError(t, err)
	buf, err := ec.Serialize()
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x01, 0x0c, 203, 0, 113, 10, 0x00, 0x01}, buf)
	assert.True(t, ec.IsCopy())
	assert.Equal(t, "copy-to-ip: 203.0.113.10", ec.String())
}

func TestFlowSpecRedirectToIPv4ParseRoundTrip(t *testing.T) {
	for _, isCopy := range []bool{false, true} {
		orig, err := NewFlowSpecRedirectToIPv4Extended(netip.MustParseAddr("10.0.0.42"), isCopy)
		assert.NoError(t, err)
		buf, err := orig.Serialize()
		assert.NoError(t, err)

		parsed, err := ParseExtended(buf)
		assert.NoError(t, err)
		got, ok := parsed.(*FlowSpecRedirectToIPv4Extended)
		assert.True(t, ok, "parsed as %T", parsed)
		assert.Equal(t, orig.Target, got.Target)
		assert.Equal(t, isCopy, got.Copy)
	}
}

// Reserved bits must be ignored on receipt and never re-originated.
func TestFlowSpecRedirectToIPv4IgnoresReservedBits(t *testing.T) {
	wire := []byte{0x01, 0x0c, 203, 0, 113, 10, 0xff, 0xfe} // reserved set, C clear
	parsed, err := ParseExtended(wire)
	assert.NoError(t, err)
	got, ok := parsed.(*FlowSpecRedirectToIPv4Extended)
	assert.True(t, ok, "parsed as %T", parsed)
	assert.False(t, got.IsCopy())

	out, err := got.Serialize()
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x01, 0x0c, 203, 0, 113, 10, 0x00, 0x00}, out,
		"reserved bits must not be re-originated")

	wire[7] = 0xff // reserved set, C set
	parsed, err = ParseExtended(wire)
	assert.NoError(t, err)
	assert.True(t, parsed.(*FlowSpecRedirectToIPv4Extended).IsCopy())
}

func TestFlowSpecRedirectToIPv4RejectsNonIPv4(t *testing.T) {
	_, err := NewFlowSpecRedirectToIPv4Extended(netip.MustParseAddr("2001:db8::1"), false)
	assert.Error(t, err)
}

// Only 0x0c is the redirect action; other subtypes stay generic.
func TestFlowSpecRedirectToIPv4DoesNotShadowRT(t *testing.T) {
	rt, err := NewIPv4AddressSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, netip.MustParseAddr("10.0.0.1"), 100, true)
	assert.NoError(t, err)
	buf, err := rt.Serialize()
	assert.NoError(t, err)
	parsed, err := ParseExtended(buf)
	assert.NoError(t, err)
	_, isRedirect := parsed.(*FlowSpecRedirectToIPv4Extended)
	assert.False(t, isRedirect)
}

func TestFlowSpecRedirectToIPv6Serialize(t *testing.T) {
	ec, err := NewFlowSpecRedirectToIPv6Extended(netip.MustParseAddr("2001:db8::1"), false)
	assert.NoError(t, err)
	buf, err := ec.Serialize()
	assert.NoError(t, err)
	assert.Len(t, buf, 20)
	// IPv6 address-specific EC (RFC 5701) type 0x00, subtype 0x0c.
	assert.Equal(t, byte(0x00), buf[0])
	assert.Equal(t, byte(0x0c), buf[1])
	assert.Equal(t, netip.MustParseAddr("2001:db8::1").AsSlice(), buf[2:18])
	assert.Equal(t, []byte{0x00, 0x00}, buf[18:20])
	assert.Equal(t, "redirect-to-ip: 2001:db8::1", ec.String())
}

func TestFlowSpecRedirectToIPv6ParseRoundTrip(t *testing.T) {
	for _, isCopy := range []bool{false, true} {
		orig, err := NewFlowSpecRedirectToIPv6Extended(netip.MustParseAddr("2001:db8::42"), isCopy)
		assert.NoError(t, err)
		buf, err := orig.Serialize()
		assert.NoError(t, err)

		parsed, err := ParseIP6Extended(buf)
		assert.NoError(t, err)
		got, ok := parsed.(*FlowSpecRedirectToIPv6Extended)
		assert.True(t, ok, "parsed as %T", parsed)
		assert.Equal(t, orig.Target, got.Target)
		assert.Equal(t, isCopy, got.Copy)
	}
}

func TestFlowSpecRedirectToIPv6RejectsNonIPv6(t *testing.T) {
	_, err := NewFlowSpecRedirectToIPv6Extended(netip.MustParseAddr("192.0.2.1"), false)
	assert.Error(t, err)
}

// Same for the IPv6 dispatch.
func TestFlowSpecRedirectToIPv6DoesNotShadowRT(t *testing.T) {
	rt, err := NewIPv6AddressSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, netip.MustParseAddr("2001:db8::1"), 100, true)
	assert.NoError(t, err)
	buf, err := rt.Serialize()
	assert.NoError(t, err)
	parsed, err := ParseIP6Extended(buf)
	assert.NoError(t, err)
	_, isRedirect := parsed.(*FlowSpecRedirectToIPv6Extended)
	assert.False(t, isRedirect)
}

// What the decoder accepts, the encoder must be able to re-originate.
func TestFlowSpecRedirectToIPv6UnmapsV4MappedTarget(t *testing.T) {
	wire := make([]byte, 20)
	wire[0] = 0x00 // transitive IPv6-address-specific
	wire[1] = 0x0c
	copy(wire[2:18], netip.MustParseAddr("::ffff:198.51.100.11").AsSlice())

	parsed, err := ParseIP6Extended(wire)
	assert.NoError(t, err)
	got, ok := parsed.(*FlowSpecRedirectToIPv6Extended)
	assert.True(t, ok, "parsed as %T", parsed)

	_, err = got.Serialize()
	assert.NoError(t, err, "a parsed target must be re-serializable")
}

// A truncated community must be refused by the length guard rather
// than reaching the fixed-offset reads in the redirect branches.
func TestFlowSpecRedirectToIPRejectsShortBuffers(t *testing.T) {
	v4 := []byte{0x01, 0x0c, 203, 0, 113, 10, 0x00, 0x00}
	for n := range v4 {
		_, err := ParseExtended(v4[:n])
		assert.Error(t, err, "ParseExtended accepted %d bytes", n)
	}

	v6 := make([]byte, 20)
	v6[0], v6[1] = 0x00, 0x0c
	for n := range v6 {
		_, err := ParseIP6Extended(v6[:n])
		assert.Error(t, err, "ParseIP6Extended accepted %d bytes", n)
	}
}

// type and subtype already name the action, so the remaining fields
// carry only the value, as the other action communities do.
func TestFlowSpecRedirectToIPMarshalJSON(t *testing.T) {
	v4, err := NewFlowSpecRedirectToIPv4Extended(netip.MustParseAddr("198.51.100.11"), true)
	assert.NoError(t, err)
	b, err := json.Marshal(v4)
	assert.NoError(t, err)
	assert.JSONEq(t, `{"type":1,"subtype":12,"target":"198.51.100.11","copy":true}`, string(b))

	v6, err := NewFlowSpecRedirectToIPv6Extended(netip.MustParseAddr("2001:db8::1"), false)
	assert.NoError(t, err)
	b, err = json.Marshal(v6)
	assert.NoError(t, err)
	assert.JSONEq(t, `{"type":0,"subtype":12,"target":"2001:db8::1","copy":false}`, string(b))
}
