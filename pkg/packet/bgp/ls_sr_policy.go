package bgp

// This file implements the BGP-LS SR Policy Candidate Path NLRI (type 5)
// defined in RFC 9857 "Advertisement of Segment Routing Policies Using BGP
// Link-State": the NLRI with the SR Policy Candidate Path Descriptor TLV
// (554) and the headend Local Node Descriptors TLV. The attribute TLVs of
// RFC 9857 section 5 are not decoded yet. PathAttributeLs keeps them as
// opaque TLVs and re-serializes them unchanged.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// lsAddrBytes returns addr as a fixed-size slice of n (4 or 16) bytes. An
// invalid address yields n zero bytes.
func lsAddrBytes(addr netip.Addr, n int) []byte {
	if !addr.IsValid() {
		return make([]byte, n)
	}
	if n == 4 {
		a := addr.Unmap().As4()
		return a[:]
	}
	a := addr.As16()
	return a[:]
}

// SR Policy Candidate Path Descriptor TLV (554), RFC 9857 Section 4.1

const (
	lsSrPolicyCPDescFlagEndpointV6   uint8 = 1 << 7 // E-Flag
	lsSrPolicyCPDescFlagOriginatorV6 uint8 = 1 << 6 // O-Flag
)

// LsSrPolicyCandidatePathDescriptor is the decoded content of the SR Policy
// Candidate Path Descriptor TLV.
type LsSrPolicyCandidatePathDescriptor struct {
	ProtocolOrigin    uint8      `json:"protocol_origin"`
	Endpoint          netip.Addr `json:"endpoint"`
	Color             uint32     `json:"color"`
	OriginatorASN     uint32     `json:"originator_asn"`
	OriginatorAddress netip.Addr `json:"originator_address"`
	Discriminator     uint32     `json:"discriminator"`
}

func (d *LsSrPolicyCandidatePathDescriptor) String() string {
	return fmt.Sprintf("{Endpoint: %s Color: %d Origin: %d Originator: %d/%s Discriminator: %d}",
		d.Endpoint, d.Color, d.ProtocolOrigin, d.OriginatorASN, d.OriginatorAddress, d.Discriminator)
}

type LsTLVSrPolicyCandidatePathDescriptor struct {
	LsTLV
	ProtocolOrigin    uint8
	Flags             uint8
	Endpoint          netip.Addr
	Color             uint32
	OriginatorASN     uint32
	OriginatorAddress netip.Addr
	Discriminator     uint32
}

func lsSrPolicyCPDescLen(endpoint, originator netip.Addr) uint16 {
	n := 4 + 4 + 4 + 4
	if endpoint.Is6() {
		n += 16
	} else {
		n += 4
	}
	if originator.Is6() {
		n += 16
	} else {
		n += 4
	}
	return uint16(n)
}

func NewLsTLVSrPolicyCandidatePathDescriptor(d *LsSrPolicyCandidatePathDescriptor) *LsTLVSrPolicyCandidatePathDescriptor {
	endpoint := d.Endpoint.Unmap()
	originator := d.OriginatorAddress.Unmap()

	var flags uint8
	if endpoint.Is6() {
		flags |= lsSrPolicyCPDescFlagEndpointV6
	}
	if originator.Is6() {
		flags |= lsSrPolicyCPDescFlagOriginatorV6
	}

	return &LsTLVSrPolicyCandidatePathDescriptor{
		LsTLV: LsTLV{
			Type:   LS_TLV_SR_POLICY_CP_DESC,
			Length: lsSrPolicyCPDescLen(endpoint, originator),
		},
		ProtocolOrigin:    d.ProtocolOrigin,
		Flags:             flags,
		Endpoint:          endpoint,
		Color:             d.Color,
		OriginatorASN:     d.OriginatorASN,
		OriginatorAddress: originator,
		Discriminator:     d.Discriminator,
	}
}

func (l *LsTLVSrPolicyCandidatePathDescriptor) Extract() *LsSrPolicyCandidatePathDescriptor {
	return &LsSrPolicyCandidatePathDescriptor{
		ProtocolOrigin:    l.ProtocolOrigin,
		Endpoint:          l.Endpoint,
		Color:             l.Color,
		OriginatorASN:     l.OriginatorASN,
		OriginatorAddress: l.OriginatorAddress,
		Discriminator:     l.Discriminator,
	}
}

func (l *LsTLVSrPolicyCandidatePathDescriptor) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_POLICY_CP_DESC {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) < 4 {
		return malformedAttrListErr("Incorrect SR Policy Candidate Path Descriptor length")
	}

	l.ProtocolOrigin = value[0]
	l.Flags = value[1]
	// value[2:4] is reserved and ignored.

	epLen := 4
	if l.Flags&lsSrPolicyCPDescFlagEndpointV6 != 0 {
		epLen = 16
	}
	origLen := 4
	if l.Flags&lsSrPolicyCPDescFlagOriginatorV6 != 0 {
		origLen = 16
	}

	if len(value) != 4+epLen+4+4+origLen+4 {
		return malformedAttrListErr("Incorrect SR Policy Candidate Path Descriptor length")
	}

	p := 4
	l.Endpoint, _ = netip.AddrFromSlice(value[p : p+epLen])
	p += epLen
	l.Color = binary.BigEndian.Uint32(value[p : p+4])
	p += 4
	l.OriginatorASN = binary.BigEndian.Uint32(value[p : p+4])
	p += 4
	l.OriginatorAddress, _ = netip.AddrFromSlice(value[p : p+origLen])
	p += origLen
	l.Discriminator = binary.BigEndian.Uint32(value[p : p+4])

	return nil
}

func (l *LsTLVSrPolicyCandidatePathDescriptor) Serialize() ([]byte, error) {
	if !l.Endpoint.IsValid() || !l.OriginatorAddress.IsValid() {
		return nil, malformedAttrListErr("SR Policy Candidate Path Descriptor requires endpoint and originator address")
	}

	// The E and O flags are derived from the address families so that the
	// encoded widths always agree with the flags.
	flags := l.Flags &^ (lsSrPolicyCPDescFlagEndpointV6 | lsSrPolicyCPDescFlagOriginatorV6)
	epLen, origLen := 4, 4
	if l.Endpoint.Unmap().Is6() {
		flags |= lsSrPolicyCPDescFlagEndpointV6
		epLen = 16
	}
	if l.OriginatorAddress.Unmap().Is6() {
		flags |= lsSrPolicyCPDescFlagOriginatorV6
		origLen = 16
	}

	buf := make([]byte, 0, 4+epLen+4+4+origLen+4)
	buf = append(buf, l.ProtocolOrigin, flags, 0, 0)
	buf = append(buf, lsAddrBytes(l.Endpoint, epLen)...)
	buf = binary.BigEndian.AppendUint32(buf, l.Color)
	buf = binary.BigEndian.AppendUint32(buf, l.OriginatorASN)
	buf = append(buf, lsAddrBytes(l.OriginatorAddress, origLen)...)
	buf = binary.BigEndian.AppendUint32(buf, l.Discriminator)

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrPolicyCandidatePathDescriptor) String() string {
	return l.Extract().String()
}

func (l *LsTLVSrPolicyCandidatePathDescriptor) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		*LsSrPolicyCandidatePathDescriptor
	}{
		l.Type,
		l.Extract(),
	})
}

func (l *LsTLVSrPolicyCandidatePathDescriptor) GetLsTLV() LsTLV {
	return l.LsTLV
}

// SR Policy Candidate Path NLRI (type 5), RFC 9857 Section 4

// LsSrPolicyCandidatePathNLRI carries the headend Local Node Descriptors TLV
// (256) and the SR Policy Candidate Path Descriptor TLV (554). TLVs holds
// every received TLV in wire order, unknown and repeated ones included, so
// that they are preserved and propagated (RFC 9552 Section 5.1).
type LsSrPolicyCandidatePathNLRI struct {
	LsNLRI
	LocalNodeDesc     LsTLVInterface
	CandidatePathDesc LsTLVInterface
	TLVs              []LsTLVInterface
}

// String returns a representation that is unique per candidate path: it is
// used as the RIB destination key for BGP-LS routes, so every descriptor
// field and the NLRI header identifiers must be part of it.
func (l *LsSrPolicyCandidatePathNLRI) String() string {
	if l.LocalNodeDesc == nil || l.CandidatePathDesc == nil {
		return "SRPOLICY_CP { EMPTY }"
	}

	local, ok := l.LocalNodeDesc.(*LsTLVNodeDescriptor)
	if !ok {
		return "SRPOLICY_CP { INVALID }"
	}
	cpTLV, ok := l.CandidatePathDesc.(*LsTLVSrPolicyCandidatePathDescriptor)
	if !ok {
		return "SRPOLICY_CP { INVALID }"
	}
	cp := cpTLV.Extract()

	// Preserved unknown and repeated TLVs are part of the key too.
	var unknown strings.Builder
	for _, tlv := range l.TLVs {
		if u, ok := tlv.(*lsTLVUnknown); ok {
			fmt.Fprintf(&unknown, " TLV %d: %x", u.Type, u.Value)
		}
	}

	return fmt.Sprintf("SRPOLICY_CP { LOCAL_NODE: %s ENDPOINT: %s COLOR: %d ORIGIN: %d ORIGINATOR: %d/%s DISCRIMINATOR: %d%s %s:%d }",
		lsSrPolicyHeadendString(local), cp.Endpoint, cp.Color, cp.ProtocolOrigin, cp.OriginatorASN, cp.OriginatorAddress, cp.Discriminator,
		unknown.String(), l.ProtocolID.String(), l.Identifier)
}

// lsSrPolicyHeadendString renders the headend node descriptor sub-TLVs as
// received, in wire order. LsNodeDescriptor.String omits the IGP fields
// when a BGP Router-ID is present, but every sub-TLV is part of this NLRI's
// key and must distinguish destinations in the RIB. Only the sub-TLVs that
// were received are printed, so a descriptor carrying an OSPF area of 0 is
// told apart from one carrying no area at all.
func lsSrPolicyHeadendString(nd *LsTLVNodeDescriptor) string {
	fields := make([]string, 0, len(nd.SubTLVs))
	for _, sub := range nd.SubTLVs {
		switch v := sub.(type) {
		case *LsTLVAutonomousSystem:
			fields = append(fields, fmt.Sprintf("ASN: %d", v.ASN))
		case *LsTLVBgpLsID:
			fields = append(fields, fmt.Sprintf("BGP LS ID: %d", v.BGPLsID))
		case *LsTLVOspfAreaID:
			fields = append(fields, fmt.Sprintf("OSPF AREA: %d", v.AreaID))
		case *LsTLVIgpRouterID:
			id, _ := parseIGPRouterID(v.RouterID)
			fields = append(fields, fmt.Sprintf("IGP ROUTER ID: %s", id))
		case *LsTLVBgpRouterID:
			fields = append(fields, fmt.Sprintf("BGP ROUTER ID: %s", v.RouterID))
		case *LsTLVBgpConfederationMember:
			fields = append(fields, fmt.Sprintf("CONFEDERATION: %d", v.BgpConfederationMember))
		case *LsTLVLocalIPv4RouterID:
			fields = append(fields, fmt.Sprintf("IPv4 ROUTER ID: %s", v.IP))
		case *LsTLVLocalIPv6RouterID:
			fields = append(fields, fmt.Sprintf("IPv6 ROUTER ID: %s", v.IP))
		case *lsTLVUnknown:
			fields = append(fields, fmt.Sprintf("TLV %d: %x", v.Type, v.Value))
		}
	}
	return "{" + strings.Join(fields, ", ") + "}"
}

func (l *LsSrPolicyCandidatePathNLRI) DecodeFromBytes(data []byte) error {
	if err := l.LsNLRI.DecodeFromBytes(data); err != nil {
		return err
	}

	tlvs := data[lsNLRIHdrLen:]

	for len(tlvs) >= tlvHdrLen {
		hdr := &LsTLV{}
		if _, err := hdr.DecodeFromBytes(tlvs); err != nil {
			return err
		}

		var tlv LsTLVInterface
		switch hdr.Type {
		case LS_TLV_LOCAL_NODE_DESC:
			if l.LocalNodeDesc == nil {
				nd := &LsTLVNodeDescriptor{}
				if err := nd.decodeFromBytes(tlvs, true); err != nil {
					return err
				}
				l.LocalNodeDesc = nd
				l.TLVs = append(l.TLVs, nd)
				tlvs = tlvs[hdr.Len():]
				continue
			}
		case LS_TLV_SR_POLICY_CP_DESC:
			if l.CandidatePathDesc == nil {
				tlv = &LsTLVSrPolicyCandidatePathDescriptor{}
			}
		}

		// The first instance of a TLV is used (RFC 9857). Unknown TLVs and
		// repeated instances are kept as opaque TLVs so that they are
		// preserved and propagated (RFC 9552 Section 5.1).
		if tlv == nil {
			tlv = &lsTLVUnknown{}
		}

		if err := tlv.DecodeFromBytes(tlvs); err != nil {
			return err
		}
		l.TLVs = append(l.TLVs, tlv)
		tlvs = tlvs[tlv.Len():]

		if hdr.Type == LS_TLV_SR_POLICY_CP_DESC && l.CandidatePathDesc == nil {
			l.CandidatePathDesc = tlv
		}
	}

	if l.LocalNodeDesc == nil || l.CandidatePathDesc == nil {
		return malformedAttrListErr("Required TLV missing")
	}

	return nil
}

func (l *LsSrPolicyCandidatePathNLRI) Serialize() ([]byte, error) {
	if l.LocalNodeDesc == nil || l.CandidatePathDesc == nil {
		return nil, errors.New("required TLV missing")
	}

	// A hand-constructed NLRI carries only the descriptor fields; a decoded
	// one serializes every received TLV in wire order.
	tlvs := l.TLVs
	if len(tlvs) == 0 {
		tlvs = []LsTLVInterface{l.LocalNodeDesc, l.CandidatePathDesc}
	}

	buf := make([]byte, 0)
	for _, tlv := range tlvs {
		s, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, s...)
	}

	return l.LsNLRI.Serialize(buf)
}

func (l *LsSrPolicyCandidatePathNLRI) MarshalJSON() ([]byte, error) {
	local, err := extractLsNodeDesc(l.LocalNodeDesc, "local")
	if err != nil {
		return nil, err
	}
	cpTLV, ok := l.CandidatePathDesc.(*LsTLVSrPolicyCandidatePathDescriptor)
	if !ok {
		return nil, fmt.Errorf("invalid SR Policy candidate path descriptor type %T", l.CandidatePathDesc)
	}

	return json.Marshal(struct {
		Type          LsNLRIType                        `json:"type"`
		LocalNode     LsNodeDescriptor                  `json:"local_node_desc"`
		CandidatePath LsSrPolicyCandidatePathDescriptor `json:"candidate_path_desc"`
	}{
		Type:          l.Type(),
		LocalNode:     *local,
		CandidatePath: *cpTLV.Extract(),
	})
}
