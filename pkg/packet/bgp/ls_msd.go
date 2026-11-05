package bgp

import (
	"encoding/json"
	"fmt"
)

// LsMSDEntry is one Maximum SID Depth type/value pair from RFC 8814.
// Unknown types, repeated types, and zero values are retained unchanged.
type LsMSDEntry struct {
	Type  uint8 `json:"type"`
	Value uint8 `json:"value"`
}

// decodeLsMSD validates and decodes one MSD TLV without aliasing its wire input.
func decodeLsMSD(data []byte, typ LsTLVType) (LsTLV, []LsMSDEntry, error) {
	var header LsTLV
	value, err := header.DecodeFromBytes(data)
	if err != nil {
		return LsTLV{}, nil, err
	}
	if header.Type != typ {
		return LsTLV{}, nil, malformedAttrListErr("Unexpected MSD TLV type")
	}
	if len(value) == 0 || len(value)%2 != 0 {
		return LsTLV{}, nil, malformedAttrListErr("Incorrect MSD TLV length")
	}
	entries := make([]LsMSDEntry, len(value)/2)
	for index := range entries {
		entries[index] = LsMSDEntry{Type: value[2*index], Value: value[2*index+1]}
	}
	return header, entries, nil
}

func serializeLsMSD(header LsTLV, typ LsTLVType, entries []LsMSDEntry) ([]byte, error) {
	// An MSD TLV has one or more two-octet entries and a 16-bit length.
	if header.Type != typ || len(entries) == 0 || len(entries) > 65535/2 || int(header.Length) != 2*len(entries) {
		return nil, malformedAttrListErr("Incorrect MSD TLV length or type")
	}
	value := make([]byte, 2*len(entries))
	for index, entry := range entries {
		value[2*index], value[2*index+1] = entry.Type, entry.Value
	}
	return header.Serialize(value)
}

// LsTLVNodeMSD is the Node MSD TLV defined by RFC 8814.
// Entries preserve wire order and every type/value pair.
type LsTLVNodeMSD struct {
	LsTLV
	Entries []LsMSDEntry
}

// NewLsTLVNodeMSD constructs a Node MSD TLV using entries without copying.
// Serialize rejects an empty list or more than 32767 entries.
func NewLsTLVNodeMSD(entries []LsMSDEntry) *LsTLVNodeMSD {
	return &LsTLVNodeMSD{
		LsTLV:   LsTLV{Type: LS_TLV_NODE_MSD, Length: uint16(2 * len(entries))},
		Entries: entries,
	}
}

// DecodeFromBytes implements [LsTLVInterface]. It replaces the receiver only
// after successful decoding, and the decoded entries do not alias data.
func (l *LsTLVNodeMSD) DecodeFromBytes(data []byte) error {
	header, entries, err := decodeLsMSD(data, LS_TLV_NODE_MSD)
	if err != nil {
		return err
	}
	l.LsTLV, l.Entries = header, entries
	return nil
}

// Serialize implements [LsTLVInterface].
func (l *LsTLVNodeMSD) Serialize() ([]byte, error) {
	return serializeLsMSD(l.LsTLV, LS_TLV_NODE_MSD, l.Entries)
}

// GetLsTLV implements [LsTLVInterface].
func (l *LsTLVNodeMSD) GetLsTLV() LsTLV { return l.LsTLV }

// String implements [LsTLVInterface].
func (l *LsTLVNodeMSD) String() string {
	return fmt.Sprintf("{Node MSD: %v}", l.Entries)
}

// MarshalJSON implements [LsTLVInterface].
func (l *LsTLVNodeMSD) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type    LsTLVType    `json:"type"`
		Entries []LsMSDEntry `json:"entries"`
	}{Type: l.Type, Entries: l.Entries})
}

// LsTLVLinkMSD is the Link MSD TLV defined by RFC 8814.
// Entries preserve wire order and every type/value pair.
type LsTLVLinkMSD struct {
	LsTLV
	Entries []LsMSDEntry
}

// NewLsTLVLinkMSD constructs a Link MSD TLV using entries without copying.
// Serialize rejects an empty list or more than 32767 entries.
func NewLsTLVLinkMSD(entries []LsMSDEntry) *LsTLVLinkMSD {
	return &LsTLVLinkMSD{
		LsTLV:   LsTLV{Type: LS_TLV_LINK_MSD, Length: uint16(2 * len(entries))},
		Entries: entries,
	}
}

// DecodeFromBytes implements [LsTLVInterface]. It replaces the receiver only
// after successful decoding, and the decoded entries do not alias data.
func (l *LsTLVLinkMSD) DecodeFromBytes(data []byte) error {
	header, entries, err := decodeLsMSD(data, LS_TLV_LINK_MSD)
	if err != nil {
		return err
	}
	l.LsTLV, l.Entries = header, entries
	return nil
}

// Serialize implements [LsTLVInterface].
func (l *LsTLVLinkMSD) Serialize() ([]byte, error) {
	return serializeLsMSD(l.LsTLV, LS_TLV_LINK_MSD, l.Entries)
}

// GetLsTLV implements [LsTLVInterface].
func (l *LsTLVLinkMSD) GetLsTLV() LsTLV { return l.LsTLV }

// String implements [LsTLVInterface].
func (l *LsTLVLinkMSD) String() string {
	return fmt.Sprintf("{Link MSD: %v}", l.Entries)
}

// MarshalJSON implements [LsTLVInterface].
func (l *LsTLVLinkMSD) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type    LsTLVType    `json:"type"`
		Entries []LsMSDEntry `json:"entries"`
	}{Type: l.Type, Entries: l.Entries})
}
