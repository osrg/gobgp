// Copyright (C) 2026 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// mrt-updates reads an MRT TABLE_DUMP_V2 RIB dump, takes the routes of one
// peer and writes them as BGP UPDATE messages in MRT BGP4MP_MESSAGE_AS4
// records. Routes with the same path attributes go in the same UPDATEs, the
// way a BGP speaker sends them, so the output can be fed to
// table.ProcessMessage to get paths that look like the ones received from
// that peer. It is used by the UPDATE packer benchmarks in
// internal/pkg/table.
//
// Usage:
//
//	go run ./tools/mrt-updates [-family ipv4|ipv6] [-peer index] -o out rib
//
// By default the peer with the most routes of the family is used.
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/mrt"
)

// readRecords calls fn for each MRT record of the file.
func readRecords(name string, fn func(h *mrt.MRTHeader, body []byte) error) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	hbuf := make([]byte, mrt.MRT_COMMON_HEADER_LEN)
	for {
		if _, err := io.ReadFull(r, hbuf); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		h, err := mrt.ParseHeader(hbuf)
		if err != nil {
			return err
		}
		body := make([]byte, h.Len)
		if _, err := io.ReadFull(r, body); err != nil {
			return err
		}
		if err := fn(h, body); err != nil {
			return err
		}
	}
}

// ribEntry is one RIB entry of a RIB record, not decoded.
type ribEntry struct {
	peerIndex uint16
	attrs     []byte
}

// walkRib parses the prefix and the entry headers of a RIB record without
// decoding the path attributes (RFC 6396 4.3.2).
func walkRib(body []byte, is6 bool, fn func(netip.Prefix, ribEntry)) error {
	errShort := errors.New("RIB record too short")
	if len(body) < 5 {
		return errShort
	}
	plen := int(body[4])
	body = body[5:]
	n := (plen + 7) / 8
	if len(body) < n+2 {
		return errShort
	}
	var prefix netip.Prefix
	if is6 {
		var a [16]byte
		copy(a[:], body[:n])
		prefix = netip.PrefixFrom(netip.AddrFrom16(a), plen)
	} else {
		var a [4]byte
		copy(a[:], body[:n])
		prefix = netip.PrefixFrom(netip.AddrFrom4(a), plen)
	}
	if !prefix.IsValid() {
		return fmt.Errorf("invalid prefix length %d", plen)
	}
	body = body[n:]
	count := binary.BigEndian.Uint16(body)
	body = body[2:]
	for range count {
		if len(body) < 8 {
			return errShort
		}
		e := ribEntry{peerIndex: binary.BigEndian.Uint16(body)}
		l := int(binary.BigEndian.Uint16(body[6:]))
		body = body[8:]
		if len(body) < l {
			return errShort
		}
		e.attrs = body[:l]
		body = body[l:]
		fn(prefix, e)
	}
	return nil
}

// shortMpReach rewrites MP_REACH_NLRI in attrs to the short form that RFC
// 6396 4.3.4 defines:
//
//	Since the AFI, SAFI, and NLRI information is already encoded in the
//	RIB Entry Header or RIB_GENERIC Entry Header, only the Next Hop
//	Address Length and Next Hop Address fields are included.
//
// Some collectors (RouteViews among them) write the full attribute with
// AFI, SAFI and the NLRI of the entry. Then the attribute bytes differ for
// every prefix, and the MRT decoder, which expects the short form, reads a
// wrong next hop. The full form starts with the AFI, whose first octet is
// 0. The first octet of the short form is the Next Hop Address Length,
// which is not 0.
func shortMpReach(attrs []byte) ([]byte, error) {
	errShort := errors.New("path attribute too short")
	out := attrs
	for rest, off := attrs, 0; len(rest) > 0; {
		if len(rest) < 3 {
			return nil, errShort
		}
		flags, typ := bgp.BGPAttrFlag(rest[0]), bgp.BGPAttrType(rest[1])
		hl, l := 3, int(rest[2])
		if flags&bgp.BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
			if len(rest) < 4 {
				return nil, errShort
			}
			hl, l = 4, int(binary.BigEndian.Uint16(rest[2:]))
		}
		if len(rest) < hl+l {
			return nil, errShort
		}
		value := rest[hl : hl+l]
		if typ == bgp.BGP_ATTR_TYPE_MP_REACH_NLRI && l > 0 && value[0] == 0 {
			// AFI(2), SAFI(1), Next Hop Length(1), Next Hop.
			if l < 4 || l < 4+int(value[3]) {
				return nil, errShort
			}
			nh := value[3 : 4+int(value[3])]
			out = make([]byte, 0, len(attrs))
			out = append(out, attrs[:off]...)
			out = append(out, byte(flags&^bgp.BGP_ATTR_FLAG_EXTENDED_LENGTH), byte(typ), byte(len(nh)))
			out = append(out, nh...)
			out = append(out, rest[hl+l:]...)
			return out, nil
		}
		off += hl + l
		rest = rest[hl+l:]
	}
	return out, nil
}

// group is the routes that share the same path attribute bytes, in the
// order of the dump.
type group struct {
	attrs    []byte
	prefixes []netip.Prefix
}

// decodeAttrs decodes the path attributes of a RIB entry. It builds a RIB
// record with that one entry and gives it to mrt.ParseBody, which knows the
// short MP_REACH_NLRI form of RFC 6396 4.3.4.
func decodeAttrs(subtype mrt.MRTSubTypeTableDumpv2, prefix netip.Prefix, attrs []byte) ([]bgp.PathAttributeInterface, error) {
	n := (prefix.Bits() + 7) / 8
	body := make([]byte, 0, 4+1+n+2+8+len(attrs))
	body = append(body, 0, 0, 0, 0, byte(prefix.Bits()))
	body = append(body, prefix.Addr().AsSlice()[:n]...)
	body = binary.BigEndian.AppendUint16(body, 1)
	body = append(body, 0, 0, 0, 0, 0, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(attrs)))
	body = append(body, attrs...)
	h := &mrt.MRTHeader{Type: mrt.TABLE_DUMPv2, SubType: uint16(subtype), Len: uint32(len(body))}
	msg, err := mrt.ParseBody(body, h)
	if err != nil {
		return nil, err
	}
	return msg.Body.(*mrt.Rib).Entries[0].PathAttributes, nil
}

func nlriLen(p netip.Prefix) int {
	return 1 + (p.Bits()+7)/8
}

// buildUpdates puts the prefixes of g in as few UPDATEs as fit in 4096
// bytes. IPv4 routes use the NLRI field, IPv6 routes MP_REACH_NLRI.
func buildUpdates(family bgp.Family, attrs []bgp.PathAttributeInterface, prefixes []netip.Prefix) ([]*bgp.BGPMessage, error) {
	const maxLen = bgp.BGP_MAX_MESSAGE_LENGTH
	// BGP header, Withdrawn Routes Length, Total Path Attribute Length.
	base := bgp.BGP_HEADER_LENGTH + 2 + 2
	reachPos := -1
	var reach *bgp.PathAttributeMpReachNLRI
	for i, a := range attrs {
		if r, ok := a.(*bgp.PathAttributeMpReachNLRI); ok {
			reachPos, reach = i, r
			continue
		}
		b, err := a.Serialize()
		if err != nil {
			return nil, err
		}
		base += len(b)
	}
	if family == bgp.RF_IPv6_UC {
		if reach == nil {
			return nil, errors.New("IPv6 route without MP_REACH_NLRI")
		}
		// Attribute header with the extended length, AFI, SAFI, Next
		// Hop Length, Next Hop, Reserved.
		nhLen := 16
		if reach.LinkLocalNexthop.IsValid() {
			nhLen = 32
		}
		base += 4 + 2 + 1 + 1 + nhLen + 1
	}

	var msgs []*bgp.BGPMessage
	for len(prefixes) > 0 {
		size, n := base, 0
		for n < len(prefixes) && (n == 0 || size+nlriLen(prefixes[n]) <= maxLen) {
			size += nlriLen(prefixes[n])
			n++
		}
		nlris := make([]bgp.PathNLRI, 0, n)
		for _, p := range prefixes[:n] {
			nlri, err := bgp.NewIPAddrPrefix(p)
			if err != nil {
				return nil, err
			}
			nlris = append(nlris, bgp.PathNLRI{NLRI: nlri})
		}
		prefixes = prefixes[n:]

		var msg *bgp.BGPMessage
		if family == bgp.RF_IPv4_UC {
			msg = bgp.NewBGPUpdateMessage(nil, attrs, nlris)
		} else {
			nexthops := []netip.Addr{reach.Nexthop}
			if reach.LinkLocalNexthop.IsValid() {
				nexthops = append(nexthops, reach.LinkLocalNexthop)
			}
			r, err := bgp.NewPathAttributeMpReachNLRI(family, nlris, nexthops...)
			if err != nil {
				return nil, err
			}
			a := append([]bgp.PathAttributeInterface(nil), attrs...)
			a[reachPos] = r
			msg = bgp.NewBGPUpdateMessage(nil, a, nil)
		}
		msgs = append(msgs, msg)
	}
	return msgs, nil
}

func main() {
	familyName := flag.String("family", "ipv4", "address family to take: ipv4 or ipv6")
	peerIndex := flag.Int("peer", -1, "peer index in the PEER_INDEX_TABLE (default: the peer with the most routes)")
	out := flag.String("o", "", "output file")
	flag.Parse()
	if flag.NArg() != 1 || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: mrt-updates [-family ipv4|ipv6] [-peer index] -o out rib")
		os.Exit(2)
	}
	in := flag.Arg(0)

	var family bgp.Family
	var subtype mrt.MRTSubTypeTableDumpv2
	switch *familyName {
	case "ipv4":
		family, subtype = bgp.RF_IPv4_UC, mrt.RIB_IPV4_UNICAST
	case "ipv6":
		family, subtype = bgp.RF_IPv6_UC, mrt.RIB_IPV6_UNICAST
	default:
		log.Fatalf("unknown family %q", *familyName)
	}
	is6 := family == bgp.RF_IPv6_UC
	isRib := func(h *mrt.MRTHeader) bool {
		return h.Type == mrt.TABLE_DUMPv2 && mrt.MRTSubTypeTableDumpv2(h.SubType) == subtype
	}

	// Pass 1: the peer table and the number of routes per peer.
	var peers []*mrt.Peer
	var timestamp time.Time
	counts := make(map[uint16]int)
	err := readRecords(in, func(h *mrt.MRTHeader, body []byte) error {
		if h.Type == mrt.TABLE_DUMPv2 && mrt.MRTSubTypeTableDumpv2(h.SubType) == mrt.PEER_INDEX_TABLE {
			msg, err := mrt.ParseBody(body, h)
			if err != nil {
				return err
			}
			peers = msg.Body.(*mrt.PeerIndexTable).Peers
			timestamp = h.GetTime()
			return nil
		}
		if !isRib(h) {
			return nil
		}
		return walkRib(body, is6, func(_ netip.Prefix, e ribEntry) {
			counts[e.peerIndex]++
		})
	})
	if err != nil {
		log.Fatal(err)
	}
	if peers == nil {
		log.Fatal("no PEER_INDEX_TABLE")
	}
	indexes := make([]uint16, 0, len(counts))
	for i := range counts {
		indexes = append(indexes, i)
	}
	sort.Slice(indexes, func(a, b int) bool { return counts[indexes[a]] > counts[indexes[b]] })
	for _, i := range indexes[:min(len(indexes), 5)] {
		log.Printf("peer %d AS%d %s: %d routes", i, peers[i].AS, peers[i].IpAddress, counts[i])
	}
	selected := uint16(*peerIndex)
	if *peerIndex < 0 {
		if len(indexes) == 0 {
			log.Fatalf("no %s routes", *familyName)
		}
		selected = indexes[0]
	}
	if int(selected) >= len(peers) {
		log.Fatalf("peer index %d out of range", selected)
	}
	peer := peers[selected]
	log.Printf("using peer %d AS%d %s", selected, peer.AS, peer.IpAddress)

	// Pass 2: group the routes of the peer by their attribute bytes.
	groups := make(map[string]*group)
	var order []*group
	err = readRecords(in, func(h *mrt.MRTHeader, body []byte) error {
		if !isRib(h) {
			return nil
		}
		var errEntry error
		err := walkRib(body, is6, func(p netip.Prefix, e ribEntry) {
			if e.peerIndex != selected || errEntry != nil {
				return
			}
			attrs, err := shortMpReach(e.attrs)
			if err != nil {
				errEntry = fmt.Errorf("%s: %w", p, err)
				return
			}
			g, ok := groups[string(attrs)]
			if !ok {
				g = &group{attrs: attrs}
				groups[string(attrs)] = g
				order = append(order, g)
			}
			g.prefixes = append(g.prefixes, p)
		})
		if err != nil {
			return err
		}
		return errEntry
	})
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	localIP := netip.IPv4Unspecified()
	if peer.IpAddress.Is6() {
		localIP = netip.IPv6Unspecified()
	}
	routes, updates, skipped := 0, 0, 0
	sizes := make(map[string]int)
	for _, g := range order {
		attrs, err := decodeAttrs(subtype, g.prefixes[0], g.attrs)
		if err != nil {
			log.Printf("skip %d routes from %s: %v", len(g.prefixes), g.prefixes[0], err)
			skipped += len(g.prefixes)
			continue
		}
		msgs, err := buildUpdates(family, attrs, g.prefixes)
		if err != nil {
			log.Printf("skip %d routes from %s: %v", len(g.prefixes), g.prefixes[0], err)
			skipped += len(g.prefixes)
			continue
		}
		for _, msg := range msgs {
			body, err := mrt.NewBGP4MPMessage(peer.AS, 0, 0, peer.IpAddress, localIP, true, msg)
			if err != nil {
				log.Fatal(err)
			}
			m, err := mrt.NewMRTMessage(timestamp, mrt.BGP4MP, mrt.MESSAGE_AS4, body)
			if err != nil {
				log.Fatal(err)
			}
			b, err := m.Serialize()
			if err != nil {
				log.Fatalf("routes from %s: %v", g.prefixes[0], err)
			}
			if _, err := w.Write(b); err != nil {
				log.Fatal(err)
			}
		}
		routes += len(g.prefixes)
		updates += len(msgs)
		switch n := len(g.prefixes); {
		case n == 1:
			sizes["1"]++
		case n <= 10:
			sizes["2-10"]++
		case n <= 100:
			sizes["11-100"]++
		case n <= 1000:
			sizes["101-1000"]++
		default:
			sizes[">1000"]++
		}
	}
	if err := w.Flush(); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	maxGroup := 0
	for _, g := range order {
		maxGroup = max(maxGroup, len(g.prefixes))
	}
	log.Printf("%d routes in %d UPDATEs, %d attribute groups (largest %d), %d routes skipped",
		routes, updates, len(order), maxGroup, skipped)
	log.Printf("routes per group: 1: %d, 2-10: %d, 11-100: %d, 101-1000: %d, >1000: %d",
		sizes["1"], sizes["2-10"], sizes["11-100"], sizes["101-1000"], sizes[">1000"])
}
