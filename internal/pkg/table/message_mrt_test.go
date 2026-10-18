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

package table

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/mrt"
)

// The benchmarks in this file pack the routes of a real BGP table. The
// input is UPDATEs in MRT BGP4MP records, made from an MRT RIB dump by
// tools/mrt-updates. They are skipped when the input is not given:
//
//	go run ./tools/mrt-updates -o v4.updates rib
//	go run ./tools/mrt-updates -family ipv6 -o v6.updates rib6
//	GOBGP_BENCH_MRT_V4=$PWD/v4.updates GOBGP_BENCH_MRT_V6=$PWD/v6.updates \
//	    go test -run '^$' -bench MRT ./internal/pkg/table

// loadMRTPaths reads the UPDATEs in the MRT file and returns the paths that
// ProcessMessage makes from them.
func loadMRTPaths(b *testing.B, name string) []*Path {
	f, err := os.Open(name)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	r := bufio.NewReader(f)
	peers := make(map[netip.Addr]*PeerInfo)
	var paths []*Path
	hbuf := make([]byte, mrt.MRT_COMMON_HEADER_LEN)
	for {
		if _, err := io.ReadFull(r, hbuf); err != nil {
			if err == io.EOF {
				break
			}
			b.Fatal(err)
		}
		h, err := mrt.ParseHeader(hbuf)
		if err != nil {
			b.Fatal(err)
		}
		body := make([]byte, h.Len)
		if _, err := io.ReadFull(r, body); err != nil {
			b.Fatal(err)
		}
		msg, err := mrt.ParseBody(body, h)
		if err != nil {
			b.Fatal(err)
		}
		m, ok := msg.Body.(*mrt.BGP4MPMessage)
		if !ok {
			b.Fatalf("%s: not a BGP4MP message: %v", name, msg.Header)
		}
		peer, ok := peers[m.PeerIpAddress]
		if !ok {
			peer = &PeerInfo{
				PeerType: oc.PEER_TYPE_EXTERNAL,
				AS:       m.PeerAS,
				LocalAS:  65000,
				ID:       netip.MustParseAddr("192.0.2.1"),
				LocalID:  netip.MustParseAddr("192.0.2.254"),
				Address:  m.PeerIpAddress,
			}
			peers[m.PeerIpAddress] = peer
		}
		for _, p := range ProcessMessage(m.BGPMessage, peer, h.GetTime(), false) {
			if !p.GetNexthop().IsValid() {
				b.Fatalf("%s: %s has no next hop", name, p.GetNlri())
			}
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		b.Fatalf("%s: no paths", name)
	}
	return paths
}

// BenchmarkCreateUpdateMsgFromPathsMRT packs the paths of a real table for
// one peer of each kind. What UpdatePathAttrs does to a path decides how
// much the packer has to compare:
//
//   - rs: a route server client gets the paths as they are, so the paths of
//     one received UPDATE share all their attribute objects.
//   - ibgp: each path gets a new LOCAL_PREF.
//   - rr: each path gets a new LOCAL_PREF, ORIGINATOR_ID and CLUSTER_LIST.
//   - ebgp: each path gets a new AS_PATH and loses MED.
func BenchmarkCreateUpdateMsgFromPathsMRT(b *testing.B) {
	files := []struct {
		name, env string
		local     netip.Addr
	}{
		{"v4", "GOBGP_BENCH_MRT_V4", netip.MustParseAddr("192.0.2.254")},
		{"v6", "GOBGP_BENCH_MRT_V6", netip.MustParseAddr("2001:db8::254")},
	}
	peers := []struct {
		name string
		info func(local netip.Addr) *PeerInfo
	}{
		{"rs", func(local netip.Addr) *PeerInfo {
			return &PeerInfo{RouteServerClient: true}
		}},
		{"ibgp", func(local netip.Addr) *PeerInfo {
			return &PeerInfo{PeerType: oc.PEER_TYPE_INTERNAL, AS: 65000, LocalAS: 65000, LocalAddress: local}
		}},
		{"rr", func(local netip.Addr) *PeerInfo {
			return &PeerInfo{
				PeerType: oc.PEER_TYPE_INTERNAL, AS: 65000, LocalAS: 65000, LocalAddress: local,
				RouteReflectorClient:    true,
				RouteReflectorClusterID: netip.MustParseAddr("192.0.2.254"),
			}
		}},
		{"ebgp", func(local netip.Addr) *PeerInfo {
			return &PeerInfo{PeerType: oc.PEER_TYPE_EXTERNAL, AS: 65100, LocalAS: 65000, LocalAddress: local}
		}},
	}
	global := &oc.Global{Config: oc.GlobalConfig{As: 65000, RouterId: netip.MustParseAddr("192.0.2.254")}}

	// Each file is read once. mixed is v4 followed by v6, as for a peer
	// with both families.
	type input struct {
		name  string
		paths [][]*Path
		local []netip.Addr
	}
	var inputs []input
	var mixed input
	for _, f := range files {
		name := os.Getenv(f.env)
		if name == "" {
			continue
		}
		paths := loadMRTPaths(b, name)
		inputs = append(inputs, input{name: f.name, paths: [][]*Path{paths}, local: []netip.Addr{f.local}})
		mixed.paths = append(mixed.paths, paths)
		mixed.local = append(mixed.local, f.local)
	}
	if len(inputs) == 0 {
		b.Skip("GOBGP_BENCH_MRT_V4 and GOBGP_BENCH_MRT_V6 are not set")
	}
	if len(inputs) == 2 {
		mixed.name = "mixed"
		inputs = append(inputs, mixed)
	}

	for _, in := range inputs {
		for _, peer := range peers {
			b.Run(in.name+"/"+peer.name, func(b *testing.B) {
				// The paths for a peer are made for each run, the
				// way they are made for each peer that gets them.
				// A path that was packed once can keep state, such
				// as the attribute hash, that makes the next run
				// faster.
				clone := func() []*Path {
					var paths []*Path
					for i, ps := range in.paths {
						info := peer.info(in.local[i])
						for _, p := range ps {
							paths = append(paths, UpdatePathAttrs(logger, global, info, p))
						}
					}
					return paths
				}
				var n int
				b.ReportAllocs()
				for b.Loop() {
					b.StopTimer()
					paths := clone()
					n = len(paths)
					b.StartTimer()
					CreateUpdateMsgFromPaths(paths)
				}
				b.ReportMetric(float64(n), "paths")
			})
		}
	}
}
