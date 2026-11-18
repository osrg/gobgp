package table

import (
	"encoding/binary"
	"log/slog"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// TestMemoryFootprint builds the Adj-RIB-In of several peers and the
// Loc-RIB over them, as the server does for a full table, and reports the
// live heap objects and bytes that each path adds. It measures, it does not
// check, so it runs only when GOBGP_MEM_FOOTPRINT is set. The size can be
// changed with GOBGP_MEM_PREFIXES and GOBGP_MEM_PEERS.
func TestMemoryFootprint(t *testing.T) {
	if os.Getenv("GOBGP_MEM_FOOTPRINT") == "" {
		t.Skip("set GOBGP_MEM_FOOTPRINT to measure the memory footprint")
	}
	prefixes := footprintEnvInt(t, "GOBGP_MEM_PREFIXES", 200000)
	peers := footprintEnvInt(t, "GOBGP_MEM_PEERS", 3)
	log := slog.New(slog.DiscardHandler)
	families := []bgp.Family{bgp.RF_IPv4_UC}

	var before, after runtime.MemStats
	footprintGC()
	runtime.ReadMemStats(&before)

	loc := NewTable(log, bgp.RF_IPv4_UC)
	adjs := make([]*AdjRib, peers)
	now := time.Now()
	for i := range peers {
		addr := netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
		src := &PeerInfo{AS: 65000, LocalAS: 65000, ID: addr, Address: addr}
		nh, err := bgp.NewPathAttributeNextHop(addr)
		if err != nil {
			t.Fatal(err)
		}
		// The paths of one UPDATE share the attributes. A peer sends a
		// full table in many UPDATEs, so every 16 prefixes get their own.
		var attrs []bgp.PathAttributeInterface
		adjs[i] = NewAdjRib(log, families)
		batch := make([]*Path, 0, 16)
		for j := range prefixes {
			if j%16 == 0 {
				attrs = []bgp.PathAttributeInterface{
					bgp.NewPathAttributeOrigin(0),
					nh,
					bgp.NewPathAttributeLocalPref(100),
				}
			}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(j)<<8|1<<31)
			nlri, err := bgp.NewIPAddrPrefix(netip.PrefixFrom(netip.AddrFrom4(b), 24))
			if err != nil {
				t.Fatal(err)
			}
			p := NewPath(bgp.RF_IPv4_UC, src, bgp.PathNLRI{NLRI: nlri}, false, attrs, now, false)
			batch = append(batch, p)
			if len(batch) == cap(batch) || j == prefixes-1 {
				adjs[i].Update(batch)
				for _, p := range batch {
					loc.update(p, oc.RouteSelectionOptionsConfig{})
				}
				batch = batch[:0]
			}
		}
	}

	footprintGC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(loc)
	runtime.KeepAlive(adjs)

	paths := float64(prefixes * peers)
	objects := float64(after.HeapObjects) - float64(before.HeapObjects)
	bytes := float64(after.HeapAlloc) - float64(before.HeapAlloc)
	t.Logf("prefixes=%d peers=%d paths=%d", prefixes, peers, prefixes*peers)
	t.Logf("HeapObjects before=%d after=%d delta=%.0f per_path=%.2f", before.HeapObjects, after.HeapObjects, objects, objects/paths)
	t.Logf("HeapAlloc before=%d after=%d delta=%.0f per_path=%.1f", before.HeapAlloc, after.HeapAlloc, bytes, bytes/paths)
}

func footprintEnvInt(t *testing.T, name string, def int) int {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		t.Fatalf("%s=%q is not a positive integer", name, v)
	}
	return n
}

func footprintGC() {
	runtime.GC()
	runtime.GC()
}
