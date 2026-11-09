// Copyright (C) 2026 Pau Nadeu.
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

package server

import (
	"context"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

type indexPathOption func(*apiutil.Path)

func withSource(as uint32, id string) indexPathOption {
	return func(p *apiutil.Path) {
		p.PeerASN = as
		p.PeerID = netip.MustParseAddr(id)
	}
}

func noImplicitWithdraw(p *apiutil.Path) { p.NoImplicitWithdraw = true }

func withdrawal(p *apiutil.Path) { p.Withdrawal = true }

func withPathID(id uint32) indexPathOption {
	return func(p *apiutil.Path) { p.RemoteID = id }
}

func withLabel(label uint32) indexPathOption {
	return func(p *apiutil.Path) {
		lu := p.Nlri.(*bgp.LabeledIPAddrPrefix)
		nlri, err := bgp.NewLabeledIPAddrPrefix(lu.Prefix, *bgp.NewMPLSLabelStack(label))
		if err != nil {
			panic(err)
		}
		p.Nlri = nlri
	}
}

func indexPath(t testing.TB, family bgp.Family, prefix, nexthop string, opts ...indexPathOption) *apiutil.Path {
	t.Helper()
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
	require.NoError(t, err)
	var nlri bgp.NLRI
	switch family {
	case bgp.RF_IPv4_UC:
		nlri, err = bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	case bgp.RF_IPv4_MPLS:
		nlri, err = bgp.NewLabeledIPAddrPrefix(netip.MustParsePrefix(prefix), *bgp.NewMPLSLabelStack(100))
	default:
		t.Fatalf("unsupported family %s", family)
	}
	require.NoError(t, err)
	p := &apiutil.Path{
		Family: family,
		Nlri:   nlri,
		Attrs:  []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func addIndexed(t testing.TB, s *BgpServer, vrf string, p *apiutil.Path) uuid.UUID {
	t.Helper()
	r, err := s.AddPath(apiutil.AddPathRequest{VRFID: vrf, Paths: []*apiutil.Path{p}})
	require.NoError(t, err)
	return r[0].UUID
}

func deleteUUID(s *BgpServer, id uuid.UUID) error {
	return s.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{id}})
}

// localPaths lists the local paths of a family of the global table as
// "<prefix> <next hop>".
func localPaths(t testing.TB, s *BgpServer, family bgp.Family) []string {
	t.Helper()
	var out []string
	require.NoError(t, s.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: family},
		func(prefix bgp.NLRI, paths []*apiutil.Path) {
			for _, p := range paths {
				nh := ""
				for _, a := range p.Attrs {
					switch a := a.(type) {
					case *bgp.PathAttributeNextHop:
						nh = a.Value.String()
					case *bgp.PathAttributeMpReachNLRI:
						nh = a.Nexthop.String()
					}
				}
				out = append(out, prefix.String()+" "+nh)
			}
		}))
	return out
}

const cannotFind = "can't find a specified path(s) with the given UUID(s)"

// Regression: unicast and labeled unicast for one prefix used to share an
// entry. After the second AddPath the first UUID failed, and the surviving
// one deleted the local paths of both families. Each UUID now names its own
// path.
func TestUUIDIsPerFamily(t *testing.T) {
	s := startContextServer(t)
	uc := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.1.0.0/24", "10.0.0.1"))
	lu := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_MPLS, "10.1.0.0/24", "10.0.0.1"))
	require.NotEqual(t, uc, lu)
	require.Equal(t, 2, s.pathIndex.len())

	require.NoError(t, deleteUUID(s, uc))
	require.Empty(t, localPaths(t, s, bgp.RF_IPv4_UC))
	require.Equal(t, []string{"10.1.0.0/24 10.0.0.1"}, localPaths(t, s, bgp.RF_IPv4_MPLS), "the labeled path stays")
	require.EqualError(t, deleteUUID(s, uc), cannotFind)
	require.NoError(t, deleteUUID(s, lu))
	require.Empty(t, localPaths(t, s, bgp.RF_IPv4_MPLS))
	require.Zero(t, s.pathIndex.len())
}

// Regression: a delete of all local paths of one family used to clear every
// UUID, so the paths of other families could no longer be deleted by UUID.
func TestDeleteAllOfOneFamilyKeepsOtherUUIDs(t *testing.T) {
	s := startContextServer(t)
	uc := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.2.0.0/24", "10.0.0.1"))
	lu := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_MPLS, "10.2.1.0/24", "10.0.0.1"))
	family := bgp.RF_IPv4_MPLS
	require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{DeleteAll: true, DeleteFamily: &family}))
	require.Empty(t, localPaths(t, s, bgp.RF_IPv4_MPLS))
	require.EqualError(t, deleteUUID(s, lu), cannotFind)
	require.NoError(t, deleteUUID(s, uc), "the unicast UUID still deletes its path")
	require.Empty(t, localPaths(t, s, bgp.RF_IPv4_UC))
}

// A UUID ends when another write takes its slot or empties it, and then
// deletes nothing, whatever is in the slot now.
func TestUUIDEndsWhenItsPathIsReplaced(t *testing.T) {
	s := startContextServer(t)
	ctx := context.Background()

	// Replaced by another AddPath.
	old := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.3.0.0/24", "10.0.0.1"))
	cur := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.3.0.0/24", "10.0.0.2"))
	require.EqualError(t, deleteUUID(s, old), cannotFind)
	require.Equal(t, []string{"10.3.0.0/24 10.0.0.2"}, localPaths(t, s, bgp.RF_IPv4_UC))
	require.NoError(t, deleteUUID(s, cur))

	// Replaced by AddPathStream, the path a zebra route takes as well: the
	// stale UUID used to delete the new path.
	old = addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.3.1.0/24", "10.0.0.1"))
	streamed, err := apiutil2Path(indexPath(t, bgp.RF_IPv4_UC, "10.3.1.0/24", "10.0.0.3"), false)
	require.NoError(t, err)
	require.NoError(t, s.addPathStream(ctx, "", []*table.Path{streamed}))
	require.EqualError(t, deleteUUID(s, old), cannotFind)
	require.Equal(t, []string{"10.3.1.0/24 10.0.0.3"}, localPaths(t, s, bgp.RF_IPv4_UC), "the streamed path stays")
	require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{indexPath(t, bgp.RF_IPv4_UC, "10.3.1.0/24", "10.0.0.3")}}))

	// Withdrawn by an AddPath withdrawal.
	old = addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.3.2.0/24", "10.0.0.1"))
	addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.3.2.0/24", "10.0.0.1", withdrawal))
	require.EqualError(t, deleteUUID(s, old), cannotFind)

	// Deleted by key.
	old = addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.3.3.0/24", "10.0.0.1"))
	require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{indexPath(t, bgp.RF_IPv4_UC, "10.3.3.0/24", "10.0.0.1")}}))
	require.EqualError(t, deleteUUID(s, old), cannotFind)
	// A new path in the slot is not taken by the old UUID.
	cur = addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.3.3.0/24", "10.0.0.4"))
	require.EqualError(t, deleteUUID(s, old), cannotFind)
	require.Equal(t, []string{"10.3.3.0/24 10.0.0.4"}, localPaths(t, s, bgp.RF_IPv4_UC))
	require.NoError(t, deleteUUID(s, cur))
	require.Zero(t, s.pathIndex.len())
}

// The source and the path identifier are part of the slot: paths of two
// sources for one prefix are two slots.
func TestUUIDSlotHasTheSource(t *testing.T) {
	s := startContextServer(t)
	a := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.4.0.0/24", "10.0.0.1"))
	b := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.4.0.0/24", "10.0.0.2", withSource(2, "1.1.1.2")))
	require.Len(t, localPaths(t, s, bgp.RF_IPv4_UC), 2)
	require.NoError(t, deleteUUID(s, b))
	require.Equal(t, []string{"10.4.0.0/24 10.0.0.1"}, localPaths(t, s, bgp.RF_IPv4_UC))
	require.NoError(t, deleteUUID(s, a))
}

// With no_implicit_withdraw, paths of one slot coexist. A delete by either
// UUID deletes every local path of the slot, as it did before, and both
// UUIDs end.
func TestUUIDWithNoImplicitWithdraw(t *testing.T) {
	s := startContextServer(t)
	a := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.5.0.0/24", "10.0.0.1", noImplicitWithdraw))
	b := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.5.0.0/24", "10.0.0.2", noImplicitWithdraw))
	require.Len(t, localPaths(t, s, bgp.RF_IPv4_UC), 2)
	require.Equal(t, 2, s.pathIndex.len())
	require.NoError(t, deleteUUID(s, a))
	require.Empty(t, localPaths(t, s, bgp.RF_IPv4_UC))
	require.EqualError(t, deleteUUID(s, b), cannotFind)
	require.Zero(t, s.pathIndex.len())
}

// A path the global import policy rejects is never installed, and the
// rejection withdraws the path that was in the slot. Both entries end at
// once, and neither UUID deletes anything afterwards.
func TestUUIDWhenImportPolicyRejects(t *testing.T) {
	s := startContextServer(t)
	ctx := context.Background()
	setImport := func(action api.RouteAction) {
		t.Helper()
		require.NoError(t, s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
			Assignment: &api.PolicyAssignment{Name: table.GLOBAL_RIB_NAME, Direction: api.PolicyDirection_POLICY_DIRECTION_IMPORT, DefaultAction: action},
		}))
	}
	installed := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.6.0.0/24", "10.0.0.1"))
	setImport(api.RouteAction_ROUTE_ACTION_REJECT)
	rejected := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.6.0.0/24", "10.0.0.2"))
	require.Empty(t, localPaths(t, s, bgp.RF_IPv4_UC))
	require.Zero(t, s.pathIndex.len(), "the rejection ended the installed entry and added none")
	require.EqualError(t, deleteUUID(s, installed), cannotFind)
	require.EqualError(t, deleteUUID(s, rejected), cannotFind)
	setImport(api.RouteAction_ROUTE_ACTION_ACCEPT)
	again := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.6.0.0/24", "10.0.0.3"))
	require.NoError(t, deleteUUID(s, again))
}

// Deleting a VRF ends the UUIDs of the paths written to it.
func TestUUIDEndsWithItsVrf(t *testing.T) {
	s := startContextServer(t)
	ctx := context.Background()
	rd, err := apiutil.MarshalRD(bgp.NewRouteDistinguisherTwoOctetAS(65000, 10))
	require.NoError(t, err)
	rt, err := apiutil.MarshalRT(bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 10, true))
	require.NoError(t, err)
	require.NoError(t, s.AddVrf(ctx, &api.AddVrfRequest{Vrf: &api.Vrf{Name: "red", Rd: rd, ImportRt: []*api.RouteTarget{rt}, ExportRt: []*api.RouteTarget{rt}, Id: 10}}))
	inVrf := addIndexed(t, s, "red", indexPath(t, bgp.RF_IPv4_UC, "10.7.0.0/24", "10.0.0.1"))
	global := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.7.0.0/24", "10.0.0.1"))
	require.Len(t, localPaths(t, s, bgp.RF_IPv4_VPN), 1)
	require.NoError(t, s.DeleteVrf(ctx, &api.DeleteVrfRequest{Name: "red"}))
	require.Equal(t, 1, s.pathIndex.len())
	require.EqualError(t, deleteUUID(s, inVrf), cannotFind)
	require.NoError(t, deleteUUID(s, global), "the global path of the same prefix is another slot")
}

// An EVPN MAC move withdraws a local MAC/IP path inside the table. Its UUID
// then deletes nothing.
func TestUUIDAfterEVPNMacMove(t *testing.T) {
	s, source, _ := newEVPNMobilityServer(t, false)
	local := toPathApiUtil(addPathEVPNMacPath(t, nil, 1, 1, 0))
	id := addIndexed(t, s, "", local)
	moved := addPathEVPNMacPath(t, source.peerInfo.Load(), 2, 2, 1)
	s.propagateUpdate(source, []*table.Path{moved})
	require.EqualError(t, deleteUUID(s, id), cannotFind)
	require.Zero(t, s.pathIndex.len())
}

// ListPath reports the UUID of each local path of the global table that
// AddPath gave one, with and without a prefix filter.
func TestListPathReportsUUID(t *testing.T) {
	s := startContextServer(t)
	g := &server{bgpServer: s, shared: s.shared}
	id := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.8.0.0/24", "10.0.0.1"))
	streamed, err := apiutil2Path(indexPath(t, bgp.RF_IPv4_UC, "10.8.1.0/24", "10.0.0.1"), false)
	require.NoError(t, err)
	require.NoError(t, s.addPathStream(context.Background(), "", []*table.Path{streamed}))
	for _, prefixes := range [][]*api.TableLookupPrefix{nil, {{Prefix: "10.8.0.0/24"}}} {
		got := map[string][]byte{}
		require.NoError(t, g.listPath(context.Background(), &api.ListPathRequest{
			TableType: api.TableType_TABLE_TYPE_GLOBAL,
			Family:    &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
			Prefixes:  prefixes,
		}, func(d *api.Destination) {
			got[d.Prefix] = d.Paths[0].Uuid
		}))
		require.Equal(t, id[:], got["10.8.0.0/24"])
		if prefixes == nil {
			require.Contains(t, got, "10.8.1.0/24")
			require.Empty(t, got["10.8.1.0/24"], "a streamed path has no UUID")
		}
	}
}

func indexTablePaths(def int) int {
	if v, err := strconv.ParseUint(os.Getenv("GOBGP_INDEX_TABLE_PATHS"), 10, 31); err == nil && v > 0 {
		return int(v)
	}
	return def
}

// fillLocal adds n local paths with UUIDs in 20.0.0.0/8 and beyond.
func fillLocal(tb testing.TB, s *BgpServer, n int) []uuid.UUID {
	tb.Helper()
	ids := make([]uuid.UUID, 0, n)
	const batch = 10000
	for i := 0; i < n; i += batch {
		paths := make([]*apiutil.Path, 0, batch)
		for j := i; j < i+batch && j < n; j++ {
			a := uint32(20)<<24 + uint32(j)
			addr := netip.AddrFrom4([4]byte{byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a)})
			paths = append(paths, indexPath(tb, bgp.RF_IPv4_UC, netip.PrefixFrom(addr, 32).String(), "10.0.0.1"))
		}
		r, err := s.AddPath(apiutil.AddPathRequest{Paths: paths})
		require.NoError(tb, err)
		for _, x := range r {
			ids = append(ids, x.UUID)
		}
	}
	return ids
}

// On a large table a delete by UUID reads one destination: 100 deletes cost
// less than one walk of the table, which is what a delete by UUID did.
func TestDeleteByUUIDOnLargeTable(t *testing.T) {
	if testing.Short() {
		t.Skip("large table")
	}
	s := startContextServer(t)
	n := indexTablePaths(200000)
	ids := fillLocal(t, s, n)
	start := time.Now()
	require.NoError(t, s.mgmtOperation(func() error {
		_ = s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, s.globalRib.GetRFlist())
		return nil
	}, false))
	walk := time.Since(start)
	start = time.Now()
	for _, id := range ids[:100] {
		require.NoError(t, deleteUUID(s, id))
	}
	deletes := time.Since(start)
	t.Logf("%d paths: one walk %v, 100 deletes by UUID %v", n, walk, deletes)
	require.Less(t, deletes, walk)
	require.Equal(t, n-100, s.pathIndex.len())
}

// BenchmarkDeleteByUUID deletes by UUID on a table of
// GOBGP_INDEX_TABLE_PATHS (default 1M) local paths.
func BenchmarkDeleteByUUID(b *testing.B) {
	s := NewBgpServer()
	go s.Serve()
	require.NoError(b, s.StartBgp(context.Background(), &api.StartBgpRequest{Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1}}))
	defer s.Stop()
	n := indexTablePaths(1000000)
	ids := fillLocal(b, s, n)
	b.ResetTimer()
	for i := range b.N {
		b.StopTimer()
		id := ids[i%len(ids)]
		if i >= len(ids) {
			id = addIndexed(b, s, "", indexPath(b, bgp.RF_IPv4_UC, "30.0.0.0/32", "10.0.0.1"))
		}
		b.StartTimer()
		if err := deleteUUID(s, id); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(n), "table-paths")
}

// Regression: one stream message withdraws a no_implicit_withdraw path and
// adds an ordinary path in the same slot. Only the final table used to be
// read, which still held a path in the slot, so the old UUID survived and
// deleted the new path.
func TestUUIDEndsInsideOneStreamMessage(t *testing.T) {
	s := startContextServer(t)
	g := &server{bgpServer: s, shared: s.shared}
	old := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.9.0.0/24", "10.0.0.1", noImplicitWithdraw))
	w, err := apiutil2Path(indexPath(t, bgp.RF_IPv4_UC, "10.9.0.0/24", "10.0.0.1", withdrawal), false)
	require.NoError(t, err)
	add, err := apiutil2Path(indexPath(t, bgp.RF_IPv4_UC, "10.9.0.0/24", "10.0.0.2"), false)
	require.NoError(t, err)
	require.NoError(t, s.addPathStream(context.Background(), "", []*table.Path{w, add}))
	require.Equal(t, []string{"10.9.0.0/24 10.0.0.2"}, localPaths(t, s, bgp.RF_IPv4_UC))
	require.Zero(t, s.pathIndex.len())
	var reported []byte
	require.NoError(t, g.listPath(context.Background(), &api.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family:    &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
	}, func(d *api.Destination) { reported = d.Paths[0].Uuid }))
	require.Empty(t, reported, "ListPath reports no stale UUID")
	require.EqualError(t, deleteUUID(s, old), cannotFind)
	require.Equal(t, []string{"10.9.0.0/24 10.0.0.2"}, localPaths(t, s, bgp.RF_IPv4_UC), "the new path stays")
}

// The path identifier is part of the slot.
func TestUUIDSlotHasThePathID(t *testing.T) {
	s := startContextServer(t)
	a := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.10.0.0/24", "10.0.0.1", withPathID(1)))
	b := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_UC, "10.10.0.0/24", "10.0.0.2", withPathID(2)))
	require.Len(t, localPaths(t, s, bgp.RF_IPv4_UC), 2)
	require.NoError(t, deleteUUID(s, a))
	require.Equal(t, []string{"10.10.0.0/24 10.0.0.2"}, localPaths(t, s, bgp.RF_IPv4_UC))
	require.NoError(t, deleteUUID(s, b))
}

// A label is not part of a labeled-unicast slot: a path with another label
// replaces the first, whose UUID ends.
func TestUUIDLabelChange(t *testing.T) {
	s := startContextServer(t)
	a := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_MPLS, "10.11.0.0/24", "10.0.0.1", withLabel(100)))
	b := addIndexed(t, s, "", indexPath(t, bgp.RF_IPv4_MPLS, "10.11.0.0/24", "10.0.0.1", withLabel(200)))
	require.Len(t, localPaths(t, s, bgp.RF_IPv4_MPLS), 1)
	require.EqualError(t, deleteUUID(s, a), cannotFind)
	require.Len(t, localPaths(t, s, bgp.RF_IPv4_MPLS), 1)
	require.NoError(t, deleteUUID(s, b))
	require.Empty(t, localPaths(t, s, bgp.RF_IPv4_MPLS))
}

// lsNodeOfArea is a BGP-LS node NLRI of the OSPF protocol whose descriptor
// carries the given area, which NLRI.String omits.
func lsNodeOfArea(t *testing.T, area byte) bgp.NLRI {
	t.Helper()
	nlri, err := bgp.NLRIFromSlice(bgp.RF_LS, []byte{
		0x00, 0x01, 0x00, 0x25,
		0x03,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x18,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8,
		0x02, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, area,
		0x02, 0x03, 0x00, 0x04, 0x0a, 0x00, 0x00, 0x01,
	})
	require.NoError(t, err)
	return nlri
}

// Two BGP-LS nodes whose NLRIs print alike, differing only in their OSPF
// area, are two slots: the slot is keyed by the serialized NLRI.
func TestUUIDBgpLsIdentity(t *testing.T) {
	s := startContextServer(t)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	lsPath := func(area byte) *apiutil.Path {
		return &apiutil.Path{Family: bgp.RF_LS, Nlri: lsNodeOfArea(t, area), Attrs: []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}}
	}
	require.Equal(t, lsNodeOfArea(t, 1).String(), lsNodeOfArea(t, 2).String())
	a := addIndexed(t, s, "", lsPath(1))
	b := addIndexed(t, s, "", lsPath(2))
	require.Len(t, localPaths(t, s, bgp.RF_LS), 2)
	require.NoError(t, deleteUUID(s, a))
	require.Len(t, localPaths(t, s, bgp.RF_LS), 1, "the node of the other area stays")
	require.NoError(t, deleteUUID(s, b))
	require.Empty(t, localPaths(t, s, bgp.RF_LS))
}

// DeleteVrf does not withdraw VPN FlowSpec paths, so the paths written to
// a VRF in both FlowSpec families keep their UUIDs.
func TestUUIDOfVrfFlowSpecOutlivesTheVrf(t *testing.T) {
	s := startContextServer(t)
	ctx := context.Background()
	rd, err := apiutil.MarshalRD(bgp.NewRouteDistinguisherTwoOctetAS(65000, 20))
	require.NoError(t, err)
	rt, err := apiutil.MarshalRT(bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 20, true))
	require.NoError(t, err)
	require.NoError(t, s.AddVrf(ctx, &api.AddVrfRequest{Vrf: &api.Vrf{Name: "blue", Rd: rd, ImportRt: []*api.RouteTarget{rt}, ExportRt: []*api.RouteTarget{rt}, Id: 20}}))
	fs := func(family bgp.Family, component bgp.FlowSpecComponentInterface) *apiutil.Path {
		nlri, err := bgp.NewFlowSpecUnicast(family, []bgp.FlowSpecComponentInterface{component})
		require.NoError(t, err)
		mp, err := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri}})
		require.NoError(t, err)
		return &apiutil.Path{Family: family, Nlri: nlri, Attrs: []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), mp}}
	}
	p4, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.12.0.0/24"))
	require.NoError(t, err)
	p6, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8:12::/64"))
	require.NoError(t, err)
	id4 := addIndexed(t, s, "blue", fs(bgp.RF_FS_IPv4_UC, bgp.NewFlowSpecDestinationPrefix(p4)))
	id6 := addIndexed(t, s, "blue", fs(bgp.RF_FS_IPv6_UC, bgp.NewFlowSpecDestinationPrefix6(p6, 0)))
	require.Len(t, localPaths(t, s, bgp.RF_FS_IPv4_VPN), 1)
	require.Len(t, localPaths(t, s, bgp.RF_FS_IPv6_VPN), 1)
	require.NoError(t, s.DeleteVrf(ctx, &api.DeleteVrfRequest{Name: "blue"}))
	require.Len(t, localPaths(t, s, bgp.RF_FS_IPv4_VPN), 1, "VPN FlowSpec outlives the VRF")
	require.Equal(t, 2, s.pathIndex.len())
	require.NoError(t, deleteUUID(s, id4))
	require.NoError(t, deleteUUID(s, id6))
	require.Empty(t, localPaths(t, s, bgp.RF_FS_IPv4_VPN))
	require.Empty(t, localPaths(t, s, bgp.RF_FS_IPv6_VPN))
}

func benchIndexServer(b *testing.B) *BgpServer {
	b.Helper()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(b, s.StartBgp(context.Background(), &api.StartBgpRequest{Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1}}))
	b.Cleanup(s.Stop)
	return s
}

// hostPaths returns n /32 paths of 20.0.0.0/8 and beyond, offset by base,
// as the table holds them.
func hostPaths(base uint32, n int, withdraw bool) []*table.Path {
	nh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}
	paths := make([]*table.Path, n)
	for j := range paths {
		a := base + uint32(j)
		nlri, _ := bgp.NewIPAddrPrefix(netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a)}), 32))
		paths[j] = table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, withdraw, attrs, time.Now(), false)
	}
	return paths
}

// BenchmarkDeleteCoexistingSlot deletes by one UUID a slot of k coexisting
// no_implicit_withdraw paths, each with its UUID: the whole slot is
// withdrawn and its entries reconciled once.
func BenchmarkDeleteCoexistingSlot(b *testing.B) {
	for _, k := range []int{1, 10, 100, 1000} {
		b.Run("k="+strconv.Itoa(k), func(b *testing.B) {
			s := benchIndexServer(b)
			for range b.N {
				b.StopTimer()
				var first uuid.UUID
				for j := range k {
					nh := netip.AddrFrom4([4]byte{10, 1, byte(j >> 8), byte(j)}).String()
					id := addIndexed(b, s, "", indexPath(b, bgp.RF_IPv4_UC, "30.0.0.0/24", nh, noImplicitWithdraw))
					if j == 0 {
						first = id
					}
				}
				b.StartTimer()
				if err := deleteUUID(s, first); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if s.pathIndex.len() != 0 {
				b.Fatalf("%d entries left", s.pathIndex.len())
			}
		})
	}
}

// BenchmarkStreamWithIndex writes 10,000 new paths with AddPathStream to a
// table of GOBGP_INDEX_TABLE_PATHS (default 1M) local paths, of which none,
// one or all have a UUID. The written slots have no entry, so they go to the
// table in runs; the cost of a non-empty index is the slot key of each path.
func BenchmarkStreamWithIndex(b *testing.B) {
	n := indexTablePaths(1000000)
	for _, indexed := range []string{"none", "one", "all"} {
		b.Run("index="+indexed, func(b *testing.B) {
			s := benchIndexServer(b)
			ctx := context.Background()
			if indexed == "all" {
				fillLocal(b, s, n)
			} else {
				for i := 0; i < n; i += 10000 {
					require.NoError(b, s.addPathStream(ctx, "", hostPaths(uint32(20)<<24+uint32(i), min(10000, n-i), false)))
				}
				if indexed == "one" {
					addIndexed(b, s, "", indexPath(b, bgp.RF_IPv4_UC, "30.0.0.0/32", "10.0.0.1"))
				}
			}
			const batch = 10000
			base := uint32(40) << 24
			b.ResetTimer()
			for range b.N {
				add := hostPaths(base, batch, false)
				if err := s.addPathStream(ctx, "", add); err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				require.NoError(b, s.addPathStream(ctx, "", hostPaths(base, batch, true)))
				b.StartTimer()
			}
			b.StopTimer()
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*batch), "ns/path")
			b.ReportMetric(float64(s.pathIndex.len()), "index-entries")
		})
	}
}
