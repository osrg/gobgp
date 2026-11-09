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
// rejection withdraws the path that was in the slot. Neither UUID deletes
// anything afterwards.
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
	require.EqualError(t, deleteUUID(s, installed), cannotFind)
	require.EqualError(t, deleteUUID(s, rejected), cannotFind)
	require.Zero(t, s.pathIndex.len(), "the delete that found nothing ended the entry")
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
