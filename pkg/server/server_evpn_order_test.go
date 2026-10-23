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

package server

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/dgryski/go-farm"
	"github.com/stretchr/testify/require"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

var (
	evpnMac  = "00:11:22:33:44:55"
	evpnESI1 = bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY, Value: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1}}
	evpnESI2 = bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY, Value: []byte{2, 2, 2, 2, 2, 2, 2, 2, 2}}
	evpnESI3 = bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY, Value: []byte{3, 3, 3, 3, 3, 3, 3, 3, 3}}
)

// newEVPNMacPath returns a MAC/IP advertisement for evpnMac. The RD is part of
// the destination, the ESI is not. A nil source makes the path a local one.
func newEVPNMacPath(t testing.TB, source *table.PeerInfo, rdAdmin uint16, esi bgp.EthernetSegmentIdentifier, seq uint32, isWithdraw bool) *table.Path {
	t.Helper()
	nh := netip.MustParseAddr("10.0.0.1")
	nlri, err := bgp.NewEVPNMacIPAdvertisementRoute(bgp.NewRouteDistinguisherTwoOctetAS(rdAdmin, 1), esi, 0, evpnMac, netip.Addr{}, []uint32{100})
	require.NoError(t, err)
	mp, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_EVPN, []bgp.PathNLRI{{NLRI: nlri}}, nh)
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		mp,
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
			bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 1, true),
			bgp.NewMacMobilityExtended(seq, false),
		}),
	}
	return table.NewPath(bgp.RF_EVPN, source, bgp.PathNLRI{NLRI: nlri}, isWithdraw, attrs, time.Now(), false)
}

func startEVPNTestServer(t *testing.T) *BgpServer {
	t.Helper()
	ctx := context.Background()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{Asn: 1111, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(ctx, &api.StopBgpRequest{}))
	})
	return s
}

func newEVPNTestPeer(t *testing.T, s *BgpServer, address string) *peer {
	t.Helper()
	p := newPeerandInfo(t, 1111, 1112, address, s.globalRib)
	p.policy = s.policy
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	open, err := bgp.NewBGPOpenMessage(1112, 90, netip.MustParseAddr(address), nil)
	require.NoError(t, err)
	p.fsm.recvOpen = open
	return p
}

// An update that withdraws the local path of another destination (EVPN MAC
// mobility) has to keep that destination ordered until it has notified. If it
// does not, a concurrent withdrawal of the path that became best there can
// notify first, and the stale announcement that follows leaves the watchers
// with a route that is gone.
func TestPropagateUpdateKeepsMacMobilityTargetOrdered(t *testing.T) {
	s := startEVPNTestServer(t)
	p1 := newEVPNTestPeer(t, s, "10.1.142.66")
	p2 := newEVPNTestPeer(t, s, "10.1.142.67")

	const rdLocal, rdTrigger = 1, 2
	// L is the local path of D2, R is a remote path of D2 and A, from p1,
	// moves the MAC away from L's ESI. D1 is the destination of A.
	local := newEVPNMacPath(t, nil, rdLocal, evpnESI1, 0, false)
	remote := newEVPNMacPath(t, p2.peerInfo.Load(), rdLocal, evpnESI2, 0, false)
	trigger := newEVPNMacPath(t, p1.peerInfo.Load(), rdTrigger, evpnESI3, 1, false)

	// The test is only worth something if the two destinations would not
	// share a bucket when it is picked from the prefix.
	byPrefix := func(p *table.Path) uint64 {
		k := p.GetDestLocalKey()
		return farm.Hash64([]byte(k.Family.String()+k.Prefix)) % uint64(propagateBucketCount)
	}
	require.NotEqual(t, byPrefix(trigger), byPrefix(local), "pick other RDs")

	s.propagateUpdate(nil, []*table.Path{local})
	s.propagateUpdate(p2, []*table.Path{remote})

	// Hold the trigger between its table update and its notifications.
	inFilter := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	w, err := s.watch(func(o *watchOptions) {
		o.postUpdate = true
		o.postUpdateFilter = func(watchEvent) bool {
			once.Do(func() {
				close(inFilter)
				<-release
			})
			return true
		}
	})
	require.NoError(t, err)
	t.Cleanup(w.Stop)

	triggerDone := make(chan struct{})
	go func() {
		defer close(triggerDone)
		s.propagateUpdate(p1, []*table.Path{trigger})
	}()
	<-inFilter

	// MAC mobility withdrew L, so D2 was modified, and the trigger has not
	// notified yet.
	mac, err := net.ParseMAC(evpnMac)
	require.NoError(t, err)
	for _, p := range s.globalRib.GetPathListWithMac(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_EVPN}, trigger.GetRouteTargets()[0], mac) {
		if p.IsLocal() {
			close(release)
			<-triggerDone
			t.Fatal("MAC mobility did not withdraw the local path")
		}
	}

	// Nobody else may modify D2 now: the withdrawal of R has to wait for
	// the notifications of the trigger. It may be blocked on the watcher too,
	// so look at the table, not at whether it returned.
	withdrawDone := make(chan struct{})
	go func() {
		defer close(withdrawDone)
		s.propagateUpdate(p2, []*table.Path{newEVPNMacPath(t, p2.peerInfo.Load(), rdLocal, evpnESI2, 0, true)})
	}()
	remoteHeld := func() bool {
		for _, p := range s.globalRib.GetPathListWithMac(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_EVPN}, trigger.GetRouteTargets()[0], mac) {
			if !p.IsLocal() && p.GetSource().Address == p2.peerInfo.Load().Address {
				return true
			}
		}
		return false
	}
	require.True(t, remoteHeld())
	time.Sleep(200 * time.Millisecond)
	if !remoteHeld() {
		close(release)
		<-triggerDone
		t.Fatal("a withdrawal for the MAC modified the table between the table update and the notifications of the update that withdrew its local path")
	}

	close(release)
	for _, c := range []chan struct{}{triggerDone, withdrawDone} {
		select {
		case <-c:
		case <-time.After(30 * time.Second):
			t.Fatal("propagateUpdate did not return")
		}
	}
}

// Two EVPN updates that each withdraw a local path under the destination of
// the other one must not deadlock.
func TestPropagateUpdateMacMobilityConcurrent(t *testing.T) {
	s := startEVPNTestServer(t)
	p1 := newEVPNTestPeer(t, s, "10.1.142.66")
	p2 := newEVPNTestPeer(t, s, "10.1.142.67")

	const rdA, rdB = 1, 2
	for round := range 200 {
		s.propagateUpdate(nil, []*table.Path{
			newEVPNMacPath(t, nil, rdA, evpnESI1, 0, false),
			newEVPNMacPath(t, nil, rdB, evpnESI2, 0, false),
		})
		// x lives in A and y in B. Both are above the local sequence number
		// and carry another ESI, so each one withdraws both local paths.
		x := newEVPNMacPath(t, p1.peerInfo.Load(), rdA, evpnESI3, 1, false)
		y := newEVPNMacPath(t, p2.peerInfo.Load(), rdB, evpnESI3, 1, false)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); s.propagateUpdate(p1, []*table.Path{x}) }()
		go func() { defer wg.Done(); s.propagateUpdate(p2, []*table.Path{y}) }()
		finished := make(chan struct{})
		go func() { wg.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(30 * time.Second):
			t.Fatalf("deadlock in round %d", round)
		}

		// Start the next round from an empty table.
		s.propagateUpdate(p1, []*table.Path{newEVPNMacPath(t, p1.peerInfo.Load(), rdA, evpnESI3, 1, true)})
		s.propagateUpdate(p2, []*table.Path{newEVPNMacPath(t, p2.peerInfo.Load(), rdB, evpnESI3, 1, true)})
	}
}

// Every MAC/IP advertisement of one MAC shares a bucket whatever its RD, IP
// address, ETag and ESI are, and so does its withdrawal. Other prefixes keep
// the bucket of their destination.
func TestPropagateBucketEVPNMacIP(t *testing.T) {
	d := newSharedData()
	macPath := func(mac string, rdAdmin uint16, esi bgp.EthernetSegmentIdentifier, etag uint32, ip string, isWithdraw bool) *table.Path {
		var addr netip.Addr
		if ip != "" {
			addr = netip.MustParseAddr(ip)
		}
		nlri, err := bgp.NewEVPNMacIPAdvertisementRoute(bgp.NewRouteDistinguisherTwoOctetAS(rdAdmin, 1), esi, etag, mac, addr, []uint32{100})
		require.NoError(t, err)
		return table.NewPath(bgp.RF_EVPN, nil, bgp.PathNLRI{NLRI: nlri}, isWithdraw, []bgp.PathAttributeInterface{}, time.Now(), false)
	}

	want := d.propagateBucket(macPath(evpnMac, 1, evpnESI1, 0, "", false))
	var paths []*table.Path
	for rd := uint16(1); rd <= 64; rd++ {
		paths = append(paths,
			macPath(evpnMac, rd, evpnESI1, 0, "", false),
			macPath(evpnMac, rd, evpnESI2, uint32(rd), "192.0.2.1", false),
			macPath(evpnMac, rd, evpnESI3, 0, "2001:db8::1", false),
			macPath(evpnMac, rd, evpnESI1, 0, "", true),
		)
	}
	for _, p := range paths {
		require.Same(t, want, d.propagateBucket(p), "%s", p.GetNlri())
	}

	// Another MAC spreads over the buckets.
	seen := map[*sync.Mutex]struct{}{}
	for i := range 256 {
		seen[d.propagateBucket(macPath(net.HardwareAddr{0, 0x11, 0x22, 0x33, 0x44, byte(i)}.String(), 1, evpnESI1, 0, "", false))] = struct{}{}
	}
	require.Greater(t, len(seen), 1)

	// A prefix of another family keeps the bucket of its destination.
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	require.NoError(t, err)
	v4 := table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{}, time.Now(), false)
	key := v4.GetDestLocalKey()
	idx := farm.Hash64([]byte(key.Family.String()+key.Prefix)) % uint64(len(d.propagateBuckets))
	require.Same(t, &d.propagateBuckets[idx], d.propagateBucket(v4))

	// So does an EVPN route that carries no MAC address.
	ead := bgp.NewEVPNEthernetAutoDiscoveryRoute(bgp.NewRouteDistinguisherTwoOctetAS(1, 1), evpnESI1, 0, 100)
	p := table.NewPath(bgp.RF_EVPN, nil, bgp.PathNLRI{NLRI: ead}, false, []bgp.PathAttributeInterface{}, time.Now(), false)
	key = p.GetDestLocalKey()
	idx = farm.Hash64([]byte(key.Family.String()+key.Prefix)) % uint64(len(d.propagateBuckets))
	require.Same(t, &d.propagateBuckets[idx], d.propagateBucket(p))
}
