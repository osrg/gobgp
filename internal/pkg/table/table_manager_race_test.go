// Copyright (C) 2026 Cisco
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
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

// TestTableManager_UpdateRace tests concurrent calls to TableManager.Update()
// Run with: go test -race -run TestTableManager_UpdateRace
func TestTableManager_UpdateRace(t *testing.T) {
	logger := slog.Default()
	rfList := []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC, bgp.RF_EVPN}
	manager := NewTableManager(logger, rfList)

	numGoroutines := 50
	numPathsPerGoroutine := 100
	var wg sync.WaitGroup

	// Create multiple peer infos for different sources
	peers := make([]*PeerInfo, 10)
	for i := range peers {
		peers[i] = &PeerInfo{
			AS:      65000 + uint32(i),
			LocalAS: 65000,
			ID:      netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", i+1)),
			LocalID: netip.MustParseAddr("10.0.0.1"),
			Address: netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", i+1)),
		}
	}

	// Test 1: Concurrent updates to different IPv4 prefixes
	t.Run("ConcurrentDifferentPrefixes", func(t *testing.T) {
		for i := range numGoroutines {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				peerInfo := peers[goroutineID%len(peers)]

				for j := range numPathsPerGoroutine {
					// Create unique prefix for each path
					prefix := fmt.Sprintf("10.%d.%d.0/24", goroutineID, j)
					nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))

					nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.1.1"))
					attrs := []bgp.PathAttributeInterface{
						bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
						nexthop,
					}

					path := NewPath(bgp.RF_IPv4_UC, peerInfo, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
					updates := manager.Update(path)
					assert.NotNil(t, updates)
				}
			}(i)
		}
		wg.Wait()
	})

	// Test 2: Concurrent updates to the SAME prefix from different peers
	t.Run("ConcurrentSamePrefix", func(t *testing.T) {
		for i := range numGoroutines {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				peerInfo := peers[goroutineID%len(peers)]

				nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("192.168.100.0/24"))
				nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr(fmt.Sprintf("192.168.1.%d", goroutineID%254+1)))
				attrs := []bgp.PathAttributeInterface{
					bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
					nexthop,
					bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
						bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65000 + uint32(goroutineID)}),
					}),
				}

				path := NewPath(bgp.RF_IPv4_UC, peerInfo, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
				updates := manager.Update(path)
				assert.NotNil(t, updates)
			}(i)
		}
		wg.Wait()
	})

	// Test 3: Mix of announcements and withdrawals
	t.Run("ConcurrentAnnouncementsAndWithdrawals", func(t *testing.T) {
		for i := range numGoroutines {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				peerInfo := peers[goroutineID%len(peers)]

				for j := range numPathsPerGoroutine {
					prefix := fmt.Sprintf("172.16.%d.0/24", (goroutineID*100+j)%255)
					nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
					assert.NoError(t, err)

					isWithdraw := j%2 == 0
					var attrs []bgp.PathAttributeInterface
					if !isWithdraw {
						nexthop, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.1.1"))
						assert.NoError(t, err)
						attrs = []bgp.PathAttributeInterface{
							bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
							nexthop,
						}
					}

					path := NewPath(bgp.RF_IPv4_UC, peerInfo, bgp.PathNLRI{NLRI: nlri}, isWithdraw, attrs, time.Now(), false)
					updates := manager.Update(path)
					assert.NotNil(t, updates)
				}
			}(i)
		}
		wg.Wait()
	})

	// Test 4: Concurrent updates across different routing families
	t.Run("ConcurrentDifferentFamilies", func(t *testing.T) {
		for i := range numGoroutines {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				peerInfo := peers[goroutineID%len(peers)]

				// Alternate between IPv4 and IPv6
				if goroutineID%2 == 0 {
					// IPv4
					nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/24", goroutineID)))
					nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.1.1"))
					attrs := []bgp.PathAttributeInterface{
						bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
						nexthop,
					}
					path := NewPath(bgp.RF_IPv4_UC, peerInfo, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
					updates := manager.Update(path)
					assert.NotNil(t, updates)
				} else {
					// IPv6
					nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/64", goroutineID)))
					nexthop := netip.MustParseAddr("2001:db8::1")
					mpreach, _ := bgp.NewPathAttributeMpReachNLRI(
						bgp.RF_IPv6_UC,
						[]bgp.PathNLRI{{NLRI: nlri}},
						nexthop,
					)
					attrs := []bgp.PathAttributeInterface{
						bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
						mpreach,
					}
					path := NewPath(bgp.RF_IPv6_UC, peerInfo, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
					updates := manager.Update(path)
					assert.NotNil(t, updates)
				}
			}(i)
		}
		wg.Wait()
	})

	// Test 5: Rapid update/withdraw cycles on same prefixes
	t.Run("ConcurrentUpdateWithdrawCycles", func(t *testing.T) {
		numPrefixes := 20
		cyclesPerPrefix := 10

		for prefixID := range numPrefixes {
			wg.Add(1)
			go func(pid int) {
				defer wg.Done()
				peerInfo := peers[pid%len(peers)]
				prefix := fmt.Sprintf("203.0.%d.0/24", pid)
				nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))

				for range cyclesPerPrefix {
					// Announce
					nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.1.1"))
					attrs := []bgp.PathAttributeInterface{
						bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
						nexthop,
					}
					path := NewPath(bgp.RF_IPv4_UC, peerInfo, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
					updates := manager.Update(path)
					assert.NotNil(t, updates)

					// Withdraw
					path = NewPath(bgp.RF_IPv4_UC, peerInfo, bgp.PathNLRI{NLRI: nlri}, true, []bgp.PathAttributeInterface{}, time.Now(), false)
					updates = manager.Update(path)
					assert.NotNil(t, updates)
				}
			}(prefixID)
		}
		wg.Wait()
	})

	// Test 6: EVPN MAC mobility scenario
	t.Run("ConcurrentEVPNUpdates", func(t *testing.T) {
		// Create EVPN paths with MAC/IP advertisements
		for i := range numGoroutines / 2 {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				peerInfo := peers[goroutineID%len(peers)]

				for j := range 10 {
					// Create EVPN MAC/IP Advertisement
					mac := []byte{0x00, 0x11, 0x22, 0x33, byte(goroutineID), byte(j)}
					etag := uint32(100)
					esi := bgp.EthernetSegmentIdentifier{}

					macIpAdv := &bgp.EVPNMacIPAdvertisementRoute{
						RD:         bgp.NewRouteDistinguisherTwoOctetAS(65000, uint32(goroutineID)),
						ESI:        esi,
						ETag:       etag,
						MacAddress: mac,
						Labels:     []uint32{10000 + uint32(goroutineID)},
					}

					nlri := bgp.NewEVPNNLRI(bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT, macIpAdv)

					rt := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, uint32(100+goroutineID), false)
					nexthop := netip.MustParseAddr("192.168.1.1")

					mpreach, _ := bgp.NewPathAttributeMpReachNLRI(
						bgp.RF_EVPN,
						[]bgp.PathNLRI{{NLRI: nlri}},
						nexthop,
					)

					attrs := []bgp.PathAttributeInterface{
						bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
						mpreach,
						bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{rt}),
					}

					path := NewPath(bgp.RF_EVPN, peerInfo, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
					updates := manager.Update(path)
					assert.NotNil(t, updates)
				}
			}(i)
		}
		wg.Wait()
	})
}

// TestTableManager_UpdateAndReadRace tests concurrent Update and read operations
func TestTableManager_UpdateAndReadRace(t *testing.T) {
	logger := slog.Default()
	rfList := []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC}
	manager := NewTableManager(logger, rfList)

	peerInfo := &PeerInfo{
		AS:      65000,
		LocalAS: 65000,
		ID:      netip.MustParseAddr("10.0.0.1"),
		LocalID: netip.MustParseAddr("10.0.0.1"),
		Address: netip.MustParseAddr("10.0.0.1"),
	}

	var wg sync.WaitGroup
	stopChan := make(chan struct{})

	// Writer goroutines
	for i := range 10 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			counter := 0
			for {
				select {
				case <-stopChan:
					return
				default:
					prefix := fmt.Sprintf("10.%d.%d.0/24", id, counter%256)
					nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
					nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.1.1"))
					attrs := []bgp.PathAttributeInterface{
						bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
						nexthop,
					}
					path := NewPath(bgp.RF_IPv4_UC, peerInfo, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
					manager.Update(path)
					counter++
				}
			}
		}(i)
	}

	// Reader goroutines
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopChan:
					return
				default:
					// Various read operations
					_ = manager.GetBestPathList(GLOBAL_RIB_NAME, 0, rfList)
					_ = manager.GetPathList(GLOBAL_RIB_NAME, 0, rfList)
					_ = manager.GetBestMultiPathList(GLOBAL_RIB_NAME, rfList)

					nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
					assert.NoError(t, err)
					tbl, ok := manager.GetTable(bgp.RF_IPv4_UC)
					assert.True(t, ok)
					_, err = tbl.Select(TableSelectOption{
						LookupPrefixes: []*apiutil.LookupPrefix{
							{
								Prefix: "10.0.0.0/24",
							},
						},
					})
					assert.NoError(t, err)
					_ = manager.GetDestination(NewPath(
						bgp.RF_IPv4_UC,
						peerInfo,
						bgp.PathNLRI{NLRI: nlri},
						false,
						nil,
						time.Now(),
						false,
					))
				}
			}
		}()
	}

	// Let it run for a bit
	time.Sleep(200 * time.Millisecond)
	close(stopChan)
	wg.Wait()
}

// TestTableManager_ConcurrentVrfAndUpdate tests concurrent VRF operations and updates
func TestTableManager_ConcurrentVrfAndUpdate(t *testing.T) {
	logger := slog.Default()
	rfList := []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv4_VPN, bgp.RF_RTC_UC}
	manager := NewTableManager(logger, rfList)

	peerInfo := &PeerInfo{
		AS:      65000,
		LocalAS: 65000,
		ID:      netip.MustParseAddr("10.0.0.1"),
		LocalID: netip.MustParseAddr("10.0.0.1"),
		Address: netip.MustParseAddr("10.0.0.1"),
	}

	var wg sync.WaitGroup

	// Goroutines adding/deleting VRFs
	for i := range 5 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			vrfName := fmt.Sprintf("vrf%d", id)
			rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, uint32(id))
			rt := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, uint32(id), false)

			// Add VRF
			_, err := manager.AddVrf(vrfName, uint32(id), rd, []bgp.ExtendedCommunityInterface{rt}, []bgp.ExtendedCommunityInterface{rt}, peerInfo)
			if err != nil {
				return
			}

			// Let it exist for a bit
			time.Sleep(50 * time.Millisecond)

			// Delete VRF
			_, _ = manager.DeleteVrf(vrfName)
		}(i)
	}

	// Goroutines doing updates
	for i := range 10 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := range 50 {
				prefix := fmt.Sprintf("172.16.%d.0/24", (id*50+j)%256)
				nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
				nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.1.1"))
				attrs := []bgp.PathAttributeInterface{
					bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
					nexthop,
				}
				path := NewPath(bgp.RF_IPv4_UC, peerInfo, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
				manager.Update(path)
				time.Sleep(1 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
}
