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

//go:build linux

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/osrg/gobgp/v4/api"
)

// newUnnumberedLink creates a dummy interface with one permanent IPv6
// link-local neighbor, which is what an unnumbered neighbor resolves to. It
// needs CAP_NET_ADMIN, so the test is skipped without it; any other error
// fails the test. The link lives in the current network namespace, because
// the Serve goroutine, which resolves the interface, may run on any OS
// thread.
func newUnnumberedLink(t *testing.T) string {
	t.Helper()

	name := fmt.Sprintf("gobgp-un%d", os.Getpid()%100000)
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("CAP_NET_ADMIN is required: %v", err)
		}
		require.NoError(t, err)
	}
	// Look the link up again to get the index the kernel assigned.
	link, err := netlink.LinkByName(name)
	require.NoError(t, err)
	t.Cleanup(func() { _ = netlink.LinkDel(link) })
	require.NoError(t, netlink.LinkSetUp(link))

	hw, err := net.ParseMAC("02:00:00:00:00:02")
	require.NoError(t, err)
	require.NoError(t, netlink.NeighAdd(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       netlink.FAMILY_V6,
		State:        netlink.NUD_PERMANENT,
		IP:           net.ParseIP("fe80::2"),
		HardwareAddr: hw,
	}))
	return name
}

// TestDeletePeerUnnumberedInterface deletes an unnumbered neighbor by its
// interface alone. Such a request has no address, which DeletePeer used to
// parse unconditionally.
func TestDeletePeerUnnumberedInterface(t *testing.T) {
	iface := newUnnumberedLink(t)

	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	ctx := context.Background()
	err = s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{NeighborInterface: iface, PeerAsn: 2},
	}})
	require.NoError(t, err)

	countPeers := func() int {
		n := 0
		require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{}, func(*api.Peer) { n++ }))
		return n
	}
	require.Equal(t, 1, countPeers())

	err = s.DeletePeer(ctx, &api.DeletePeerRequest{Interface: iface})
	require.NoError(t, err)
	require.Equal(t, 0, countPeers())
}
