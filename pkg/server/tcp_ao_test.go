// Copyright (C) 2026 The GoBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func testTcpAoKeychain(name string) *api.TcpAoKeychain {
	return &api.TcpAoKeychain{
		Name: name,
		Keys: []*api.TcpAoKey{{
			SendId:            1,
			ReceiveId:         2,
			Algorithm:         api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96,
			ExcludeTcpOptions: true,
			MasterKey:         []byte("secret"),
		}},
	}
}

func TestTcpAoKeychainValidation(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})
	add := func(keychain *api.TcpAoKeychain) error {
		return s.AddTcpAoKeychain(context.Background(), &api.AddTcpAoKeychainRequest{Keychain: keychain})
	}
	update := func(request *api.UpdateTcpAoKeychainRequest) error {
		_, err := s.UpdateTcpAoKeychain(context.Background(), request)
		return err
	}

	// The update cases below all fail, so none of them changes this keychain.
	require.NoError(t, add(&api.TcpAoKeychain{
		Name: "update-chain",
		Keys: []*api.TcpAoKey{
			{SendId: 5, ReceiveId: 15, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("five")},
			{SendId: 9, ReceiveId: 19, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96, MasterKey: []byte("nine")},
		},
	}))

	tests := []struct {
		name string
		fn   func() error
		code codes.Code
	}{
		{
			name: "missing keychain",
			fn:   func() error { return add(nil) },
			code: codes.InvalidArgument,
		},
		{
			name: "missing name",
			fn:   func() error { return add(testTcpAoKeychain("")) },
			code: codes.InvalidArgument,
		},
		{
			name: "no keys",
			fn:   func() error { return add(&api.TcpAoKeychain{Name: "chain"}) },
			code: codes.InvalidArgument,
		},
		{
			name: "nil key",
			fn:   func() error { return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{nil}}) },
			code: codes.InvalidArgument,
		},
		{
			name: "send ID overflow",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{SendId: 256, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "receive ID overflow",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{ReceiveId: 256, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "duplicate send ID",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{
					{SendId: 1, ReceiveId: 1, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}},
					{SendId: 1, ReceiveId: 2, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{2}},
				}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "duplicate receive ID",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{
					{SendId: 1, ReceiveId: 1, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}},
					{SendId: 2, ReceiveId: 1, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{2}},
				}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "unspecified algorithm",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{MasterKey: []byte{1}}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "unknown algorithm",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{Algorithm: api.TcpAoAlgorithm(99), MasterKey: []byte{1}}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "empty master key",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "long master key",
			fn: func() error {
				return add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: make([]byte, netutils.TCPAOMaxKeyLen+1)}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "nil update request",
			fn:   func() error { return update(nil) },
			code: codes.InvalidArgument,
		},
		{
			name: "missing update name",
			fn:   func() error { return update(&api.UpdateTcpAoKeychainRequest{}) },
			code: codes.InvalidArgument,
		},
		{
			name: "nil delete request",
			fn:   func() error { return s.DeleteTcpAoKeychain(context.Background(), nil) },
			code: codes.InvalidArgument,
		},
		{
			name: "missing delete name",
			fn: func() error {
				return s.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "nil list request",
			fn: func() error {
				return s.ListTcpAoKeychain(context.Background(), nil, func(*api.TcpAoKeychain) {})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "nil list callback",
			fn: func() error {
				return s.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{}, nil)
			},
			code: codes.InvalidArgument,
		},
		{
			name: "delete missing key",
			fn: func() error {
				return update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", DeleteKeys: []*api.TcpAoKey{{SendId: 5, ReceiveId: 99}}})
			},
			code: codes.NotFound,
		},
		{
			name: "delete key twice",
			fn: func() error {
				return update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", DeleteKeys: []*api.TcpAoKey{
					{SendId: 5, ReceiveId: 15},
					{SendId: 5, ReceiveId: 15},
				}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "add duplicate send ID",
			fn: func() error {
				return update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", AddKeys: []*api.TcpAoKey{{
					SendId: 9, ReceiveId: 29, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("duplicate"),
				}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "add duplicate receive ID",
			fn: func() error {
				return update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", AddKeys: []*api.TcpAoKey{{
					SendId: 29, ReceiveId: 19, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("duplicate"),
				}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "add send ID overflow",
			fn: func() error {
				return update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", AddKeys: []*api.TcpAoKey{{
					SendId: 256, ReceiveId: 29, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("overflow"),
				}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "add receive ID overflow",
			fn: func() error {
				return update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", AddKeys: []*api.TcpAoKey{{
					SendId: 29, ReceiveId: 256, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("overflow"),
				}}})
			},
			code: codes.InvalidArgument,
		},
		{
			name: "delete every key",
			fn: func() error {
				return update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", DeleteKeys: []*api.TcpAoKey{
					{SendId: 5, ReceiveId: 15},
					{SendId: 9, ReceiveId: 19},
				}})
			},
			code: codes.InvalidArgument,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.code, status.Code(tt.fn()))
		})
	}
}

func TestTcpAoKeychainOperations(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gobgp.sock")
	socketAddr := "unix://" + socketPath
	s := NewBgpServer(GrpcListenAddress(socketAddr))
	go s.Serve()
	t.Cleanup(s.Stop)
	require.Eventually(t, func() bool {
		_, err := os.Stat(socketPath)
		return err == nil
	}, time.Second, 10*time.Millisecond)

	conn, err := grpc.NewClient(socketAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	client := api.NewGoBgpServiceClient(conn)

	_, err = client.AddTcpAoKeychain(context.Background(), &api.AddTcpAoKeychainRequest{
		Keychain: testTcpAoKeychain("chain"),
	})
	require.NoError(t, err)

	updated, err := client.UpdateTcpAoKeychain(context.Background(), &api.UpdateTcpAoKeychainRequest{
		Name: "chain",
		DeleteKeys: []*api.TcpAoKey{{
			SendId:    1,
			ReceiveId: 2,
		}},
		AddKeys: []*api.TcpAoKey{{
			SendId: 1, ReceiveId: 2, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96, MasterKey: []byte("replacement"),
		}},
	})
	require.NoError(t, err)
	require.NotNil(t, updated.Keychain)
	require.Len(t, updated.Keychain.Keys, 1)
	assert.Equal(t, uint32(1), updated.Keychain.Keys[0].SendId)
	assert.Equal(t, uint32(2), updated.Keychain.Keys[0].ReceiveId)
	assert.Equal(t, api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96, updated.Keychain.Keys[0].Algorithm)
	assert.Empty(t, updated.Keychain.Keys[0].MasterKey)

	stream, err := client.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{Name: "chain"})
	require.NoError(t, err)
	listed, err := stream.Recv()
	require.NoError(t, err)
	assert.True(t, proto.Equal(updated.Keychain, listed.Keychain),
		"listed %v, updated %v", listed.Keychain, updated.Keychain)
	_, err = stream.Recv()
	assert.ErrorIs(t, err, io.EOF)

	_, err = client.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{Name: "chain"})
	require.NoError(t, err)
	// Name is a filter, so listing a keychain that does not exist yields no
	// entries rather than an error.
	stream, err = client.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{Name: "chain"})
	require.NoError(t, err)
	_, err = stream.Recv()
	assert.ErrorIs(t, err, io.EOF)
}

func tcpAoTestPeer(address, chain string, preferredSendID uint32) *api.Peer {
	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: address,
			PeerAsn:         65001,
		},
		Transport: &api.Transport{PassiveMode: true},
	}
	if chain != "" {
		peer.TcpAo = &api.TcpAoPeerConfig{
			Keychain: chain,
			SendId:   preferredSendID,
		}
	}
	return peer
}

func startTcpAoTestServer(t *testing.T, opts ...ServerOption) *BgpServer {
	t.Helper()
	s := NewBgpServer(opts...)
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{Global: &api.Global{
		Asn:        65000,
		RouterId:   "192.0.2.254",
		ListenPort: -1,
	}}))
	t.Cleanup(func() {
		if s.isServing.Load() {
			require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
		}
	})
	return s
}

func addTcpAoTestKeychain(t *testing.T, s *BgpServer, name string, sendID, receiveID uint32) {
	t.Helper()
	chain := testTcpAoKeychain(name)
	chain.Keys[0].SendId = sendID
	chain.Keys[0].ReceiveId = receiveID
	err := s.AddTcpAoKeychain(context.Background(), &api.AddTcpAoKeychainRequest{Keychain: chain})
	require.NoError(t, err)
}

func TestTcpAoPeerOperations(t *testing.T) {
	s := startTcpAoTestServer(t)
	addTcpAoTestKeychain(t, s, "primary", 1, 2)
	addTcpAoTestKeychain(t, s, "replacement", 3, 4)

	// TCP-AO and TCP-MD5 authentication are mutually exclusive.
	err := s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "192.0.2.10",
			PeerAsn:         65001,
			AuthPassword:    "md5",
		},
		Transport: &api.Transport{
			PassiveMode: true,
		},
		TcpAo: &api.TcpAoPeerConfig{Keychain: "primary", SendId: 1},
	}})
	assert.Error(t, err)

	// A zoned link-local peer is accepted.
	linkLocalPeer := tcpAoTestPeer("fe80::1%lo", "primary", 1)
	linkLocalPeer.Transport.LocalAddress = "::"
	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: linkLocalPeer}))
	require.NoError(t, s.DeletePeer(context.Background(), &api.DeletePeerRequest{Address: "fe80::1%lo"}))

	// TCP-AO can be attached to an existing peer through UpdatePeer.
	plainPeerRequest := tcpAoTestPeer("192.0.2.2", "", 0)
	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: plainPeerRequest}))
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: tcpAoTestPeer("192.0.2.2", "primary", 1)})
	require.NoError(t, err)
	plainPeer := s.neighborMap[netip.MustParseAddr("192.0.2.2")]
	require.NotNil(t, plainPeer.fsm.tcpAoKeyBinding.Load())
	assert.Equal(t, "primary", plainPeer.fsm.tcpAoKeyBinding.Load().keychain.name)
	require.NoError(t, s.DeletePeer(context.Background(), &api.DeletePeerRequest{Address: "192.0.2.2"}))

	// A newly added peer resolves its configured keychain and preferred send ID.
	peerRequest := tcpAoTestPeer("192.0.2.1", "primary", 1)
	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peerRequest}))
	peer := s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	require.NotNil(t, peer)
	keyBinding := peer.fsm.tcpAoKeyBinding.Load()
	require.NotNil(t, keyBinding)
	assert.Equal(t, "primary", keyBinding.keychain.name)
	assert.Equal(t, uint8(1), keyBinding.preferredSendID)

	// ListPeer exposes the effective TCP-AO configuration.
	var listed *api.Peer
	require.NoError(t, s.ListPeer(context.Background(), &api.ListPeerRequest{Address: "192.0.2.1"}, func(peer *api.Peer) {
		listed = peer
	}))
	require.NotNil(t, listed.GetTcpAo())
	assert.Equal(t, "primary", listed.GetTcpAo().GetKeychain())
	assert.Equal(t, uint32(1), listed.GetTcpAo().GetSendId())

	// Omitting tcp_ao removes the configured attachment.
	withoutTcpAo := tcpAoTestPeer("192.0.2.1", "", 0)
	withoutTcpAo.Conf.Description = "updated"
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: withoutTcpAo})
	require.NoError(t, err)
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	require.NotNil(t, peer)
	assert.Nil(t, peer.fsm.tcpAoKeyBinding.Load())
	assert.Empty(t, peer.fsm.pConf.ReadOnly().TcpAo.Config.Keychain)

	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: tcpAoTestPeer("192.0.2.1", "primary", 1)})
	require.NoError(t, err)
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	require.NotNil(t, peer.fsm.tcpAoKeyBinding.Load())
	assert.Equal(t, "primary", peer.fsm.tcpAoKeyBinding.Load().keychain.name)

	// Updating with the same attachment preserves the selected key.
	sameTcpAo := tcpAoTestPeer("192.0.2.1", "primary", 1)
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: sameTcpAo})
	require.NoError(t, err)
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	require.NotNil(t, peer)
	assert.Equal(t, uint8(1), peer.fsm.pConf.ReadOnly().TcpAo.Config.SendId)

	// Replacing the keychain recreates the peer so new sockets use the new keys.
	previousPeer := peer
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: tcpAoTestPeer("192.0.2.1", "replacement", 3)})
	require.NoError(t, err)
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	assert.NotSame(t, previousPeer, peer)
	assert.Equal(t, "replacement", peer.fsm.tcpAoKeyBinding.Load().keychain.name)

	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: tcpAoTestPeer("192.0.2.1", "primary", 1)})
	require.NoError(t, err)
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	assert.Equal(t, "primary", peer.fsm.tcpAoKeyBinding.Load().keychain.name)

	// A referenced keychain cannot be deleted.
	err = s.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{Name: "primary"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	// Adding a key updates the shared binding and makes older socket snapshots stale.
	_, err = s.UpdateTcpAoKeychain(context.Background(), &api.UpdateTcpAoKeychainRequest{
		Name:    "primary",
		AddKeys: []*api.TcpAoKey{{SendId: 5, ReceiveId: 6, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("new")}},
	})
	require.NoError(t, err)
	peerKeys, err := peer.fsm.tcpAoKeyBinding.Load().socketKeys()
	require.NoError(t, err)
	require.Len(t, peerKeys.keys, 2)

	// Selecting the newly added key rotates the peer in place.
	rotated := tcpAoTestPeer("192.0.2.1", "primary", 5)
	previousPeer = peer
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: rotated})
	require.NoError(t, err)
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	assert.Same(t, previousPeer, peer)
	assert.Equal(t, uint8(5), peer.fsm.tcpAoKeyBinding.Load().preferredSendID)
	assert.Equal(t, uint8(5), peer.fsm.pConf.ReadOnly().TcpAo.Config.SendId)

	// The old key can be removed after the peer has switched away from it.
	_, err = s.UpdateTcpAoKeychain(context.Background(), &api.UpdateTcpAoKeychainRequest{
		Name:       "primary",
		DeleteKeys: []*api.TcpAoKey{{SendId: 1, ReceiveId: 2}},
	})
	require.NoError(t, err)
	peerKeys, err = peer.fsm.tcpAoKeyBinding.Load().socketKeys()
	require.NoError(t, err)
	require.Len(t, peerKeys.keys, 1)
	assert.Equal(t, uint8(5), peerKeys.keys[0].SendID)

	// The preferred and last remaining key cannot be removed.
	_, err = s.UpdateTcpAoKeychain(context.Background(), &api.UpdateTcpAoKeychainRequest{
		Name:       "primary",
		DeleteKeys: []*api.TcpAoKey{{SendId: 5, ReceiveId: 6}},
	})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	// Changing the bind interface used as the Linux VRF socket scope recreates the peer while retaining TCP-AO.
	changedBindInterface := tcpAoTestPeer("192.0.2.1", "primary", 5)
	changedBindInterface.Transport.BindInterface = "blue"
	previousPeer = peer
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: changedBindInterface})
	require.NoError(t, err)
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	assert.NotSame(t, previousPeer, peer)
	assert.Equal(t, "blue", peer.fsm.pConf.ReadOnly().Transport.Config.BindInterface)
	assert.Equal(t, "blue", s.tcpAoBindInterface(peer.fsm.pConf.ReadOnly().Transport.Config))
	assert.Equal(t, "primary", peer.fsm.tcpAoKeyBinding.Load().keychain.name)

	// Socket synchronization is best effort: a socket failure does not reject a
	// valid keychain update or roll back the stored key.
	failedSocket, failedPeer := net.Pipe()
	peer.fsm.lock.Lock()
	peer.fsm.conn = failedSocket
	peer.fsm.lock.Unlock()
	_, err = s.UpdateTcpAoKeychain(context.Background(), &api.UpdateTcpAoKeychainRequest{
		Name:    "primary",
		AddKeys: []*api.TcpAoKey{{SendId: 7, ReceiveId: 8, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("newest")}},
	})
	require.NoError(t, err)
	assert.True(t, peer.fsm.tcpAoKeyBinding.Load().keychain.hasSendID(7))
	peer.fsm.lock.Lock()
	peer.fsm.conn = nil
	peer.fsm.lock.Unlock()
	_ = failedSocket.Close()
	_ = failedPeer.Close()

	require.NoError(t, s.DeletePeer(context.Background(), &api.DeletePeerRequest{Address: "192.0.2.1"}))
	require.NoError(t, s.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{Name: "primary"}))

	// A peer in a logical VRF resolves and retains its TCP-AO keychain binding.
	addTcpAoTestKeychain(t, s, "vrf-chain", 1, 2)
	addVrf(t, s, "blue", "65000:100", []string{"65000:100"}, []string{"65000:100"}, 1)

	peerRequest = tcpAoTestPeer("192.0.2.20", "vrf-chain", 1)
	peerRequest.Conf.Vrf = "blue"
	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peerRequest}))

	peer = s.neighborMap[netip.MustParseAddr("192.0.2.20")]
	require.NotNil(t, peer)
	assert.Equal(t, "blue", peer.fsm.pConf.ReadOnly().Config.Vrf)
	keyBinding = peer.fsm.tcpAoKeyBinding.Load()
	require.NotNil(t, keyBinding)
	assert.Equal(t, "vrf-chain", keyBinding.keychain.name)

	// A peer inherits the TCP-AO attachment from its peer group.
	addTcpAoTestKeychain(t, s, "group-chain", 1, 2)
	require.NoError(t, s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf: &api.PeerGroupConf{
			PeerGroupName: "ao-group",
			PeerAsn:       65001,
		},
		TcpAo: &api.TcpAoPeerConfig{Keychain: "group-chain", SendId: 1},
	}}))
	groupPeer := tcpAoTestPeer("192.0.2.11", "", 0)
	groupPeer.Conf.PeerGroup = "ao-group"
	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: groupPeer}))
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.11")]
	keyBinding = peer.fsm.tcpAoKeyBinding.Load()
	require.NotNil(t, keyBinding)
	assert.Equal(t, "group-chain", keyBinding.keychain.name)
	assert.Equal(t, "group-chain", string(peer.fsm.pConf.ReadOnly().TcpAo.Config.Keychain))
}
