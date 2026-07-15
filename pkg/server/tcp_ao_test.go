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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
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
		_, err := s.AddTcpAoKeychain(context.Background(), &api.AddTcpAoKeychainRequest{Keychain: keychain})
		return err
	}
	update := func(request *api.UpdateTcpAoKeychainRequest) error {
		_, err := s.UpdateTcpAoKeychain(context.Background(), request)
		return err
	}
	tests := []struct {
		name string
		err  error
		code codes.Code
	}{
		{
			name: "missing keychain",
			err:  add(nil),
			code: codes.InvalidArgument,
		},
		{
			name: "missing name",
			err:  add(testTcpAoKeychain("")),
			code: codes.InvalidArgument,
		},
		{
			name: "no keys",
			err:  add(&api.TcpAoKeychain{Name: "chain"}),
			code: codes.InvalidArgument,
		},
		{
			name: "nil key",
			err:  add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{nil}}),
			code: codes.InvalidArgument,
		},
		{
			name: "send ID overflow",
			err:  add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{SendId: 256, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}}}}),
			code: codes.InvalidArgument,
		},
		{
			name: "receive ID overflow",
			err:  add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{ReceiveId: 256, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}}}}),
			code: codes.InvalidArgument,
		},
		{
			name: "duplicate send ID",
			err: add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{
				{SendId: 1, ReceiveId: 1, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}},
				{SendId: 1, ReceiveId: 2, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{2}},
			}}),
			code: codes.InvalidArgument,
		},
		{
			name: "duplicate receive ID",
			err: add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{
				{SendId: 1, ReceiveId: 1, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}},
				{SendId: 2, ReceiveId: 1, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{2}},
			}}),
			code: codes.InvalidArgument,
		},
		{
			name: "unspecified algorithm",
			err:  add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{MasterKey: []byte{1}}}}),
			code: codes.InvalidArgument,
		},
		{
			name: "unknown algorithm",
			err:  add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{Algorithm: api.TcpAoAlgorithm(99), MasterKey: []byte{1}}}}),
			code: codes.InvalidArgument,
		},
		{
			name: "empty master key",
			err:  add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96}}}),
			code: codes.InvalidArgument,
		},
		{
			name: "long master key",
			err:  add(&api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: make([]byte, tcpAoMaxMasterKeyBytes+1)}}}),
			code: codes.InvalidArgument,
		},
		{
			name: "nil update request",
			err:  update(nil),
			code: codes.InvalidArgument,
		},
		{
			name: "missing update name",
			err:  update(&api.UpdateTcpAoKeychainRequest{}),
			code: codes.InvalidArgument,
		},
		{
			name: "nil delete request",
			err:  s.DeleteTcpAoKeychain(context.Background(), nil),
			code: codes.InvalidArgument,
		},
		{
			name: "missing delete name",
			err:  s.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{}),
			code: codes.InvalidArgument,
		},
		{
			name: "nil list request",
			err:  s.ListTcpAoKeychain(context.Background(), nil, func(*api.TcpAoKeychain) {}),
			code: codes.InvalidArgument,
		},
		{
			name: "nil list callback",
			err:  s.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{}, nil),
			code: codes.InvalidArgument,
		},
		{
			name: "valid keychain for update",
			err: add(&api.TcpAoKeychain{
				Name: "update-chain",
				Keys: []*api.TcpAoKey{
					{SendId: 5, ReceiveId: 15, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("five")},
					{SendId: 9, ReceiveId: 19, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96, MasterKey: []byte("nine")},
				},
			}),
			code: codes.OK,
		},
		{
			name: "delete missing key",
			err:  update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", DeleteKeys: []*api.TcpAoKey{{SendId: 5, ReceiveId: 99}}}),
			code: codes.NotFound,
		},
		{
			name: "delete key twice",
			err: update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", DeleteKeys: []*api.TcpAoKey{
				{SendId: 5, ReceiveId: 15},
				{SendId: 5, ReceiveId: 15},
			}}),
			code: codes.InvalidArgument,
		},
		{
			name: "add duplicate send ID",
			err: update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", AddKeys: []*api.TcpAoKey{{
				SendId: 9, ReceiveId: 29, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("duplicate"),
			}}}),
			code: codes.AlreadyExists,
		},
		{
			name: "add duplicate receive ID",
			err: update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", AddKeys: []*api.TcpAoKey{{
				SendId: 29, ReceiveId: 19, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("duplicate"),
			}}}),
			code: codes.AlreadyExists,
		},
		{
			name: "delete every key",
			err: update(&api.UpdateTcpAoKeychainRequest{Name: "update-chain", DeleteKeys: []*api.TcpAoKey{
				{SendId: 5, ReceiveId: 15},
				{SendId: 9, ReceiveId: 19},
			}}),
			code: codes.InvalidArgument,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.code, status.Code(tt.err))
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

	added, err := client.AddTcpAoKeychain(context.Background(), &api.AddTcpAoKeychainRequest{
		Keychain: testTcpAoKeychain("chain"),
	})
	require.NoError(t, err)
	require.NotNil(t, added.Keychain)
	require.Len(t, added.Keychain.Keys, 1)
	assert.Empty(t, added.Keychain.Keys[0].MasterKey)

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
	assert.Equal(t, updated.Keychain, listed.Keychain)
	_, err = stream.Recv()
	assert.ErrorIs(t, err, io.EOF)

	_, err = client.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{Name: "chain"})
	require.NoError(t, err)
	stream, err = client.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{Name: "chain"})
	require.NoError(t, err)
	_, err = stream.Recv()
	assert.Equal(t, codes.NotFound, status.Code(err))
}
