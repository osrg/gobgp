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

package main

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestTcpAoKeychainCommands(t *testing.T) {
	const (
		keychainName     = "fabric"
		masterKeyZero    = "secret"
		masterKeyOne     = "other"
		masterKeyTwo     = "ninety-six"
		masterKeyThree   = "one-twenty-eight"
		masterKeyUpdated = "new"
	)

	fake := newTestTcpAOClient(t)
	keyDir := t.TempDir()
	keyFile := func(name, value string) string {
		path := filepath.Join(keyDir, name)
		encoded := base64.StdEncoding.EncodeToString([]byte(value)) + "\n"
		require.NoError(t, os.WriteFile(path, []byte(encoded), 0o600))
		return "file:" + path
	}

	command := newKeychainCmd()
	command.SetArgs([]string{
		"add", keychainName,
		"--key", "0,10,hmac-sha-1-96," + keyFile("zero", masterKeyZero),
		"--key", "1,11,aes-128-cmac-96," + keyFile("one", masterKeyOne) + ",exclude-tcp-options",
		"--key", "2,12,hmac-sha-256-96," + keyFile("two", masterKeyTwo),
		"--key", "3,13,hmac-sha-256-128," + keyFile("three", masterKeyThree),
	})
	require.NoError(t, command.Execute())
	require.NotNil(t, fake.addKeychain)
	assert.Equal(t, keychainName, fake.addKeychain.Keychain.Name)
	require.Len(t, fake.addKeychain.Keychain.Keys, 4)
	assert.Equal(t, api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, fake.addKeychain.Keychain.Keys[0].Algorithm)
	assert.Equal(t, api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96, fake.addKeychain.Keychain.Keys[1].Algorithm)
	assert.Equal(t, api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_96, fake.addKeychain.Keychain.Keys[2].Algorithm)
	assert.Equal(t, api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_128, fake.addKeychain.Keychain.Keys[3].Algorithm)
	for i, masterKey := range []string{masterKeyZero, masterKeyOne, masterKeyTwo, masterKeyThree} {
		assert.Equal(t, []byte(masterKey), fake.addKeychain.Keychain.Keys[i].MasterKey)
	}

	command = newKeychainCmd()
	command.SetArgs([]string{
		"update", keychainName,
		"--add-key", "2,12,hmac-sha-1-96," + keyFile("updated", masterKeyUpdated),
		"--delete-key", "1,11",
	})
	require.NoError(t, command.Execute())
	require.NotNil(t, fake.updateKeychain)
	require.Len(t, fake.updateKeychain.AddKeys, 1)
	require.Len(t, fake.updateKeychain.DeleteKeys, 1)
	assert.Equal(t, []byte(masterKeyUpdated), fake.updateKeychain.AddKeys[0].MasterKey)
	assert.Equal(t, uint32(1), fake.updateKeychain.DeleteKeys[0].SendId)

	command = newKeychainCmd()
	command.SetArgs([]string{"del", keychainName})
	require.NoError(t, command.Execute())
	require.NotNil(t, fake.deleteKeychain)
	assert.Equal(t, keychainName, fake.deleteKeychain.Name)
}

func TestParseTcpAoKeyRejectsInvalidMasterKey(t *testing.T) {
	const inlineMasterKey = "secret"

	keyDir := t.TempDir()
	keyFile := func(name, value string) string {
		path := filepath.Join(keyDir, name)
		require.NoError(t, os.WriteFile(path, []byte(value), 0o600))
		return "file:" + path
	}
	tests := []struct {
		name      string
		masterKey string
		errorText string
	}{
		{name: "empty file", masterKey: keyFile("empty", ""), errorText: "must decode to 1-80 bytes"},
		{name: "oversized file", masterKey: keyFile("oversized", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", netutils.TCPAOMaxKeyLen+1)))), errorText: "must decode to 1-80 bytes"},
		{name: "invalid base64", masterKey: keyFile("invalid-base64", "not base64"), errorText: "must contain a base64-encoded key"},
		{name: "inline secret", masterKey: inlineMasterKey, errorText: "must be specified as file:<path>"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseTcpAoKey("0,10,hmac-sha-1-96," + test.masterKey)
			require.ErrorContains(t, err, test.errorText)
		})
	}
}

func TestNeighborAddTcpAoPeerConfig(t *testing.T) {
	fake := newTestTcpAOClient(t)
	require.NoError(t, modNeighbor(cmdAdd, []string{
		"192.0.2.1", "as", "65001", "tcp-ao-keychain", "fabric", "tcp-ao-send-id", "11",
	}))
	require.NotNil(t, fake.addPeer)
	require.NotNil(t, fake.addPeer.Peer.GetTcpAo())
	assert.Equal(t, "fabric", fake.addPeer.Peer.GetTcpAo().GetKeychain())
	assert.Equal(t, uint32(11), fake.addPeer.Peer.GetTcpAo().GetSendId())
}

func TestFormatTcpAoPeerState(t *testing.T) {
	state := &api.TcpAoPeerState{
		Keys: []*api.TcpAoKeyState{
			{SendId: 2, ReceiveId: 12, ReceiveNext: true, PacketsGood: 7, PacketsBad: 3},
			{SendId: 3, ReceiveId: 13, Current: true, PacketsGood: 42},
			{SendId: 1, ReceiveId: 11, PacketsGood: 5},
		},
		PacketsKeyNotFound: 2,
		PacketsAoRequired:  3,
		PacketsDroppedIcmp: 4,
	}
	expected := `  TCP-AO socket counters:
    Key not found: 2, AO required: 3, Dropped ICMP: 4
  TCP-AO socket key state:
    Send ID Receive ID Current Receive next Packets good Packets bad
          1         11   false        false            5           0
          2         12   false         true            7           3
          3         13    true        false           42           0
`
	assert.Equal(t, expected, formatTcpAoPeerState(state))
}

type testTCPAOClient struct {
	api.GoBgpServiceClient
	addKeychain    *api.AddTcpAoKeychainRequest
	updateKeychain *api.UpdateTcpAoKeychainRequest
	deleteKeychain *api.DeleteTcpAoKeychainRequest
	addPeer        *api.AddPeerRequest
}

func (c *testTCPAOClient) AddTcpAoKeychain(_ context.Context, request *api.AddTcpAoKeychainRequest, _ ...grpc.CallOption) (*api.AddTcpAoKeychainResponse, error) {
	c.addKeychain = request
	return &api.AddTcpAoKeychainResponse{}, nil
}

func (c *testTCPAOClient) UpdateTcpAoKeychain(_ context.Context, request *api.UpdateTcpAoKeychainRequest, _ ...grpc.CallOption) (*api.UpdateTcpAoKeychainResponse, error) {
	c.updateKeychain = request
	return &api.UpdateTcpAoKeychainResponse{}, nil
}

func (c *testTCPAOClient) DeleteTcpAoKeychain(_ context.Context, request *api.DeleteTcpAoKeychainRequest, _ ...grpc.CallOption) (*api.DeleteTcpAoKeychainResponse, error) {
	c.deleteKeychain = request
	return &api.DeleteTcpAoKeychainResponse{}, nil
}

func (c *testTCPAOClient) AddPeer(_ context.Context, request *api.AddPeerRequest, _ ...grpc.CallOption) (*api.AddPeerResponse, error) {
	c.addPeer = request
	return &api.AddPeerResponse{}, nil
}

func newTestTcpAOClient(t *testing.T) *testTCPAOClient {
	t.Helper()
	previousClient := client
	previousContext := ctx
	fake := &testTCPAOClient{}
	client = fake
	ctx = context.Background()
	t.Cleanup(func() {
		client = previousClient
		ctx = previousContext
	})
	return fake
}
