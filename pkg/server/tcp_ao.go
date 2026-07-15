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
	"maps"
	"slices"
	"sync"

	"github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tcpAoMaxMasterKeyBytes matches TCP_AO_MAXKEYLEN from Linux's include/uapi/linux/tcp.h.
const tcpAoMaxMasterKeyBytes = 80

type tcpAoKey struct {
	sendID            uint8
	receiveID         uint8
	algorithm         api.TcpAoAlgorithm
	excludeTCPOptions bool
	masterKey         []byte
}
type tcpAoKeychain struct {
	mu   sync.RWMutex
	name string
	keys map[uint8]tcpAoKey
}

type tcpAoKeychainStore struct {
	// keychains must only be accessed from mgmtOperation callbacks while shared.mu is held.
	keychains map[string]*tcpAoKeychain
}

func newTcpAoKeychainStore() *tcpAoKeychainStore {
	return &tcpAoKeychainStore{keychains: make(map[string]*tcpAoKeychain)}
}

func (s *tcpAoKeychainStore) addKeychain(chain *tcpAoKeychain) {
	s.keychains[chain.name] = chain
}

func (s *tcpAoKeychainStore) getKeychain(name string) (*tcpAoKeychain, bool) {
	chain, ok := s.keychains[name]
	return chain, ok
}

func (s *tcpAoKeychainStore) getAllKeychains() []*tcpAoKeychain {
	return slices.Collect(maps.Values(s.keychains))
}

func (s *tcpAoKeychainStore) deleteKeychain(name string) bool {
	chain, ok := s.keychains[name]
	if !ok {
		return false
	}
	chain.clearKeys()
	delete(s.keychains, name)
	return true
}

func (s *tcpAoKeychainStore) clearAllKeychains() {
	for _, chain := range s.keychains {
		chain.clearKeys()
	}
	clear(s.keychains)
}

func newTcpAoKeychain(a *api.TcpAoKeychain) (*tcpAoKeychain, error) {
	keys, err := newTcpAoKeys(a.Name, a.Keys)
	if err != nil {
		return nil, err
	}
	keyMap := make(map[uint8]tcpAoKey, len(keys))
	for _, key := range keys {
		keyMap[key.sendID] = key
	}
	return &tcpAoKeychain{name: a.Name, keys: keyMap}, nil
}

func newTcpAoKeys(chainName string, keys []*api.TcpAoKey) ([]tcpAoKey, error) {
	if len(keys) == 0 || len(keys) > 256 {
		return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q must contain between 1 and 256 keys", chainName)
	}
	sendIDs := make(map[uint32]struct{}, len(keys))
	receiveIDs := make(map[uint32]struct{}, len(keys))
	for i, key := range keys {
		if key == nil {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q contains a nil key at index %d", chainName, i)
		}
		if key.SendId > 255 {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key %d has send ID %d outside 0..255", chainName, i, key.SendId)
		}
		if key.ReceiveId > 255 {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key %d has receive ID %d outside 0..255", chainName, i, key.ReceiveId)
		}
		if _, ok := sendIDs[key.SendId]; ok {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q has duplicate send ID %d", chainName, key.SendId)
		}
		if _, ok := receiveIDs[key.ReceiveId]; ok {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q has duplicate receive ID %d", chainName, key.ReceiveId)
		}
		switch key.Algorithm {
		case api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96,
			api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96:
		default:
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key %d has unsupported algorithm %s", chainName, i, key.Algorithm)
		}
		if len(key.MasterKey) == 0 || len(key.MasterKey) > tcpAoMaxMasterKeyBytes {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key %d master key must contain between 1 and %d bytes", chainName, i, tcpAoMaxMasterKeyBytes)
		}
		sendIDs[key.SendId] = struct{}{}
		receiveIDs[key.ReceiveId] = struct{}{}
	}

	result := make([]tcpAoKey, 0, len(keys))
	for _, apiKey := range keys {
		key := tcpAoKey{
			sendID:            uint8(apiKey.SendId),
			receiveID:         uint8(apiKey.ReceiveId),
			algorithm:         apiKey.Algorithm,
			excludeTCPOptions: apiKey.ExcludeTcpOptions,
			masterKey:         append([]byte{}, apiKey.MasterKey...),
		}
		result = append(result, key)
	}
	return result, nil
}

func (c *tcpAoKeychain) toAPIKeychain() *api.TcpAoKeychain {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := &api.TcpAoKeychain{
		Name: c.name,
		Keys: make([]*api.TcpAoKey, 0, len(c.keys)),
	}
	sendIDs := make([]uint8, 0, len(c.keys))
	for sendID := range c.keys {
		sendIDs = append(sendIDs, sendID)
	}
	slices.Sort(sendIDs)
	for _, sendID := range sendIDs {
		key := c.keys[sendID]
		result.Keys = append(result.Keys, &api.TcpAoKey{
			SendId:            uint32(key.sendID),
			ReceiveId:         uint32(key.receiveID),
			Algorithm:         key.algorithm,
			ExcludeTcpOptions: key.excludeTCPOptions,
			// MasterKey is intentionally omitted
		})
	}
	return result
}

func (c *tcpAoKeychain) getKey(sendID, receiveID uint8) (tcpAoKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key, ok := c.keys[sendID]
	if !ok || key.receiveID != receiveID {
		return tcpAoKey{}, false
	}
	return key, true
}

func (c *tcpAoKeychain) updateKeys(added, deleted []tcpAoKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, deletedKey := range deleted {
		key, ok := c.keys[deletedKey.sendID]
		if !ok || key.receiveID != deletedKey.receiveID {
			continue
		}
		clear(key.masterKey)
		delete(c.keys, deletedKey.sendID)
	}
	for _, key := range added {
		c.keys[key.sendID] = key
	}
}

func (c *tcpAoKeychain) clearKeys() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, key := range c.keys {
		clear(key.masterKey)
	}
	clear(c.keys)
}
