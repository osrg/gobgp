// Copyright (C) 2026 The GoBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package netutils

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func skipTCPAONotSupported(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EOPNOTSUPP) {
		t.Skipf("running kernel does not support TCP-AO: %v", err)
	}
	require.NoError(t, err)
}

func TestTCPAOKeyLifecycle(t *testing.T) {
	// create listener socket with one TCP-AO key
	peer := netip.MustParsePrefix("127.0.0.1/32")
	config := TCPAOConfig{Keys: []TCPAOKey{{
		SendID: 7, ReceiveID: 9, Algorithm: TCPAOAlgorithmHMACSHA1, MasterKey: []byte("secret"),
	}}}
	listenConfig := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		return AddTCPAOKeysSockopt(raw, peer, "", config)
	}}
	listenConfig.SetMultipathTCP(false)
	listener, err := listenConfig.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	t.Cleanup(func() { listener.Close() })
	skipTCPAONotSupported(t, err)

	tcpListener, ok := listener.(*net.TCPListener)
	require.True(t, ok)
	raw, err := tcpListener.SyscallConn()
	require.NoError(t, err)
	counters, err := GetTCPAOSocketCountersSockopt(raw)
	require.NoError(t, err)
	require.Equal(t, TCPAOSocketCounters{}, counters)

	// add another key
	addConfig := TCPAOConfig{Keys: []TCPAOKey{{
		SendID: 8, ReceiveID: 10, Algorithm: TCPAOAlgorithmHMACSHA1, MasterKey: []byte("secret"),
	}}}
	err = AddTCPAOKeysSockopt(raw, peer, "", addConfig)
	require.NoError(t, err)

	// get both keys
	states, err := GetTCPAOKeyStateSockopt(raw)
	require.NoError(t, err)
	require.Len(t, states, 2)
	statesBySendID := make(map[uint8]TCPAOKeyState, len(states))
	for _, state := range states {
		statesBySendID[state.SendID] = state
	}
	for _, key := range append(config.Keys, addConfig.Keys...) {
		state, ok := statesBySendID[key.SendID]
		require.True(t, ok)
		require.Equal(t, key.ReceiveID, state.ReceiveID)
	}

	// delete the first key
	err = DeleteTCPAOKeysSockopt(raw, peer, "", TCPAOConfig{Keys: []TCPAOKey{{
		SendID: 7, ReceiveID: 9,
	}}})
	require.NoError(t, err)
	states, err = GetTCPAOKeyStateSockopt(raw)
	require.NoError(t, err)
	require.Len(t, states, 1)
	require.Equal(t, uint8(8), states[0].SendID)
	require.Equal(t, uint8(10), states[0].ReceiveID)

	// delete the remaining key
	err = DeleteTCPAOKeysSockopt(raw, peer, "", TCPAOConfig{Keys: []TCPAOKey{{
		SendID: 8, ReceiveID: 10,
	}}})
	require.NoError(t, err)
	states, err = GetTCPAOKeyStateSockopt(raw)
	require.NoError(t, err)
	require.Empty(t, states)
}

func TestTCPAOKeySelection(t *testing.T) {
	// create server socket with two TCP-AO keys
	peer := netip.MustParsePrefix("127.0.0.1/32")
	serverConfig := TCPAOConfig{Keys: []TCPAOKey{
		{SendID: 20, ReceiveID: 10, Algorithm: TCPAOAlgorithmHMACSHA1, MasterKey: []byte("secret")},
		{SendID: 21, ReceiveID: 11, Algorithm: TCPAOAlgorithmHMACSHA1, MasterKey: []byte("secret")},
	}}
	listenConfig := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		return AddTCPAOKeysSockopt(raw, peer, "", serverConfig)
	}}
	listenConfig.SetMultipathTCP(false)
	listener, err := listenConfig.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	t.Cleanup(func() { listener.Close() })
	skipTCPAONotSupported(t, err)

	// create client socket with two TCP-AO keys
	current := uint8(10)
	clientConfig := TCPAOConfig{
		Keys: []TCPAOKey{
			{SendID: 10, ReceiveID: 20, Algorithm: TCPAOAlgorithmHMACSHA1, MasterKey: []byte("secret")},
			{SendID: 11, ReceiveID: 21, Algorithm: TCPAOAlgorithmHMACSHA1, MasterKey: []byte("secret")},
		},
		PreferredSendID: &current,
	}
	dialer := net.Dialer{Timeout: time.Second}
	dialer.SetMultipathTCP(false)
	dialer.Control = func(_, _ string, raw syscall.RawConn) error {
		return AddTCPAOKeysSockopt(raw, peer, "", clientConfig)
	}
	clientConn, err := dialer.DialContext(context.Background(), "tcp4", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { clientConn.Close() })
	clientRaw, err := clientConn.(*net.TCPConn).SyscallConn()
	require.NoError(t, err)

	// accept client connection
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.(*net.TCPListener).AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	var serverConn *net.TCPConn
	select {
	case serverConn = <-accepted:
	case err := <-acceptErr:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timed out accepting TCP-AO connection")
	}
	t.Cleanup(func() { serverConn.Close() })
	serverRaw, err := serverConn.SyscallConn()
	require.NoError(t, err)

	// set & verify ReceiveNext on client
	clientNext := uint8(11)
	clientConfig.PreferredSendID = &clientNext
	err = SetTCPAOKeySockopt(clientRaw, clientConfig, true, false)
	require.NoError(t, err)

	states, err := GetTCPAOKeyStateSockopt(clientRaw)
	require.NoError(t, err)
	require.Len(t, states, 2)
	statesBySendID := make(map[uint8]TCPAOKeyState, len(states))
	for _, state := range states {
		statesBySendID[state.SendID] = state
	}
	require.True(t, statesBySendID[current].Current)
	require.True(t, statesBySendID[clientNext].ReceiveNext)

	// set & verify Current on server
	serverNext := uint8(21)
	serverConfig.PreferredSendID = &serverNext
	err = SetTCPAOKeySockopt(serverRaw, serverConfig, false, true)
	require.NoError(t, err)

	states, err = GetTCPAOKeyStateSockopt(serverRaw)
	require.NoError(t, err)
	statesBySendID = make(map[uint8]TCPAOKeyState, len(states))
	for _, state := range states {
		statesBySendID[state.SendID] = state
	}
	require.True(t, statesBySendID[serverNext].Current)
}
