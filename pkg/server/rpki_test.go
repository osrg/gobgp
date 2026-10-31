// Copyright (C) 2015-2021 Nippon Telegraph and Telephone Corporation.
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
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/rtr"
)

func Test_readRTRMessageRejectsOversizedLength(t *testing.T) {
	header := make([]byte, rtr.RTR_MIN_LEN)
	header[0] = 1 // Protocol Version
	header[1] = rtr.RTR_CACHE_RESET
	binary.BigEndian.PutUint32(header[4:8], 0xffffffff)

	if _, err := readRTRMessage(bytes.NewReader(header)); err == nil {
		t.Fatal("expected an error when the RTR Length is too large, got nil")
	}
}

func Test_readRTRMessageAcceptsValidLength(t *testing.T) {
	header := make([]byte, rtr.RTR_MIN_LEN)
	header[0] = 1 // Protocol Version
	header[1] = rtr.RTR_CACHE_RESET
	binary.BigEndian.PutUint32(header[4:8], rtr.RTR_MIN_LEN)

	data, err := readRTRMessage(bytes.NewReader(header))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != rtr.RTR_MIN_LEN {
		t.Fatalf("expected %d bytes, got %d", rtr.RTR_MIN_LEN, len(data))
	}
}

func TestROAManagerDisableDeletesROAsByServerKey(t *testing.T) {
	rt := table.NewROATable(slog.Default())
	serverKey := net.JoinHostPort("192.0.2.1", "323")
	rt.Add(table.NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 24, 24, 65000, serverKey))

	m := &roaManager{
		clientMap: map[string]*roaClient{
			serverKey: {host: serverKey},
		},
		table:  rt,
		logger: slog.Default(),
	}

	if records, _ := rt.Info(bgp.RF_IPv4_UC); records[serverKey] != 1 {
		t.Fatalf("expected one ROA before disable, got %d", records[serverKey])
	}

	if err := m.Disable("192.0.2.1"); err != nil {
		t.Fatalf("unexpected disable error: %v", err)
	}

	if records, _ := rt.Info(bgp.RF_IPv4_UC); records[serverKey] != 0 {
		t.Fatalf("expected ROAs for %q to be deleted, got %d", serverKey, records[serverKey])
	}
}

func TestROAManagerResetQueryReplacesROAs(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(io.Discard, c)
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	rt := table.NewROATable(slog.Default())
	serverKey := net.JoinHostPort("192.0.2.1", "323")
	client := &roaClient{host: serverKey, conn: conn.(*net.TCPConn)}
	m := &roaManager{
		clientMap: map[string]*roaClient{serverKey: client},
		table:     rt,
		logger:    slog.Default(),
	}
	recv := func(msg rtr.RTRMessage) {
		data, err := msg.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		m.handleRTRMsg(client, &client.state, data)
	}
	announce := func(prefix string) {
		recv(rtr.NewRTRIPPrefix(netip.MustParseAddr(prefix), 24, 24, 65000, 1))
	}
	records := func() uint32 {
		r, _ := rt.Info(bgp.RF_IPv4_UC)
		return r[serverKey]
	}

	// The Reset Query sent when the session comes up.
	if err := client.softReset(); err != nil {
		t.Fatal(err)
	}
	recv(rtr.NewRTRCacheResponse(1))
	announce("10.0.0.0")
	announce("10.0.1.0")
	recv(rtr.NewRTREndOfData(1, 1))
	if got := records(); got != 2 {
		t.Fatalf("expected 2 ROAs after the first Reset Query, got %d", got)
	}

	// The cache cannot answer a Serial Query and sends Cache Reset.
	// 10.0.1.0/24 was removed in the meantime, so the answer to the
	// Reset Query no longer has it.
	recv(rtr.NewRTRCacheReset())
	recv(rtr.NewRTRCacheResponse(1))
	announce("10.0.0.0")
	recv(rtr.NewRTREndOfData(1, 5))
	if got := records(); got != 1 {
		t.Fatalf("expected 1 ROA after a Reset Query in the same session, got %d", got)
	}

	// The answer to a Serial Query is incremental.
	recv(rtr.NewRTRCacheResponse(1))
	announce("10.0.2.0")
	recv(rtr.NewRTREndOfData(1, 6))
	if got := records(); got != 2 {
		t.Fatalf("expected 2 ROAs after a Serial Query, got %d", got)
	}
}

func TestROAManagerEndOfDataStopsLifetimeTimer(t *testing.T) {
	// A canceled context keeps tryConnect from dialing.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rt := table.NewROATable(slog.Default())
	serverKey := net.JoinHostPort("192.0.2.1", "323")
	eventCh := make(chan *roaEvent)
	client := &roaClient{host: serverKey, eventCh: eventCh, lifetime: 1, ctx: ctx}
	m := &roaManager{
		clientMap: map[string]*roaClient{serverKey: client},
		table:     rt,
		logger:    slog.Default(),
	}
	recv := func(msg rtr.RTRMessage) {
		data, err := msg.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		m.handleRTRMsg(client, &client.state, data)
	}
	reload := func(serial uint32) {
		recv(rtr.NewRTRCacheResponse(1))
		recv(rtr.NewRTRIPPrefix(netip.MustParseAddr("10.0.0.0"), 24, 24, 65000, 1))
		recv(rtr.NewRTREndOfData(1, serial))
	}
	disconnect := func() {
		m.HandleROAEvent(&roaEvent{EventType: roaDisconnected, Src: serverKey})
	}
	records := func() uint32 {
		r, _ := rt.Info(bgp.RF_IPv4_UC)
		return r[serverKey]
	}

	reload(1)

	// The session drops, comes back and drops again before End of Data, and
	// the next session reloads the ROAs. The Session ID stays the same, as
	// it does unless the cache restarts.
	disconnect()
	disconnect()
	reload(2)

	select {
	case ev := <-eventCh:
		m.HandleROAEvent(ev)
	case <-time.After(1500 * time.Millisecond):
	}
	if got := records(); got != 1 {
		t.Fatalf("expected the reloaded ROA to outlive the lifetime, got %d", got)
	}

	// A cache that stays away still loses its ROAs.
	disconnect()
	select {
	case ev := <-eventCh:
		m.HandleROAEvent(ev)
	case <-time.After(5 * time.Second):
		t.Fatal("the lifetime timer did not fire")
	}
	if got := records(); got != 0 {
		t.Fatalf("expected the ROA to expire with the lifetime, got %d", got)
	}
}

func TestDeleteRpki(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	add := func() error {
		return s.AddRpki(context.Background(), &api.AddRpkiRequest{Address: "192.0.2.1", Port: 323})
	}
	del := func() error {
		return s.DeleteRpki(context.Background(), &api.DeleteRpkiRequest{Address: "192.0.2.1", Port: 323})
	}

	if err := add(); err != nil {
		t.Fatal(err)
	}
	if err := del(); err != nil {
		t.Fatal(err)
	}
	// The server is gone, so it cannot be deleted twice, and it can be
	// added again.
	if err := del(); err == nil {
		t.Fatal("deleted a server twice")
	}
	if err := add(); err != nil {
		t.Fatal(err)
	}
	if err := del(); err != nil {
		t.Fatal(err)
	}
}
