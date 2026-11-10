package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/require"
)

// These tests use real TCP peers and a receiver-owned (prefix, Path-ID) state.
// They require Linux's 127/8 loopback; no system configuration is changed.
func wireServer(t *testing.T) (*BgpServer, int) {
	t.Helper()
	probe, err := net.Listen("tcp4", "127.0.0.2:0")
	if err != nil && runtime.GOOS == "darwin" {
		t.Skipf("requires additional loopback addresses: %v", err)
	}
	require.NoError(t, err)
	require.NoError(t, probe.Close())
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	s := NewBgpServer()
	go s.Serve()
	t.Cleanup(s.Stop)
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{Global: &api.Global{Asn: 65000, RouterId: "192.0.2.254", ListenPort: int32(port), ListenAddresses: []string{"127.0.0.1"}}}))
	return s, port
}

func wireRead(c net.Conn) ([]byte, error) {
	const headerLen = 19
	header := make([]byte, headerLen)
	if n, err := io.ReadFull(c, header); err != nil {
		if n > 0 {
			return nil, fmt.Errorf("partial BGP header (%d bytes): %w", n, err)
		}
		return nil, err
	}
	if !bytes.Equal(header[:16], bytes.Repeat([]byte{0xff}, 16)) {
		return nil, fmt.Errorf("invalid BGP marker")
	}
	size := int(binary.BigEndian.Uint16(header[16:18]))
	if size < headerLen || size > 4096 {
		return nil, fmt.Errorf("invalid BGP length %d", size)
	}
	data := make([]byte, size)
	copy(data, header)
	if _, err := io.ReadFull(c, data[headerLen:]); err != nil {
		return nil, fmt.Errorf("partial BGP body: %w", err)
	}
	return data, nil
}

func wireSend(t *testing.T, c net.Conn, m *bgp.BGPMessage) {
	t.Helper()
	data, err := m.Serialize()
	require.NoError(t, err)
	require.NoError(t, c.SetWriteDeadline(time.Now().Add(3*time.Second)))
	_, err = io.Copy(c, bytes.NewReader(data))
	require.NoError(t, err)
}

func wirePeer(t *testing.T, s *BgpServer, port int, addr string, asn, sendMax uint32) net.Conn {
	t.Helper()
	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: addr, PeerAsn: asn},
		Transport: &api.Transport{PassiveMode: true, LocalAddress: "127.0.0.1"},
		Timers:    &api.Timers{Config: &api.TimersConfig{HoldTime: 90}},
		AfiSafis:  []*api.AfiSafi{{Config: &api.AfiSafiConfig{Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}}, AddPaths: &api.AddPaths{Config: &api.AddPathsConfig{SendMax: sendMax}}}},
	}}))
	d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(addr)}}
	c, err := d.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	caps := []bgp.ParameterCapabilityInterface{bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC), bgp.NewCapFourOctetASNumber(asn), bgp.NewCapRouteRefresh()}
	if sendMax > 0 {
		caps = append(caps, bgp.NewCapAddPath([]*bgp.CapAddPathTuple{bgp.NewCapAddPathTuple(bgp.RF_IPv4_UC, bgp.BGP_ADD_PATH_RECEIVE)}))
	}
	open, err := bgp.NewBGPOpenMessage(uint16(asn), 90, netip.MustParseAddr(addr), []bgp.OptionParameterInterface{bgp.NewOptionParameterCapability(caps)})
	require.NoError(t, err)
	wireSend(t, c, open)
	require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	raw, err := wireRead(c)
	require.NoError(t, err)
	require.Equal(t, byte(1), raw[18])
	msg, err := bgp.ParseBGPMessage(raw)
	require.NoError(t, err)
	hasRefresh, hasSend := false, false
	for _, opt := range msg.Body.(*bgp.BGPOpen).OptParams {
		if cp, ok := opt.(*bgp.OptionParameterCapability); ok {
			for _, cap := range cp.Capability {
				switch v := cap.(type) {
				case *bgp.CapRouteRefresh:
					hasRefresh = true
				case *bgp.CapAddPath:
					for _, tuple := range v.Tuples {
						if tuple.Family == bgp.RF_IPv4_UC && tuple.Mode&bgp.BGP_ADD_PATH_SEND != 0 {
							hasSend = true
						}
					}
				}
			}
		}
	}
	require.True(t, hasRefresh, "server must negotiate Route Refresh")
	require.Equal(t, sendMax > 0, hasSend, "ADD-PATH send capability")
	wireSend(t, c, bgp.NewBGPKeepAliveMessage())
	raw, err = wireRead(c)
	require.NoError(t, err)
	require.Equal(t, byte(4), raw[18])
	require.Eventually(t, func() bool {
		established := false
		err := s.ListPeer(context.Background(), &api.ListPeerRequest{Address: addr}, func(p *api.Peer) { established = p.State.SessionState == api.PeerState_SESSION_STATE_ESTABLISHED })
		return err == nil && established
	}, 3*time.Second, 10*time.Millisecond)
	t.Cleanup(func() {
		var p *api.Peer
		err := s.ListPeer(context.Background(), &api.ListPeerRequest{Address: addr}, func(got *api.Peer) { p = got })
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Equal(t, api.PeerState_SESSION_STATE_ESTABLISHED, p.State.SessionState)
	})
	return c
}

func wireUpdate(t *testing.T, c net.Conn, withdraw bool, asns ...uint32) {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.231.0.0/24"))
	require.NoError(t, err)
	paths := []bgp.PathNLRI{{NLRI: nlri}}
	if withdraw {
		wireSend(t, c, bgp.NewBGPUpdateMessage(paths, nil, nil))
		return
	}
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.9"))
	require.NoError(t, err)
	wireSend(t, c, bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asns)}), nh}, paths))
}

// No production UPDATE decoder or sent-path bookkeeping is used for the oracle.
func wireCollect(t *testing.T, c net.Conn, state map[uint32]bool, addPath bool, duration time.Duration) (announced, withdrawn int) {
	t.Helper()
	deadline := time.Now().Add(duration)
	require.NoError(t, c.SetReadDeadline(deadline))
	for {
		raw, err := wireRead(c)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				return
			}
			require.NoError(t, err)
		}
		require.NotEqual(t, byte(3), raw[18], "BGP NOTIFICATION: %x", raw)
		if raw[18] != 2 {
			continue
		}
		body := raw[19:]
		require.GreaterOrEqual(t, len(body), 4)
		n := int(binary.BigEndian.Uint16(body))
		require.GreaterOrEqual(t, len(body), n+4)
		attrs := int(binary.BigEndian.Uint16(body[2+n:]))
		require.GreaterOrEqual(t, len(body), 4+n+attrs)
		apply := func(data []byte, del bool) {
			for len(data) > 0 {
				id := uint32(0)
				if addPath {
					require.GreaterOrEqual(t, len(data), 5)
					id = binary.BigEndian.Uint32(data)
					data = data[4:]
				}
				bits := int(data[0])
				width := (bits + 7) / 8
				require.LessOrEqual(t, bits, 32)
				require.GreaterOrEqual(t, len(data), width+1)
				prefix := data[1 : 1+width]
				data = data[1+width:]
				if bits != 24 || len(prefix) != 3 || prefix[0] != 10 || prefix[1] != 231 || prefix[2] != 0 {
					continue
				}
				if del {
					delete(state, id)
					withdrawn++
				} else {
					state[id] = true
					announced++
				}
			}
		}
		apply(body[2:2+n], true)
		apply(body[4+n+attrs:], false)
	}
}

func wireRIBCount(t *testing.T, s *BgpServer, count int) {
	wirePathCount(t, s, api.TableType_TABLE_TYPE_GLOBAL, "", count)
}

func wirePathCount(t *testing.T, s *BgpServer, typ api.TableType, name string, count int) {
	t.Helper()
	require.Eventually(t, func() bool {
		n := 0
		err := s.ListPath(apiutil.ListPathRequest{TableType: typ, Name: name, EnableFiltered: true, Family: bgp.RF_IPv4_UC, Prefixes: []*apiutil.LookupPrefix{{Prefix: "10.231.0.0/24", LookupOption: apiutil.LOOKUP_EXACT}}}, func(_ bgp.NLRI, p []*apiutil.Path) { n += len(p) })
		return err == nil && n == count
	}, 3*time.Second, 10*time.Millisecond)
}
