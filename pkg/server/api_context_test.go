package server

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/require"
)

// startContextServer starts a server whose management loop serves requests.
func startContextServer(t *testing.T) *BgpServer {
	t.Helper()
	s := NewBgpServer()
	t.Cleanup(s.bfdServer.Stop)
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	t.Cleanup(func() {
		//nolint: errcheck // ignore error
		s.StopBgp(context.Background(), &api.StopBgpRequest{})
	})
	return s
}

// blockLoop occupies the management loop until the returned function is
// called, as a long operation such as a large ListPath does. The returned
// function may be called more than once.
func blockLoop(t *testing.T, s *BgpServer) func() {
	t.Helper()
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		//nolint: errcheck // ignore error
		s.mgmtOperation(func() error {
			close(started)
			<-release
			return nil
		}, false)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("the management loop did not run the blocking operation")
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			close(release)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("the blocking operation did not finish")
			}
		})
	}
}

// returnsWhileBusy runs call while the management loop is held and returns
// its error. A call that is still waiting for the loop after its context
// ended fails the test instead of hanging it.
func returnsWhileBusy(t *testing.T, release func(), call func() error) error {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- call() }()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		release()
		t.Fatal("the request kept waiting for the busy management loop after its context ended")
		return nil
	}
}

func contextTestPath(t *testing.T, prefix string) *api.Path {
	t.Helper()
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	path, err := apiutil.NewPath(bgp.RF_IPv4_UC, nlri, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now())
	require.NoError(t, err)
	return path
}

func globalPrefixes(t *testing.T, s *BgpServer) []string {
	t.Helper()
	var prefixes []string
	require.NoError(t, s.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: bgp.RF_IPv4_UC},
		func(prefix bgp.NLRI, _ []*apiutil.Path) {
			prefixes = append(prefixes, prefix.String())
		}))
	return prefixes
}

// A gRPC AddPath whose deadline expires while the management loop is busy
// returns the deadline error, and the path is never added.
func TestGrpcAddPathDeadlineWhileLoopBusy(t *testing.T) {
	s := startContextServer(t)
	g := &server{bgpServer: s, shared: s.shared}
	release := blockLoop(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := returnsWhileBusy(t, release, func() error {
		_, err := g.AddPath(ctx, &api.AddPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Path: contextTestPath(t, "10.10.0.0/24")})
		return err
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	release()
	require.Empty(t, globalPrefixes(t, s))
}

// A gRPC DeletePath whose deadline expires while the management loop is busy
// returns the deadline error, and the path stays.
func TestGrpcDeletePathDeadlineWhileLoopBusy(t *testing.T) {
	s := startContextServer(t)
	g := &server{bgpServer: s, shared: s.shared}
	path := contextTestPath(t, "10.10.0.0/24")
	_, err := g.AddPath(context.Background(), &api.AddPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Path: path})
	require.NoError(t, err)
	release := blockLoop(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err = returnsWhileBusy(t, release, func() error {
		_, err := g.DeletePath(ctx, &api.DeletePathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Path: path})
		return err
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	release()
	require.Equal(t, []string{"10.10.0.0/24"}, globalPrefixes(t, s))
}

// A batch of AddPathStream whose context ends while the management loop is
// busy is not added.
func TestAddPathStreamCanceledWhileLoopBusy(t *testing.T) {
	s := startContextServer(t)
	path, err := api2Path(api.TableType_TABLE_TYPE_GLOBAL, contextTestPath(t, "10.10.0.0/24"))
	require.NoError(t, err)
	release := blockLoop(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = returnsWhileBusy(t, release, func() error {
		return s.addPathStream(ctx, "", []*table.Path{path})
	})
	require.ErrorIs(t, err, context.Canceled)
	release()
	require.Empty(t, globalPrefixes(t, s))
}

// The public AddPath and DeletePath keep working without a context.
func TestAddDeletePathWithoutContext(t *testing.T) {
	s := startContextServer(t)
	path := mustApi2apiutilPath(contextTestPath(t, "10.10.0.0/24"))
	_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{path}})
	require.NoError(t, err)
	require.Equal(t, []string{"10.10.0.0/24"}, globalPrefixes(t, s))
	require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{path}}))
	require.Empty(t, globalPrefixes(t, s))
}
