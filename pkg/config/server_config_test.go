package config

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T) (*server.BgpServer, context.Context) {
	t.Helper()
	s := server.NewBgpServer()
	go s.Serve()
	t.Cleanup(func() { _ = s.StopBgp(context.Background(), &api.StopBgpRequest{}) })
	return s, context.Background()
}

func baseGlobal(port int32) oc.Global {
	return oc.Global{Config: oc.GlobalConfig{As: 65001, RouterId: netip.MustParseAddr("10.0.0.1"), Port: port}}
}

func listAggregates(t *testing.T, s *server.BgpServer, ctx context.Context) []*api.AggregateAddressInfo {
	t.Helper()
	var out []*api.AggregateAddressInfo
	require.NoError(t, s.ListAggregate(ctx, &api.ListAggregateRequest{}, func(a *api.AggregateAddressInfo) {
		out = append(out, a)
	}))
	return out
}

func TestInitialConfigAppliesAggregates(t *testing.T) {
	s, ctx := newTestServer(t)
	cfg := &oc.BgpConfigSet{
		Global: baseGlobal(-1),
	}
	cfg.Global.Aggregates = []oc.Aggregate{
		{Config: oc.AggregateConfig{Prefix: netip.MustParsePrefix("10.0.0.0/8"), SummaryOnly: true}},
	}
	_, err := InitialConfig(ctx, s, cfg, false)
	require.NoError(t, err)

	aggs := listAggregates(t, s, ctx)
	require.Len(t, aggs, 1)
	assert.Equal(t, "10.0.0.0/8", aggs[0].Aggregate.Prefix)
	assert.True(t, aggs[0].Aggregate.SummaryOnly)
}

func TestUpdateConfigAggregateDiff(t *testing.T) {
	s, ctx := newTestServer(t)
	initial := &oc.BgpConfigSet{Global: baseGlobal(-1)}
	initial.Global.Aggregates = []oc.Aggregate{
		{Config: oc.AggregateConfig{Prefix: netip.MustParsePrefix("10.0.0.0/8")}},
		{Config: oc.AggregateConfig{Prefix: netip.MustParsePrefix("192.168.0.0/16")}},
	}
	current, err := InitialConfig(ctx, s, initial, false)
	require.NoError(t, err)
	require.Len(t, listAggregates(t, s, ctx), 2)

	updated := &oc.BgpConfigSet{Global: baseGlobal(-1)}
	updated.Global.Aggregates = []oc.Aggregate{
		{Config: oc.AggregateConfig{Prefix: netip.MustParsePrefix("10.0.0.0/8"), SummaryOnly: true}},
		{Config: oc.AggregateConfig{Prefix: netip.MustParsePrefix("172.16.0.0/12")}},
	}
	_, err = UpdateConfig(ctx, s, current, updated)
	require.NoError(t, err)

	aggs := listAggregates(t, s, ctx)
	require.Len(t, aggs, 2)
	prefixes := map[string]bool{}
	for _, a := range aggs {
		prefixes[a.Aggregate.Prefix] = true
		if a.Aggregate.Prefix == "10.0.0.0/8" {
			assert.True(t, a.Aggregate.SummaryOnly)
		}
	}
	assert.True(t, prefixes["10.0.0.0/8"])
	assert.True(t, prefixes["172.16.0.0/12"])
	assert.False(t, prefixes["192.168.0.0/16"])
}

type ErrorCaptureHandler struct {
	mu           *sync.Mutex
	configErrors *[]string
	baseHandler  slog.Handler
}

func newErrorCaptureHandler() *ErrorCaptureHandler {
	configErrors := []string{}
	return &ErrorCaptureHandler{
		mu:           &sync.Mutex{},
		configErrors: &configErrors,
		baseHandler:  slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}),
	}
}

func (h *ErrorCaptureHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.baseHandler.Enabled(context.Background(), level)
}

func (h *ErrorCaptureHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Level >= slog.LevelError {
		h.mu.Lock()
		*h.configErrors = append(*h.configErrors, record.Message)
		h.mu.Unlock()
	}
	return h.baseHandler.Handle(ctx, record)
}

func (h *ErrorCaptureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ErrorCaptureHandler{
		mu:           h.mu,
		configErrors: h.configErrors,
		baseHandler:  h.baseHandler.WithAttrs(attrs),
	}
}

func (h *ErrorCaptureHandler) WithGroup(name string) slog.Handler {
	return &ErrorCaptureHandler{
		mu:           h.mu,
		configErrors: h.configErrors,
		baseHandler:  h.baseHandler.WithGroup(name),
	}
}

func (h *ErrorCaptureHandler) Errors() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]string(nil), *h.configErrors...)
}

func newTestBgpServer(t *testing.T) (*server.BgpServer, *ErrorCaptureHandler) {
	t.Helper()

	handler := newErrorCaptureHandler()
	logger := slog.New(handler)
	bgpServer := server.NewBgpServer(server.LoggerOption(logger, &slog.LevelVar{}))
	go bgpServer.Serve()
	t.Cleanup(bgpServer.Stop)
	return bgpServer, handler
}

func testGlobalConfig() oc.Global {
	return oc.Global{
		Config: oc.GlobalConfig{
			As:       1,
			RouterId: netip.MustParseAddr("1.1.1.1"),
			Port:     -1,
		},
	}
}

func validConfig() *oc.BgpConfigSet {
	return &oc.BgpConfigSet{
		Global: testGlobalConfig(),
	}
}

func configWithValidPeerGroup() *oc.BgpConfigSet {
	cfg := validConfig()
	cfg.Neighbors = []oc.Neighbor{
		{
			Config: oc.NeighborConfig{
				PeerGroup:       "router",
				NeighborAddress: netip.MustParseAddr("1.1.1.2"),
			},
		},
	}
	cfg.PeerGroups = []oc.PeerGroup{
		{
			Config: oc.PeerGroupConfig{
				PeerGroupName: "router",
				PeerAs:        2,
			},
		},
	}
	return cfg
}

func configWithMissingPeerGroup() *oc.BgpConfigSet {
	cfg := validConfig()
	cfg.Neighbors = []oc.Neighbor{
		{
			Config: oc.NeighborConfig{
				PeerGroup:       "not-exists",
				NeighborAddress: netip.MustParseAddr("1.1.1.2"),
			},
		},
	}
	return cfg
}

func configWithMissingPolicySet() *oc.BgpConfigSet {
	cfg := validConfig()
	cfg.PolicyDefinitions = []oc.PolicyDefinition{
		{
			Name: "policy-without-a-set",
			Statements: []oc.Statement{
				{
					Conditions: oc.Conditions{
						MatchNeighborSet: oc.MatchNeighborSet{
							NeighborSet: "not-existing-neighbor-set",
						},
					},
				},
			},
		},
	}
	return cfg
}

func TestInitialConfigAppliesValidConfig(t *testing.T) {
	ctx := context.Background()
	bgpServer, handler := newTestBgpServer(t)

	_, err := InitialConfig(ctx, bgpServer, configWithValidPeerGroup(), false)
	require.NoError(t, err)
	assert.Empty(t, handler.Errors())
}

func TestInitialConfigReturnsConfigErrors(t *testing.T) {
	for _, tt := range []struct {
		name        string
		expectedErr string
		expectedLog string
		cfg         *oc.BgpConfigSet
	}{
		{
			name:        "peer without peer-group",
			expectedErr: "failed to add peer",
			expectedLog: "failed to add peer",
			cfg:         configWithMissingPeerGroup(),
		},
		{
			name:        "policy without a set",
			expectedErr: "failed to set policies",
			expectedLog: "failed to set policies",
			cfg:         configWithMissingPolicySet(),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			bgpServer, handler := newTestBgpServer(t)

			_, err := InitialConfig(ctx, bgpServer, tt.cfg, false)
			require.ErrorContains(t, err, tt.expectedErr)
			assert.Contains(t, handler.Errors(), tt.expectedLog)
		})
	}
}

func TestUpdateConfigKeepsConfigErrorsNonFatal(t *testing.T) {
	ctx := context.Background()
	bgpServer, handler := newTestBgpServer(t)

	currentConfig, err := InitialConfig(ctx, bgpServer, validConfig(), false)
	require.NoError(t, err)

	_, err = UpdateConfig(ctx, bgpServer, currentConfig, configWithMissingPolicySet())
	require.NoError(t, err)

	assert.Contains(t, handler.Errors(), "failed to set policies")
}
