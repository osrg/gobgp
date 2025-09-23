package config

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"testing"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ErrorCaptureHandler struct {
	configErrors []string
	baseHandler  slog.Handler
}

func (h *ErrorCaptureHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.baseHandler.Enabled(context.Background(), level)
}

func (h *ErrorCaptureHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Level >= slog.LevelError {
		h.configErrors = append(h.configErrors, record.Message)
	}
	return h.baseHandler.Handle(ctx, record)
}

func (h *ErrorCaptureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ErrorCaptureHandler{
		configErrors: h.configErrors,
		baseHandler:  h.baseHandler.WithAttrs(attrs),
	}
}

func (h *ErrorCaptureHandler) WithGroup(name string) slog.Handler {
	return &ErrorCaptureHandler{
		configErrors: h.configErrors,
		baseHandler:  h.baseHandler.WithGroup(name),
	}
}

func TestConfigErrors(t *testing.T) {
	globalCfg := oc.Global{
		Config: oc.GlobalConfig{
			As:       1,
			RouterId: netip.MustParseAddr("1.1.1.1"),
			Port:     11179,
		},
	}

	for _, tt := range []struct {
		name           string
		expectedErrors []string
		cfg            *oc.BgpConfigSet
	}{
		{
			name: "peer with a valid peer-group",
			cfg: &oc.BgpConfigSet{
				Global: globalCfg,
				Neighbors: []oc.Neighbor{
					{
						Config: oc.NeighborConfig{
							PeerGroup:       "router",
							NeighborAddress: netip.MustParseAddr("1.1.1.2"),
						},
					},
				},
				PeerGroups: []oc.PeerGroup{
					{
						Config: oc.PeerGroupConfig{
							PeerGroupName: "router",
							PeerAs:        2,
						},
					},
				},
			},
		},
		{
			name:           "peer without peer-group",
			expectedErrors: []string{"Failed to add Peer"},
			cfg: &oc.BgpConfigSet{
				Global: globalCfg,
				Neighbors: []oc.Neighbor{
					{
						Config: oc.NeighborConfig{
							PeerGroup:       "not-exists",
							NeighborAddress: netip.MustParseAddr("1.1.1.2"),
						},
					},
				},
			},
		},
		{
			name:           "policy without a set",
			expectedErrors: []string{"failed to create routing policy", "failed to set policies"},
			cfg: &oc.BgpConfigSet{
				Global: globalCfg,
				PolicyDefinitions: []oc.PolicyDefinition{
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
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			basehandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
			handler := ErrorCaptureHandler{baseHandler: basehandler}
			logger := slog.New(&handler)

			bgpServer := server.NewBgpServer(server.LoggerOption(logger, &slog.LevelVar{}))
			go bgpServer.Serve()

			_, err := InitialConfig(ctx, bgpServer, tt.cfg, false)
			require.NoError(t, err)
			err = bgpServer.StopBgp(ctx, &api.StopBgpRequest{})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedErrors, handler.configErrors)
		})
	}
}
