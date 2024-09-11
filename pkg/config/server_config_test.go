package config

import (
	"context"
	"testing"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/config/oc"
	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type configErrorLogger struct {
	log.DefaultLogger

	configErrors []string
}

func (l *configErrorLogger) Fatal(msg string, fields log.Fields) {
	if fields.HasFacility(log.FacilityConfig) {
		l.configErrors = append(l.configErrors, msg)
		l.DefaultLogger.Error(msg, fields)
	} else {
		l.DefaultLogger.Fatal(msg, fields)
	}
}

func TestConfigErrors(t *testing.T) {
	globalCfg := oc.Global{
		Config: oc.GlobalConfig{
			As:       1,
			RouterId: "1.1.1.1",
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
							NeighborAddress: "1.1.1.2",
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
							NeighborAddress: "1.1.1.2",
						},
					},
				},
			},
		},
		{
			name:           "policy without a set",
			expectedErrors: []string{"failed to create routing policy"},
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
			logger := &configErrorLogger{
				DefaultLogger: *log.NewDefaultLogger(),
			}
			bgpServer := server.NewBgpServer(server.LoggerOption(logger))
			go bgpServer.Serve()

			_, err := InitialConfig(ctx, bgpServer, tt.cfg, false)
			bgpServer.StopBgp(ctx, &api.StopBgpRequest{})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedErrors, logger.configErrors)
		})
	}
}
