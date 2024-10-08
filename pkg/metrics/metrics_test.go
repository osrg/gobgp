package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apb "google.golang.org/protobuf/types/known/anypb"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
)

func TestMetrics(test *testing.T) {
	assert := assert.New(test)
	s := server.NewBgpServer()

	registry := prometheus.NewRegistry()
	registry.MustRegister(NewBgpCollector(s))

	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.Nil(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	p1 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         2,
		},
		Transport: &api.Transport{
			PassiveMode: true,
		},
	}
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p1})
	assert.Nil(err)

	t := server.NewBgpServer()
	go t.Serve()
	err = t.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	assert.Nil(err)
	defer t.StopBgp(context.Background(), &api.StopBgpRequest{})

	p2 := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         1,
		},
		Transport: &api.Transport{
			RemotePort: 10179,
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				ConnectRetry:           1,
				IdleHoldTimeAfterReset: 1,
			},
		},
	}

	ch := make(chan struct{})
	s.WatchEvent(context.Background(), &api.WatchEventRequest{Peer: &api.WatchEventRequest_Peer{}}, func(r *api.WatchEventResponse) {
		if peer := r.GetPeer(); peer != nil {
			if peer.Type == api.WatchEventResponse_PeerEvent_STATE && peer.Peer.State.SessionState == api.PeerState_ESTABLISHED {
				close(ch)
			}
		}
	})

	err = t.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p2})
	assert.Nil(err)
	<-ch

	family := &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_UNICAST,
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch = make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				ch <- struct{}{}
				return
			default:
				nlri1, _ := apb.New(&api.IPAddressPrefix{
					Prefix:    "10.1.0.0",
					PrefixLen: 24,
				})

				a1, _ := apb.New(&api.OriginAttribute{
					Origin: 0,
				})
				a2, _ := apb.New(&api.NextHopAttribute{
					NextHop: "10.0.0.1",
				})
				attrs := []*apb.Any{a1, a2}

				t.AddPath(context.Background(), &api.AddPathRequest{
					TableType: api.TableType_GLOBAL,
					Path: &api.Path{
						Family: family,
						Nlri:   nlri1,
						Pattrs: attrs,
					},
				})
				t.DeletePath(context.Background(), &api.DeletePathRequest{
					TableType: api.TableType_GLOBAL,
					Path: &api.Path{
						Family: family,
						Nlri:   nlri1,
						Pattrs: attrs,
					},
				})
			}
		}
	}()

	for i := 0; i < 100; i++ {
		metrics, err := registry.Gather()
		assert.Nil(err)
		assert.NotEmpty(metrics)
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-ch
}

func TestFSMLoopMetrics(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	fsmCollector := NewFSMTimingsCollector()
	registry := prometheus.NewRegistry()
	err := registry.Register(fsmCollector)
	assert.NoError(err)

	s := server.NewBgpServer(server.TimingHookOption(fsmCollector))
	go s.Serve()

	const metricName = "fsm_loop_mgmt_op_timing_sec"
	metrics, err := registry.Gather()
	require.NoError(err)
	hist := getMetric(metrics, metricName)
	require.NotNil(hist)
	assert.Equal(uint64(0), *hist.Metric[0].Histogram.SampleCount)

	err = s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        2,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	require.NoError(err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// StartBgp counts as single management operation
	metrics, err = registry.Gather()
	require.NoError(err)
	hist = getMetric(metrics, metricName)
	require.NotNil(hist)
	assert.Equal(uint64(1), *hist.Metric[0].Histogram.SampleCount)
}

func getMetric(metrics []*dto.MetricFamily, metricName string) *dto.MetricFamily {
	for _, m := range metrics {
		if m.GetName() == metricName {
			return m
		}
	}
	return nil
}
