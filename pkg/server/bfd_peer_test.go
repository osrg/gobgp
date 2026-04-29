package server

import (
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bfd"
	"github.com/stretchr/testify/assert"
)

func Test_NewBfdPeer(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), "127.0.0.1", oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	})
	defer p.Stop()

	assert.NotNil(p)
}

func Test_RxPacket(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), "127.0.0.1", oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	})

	assert.Equal(p.stats.rxPacket.Load(), uint64(0))

	p.Rx(&bfd.BFDHeader{})

	time.Sleep(2 * time.Second)
	p.Stop()

	assert.NotEqual(p.stats.rxPacket.Load(), uint64(0))
}

func Test_TxPacket(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	p := NewBfdPeer(ps, slog.Default(), "127.0.0.1", oc.BfdConfig{
		Port:                     13784,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	})

	err := eventually(4*time.Second, func() error {
		if p.stats.txPacket.Load() > 3 {
			return nil
		}
		return fmt.Errorf("must be: txPacket > 3")
	})
	assert.NoError(err)

	p.Stop()
}
