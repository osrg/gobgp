package channels

import (
	"time"

	"github.com/eapache/channels"
	api "github.com/osrg/gobgp/v4/api"
)

type InfiniteChannel struct {
	channels.InfiniteChannel
}

func NewInfiniteChannel() *InfiniteChannel {
	return &InfiniteChannel{
		InfiniteChannel: *channels.NewInfiniteChannel(),
	}
}

func (ch *InfiniteChannel) Push(m any, _ time.Duration) bool {
	ch.In() <- m
	return true
}

func (ch *InfiniteChannel) Stats() *api.ChannelState {
	return nil
}

func (ch *InfiniteChannel) Clean() {
	ch.Close()
	// drain all remaining items
	for range ch.Out() {
	}
}

func (ch *InfiniteChannel) SetConsumerClosed() {
}
