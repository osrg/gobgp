package channels

import (
	"github.com/eapache/channels"
	api "github.com/osrg/gobgp/v3/api"
)

type InfiniteChannel struct {
	channels.InfiniteChannel
}

func NewInfiniteChannel() *InfiniteChannel {
	return &InfiniteChannel{
		InfiniteChannel: *channels.NewInfiniteChannel(),
	}
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
