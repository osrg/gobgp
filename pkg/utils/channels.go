package utils

import (
	"context"

	"github.com/eapache/channels"
)

func CleanInfiniteChannel(ch *channels.InfiniteChannel) {
	ch.Close()
	// drain all remaining items
	for range ch.Out() {
	}
}

func PushWithContext[T any](ctx context.Context, ch chan<- T, item T) bool {
	select {
	case <-ctx.Done():
		return false
	case ch <- item:
		return true
	}
}
