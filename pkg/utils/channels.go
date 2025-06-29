package utils

import (
	"github.com/eapache/channels"
)

func CleanInfiniteChannel(ch *channels.InfiniteChannel) {
	ch.Close()
	// drain all remaining items
	for range ch.Out() {
	}
}
