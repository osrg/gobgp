package channels

import (
	"time"

	api "github.com/osrg/gobgp/v4/api"
)

type Channel interface {
	Push(m any, timeout time.Duration) bool
	Out() <-chan any

	Stats() *api.ChannelState
	Clean()
	Close()

	// Signals that the consumer has terminated,
	// and all subsequent input packets can be released immediately.
	SetConsumerClosed()
}
