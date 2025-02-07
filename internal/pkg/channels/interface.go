package channels

import api "github.com/osrg/gobgp/v3/api"

type Channel interface {
	In() chan<- any
	Out() <-chan any
	Stats() *api.ChannelState
	Clean()
	Close()
}
