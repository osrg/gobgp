package server

import (
	"testing"

	"github.com/eapache/channels"
	"go.uber.org/goleak"
)

func TestCleanInfiniteChannelDrainsBufferedOutput(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	ch := channels.NewInfiniteChannel()
	for i := range 100 {
		ch.In() <- i
	}
	cleanInfiniteChannel(ch)
	// Rescue the worker on failure, but only after checking for leaks.
	defer func() {
		for range ch.Out() {
		}
	}()
	goleak.VerifyNone(t, baseline)
	select {
	case _, ok := <-ch.Out():
		if ok {
			t.Fatal("cleanup returned with buffered output still pending")
		}
	default:
		t.Fatal("cleanup returned before the output channel closed")
	}
}
