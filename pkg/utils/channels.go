package utils

import (
	"context"

	"github.com/eapache/channels"
)

type NotificationChannel struct {
	C chan any
}

func NewNotificationChannel() *NotificationChannel {
	return &NotificationChannel{
		C: make(chan any, 1),
	}
}

func (nc *NotificationChannel) Notify() {
	select {
	case nc.C <- struct{}{}:
	default:
	}
}

func (nc *NotificationChannel) Clear() {
	select {
	case <-nc.C:
	default:
	}
}

func CleanInfiniteChannel(ch *channels.InfiniteChannel) {
	ch.Close()
	// drain all remaining items
	for range ch.Out() {
	}
}

func PushWithContext[T any](ctx context.Context, ch chan<- T, item T, wait bool) bool {
	if wait {
		select {
		case <-ctx.Done():
			return false
		case ch <- item:
			return true
		}
	} else {
		select {
		case <-ctx.Done():
			return false
		case ch <- item:
			return true
		default:
			return false
		}
	}
}
