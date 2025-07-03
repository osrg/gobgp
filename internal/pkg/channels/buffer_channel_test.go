package channels

import (
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

type msg struct {
	index    int
	pathList []*table.Path
}

func (m *msg) PathList() []*table.Path {
	return m.pathList
}

func (m *msg) SetPathList(pathList []*table.Path) {
	m.pathList = pathList
}

var _ BufferMessageInterface = &msg{}

func TestBase(t *testing.T) {
	pc := NewBufferChannel(8)
	defer pc.Close()

	pc.Push(&msg{
		index: 1,
	}, 0)
	pc.Push(&msg{
		index: 2,
	}, 0)
	pc.Push(&msg{
		index: 3,
	}, 0)
	pc.Push(&msg{
		index: 4,
	}, 0)

	// wait bufferChannel.serve()
	time.Sleep(1 * time.Second)

	{
		m := <-pc.Out()
		assert.Equal(t, m.(*msg).index, 1)
	}
	{
		m := <-pc.Out()
		assert.Equal(t, m.(*msg).index, 2)
	}
	{
		m := <-pc.Out()
		assert.Equal(t, m.(*msg).index, 3)
	}
	{
		m := <-pc.Out()
		assert.Equal(t, m.(*msg).index, 4)
	}

	time.Sleep(1 * time.Second)
	select {
	case <-pc.Out():
		assert.Fail(t, "channel not empty")
	default:
	}

	stats := pc.Stats()
	assert.Equal(t, stats, &api.ChannelState{
		In:            4,
		Notifications: 4,
		Collected:     0,
		Rewritten:     0,
		Retries:       0,
		Out:           4,
	})
}

func newPath4(ipAddress string, community uint32) *table.Path {
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeCommunities([]uint32{community})}
	path := table.NewPath(nil,
		bgp.NewIPAddrPrefix(32, ipAddress),
		false, attrs, time.Now(), false)
	path.SetTimestamp(time.Time{})
	return path
}

func newPathLabelled4(ipAddress string, community uint32) *table.Path {
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeCommunities([]uint32{community})}
	path := table.NewPath(nil,
		bgp.NewLabeledIPAddrPrefix(32, ipAddress, bgp.MPLSLabelStack{
			Labels: []uint32{community},
		}),
		false, attrs, time.Now(), false)
	path.SetTimestamp(time.Time{})
	return path
}

func newPathWithPI4(ipAddress string, community uint32, pi uint32) *table.Path {
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeCommunities([]uint32{community})}
	path := table.NewPath(nil,
		bgp.NewIPAddrPrefix(32, ipAddress),
		false, attrs, time.Now(), false)
	path.GetNlri().SetPathIdentifier(pi)
	path.SetTimestamp(time.Time{})
	return path
}

func TestCollect(t *testing.T) {
	pc := NewBufferChannel(1)
	defer pc.Close()

	pc.Push(&msg{
		index: 1,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 1),
		},
	}, 0)
	pc.Push(&msg{
		index: 2,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 2),
		},
	}, 0)
	pc.Push(&msg{
		index: 3,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 3),
		},
	}, 0)
	pc.Push(&msg{
		index: 4,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 4),
		},
	}, 0)

	// wait bufferChannel.serve()
	time.Sleep(1 * time.Second)

	{
		m := (<-pc.Out()).(*msg)
		assert.Equal(t, m.index, 4)

		path := newPath4("10.0.0.100", 4)
		assert.Equal(t, m.PathList(), []*table.Path{path})
	}

	time.Sleep(1 * time.Second)
	select {
	case <-pc.Out():
		assert.Fail(t, "channel not empty")
	default:
	}

	stats := pc.Stats()
	assert.Equal(t, stats, &api.ChannelState{
		In:            4,
		Notifications: 0,
		Collected:     4,
		Rewritten:     3,
		Retries:       1,
		Out:           1,
	})
}

func TestCollectEquals(t *testing.T) {
	pc := NewBufferChannel(1)
	defer pc.Close()

	pc.Push(&msg{
		index: 1,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 1),
		},
	}, 0)
	pc.Push(&msg{
		index: 2,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 1),
		},
	}, 0)
	pc.Push(&msg{
		index: 3,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 1),
		},
	}, 0)
	pc.Push(&msg{
		index: 4,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 1),
		},
	}, 0)

	// wait bufferChannel.serve()
	time.Sleep(1 * time.Second)

	{
		m := (<-pc.Out()).(*msg)
		assert.Equal(t, m.index, 4)

		path := newPath4("10.0.0.100", 1)
		assert.Equal(t, m.PathList(), []*table.Path{path})
	}

	time.Sleep(1 * time.Second)
	select {
	case <-pc.Out():
		assert.Fail(t, "channel not empty")
	default:
	}

	// repeat
	pc.Push(&msg{
		index: 5,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 1),
		},
	}, 0)
	pc.Push(&msg{
		index: 6,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 1),
		},
	}, 0)
	pc.Push(&msg{
		index: 7,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 1),
		},
	}, 0)
	pc.Push(&msg{
		index: 8,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 1),
		},
	}, 0)

	// wait bufferChannel.serve()
	time.Sleep(1 * time.Second)

	{
		m := (<-pc.Out()).(*msg)
		assert.Equal(t, m.index, 8)

		path := newPath4("10.0.0.100", 1)
		assert.Equal(t, m.PathList(), []*table.Path{path})
	}

	time.Sleep(1 * time.Second)
	select {
	case <-pc.Out():
		assert.Fail(t, "channel not empty")
	default:
	}

	stats := pc.Stats()
	assert.Equal(t, stats, &api.ChannelState{
		In:            8,
		Notifications: 0,
		Collected:     8,
		Rewritten:     6,
		Retries:       2,
		Out:           2,
	})
}

func TestCollectMultiNlris(t *testing.T) {
	pc := NewBufferChannel(1)
	defer pc.Close()

	pc.Push(&msg{
		index: 1,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 1),
			newPath4("10.0.0.101", 11),
		},
	}, 0)
	pc.Push(&msg{
		index: 2,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 2),
			newPath4("10.0.0.102", 22),
		},
	}, 0)
	pc.Push(&msg{
		index: 3,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 3),
			newPath4("10.0.0.103", 33),
		},
	}, 0)
	pc.Push(&msg{
		index: 4,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 4),
			newPath4("10.0.0.104", 44),
		},
	}, 0)

	// wait bufferChannel.serve()
	time.Sleep(1 * time.Second)

	{
		m := (<-pc.Out()).(*msg)
		assert.Equal(t, m.index, 4)

		assert.Equal(t, m.PathList(), []*table.Path{
			newPath4("10.0.0.100", 4),
			newPath4("10.0.0.101", 11),
			newPath4("10.0.0.102", 22),
			newPath4("10.0.0.103", 33),
			newPath4("10.0.0.104", 44),
		})
	}

	time.Sleep(1 * time.Second)
	select {
	case <-pc.Out():
		assert.Fail(t, "channel not empty")
	default:
	}

	stats := pc.Stats()
	assert.Equal(t, stats, &api.ChannelState{
		In:            4,
		Notifications: 0,
		Collected:     4,
		Rewritten:     3,
		Retries:       1,
		Out:           1,
	})
}

func TestCollectMultiRFs(t *testing.T) {
	pc := NewBufferChannel(1)
	defer pc.Close()

	pc.Push(&msg{
		index: 1,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 1),
		},
	}, 0)
	pc.Push(&msg{
		index: 2,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 2),
		},
	}, 0)
	pc.Push(&msg{
		index: 3,
		pathList: []*table.Path{
			newPathLabelled4("10.0.0.100", 3),
		},
	}, 0)
	pc.Push(&msg{
		index: 4,
		pathList: []*table.Path{
			newPathLabelled4("10.0.0.100", 4),
		},
	}, 0)

	// wait bufferChannel.serve()
	time.Sleep(1 * time.Second)

	{
		m := (<-pc.Out()).(*msg)
		assert.Equal(t, m.index, 4)

		path1 := newPath4("10.0.0.100", 2)
		path2 := newPathLabelled4("10.0.0.100", 4)
		assert.Equal(t, m.PathList(), []*table.Path{path1, path2})
	}

	time.Sleep(1 * time.Second)
	select {
	case <-pc.Out():
		assert.Fail(t, "channel not empty")
	default:
	}

	stats := pc.Stats()
	assert.Equal(t, stats, &api.ChannelState{
		In:            4,
		Notifications: 0,
		Collected:     4,
		Rewritten:     2,
		Retries:       1,
		Out:           1,
	})
}

func TestCollectMultiPIs(t *testing.T) {
	pc := NewBufferChannel(1)
	defer pc.Close()

	pc.Push(&msg{
		index: 1,
		pathList: []*table.Path{
			newPathWithPI4("10.0.0.100", 1, 100),
		},
	}, 0)
	pc.Push(&msg{
		index: 2,
		pathList: []*table.Path{
			newPathWithPI4("10.0.0.100", 2, 100),
		},
	}, 0)
	pc.Push(&msg{
		index: 3,
		pathList: []*table.Path{
			newPathWithPI4("10.0.0.100", 3, 200),
		},
	}, 0)
	pc.Push(&msg{
		index: 4,
		pathList: []*table.Path{
			newPathWithPI4("10.0.0.100", 4, 200),
		},
	}, 0)

	// wait bufferChannel.serve()
	time.Sleep(1 * time.Second)

	{
		m := (<-pc.Out()).(*msg)
		assert.Equal(t, m.index, 4)

		path1 := newPathWithPI4("10.0.0.100", 2, 100)
		path2 := newPathWithPI4("10.0.0.100", 4, 200)
		assert.Equal(t, m.PathList(), []*table.Path{path1, path2})
	}

	time.Sleep(1 * time.Second)
	select {
	case <-pc.Out():
		assert.Fail(t, "channel not empty")
	default:
	}

	stats := pc.Stats()
	assert.Equal(t, stats, &api.ChannelState{
		In:            4,
		Notifications: 0,
		Collected:     4,
		Rewritten:     2,
		Retries:       1,
		Out:           1,
	})
}

func TestAnyElement(t *testing.T) {
	pc := NewBufferChannel(8)
	defer pc.Close()

	pc.Push(1, 0)
	pc.Push(2, 0)
	pc.Push(3, 0)
	pc.Push(4, 0)

	{
		m := <-pc.Out()
		assert.Equal(t, m.(int), 1)
	}
	{
		m := <-pc.Out()
		assert.Equal(t, m.(int), 2)
	}
	{
		m := <-pc.Out()
		assert.Equal(t, m.(int), 3)
	}
	{
		m := <-pc.Out()
		assert.Equal(t, m.(int), 4)
	}

	time.Sleep(1 * time.Second)
	select {
	case <-pc.Out():
		assert.Fail(t, "channel not empty")
	default:
	}

	stats := pc.Stats()
	assert.Equal(t, stats, &api.ChannelState{
		In:            4,
		Notifications: 4,
		Collected:     0,
		Rewritten:     0,
		Retries:       0,
		Out:           4,
	})
}

func TestCollectConsumerClosed(t *testing.T) {
	pc := NewBufferChannel(1)
	defer pc.Close()

	pc.SetConsumerClosed()

	pc.Push(&msg{
		index: 1,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 1),
		},
	}, 0)
	pc.Push(&msg{
		index: 2,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 2),
		},
	}, 0)
	pc.Push(&msg{
		index: 3,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 3),
		},
	}, 0)
	pc.Push(&msg{
		index: 4,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 4),
		},
	}, 0)

	pc.Push("hello1", 0)
	pc.Push("hello2", 0)
	pc.Push("hello3", 0)

	// test passed
}

func TestCollectTimeout(t *testing.T) {
	pc := NewBufferChannel(1)
	defer pc.Close()

	pc.Push(&msg{
		index: 1,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 1),
		},
	}, 2*time.Second)
	pc.Push(&msg{
		index: 2,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 2),
		},
	}, 2*time.Second)
	pc.Push(&msg{
		index: 3,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 3),
		},
	}, 2*time.Second)
	pc.Push(&msg{
		index: 4,
		pathList: []*table.Path{
			newPath4("10.0.0.100", 4),
		},
	}, 2*time.Second)

	// wait bufferChannel.serve()
	time.Sleep(1 * time.Second)

	{
		m := (<-pc.Out()).(*msg)
		assert.Equal(t, m.index, 4)

		path := newPath4("10.0.0.100", 4)
		assert.Equal(t, m.PathList(), []*table.Path{path})
	}

	time.Sleep(1 * time.Second)
	select {
	case <-pc.Out():
		assert.Fail(t, "channel not empty")
	default:
	}

	stats := pc.Stats()
	assert.Equal(t, stats, &api.ChannelState{
		In:            4,
		Notifications: 0,
		Collected:     4,
		Rewritten:     3,
		Retries:       1,
		Out:           1,
	})

	{
		done := pc.Push("hello1", 2*time.Second)
		assert.Equal(t, done, true)
	}
	{
		done := pc.Push("hello2", 2*time.Second)
		assert.Equal(t, done, true)
	}

	// timeout
	{
		done := pc.Push("hello3", 2*time.Second)
		assert.Equal(t, done, false)
	}

	// wait bufferChannel.serve()
	time.Sleep(1 * time.Second)

	{
		m := <-pc.Out()
		assert.Equal(t, m.(string), "hello1")
	}

	{
		m := <-pc.Out()
		assert.Equal(t, m.(string), "hello2")
	}

	time.Sleep(1 * time.Second)
	select {
	case <-pc.Out():
		assert.Fail(t, "channel not empty")
	default:
	}

	stats = pc.Stats()
	assert.Equal(t, stats, &api.ChannelState{
		In:            6,
		Notifications: 2,
		Collected:     4,
		Rewritten:     3,
		Retries:       1,
		Out:           3,
	})
}
