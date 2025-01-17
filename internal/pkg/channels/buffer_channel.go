package channels

import (
	"sync/atomic"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/internal/pkg/table"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

const (
	// default input channel size.
	//   specifies a buffer size for input channel.
	defaultInSize = 64
)

type BufferMessageInterface interface {
	PathList() []*table.Path
	SetPathList(pathList []*table.Path)
}

type pathKey struct {
	rf             bgp.RouteFamily
	nlri           string
	pathIdentifier uint32
}

type BufferChannel struct {
	input  chan any
	output chan any

	in            atomic.Uint64
	notifications atomic.Uint64
	collected     atomic.Uint64
	rewritten     atomic.Uint64
	retries       atomic.Uint64
	out           atomic.Uint64
}

type bufferChannel struct {
	parent *BufferChannel

	pathIdxs map[pathKey]int
	last     BufferMessageInterface
}

func NewBufferChannel(inSize int) *BufferChannel {
	bc := &BufferChannel{
		output: make(chan any),
	}

	if inSize == 0 {
		// if inSize not set, use default value
		inSize = defaultInSize
	}
	bc.input = make(chan any, inSize)

	ibc := &bufferChannel{
		parent:   bc,
		pathIdxs: make(map[pathKey]int),
	}

	go ibc.serve()
	return bc
}

func (bc *BufferChannel) In() chan<- any {
	return bc.input
}

func (bc *BufferChannel) Out() <-chan any {
	return bc.output
}

func (bc *BufferChannel) Stats() *api.ChannelState {
	return &api.ChannelState{
		In:            bc.in.Load(),
		Notifications: bc.notifications.Load(),
		Collected:     bc.collected.Load(),
		Rewritten:     bc.rewritten.Load(),
		Retries:       bc.retries.Load(),
		Out:           bc.out.Load(),
	}
}

func (bc *BufferChannel) Clean() {
	bc.Close()
	// drain all remaining items
	for range bc.Out() {
	}
}

func (bc *BufferChannel) Close() {
	close(bc.input)
}

func (bc *bufferChannel) serve() {
	for {
		var out chan any
		if bc.last != nil {
			out = bc.parent.output
		}

		select {
		case elem, open := <-bc.parent.input:
			if !open {
				close(bc.parent.output)
				return
			}

			bc.onInput(elem)
		case out <- bc.last:
			bc.parent.out.Add(1)

			clear(bc.pathIdxs)
			bc.last = nil
		}
	}
}

func (bc *bufferChannel) onInput(anyElem any) {
	bc.parent.in.Add(1)

	elem, ok := anyElem.(BufferMessageInterface)
	if !ok || len(elem.PathList()) == 0 {
		// pass not BufferChannel's element or notification to output with blocking channel
		bc.parent.notifications.Add(1)

		if bc.last != nil {
			bc.parent.output <- bc.last
			bc.parent.out.Add(1)

			clear(bc.pathIdxs)
			bc.last = nil
		}

		bc.parent.output <- anyElem
		bc.parent.out.Add(1)
		return
	}

	if bc.last != nil {
		bc.collect(elem)
		return
	}

	select {
	case bc.parent.output <- elem:
		// done
		bc.parent.out.Add(1)
	default:
		// try output later
		bc.parent.retries.Add(1)

		bc.collect(elem)
	}
}

func (bc *bufferChannel) collect(elem BufferMessageInterface) {
	bc.parent.collected.Add(1)

	pathList := elem.PathList()

	if bc.last == nil {
		// first

		for idx, path := range pathList {
			if path == nil || path.IsEOR() {
				continue
			}

			key := pathKey{
				rf:             path.GetRouteFamily(),
				pathIdentifier: path.GetNlri().PathIdentifier(),
				nlri:           table.TableKey(path.GetNlri()),
			}

			bc.pathIdxs[key] = idx
		}
	} else {
		// merge

		nextPathsList := bc.last.PathList()

		for _, path := range pathList {
			if path == nil {
				continue
			}

			if path.IsEOR() {
				nextPathsList = append(nextPathsList, path)
				continue
			}

			key := pathKey{
				rf:             path.GetRouteFamily(),
				pathIdentifier: path.GetNlri().PathIdentifier(),
				nlri:           table.TableKey(path.GetNlri()),
			}

			idx, ok := bc.pathIdxs[key]
			if !ok {
				// new path

				bc.pathIdxs[key] = len(nextPathsList)
				nextPathsList = append(nextPathsList, path)
			} else {
				// rewrite path
				bc.parent.rewritten.Add(1)

				nextPathsList[idx] = path
			}
		}

		elem.SetPathList(nextPathsList)
	}

	bc.last = elem
}
