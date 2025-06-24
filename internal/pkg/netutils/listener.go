// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package netutils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall"

	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/osrg/gobgp/v4/pkg/log"
)

type TCPConn struct {
	*net.TCPConn
	cb func(*TCPConn)
}

func (c *TCPConn) Close() error {
	if c.cb != nil {
		c.cb(c)
	}
	return c.TCPConn.Close()
}

func (c *TCPConn) Key() string {
	if c == nil || c.TCPConn == nil {
		return ""
	}
	addr := c.RemoteAddr()
	if addr == nil {
		return ""
	}
	return addr.String()
}

// Ensure TCPConn implements net.Conn/syscall.Conn interfaces
var (
	_ net.Conn     = (*TCPConn)(nil)
	_ syscall.Conn = (*TCPConn)(nil)
)

type TCPListener struct {
	ctx          context.Context
	cancel       context.CancelFunc
	l            *net.TCPListener
	connChan     chan net.Conn
	acceptedConn cmap.ConcurrentMap[string, *TCPConn] // key is RemoteAddr().String()
	stopWg       *sync.WaitGroup                      // used to wait for acceptLoop to finish
	logger       log.Logger
}

func listenControl(logger log.Logger, bindToDev string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		family := extractFamilyFromAddress(address)
		if bindToDev != "" {
			if err := SetBindToDevSockopt(c, bindToDev); err != nil {
				logger.Warn("failed to bind Listener to device ",
					log.Fields{
						"Topic":     "Peer",
						"Key":       address,
						"BindToDev": bindToDev,
						"Error":     err,
					})
				return err
			}
		}
		// Note: Set TTL=255 for incoming connection listener in order to accept
		// connection in case for the neighbor has TTL Security settings.
		if err := setSockOptIpTtl(c, family, 255); err != nil {
			logger.Warn("cannot set TTL (255) for TCPListener",
				log.Fields{
					"Topic": "Peer",
					"Key":   address,
					"Err":   err,
				})
		}
		return nil
	}
}

func (l *TCPListener) closeConnCb(tcpConn *TCPConn) {
	key := tcpConn.Key()
	if key == "" {
		return // nothing to do
	}
	l.acceptedConn.Remove(key)
}

func (l *TCPListener) acceptLoop() {
	defer l.stopWg.Done()
	for {
		conn, err := l.l.AcceptTCP()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				l.logger.Warn("Failed to AcceptTCP",
					log.Fields{
						"Topic": "Peer",
						"Error": err,
					})
			}
			return
		}
		tcpConn := &TCPConn{
			TCPConn: conn,
			cb:      l.closeConnCb,
		}
		key := tcpConn.Key()
		l.acceptedConn.Set(key, tcpConn)

		err = conn.SetKeepAlive(false)
		if err != nil {
			l.logger.Warn("Failed to SetKeepAlive",
				log.Fields{
					"Topic": "Peer",
					"Key":   key,
					"Error": err,
				})
			return
		}

		select {
		case l.connChan <- tcpConn:
		case <-l.ctx.Done():
			return
		}
	}
}

// avoid mapped IPv6 address
func NewTCPListener(logger log.Logger, address string, port uint32, bindToDev string, connChan chan net.Conn) (*TCPListener, error) {
	proto := extractProtoFromAddress(address)
	config := net.ListenConfig{
		Control: listenControl(logger, bindToDev),
	}

	addr := net.JoinHostPort(address, strconv.Itoa(int(port)))

	listener, err := config.Listen(context.Background(), proto, addr)
	if err != nil {
		return nil, err
	}
	netListener, ok := listener.(*net.TCPListener)
	if !ok {
		return nil, fmt.Errorf("unexpected connection listener (not for TCP)")
	}

	listenerCtx, listenerCancel := context.WithCancel(context.Background())
	// Create the stopWg to wait for acceptLoop to finish
	// when Close() is called.
	stopWg := &sync.WaitGroup{}
	stopWg.Add(1)
	l := &TCPListener{
		ctx:          listenerCtx,
		cancel:       listenerCancel,
		l:            netListener,
		stopWg:       stopWg,
		connChan:     connChan,
		acceptedConn: cmap.New[*TCPConn](),
		logger:       logger,
	}
	go l.acceptLoop()
	return l, nil
}

func (l *TCPListener) Close() {
	l.cancel()
	_ = l.l.Close()
	l.stopWg.Wait()
	for t := range l.acceptedConn.IterBuffered() {
		_ = t.Val.TCPConn.Close()
	}
	l.acceptedConn.Clear()
}

func (l *TCPListener) Addr() net.Addr {
	if l.l == nil {
		return nil
	}
	return l.l.Addr()
}

func (l *TCPListener) Listener() *net.TCPListener {
	return l.l
}
