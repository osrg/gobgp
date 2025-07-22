package peering

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/bgputils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
	"github.com/osrg/gobgp/v4/pkg/utils"
)

func (fsm *fsm) connectLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	retryInterval, addr, port, password, ttl, ttlMin, mss, localAddress, localPort, bindInterface := func() (int, string, int, string, uint8, uint8, uint16, string, int, string) {
		fsm.Lock.RLock()
		defer fsm.Lock.RUnlock()

		tick := max(int(fsm.PeerConf.Timers.Config.ConnectRetry), MinConnectRetryInterval)

		addr := fsm.PeerConf.State.NeighborAddress
		port := int(bgp.BGP_PORT)
		if fsm.PeerConf.Transport.Config.RemotePort != 0 {
			port = int(fsm.PeerConf.Transport.Config.RemotePort)
		}
		password := fsm.PeerConf.Config.AuthPassword
		ttl := uint8(0)
		ttlMin := uint8(0)

		if fsm.PeerConf.TtlSecurity.Config.Enabled {
			ttl = 255
			ttlMin = fsm.PeerConf.TtlSecurity.Config.TtlMin
		} else if fsm.PeerConf.Config.PeerAs != 0 && fsm.PeerConf.Config.PeerType == oc.PEER_TYPE_EXTERNAL {
			ttl = 1
			if fsm.PeerConf.EbgpMultihop.Config.Enabled {
				ttl = fsm.PeerConf.EbgpMultihop.Config.MultihopTtl
			}
		}
		return tick, addr, port, password, ttl, ttlMin, fsm.PeerConf.Transport.Config.TcpMss, fsm.PeerConf.Transport.Config.LocalAddress, int(fsm.PeerConf.Transport.Config.LocalPort), fsm.PeerConf.Transport.Config.BindInterface
	}()

	tick := MinConnectRetryInterval
	for {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		timer := time.NewTimer(time.Duration(r.Intn(tick*1000)+tick*1000) * time.Millisecond)
		select {
		case <-ctx.Done():
			fsm.Logger.Debug("stop connect loop",
				log.Fields{
					"Topic": "Peer",
					"Key":   addr,
				})
			timer.Stop()
			return
		case <-timer.C:
			if fsm.Logger.GetLevel() >= log.DebugLevel {
				fsm.Logger.Debug("try to connect",
					log.Fields{
						"Topic": "Peer",
						"Key":   addr,
					})
			}
		}

		laddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(localAddress, strconv.Itoa(localPort)))
		if err != nil {
			fsm.Logger.Warn("failed to resolve local address",
				log.Fields{
					"Topic": "Peer",
					"Key":   addr,
				})
		}

		if err == nil {
			d := net.Dialer{
				LocalAddr: laddr,
				Timeout:   time.Duration(max(retryInterval-1, MinConnectRetryInterval)) * time.Second,
				KeepAlive: -1,
				Control: func(network, address string, c syscall.RawConn) error {
					return netutils.DialerControl(fsm.Logger, network, address, c, ttl, ttlMin, mss, password, bindInterface)
				},
			}

			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
			if err != nil {
				if fsm.Logger.GetLevel() >= log.DebugLevel {
					fsm.Logger.Debug("failed to connect",
						log.Fields{
							"Topic": "Peer",
							"Key":   addr,
							"Error": err,
						})
				}
				continue
			}

			pushed := utils.PushWithContext(ctx, fsm.ConnCh, conn, false)
			if !pushed {
				if ctx.Err() == context.Canceled {
					fsm.Logger.Debug("stop connect loop",
						log.Fields{
							"Topic": "Peer",
							"Key":   addr,
						})
					return
				}
				if fsm.Logger.GetLevel() >= log.DebugLevel {
					fsm.Logger.Debug("failed to connect",
						log.Fields{
							"Topic": "Peer",
							"Key":   addr,
							"Error": err,
						})
				}
			}
		}
		tick = retryInterval
	}
}

func (fsm *fsm) recvMessageWithError(ctx context.Context, stateReasonCh chan<- *FSMStateReason) (*FSMMsg, error) {
	sendToStateReasonCh := func(typ FSMStateReasonType, notif *bgp.BGPMessage) {
		reason := NewfsmStateReason(typ, notif, nil)
		pushed := utils.PushWithContext(ctx, stateReasonCh, reason, false)
		if !pushed {
			fsm.Logger.Warn("failed to push state reason",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
					"Data":  reason,
				})
		}
	}

	headerBuf, err := netutils.ReadAll(fsm.Conn, bgp.BGP_HEADER_LENGTH)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, nil
	} else if err != nil {
		sendToStateReasonCh(FSMReadFailed, nil)
		return nil, err
	}

	hd := &bgp.BGPHeader{}
	err = hd.DecodeFromBytes(headerBuf)
	if err != nil {
		fsm.bgpMessageStateUpdate(0, true)
		fsm.Lock.RLock()
		fsm.Logger.Warn("Session will be reset due to malformed BGP Header",
			log.Fields{
				"Topic": "Peer",
				"Key":   fsm.PeerConf.State.NeighborAddress,
				"State": fsm.State.String(),
				"Error": err,
			})
		fmsg := &FSMMsg{
			FSM:     fsm,
			MsgType: FSMMsgBGPMessage,
			MsgSrc:  fsm.PeerConf.State.NeighborAddress,
			MsgData: err,
		}
		fsm.Lock.RUnlock()
		return fmsg, err
	}

	bodyBuf, err := netutils.ReadAll(fsm.Conn, int(hd.Len)-bgp.BGP_HEADER_LENGTH)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, nil
	} else if err != nil {
		sendToStateReasonCh(FSMReadFailed, nil)
		return nil, err
	}

	now := time.Now()
	handling := bgp.ERROR_HANDLING_NONE

	fsm.Lock.RLock()
	useRevisedError := fsm.PeerConf.ErrorHandling.Config.TreatAsWithdraw
	options := fsm.MarshallingOptions
	fsm.Lock.RUnlock()

	m, err := bgp.ParseBGPBody(hd, bodyBuf, options)
	if err != nil {
		handling = fsm.handlingError(m, err, useRevisedError)
		fsm.bgpMessageStateUpdate(0, true)
	} else {
		fsm.bgpMessageStateUpdate(m.Header.Type, true)
		err = bgp.ValidateBGPMessage(m)
	}
	fsm.Lock.RLock()
	fmsg := &FSMMsg{
		FSM:       fsm,
		MsgType:   FSMMsgBGPMessage,
		MsgSrc:    fsm.PeerConf.State.NeighborAddress,
		Timestamp: now,
	}
	fsm.Lock.RUnlock()

	switch handling {
	case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
		fmsg.MsgData = m
		return fmsg, nil
	case bgp.ERROR_HANDLING_SESSION_RESET:
		fsm.Lock.RLock()
		fsm.Logger.Warn("Session will be reset due to malformed BGP message",
			log.Fields{
				"Topic": "Peer",
				"Key":   fsm.PeerConf.State.NeighborAddress,
				"State": fsm.State.String(),
				"Error": err,
			})
		fsm.Lock.RUnlock()
		fmsg.MsgData = err
		return fmsg, err
	default:
		fmsg.MsgData = m

		fsm.Lock.RLock()
		establishedState := fsm.State == bgp.BGP_FSM_ESTABLISHED
		fsm.Lock.RUnlock()

		if establishedState {
			switch m.Header.Type {
			case bgp.BGP_MSG_ROUTE_REFRESH:
				fmsg.MsgType = FSMMsgRouteRefresh
			case bgp.BGP_MSG_UPDATE:
				// if the length of h.holdTimerResetCh
				// isn't zero, the timer will be reset
				// soon anyway.
				select {
				case fsm.HoldTimerResetCh <- true:
				default:
				}
				body := m.Body.(*bgp.BGPUpdate)
				isEBGP := fsm.PeerConf.IsEBGPPeer(fsm.GlobalConf)
				isConfed := fsm.PeerConf.IsConfederationMember(fsm.GlobalConf)

				fmsg.Payload = make([]byte, len(headerBuf)+len(bodyBuf))
				copy(fmsg.Payload, headerBuf)
				copy(fmsg.Payload[len(headerBuf):], bodyBuf)

				fsm.Lock.RLock()
				rfMap := fsm.RFMap
				fsm.Lock.RUnlock()

				// Allow updates from host loopback addresses if the BGP connection
				// with the neighbour is both dialed and received on loopback
				// addresses.
				var allowLoopback bool
				if localAddr, peerAddr := fsm.PeerInfo.LocalAddress, fsm.PeerInfo.Address; localAddr.To4() != nil && peerAddr.To4() != nil {
					allowLoopback = localAddr.IsLoopback() && peerAddr.IsLoopback()
				}
				ok, err := bgp.ValidateUpdateMsg(body, rfMap, isEBGP, isConfed, allowLoopback)
				if !ok {
					handling = fsm.handlingError(m, err, useRevisedError)
				}
				if handling == bgp.ERROR_HANDLING_SESSION_RESET {
					fsm.Lock.RLock()
					fsm.Logger.Warn("Session will be reset due to malformed BGP update message",
						log.Fields{
							"Topic": "Peer",
							"Key":   fsm.PeerConf.State.NeighborAddress,
							"State": fsm.State.String(),
							"error": err,
						})
					fsm.Lock.RUnlock()
					fmsg.MsgData = err
					return fmsg, err
				}

				if routes := len(body.WithdrawnRoutes); routes > 0 {
					fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
					fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
				} else if attr := bgputils.GetPathAttrFromBGPUpdate(body, bgp.BGP_ATTR_TYPE_MP_UNREACH_NLRI); attr != nil {
					mpUnreach := attr.(*bgp.PathAttributeMpUnreachNLRI)
					if routes = len(mpUnreach.Value); routes > 0 {
						fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
						fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
					}
				}

				table.UpdatePathAttrs4ByteAs(fsm.Logger, body)

				if err = table.UpdatePathAggregator4ByteAs(body); err != nil {
					fmsg.MsgData = err
					return fmsg, err
				}

				fsm.Lock.RLock()
				peerInfo := fsm.PeerInfo
				fsm.Lock.RUnlock()
				fmsg.PathList = table.ProcessMessage(m, peerInfo, fmsg.Timestamp)
				fallthrough
			case bgp.BGP_MSG_KEEPALIVE:
				// if the length of h.holdTimerResetCh
				// isn't zero, the timer will be reset
				// soon anyway.
				select {
				case fsm.HoldTimerResetCh <- true:
				default:
				}
				if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
					return nil, nil
				}
			case bgp.BGP_MSG_NOTIFICATION:
				body := m.Body.(*bgp.BGPNotification)
				if body.ErrorCode == bgp.BGP_ERROR_CEASE && (body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN || body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET) {
					communication, rest := utils.DecodeAdministrativeCommunication(body.Data)
					fsm.Lock.RLock()
					fsm.Logger.Warn("received notification",
						log.Fields{
							"Topic":               "Peer",
							"Key":                 fsm.PeerConf.State.NeighborAddress,
							"Code":                body.ErrorCode,
							"Subcode":             body.ErrorSubcode,
							"Communicated-Reason": communication,
							"Data":                rest,
						})
					fsm.Lock.RUnlock()
				} else {
					fsm.Lock.RLock()
					fsm.Logger.Warn("received notification",
						log.Fields{
							"Topic":   "Peer",
							"Key":     fsm.PeerConf.State.NeighborAddress,
							"Code":    body.ErrorCode,
							"Subcode": body.ErrorSubcode,
							"Data":    body.Data,
						})
					fsm.Lock.RUnlock()
				}

				fsm.Lock.RLock()
				s := fsm.PeerConf.GracefulRestart.State
				hardReset := s.Enabled && s.NotificationEnabled && body.ErrorCode == bgp.BGP_ERROR_CEASE && body.ErrorSubcode == bgp.BGP_ERROR_SUB_HARD_RESET
				fsm.Lock.RUnlock()
				if hardReset {
					sendToStateReasonCh(FSMHardReset, m)
				} else {
					sendToStateReasonCh(FSMNotificationRecv, m)
				}
				return nil, nil
			}
		}
	}
	return fmsg, nil
}

func (fsm *fsm) recvMessage(ctx context.Context, recvChan chan<- any, stateReasonCh chan<- *FSMStateReason, wg *sync.WaitGroup) error {
	done := make(chan any)

	defer func() {
		wg.Done()
		close(done)
	}()

	go func() {
		select {
		case <-ctx.Done():
			fsm.Conn.SetReadDeadline(time.Now())
		case <-done:
		}
	}()

	fmsg, _ := fsm.recvMessageWithError(ctx, stateReasonCh)
	if fmsg != nil {
		recvChan <- fmsg
	}
	return nil
}

func (fsm *fsm) sendMessageloop(ctx context.Context, stateReasonCh chan<- *FSMStateReason, wg *sync.WaitGroup) error {
	sendToStateReasonCh := func(typ FSMStateReasonType, notif *bgp.BGPMessage) {
		reason := NewfsmStateReason(typ, notif, nil)
		pushed := utils.PushWithContext(ctx, stateReasonCh, reason, false)
		if !pushed {
			fsm.Logger.Warn("failed to push state reason",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
					"Data":  reason,
				})
		}
	}

	defer wg.Done()
	conn := fsm.Conn
	ticker := fsm.keepAliveTicker()
	send := func(m *bgp.BGPMessage) error {
		fsm.Lock.RLock()
		if fsm.TwoByteAsTrans && m.Header.Type == bgp.BGP_MSG_UPDATE {
			fsm.Logger.Debug("update for 2byte AS peer",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
					"Data":  m,
				})
			table.UpdatePathAttrs2ByteAs(m.Body.(*bgp.BGPUpdate))
			table.UpdatePathAggregator2ByteAs(m.Body.(*bgp.BGPUpdate))
		}

		// RFC8538 defines a Hard Reset notification subcode which
		// indicates that the BGP speaker wants to reset the session
		// without triggering graceful restart procedures. Here we map
		// notification subcodes to the Hard Reset subcode following
		// the RFC8538 suggestion.
		//
		// We check Status instead of Config because RFC8538 states
		// that A BGP speaker SHOULD NOT send a Hard Reset to a peer
		// from which it has not received the "N" bit.
		if fsm.PeerConf.GracefulRestart.State.NotificationEnabled && m.Header.Type == bgp.BGP_MSG_NOTIFICATION {
			if body := m.Body.(*bgp.BGPNotification); body.ErrorCode == bgp.BGP_ERROR_CEASE && bgp.ShouldHardReset(body.ErrorSubcode, false) {
				body.ErrorSubcode = bgp.BGP_ERROR_SUB_HARD_RESET
			}
		}

		b, err := m.Serialize(fsm.MarshallingOptions)
		fsm.Lock.RUnlock()
		if err != nil {
			fsm.Lock.RLock()
			fsm.Logger.Warn("failed to serialize",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
					"Data":  err,
				})
			fsm.Lock.RUnlock()
			fsm.bgpMessageStateUpdate(0, false)
			return nil
		}
		fsm.Lock.RLock()
		err = conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(fsm.PeerConf.Timers.State.NegotiatedHoldTime)))
		fsm.Lock.RUnlock()
		if err != nil {
			sendToStateReasonCh(FSMWriteFailed, nil)
			conn.Close()
			return fmt.Errorf("failed to set write deadline")
		}
		_, err = conn.Write(b)
		if err != nil {
			fsm.Lock.RLock()
			fsm.Logger.Warn("failed to send",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
					"Data":  err,
				})
			fsm.Lock.RUnlock()
			sendToStateReasonCh(FSMWriteFailed, nil)
			conn.Close()
			return fmt.Errorf("closed")
		}
		fsm.bgpMessageStateUpdate(m.Header.Type, false)

		switch m.Header.Type {
		case bgp.BGP_MSG_NOTIFICATION:
			body := m.Body.(*bgp.BGPNotification)
			if body.ErrorCode == bgp.BGP_ERROR_CEASE && (body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN || body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET) {
				communication, rest := utils.DecodeAdministrativeCommunication(body.Data)
				fsm.Lock.RLock()
				fsm.Logger.Warn("sent notification",
					log.Fields{
						"Topic":               "Peer",
						"Key":                 fsm.PeerConf.State.NeighborAddress,
						"State":               fsm.State.String(),
						"Code":                body.ErrorCode,
						"Subcode":             body.ErrorSubcode,
						"Communicated-Reason": communication,
						"Data":                rest,
					})
				fsm.Lock.RUnlock()
			} else {
				fsm.Lock.RLock()
				fsm.Logger.Warn("sent notification",
					log.Fields{
						"Topic":   "Peer",
						"Key":     fsm.PeerConf.State.NeighborAddress,
						"State":   fsm.State.String(),
						"Code":    body.ErrorCode,
						"Subcode": body.ErrorSubcode,
						"Data":    body.Data,
					})
				fsm.Lock.RUnlock()
			}
			sendToStateReasonCh(FSMNotificationSent, m)
			conn.Close()
			return fmt.Errorf("closed")
		case bgp.BGP_MSG_UPDATE:
			update := m.Body.(*bgp.BGPUpdate)
			if fsm.Logger.GetLevel() >= log.DebugLevel {
				fsm.Lock.RLock()
				fsm.Logger.Debug("sent update",
					log.Fields{
						"Topic":       "Peer",
						"Key":         fsm.PeerConf.State.NeighborAddress,
						"State":       fsm.State.String(),
						"nlri":        update.NLRI,
						"withdrawals": update.WithdrawnRoutes,
						"attributes":  update.PathAttributes,
					})
				fsm.Lock.RUnlock()
			}
		default:
			fsm.Lock.RLock()
			fsm.Logger.Debug("sent",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
					"data":  m,
				})
			fsm.Lock.RUnlock()
		}
		return nil
	}

	sendFromChan := func(o any) {
		switch m := o.(type) {
		case *FSMOutgoingMsg:
			fsm.Lock.RLock()
			options := fsm.MarshallingOptions
			fsm.Lock.RUnlock()
			for _, msg := range table.CreateUpdateMsgFromPaths(m.Paths, options) {
				if err := send(msg); err != nil {
					return
				}
			}
			if m.Notification != nil {
				if m.StayIdle {
					// current user is only prefix-limit
					// fix me if this is not the case
					_ = fsm.changeadminState(AdminStatePfxCt)
				}
				if err := send(m.Notification); err != nil {
					return
				}
			}
		default:
		}
	}

	for {
		select {
		case <-ctx.Done():
			// send remaining messages
			// before closing the connection
			// (for example, all the dropped routes)
			for {
				select {
				case o := <-fsm.OutgoingCh.Out():
					sendFromChan(o)
				default:
					return nil
				}
			}
		case o := <-fsm.OutgoingCh.Out():
			sendFromChan(o)
		case <-ticker.C:
			if err := send(bgp.NewBGPKeepAliveMessage()); err != nil {
				return nil
			}
		}
	}
}

func (fsm *fsm) recvMessageloop(ctx context.Context, stateReasonCh chan<- *FSMStateReason, wg *sync.WaitGroup) error {
	done := make(chan any)

	defer func() {
		wg.Done()
		close(done)
	}()

	go func() {
		select {
		case <-ctx.Done():
			fsm.Conn.SetReadDeadline(time.Now())
		case <-done:
		}
	}()

	for {
		fmsg, err := fsm.recvMessageWithError(ctx, stateReasonCh)
		if fmsg != nil && ctx.Err() == nil {
			fsm.Callback(fmsg)
		}
		if err != nil {
			return nil
		}
	}
}
