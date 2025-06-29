package peering

import (
	"context"
	"fmt"
	"math/rand"
	"net"
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

func (fsm *FSM) step(ctx context.Context) {
	var reason *FSMStateReason
	nextState := bgp.FSMState(-1)

	fsm.Lock.RLock()
	oldState := fsm.State
	neighborAddress := fsm.PeerConf.State.NeighborAddress
	fsm.Lock.RUnlock()

	fsm.Logger.Info("FSM step",
		log.Fields{
			"Topic": "Peer",
			"Key":   neighborAddress,
			"State": oldState,
		})

	switch oldState {
	case bgp.BGP_FSM_IDLE:
		nextState, reason = fsm.idle(ctx)
		// case bgp.BGP_FSM_CONNECT:
		// 	nextState = h.connect()
	case bgp.BGP_FSM_ACTIVE:
		nextState, reason = fsm.active(ctx)
	case bgp.BGP_FSM_OPENSENT:
		nextState, reason = fsm.opensent(ctx)
	case bgp.BGP_FSM_OPENCONFIRM:
		nextState, reason = fsm.openconfirm(ctx)
	case bgp.BGP_FSM_ESTABLISHED:
		nextState, reason = fsm.established(ctx)
	}

	fsm.Lock.Lock()
	fsm.Reason = reason
	sentNotification := fsm.sentNotification
	fsm.Lock.Unlock()

	if nextState == bgp.BGP_FSM_ESTABLISHED && oldState == bgp.BGP_FSM_OPENCONFIRM {
		fsm.Logger.Info("Peer Up",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"State": oldState.String(),
			})
	}

	if oldState == bgp.BGP_FSM_ESTABLISHED {
		// The main goroutine sent the notification due to
		// deconfiguration or something.
		reason := reason
		if sentNotification != nil {
			reason.Type = FSMNotificationSent
			reason.BGPNotification = sentNotification
		}
		fsm.Logger.Info("Peer Down",
			log.Fields{
				"Topic":  "Peer",
				"Key":    neighborAddress,
				"State":  oldState,
				"Reason": reason.String(),
			})
	}
	fsmg := &FSMMsg{
		MsgType: FSMMsgStateChange,
		MsgSrc:  neighborAddress,
		MsgData: &FSMMessageStateTransition{
			OldState:  oldState,
			NextState: nextState,
		},
		StateReason: reason,
	}

	fsm.stateChange(nextState)
	utils.PushWithContext(ctx, fsm.IncomingCh.In(), any(fsmg))
}

func (fsm *FSM) connectLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	fsm.Lock.RLock()
	retryInterval := max(int(fsm.PeerConf.Timers.Config.ConnectRetry), MinConnectRetryInterval)
	mss := fsm.PeerConf.Transport.Config.TcpMss
	localAddress := fsm.PeerConf.Transport.Config.LocalAddress
	localPort := int(fsm.PeerConf.Transport.Config.LocalPort)
	bindInterface := fsm.PeerConf.Transport.Config.BindInterface

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
	fsm.Lock.RUnlock()

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
		tick = retryInterval

		laddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(localAddress, strconv.Itoa(localPort)))
		if err != nil {
			fsm.Logger.Warn("failed to resolve local address",
				log.Fields{
					"Topic": "Peer",
					"Key":   addr,
				})
			continue
		}

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

		select {
		case fsm.ConnCh <- conn:
			return
		default:
			conn.Close()
			fsm.Logger.Warn("active conn is closed to avoid being blocked",
				log.Fields{
					"Topic": "Peer",
					"Key":   addr,
				})
		}
	}
}

func (fsm *FSM) afiSafiDisable(rf bgp.Family) string {
	fsm.Lock.Lock()
	defer fsm.Lock.Unlock()

	n := bgp.AddressFamilyNameMap[rf]

	for i, a := range fsm.PeerConf.AfiSafis {
		if string(a.Config.AfiSafiName) == n {
			fsm.PeerConf.AfiSafis[i].State.Enabled = false
			break
		}
	}
	newList := make([]bgp.ParameterCapabilityInterface, 0)
	for _, c := range fsm.CapMap[bgp.BGP_CAP_MULTIPROTOCOL] {
		if c.(*bgp.CapMultiProtocol).CapValue == rf {
			continue
		}
		newList = append(newList, c)
	}
	fsm.CapMap[bgp.BGP_CAP_MULTIPROTOCOL] = newList
	return n
}

func (fsm *FSM) handlingError(m *bgp.BGPMessage, e error, useRevisedError bool) bgp.ErrorHandling {
	// ineffectual assignment to handling (ineffassign)
	var handling bgp.ErrorHandling
	if m.Header.Type == bgp.BGP_MSG_UPDATE && useRevisedError {
		factor := e.(*bgp.MessageError)
		handling = factor.ErrorHandling
		switch handling {
		case bgp.ERROR_HANDLING_ATTRIBUTE_DISCARD:
			fsm.Lock.RLock()
			fsm.Logger.Warn("Some attributes were discarded",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
					"Error": e,
				})
			fsm.Lock.RUnlock()
		case bgp.ERROR_HANDLING_TREAT_AS_WITHDRAW:
			m.Body = bgp.TreatAsWithdraw(m.Body.(*bgp.BGPUpdate))
			fsm.Lock.RLock()
			fsm.Logger.Warn("the received Update message was treated as withdraw",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
					"Error": e,
				})
			fsm.Lock.RUnlock()
		case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
			rf := bgputils.ExtractFamily(factor.ErrorAttribute)
			if rf == nil {
				fsm.Lock.RLock()
				fsm.Logger.Warn("Error occurred during AFI/SAFI disabling",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.PeerConf.State.NeighborAddress,
						"State": fsm.State.String(),
					})
				fsm.Lock.RUnlock()
			} else {
				n := fsm.afiSafiDisable(*rf)
				fsm.Lock.RLock()
				fsm.Logger.Warn("Capability was disabled",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.PeerConf.State.NeighborAddress,
						"State": fsm.State.String(),
						"Error": e,
						"Cap":   n,
					})
				fsm.Lock.RUnlock()
			}
		}
	} else {
		handling = bgp.ERROR_HANDLING_SESSION_RESET
	}
	return handling
}

func sendFSMReason(ctx context.Context, reasonChan chan<- *FSMStateReason, reason FSMStateReasonType, msg *bgp.BGPMessage) {
	stateReason := NewFSMStateReason(reason, msg, nil)
	utils.PushWithContext(ctx, reasonChan, stateReason)
}

func (fsm *FSM) recvMessage(ctx context.Context, wg *sync.WaitGroup, recvChan chan<- any, reasonChan chan<- *FSMStateReason) error {
	defer wg.Done()

	headerBuf, err := netutils.ReadAllWithContext(ctx, fsm.Conn, bgp.BGP_HEADER_LENGTH)
	if err == context.Canceled {
		return nil
	} else if err != nil {
		sendFSMReason(ctx, reasonChan, FSMReadFailed, nil)
		return err
	}

	hd := &bgp.BGPHeader{}
	err = hd.DecodeFromBytes(headerBuf)
	if err != nil {
		fsm.BgpMessageStateUpdate(0, true)
		fsm.Lock.RLock()
		fsm.Logger.Warn("Session will be reset due to malformed BGP Header",
			log.Fields{
				"Topic": "Peer",
				"Key":   fsm.PeerConf.State.NeighborAddress,
				"State": fsm.State.String(),
				"Error": err,
			})
		fmsg := &FSMMsg{
			MsgType: FSMMsgBGPMessage,
			MsgSrc:  fsm.PeerConf.State.NeighborAddress,
			MsgData: err,
		}
		fsm.Lock.RUnlock()
		utils.PushWithContext(ctx, recvChan, any(fmsg))
		return err
	}

	bodyBuf, err := netutils.ReadAllWithContext(ctx, fsm.Conn, int(hd.Len)-bgp.BGP_HEADER_LENGTH)
	if err == context.Canceled {
		return nil
	} else if err != nil {
		sendFSMReason(ctx, reasonChan, FSMReadFailed, nil)
		return err
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
		fsm.BgpMessageStateUpdate(0, true)
	} else {
		fsm.BgpMessageStateUpdate(m.Header.Type, true)
		err = bgp.ValidateBGPMessage(m)
	}
	fsm.Lock.RLock()
	fmsg := &FSMMsg{
		MsgType:   FSMMsgBGPMessage,
		MsgSrc:    fsm.PeerConf.State.NeighborAddress,
		Timestamp: now,
	}
	fsm.Lock.RUnlock()

	switch handling {
	case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
		fmsg.MsgData = m
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
				case fsm.holdTimerResetCh <- true:
				default:
				}
				body := m.Body.(*bgp.BGPUpdate)
				isEBGP := fsm.PeerConf.IsEBGPPeer(fsm.GlobalConf)
				isConfed := fsm.PeerConf.IsConfederationMember(fsm.GlobalConf)

				fmsg.Payload = make([]byte, len(headerBuf)+len(bodyBuf))
				copy(fmsg.Payload, headerBuf)
				copy(fmsg.Payload[len(headerBuf):], bodyBuf)

				fsm.Lock.RLock()
				rfMap := fsm.RfMap
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
					utils.PushWithContext(ctx, recvChan, any(fmsg))
					return err
				}

				if routes := len(body.WithdrawnRoutes); routes > 0 {
					fsm.BmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
					fsm.BmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
				} else if attr := bgputils.GetPathAttrFromBGPUpdate(body, bgp.BGP_ATTR_TYPE_MP_UNREACH_NLRI); attr != nil {
					mpUnreach := attr.(*bgp.PathAttributeMpUnreachNLRI)
					if routes = len(mpUnreach.Value); routes > 0 {
						fsm.BmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
						fsm.BmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
					}
				}

				table.UpdatePathAttrs4ByteAs(fsm.Logger, body)

				if err = table.UpdatePathAggregator4ByteAs(body); err != nil {
					fmsg.MsgData = err
					utils.PushWithContext(ctx, recvChan, any(fmsg))
					return err
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
				case fsm.holdTimerResetCh <- true:
				default:
				}
				if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
					return nil
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
					sendFSMReason(ctx, reasonChan, FSMHardReset, m)
				} else {
					sendFSMReason(ctx, reasonChan, FSMNotificationRecv, m)
				}
				return nil
			}
		}
	}
	utils.PushWithContext(ctx, recvChan, any(fmsg))
	return nil
}

func (fsm *FSM) keepaliveTicker() *time.Ticker {
	fsm.Lock.RLock()
	defer fsm.Lock.RUnlock()

	negotiatedTime := fsm.PeerConf.Timers.State.NegotiatedHoldTime
	if negotiatedTime == 0 {
		return &time.Ticker{}
	}
	sec := time.Second * time.Duration(fsm.PeerConf.Timers.State.KeepaliveInterval)
	if sec == 0 {
		sec = time.Second
	}
	return time.NewTicker(sec)
}

func (fsm *FSM) sendMessageLoop(ctx context.Context, wg *sync.WaitGroup, sendChan <-chan any, reasonChan chan<- *FSMStateReason) error {
	defer wg.Done()

	ticker := fsm.keepaliveTicker()
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
			fsm.BgpMessageStateUpdate(0, false)
			return nil
		}
		fsm.Lock.RLock()
		err = fsm.Conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(fsm.PeerConf.Timers.State.NegotiatedHoldTime)))
		fsm.Lock.RUnlock()
		if err != nil {
			sendFSMReason(ctx, reasonChan, FSMWriteFailed, nil)
			return fmt.Errorf("failed to set write deadline")
		}
		_, err = fsm.Conn.Write(b)
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
			sendFSMReason(ctx, reasonChan, FSMWriteFailed, nil)
			return fmt.Errorf("closed")
		}
		fsm.BgpMessageStateUpdate(m.Header.Type, false)

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
			sendFSMReason(ctx, reasonChan, FSMNotificationSent, m)
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
				_ = send(msg)
			}
			if m.Notification != nil {
				if m.StayIdle {
					// current user is only prefix-limit
					// fix me if this is not the case
					_ = fsm.changeadminState(AdminStatePfxCt)
				}
				_ = send(m.Notification)
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			// send remaining messages
			for {
				select {
				case o := <-sendChan:
					sendFromChan(o)
				default:
					return nil
				}
			}
		case o := <-sendChan:
			sendFromChan(o)
		case <-ticker.C:
			if err := send(bgp.NewBGPKeepAliveMessage()); err != nil {
				return nil
			}
		}
	}
}

func (fsm *FSM) recvMessageLoop(ctx context.Context, wg *sync.WaitGroup, recvChan chan<- any, reasonChan chan<- *FSMStateReason) error {
	defer wg.Done()
	for {
		wg.Add(1)
		err := fsm.recvMessage(ctx, wg, recvChan, reasonChan)
		select {
		case <-ctx.Done():
			return nil
		default:
			if err != nil {
				fsm.Lock.RLock()
				fsm.Logger.Warn("failed to receive message",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.PeerConf.State.NeighborAddress,
						"State": fsm.State.String(),
						"Error": err,
					})
				fsm.Lock.RUnlock()
				return err
			}
		}
	}
}

func (fsm *FSM) changeadminState(s AdminStateType) error {
	fsm.Lock.Lock()
	defer fsm.Lock.Unlock()

	if fsm.AdminState != s {
		fsm.Logger.Debug("admin state changed",
			log.Fields{
				"Topic":      "Peer",
				"Key":        fsm.PeerConf.State.NeighborAddress,
				"State":      fsm.State.String(),
				"adminState": s.String(),
			})
		fsm.AdminState = s
		fsm.PeerConf.State.AdminDown = !fsm.PeerConf.State.AdminDown

		switch s {
		case AdminStateUp:
			fsm.Logger.Info("Administrative start",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
				})
		case AdminStateDown:
			fsm.Logger.Info("Administrative shutdown",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
				})
		case AdminStatePfxCt:
			fsm.Logger.Info("Administrative shutdown(Prefix limit reached)",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
				})
		}
	} else {
		fsm.Logger.Warn("cannot change to the same state",
			log.Fields{
				"Topic": "Peer",
				"Key":   fsm.PeerConf.State.NeighborAddress,
				"State": fsm.State.String(),
			})
		return fmt.Errorf("cannot change to the same state")
	}
	return nil
}

func (fsm *FSM) closeIncomingConn() {
	if fsm.Conn != nil {
		fsm.Conn.Close()
		fsm.Conn = nil
	}
	for c := true; c; {
		select {
		case conn := <-fsm.ConnCh:
			if conn == nil {
				continue
			}
			conn.Close()
		default:
			c = false
		}
	}
	close(fsm.ConnCh)
}
