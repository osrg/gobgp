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

	"github.com/eapache/channels"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/bgputils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
	"github.com/osrg/gobgp/v4/pkg/utils"
)

func newFSMHandler(fsm *fsm, outgoing *channels.InfiniteChannel, wg *sync.WaitGroup, callback FSMCallback) *FSMHandler {
	ctx, cancel := context.WithCancel(context.Background())
	h := &FSMHandler{
		FSM:              fsm,
		StateReasonCh:    make(chan FSMStateReason, 2),
		Outgoing:         outgoing,
		HoldTimerResetCh: make(chan bool, 2),
		Ctx:              ctx,
		CtxCancel:        cancel,
		Callback:         callback,
	}
	wg.Add(1)
	go h.loop(ctx, wg)
	return h
}

func (h *FSMHandler) connectLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	fsm := h.FSM

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

func (h *FSMHandler) afiSafiDisable(rf bgp.Family) string {
	h.FSM.Lock.Lock()
	defer h.FSM.Lock.Unlock()

	n := bgp.AddressFamilyNameMap[rf]

	for i, a := range h.FSM.PeerConf.AfiSafis {
		if string(a.Config.AfiSafiName) == n {
			h.FSM.PeerConf.AfiSafis[i].State.Enabled = false
			break
		}
	}
	newList := make([]bgp.ParameterCapabilityInterface, 0)
	for _, c := range h.FSM.CapMap[bgp.BGP_CAP_MULTIPROTOCOL] {
		if c.(*bgp.CapMultiProtocol).CapValue == rf {
			continue
		}
		newList = append(newList, c)
	}
	h.FSM.CapMap[bgp.BGP_CAP_MULTIPROTOCOL] = newList
	return n
}

func (h *FSMHandler) handlingError(m *bgp.BGPMessage, e error, useRevisedError bool) bgp.ErrorHandling {
	// ineffectual assignment to handling (ineffassign)
	var handling bgp.ErrorHandling
	if m.Header.Type == bgp.BGP_MSG_UPDATE && useRevisedError {
		factor := e.(*bgp.MessageError)
		handling = factor.ErrorHandling
		switch handling {
		case bgp.ERROR_HANDLING_ATTRIBUTE_DISCARD:
			h.FSM.Lock.RLock()
			h.FSM.Logger.Warn("Some attributes were discarded",
				log.Fields{
					"Topic": "Peer",
					"Key":   h.FSM.PeerConf.State.NeighborAddress,
					"State": h.FSM.State.String(),
					"Error": e,
				})
			h.FSM.Lock.RUnlock()
		case bgp.ERROR_HANDLING_TREAT_AS_WITHDRAW:
			m.Body = bgp.TreatAsWithdraw(m.Body.(*bgp.BGPUpdate))
			h.FSM.Lock.RLock()
			h.FSM.Logger.Warn("the received Update message was treated as withdraw",
				log.Fields{
					"Topic": "Peer",
					"Key":   h.FSM.PeerConf.State.NeighborAddress,
					"State": h.FSM.State.String(),
					"Error": e,
				})
			h.FSM.Lock.RUnlock()
		case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
			rf := bgputils.ExtractFamily(factor.ErrorAttribute)
			if rf == nil {
				h.FSM.Lock.RLock()
				h.FSM.Logger.Warn("Error occurred during AFI/SAFI disabling",
					log.Fields{
						"Topic": "Peer",
						"Key":   h.FSM.PeerConf.State.NeighborAddress,
						"State": h.FSM.State.String(),
					})
				h.FSM.Lock.RUnlock()
			} else {
				n := h.afiSafiDisable(*rf)
				h.FSM.Lock.RLock()
				h.FSM.Logger.Warn("Capability was disabled",
					log.Fields{
						"Topic": "Peer",
						"Key":   h.FSM.PeerConf.State.NeighborAddress,
						"State": h.FSM.State.String(),
						"Error": e,
						"Cap":   n,
					})
				h.FSM.Lock.RUnlock()
			}
		}
	} else {
		handling = bgp.ERROR_HANDLING_SESSION_RESET
	}
	return handling
}

func (h *FSMHandler) recvMessageWithError(ctx context.Context) (*FSMMsg, error) {
	sendToStateReasonCh := func(typ FSMStateReasonType, notif *bgp.BGPMessage) {
		reason := *NewfsmStateReason(typ, notif, nil)
		pushed := utils.PushWithContext(ctx, h.StateReasonCh, reason, false)
		if !pushed {
			h.FSM.Logger.Warn("failed to push state reason",
				log.Fields{
					"Topic": "Peer",
					"Key":   h.FSM.PeerConf.State.NeighborAddress,
					"State": h.FSM.State.String(),
					"Data":  reason,
				})
		}
	}

	headerBuf, err := netutils.ReadAll(h.Conn, bgp.BGP_HEADER_LENGTH)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, nil
	} else if err != nil {
		sendToStateReasonCh(FSMReadFailed, nil)
		return nil, err
	}

	hd := &bgp.BGPHeader{}
	err = hd.DecodeFromBytes(headerBuf)
	if err != nil {
		h.FSM.bgpMessageStateUpdate(0, true)
		h.FSM.Lock.RLock()
		h.FSM.Logger.Warn("Session will be reset due to malformed BGP Header",
			log.Fields{
				"Topic": "Peer",
				"Key":   h.FSM.PeerConf.State.NeighborAddress,
				"State": h.FSM.State.String(),
				"Error": err,
			})
		fmsg := &FSMMsg{
			FSM:     h.FSM,
			MsgType: FSMMsgBGPMessage,
			MsgSrc:  h.FSM.PeerConf.State.NeighborAddress,
			MsgData: err,
		}
		h.FSM.Lock.RUnlock()
		return fmsg, err
	}

	bodyBuf, err := netutils.ReadAll(h.Conn, int(hd.Len)-bgp.BGP_HEADER_LENGTH)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, nil
	} else if err != nil {
		sendToStateReasonCh(FSMReadFailed, nil)
		return nil, err
	}

	now := time.Now()
	handling := bgp.ERROR_HANDLING_NONE

	h.FSM.Lock.RLock()
	useRevisedError := h.FSM.PeerConf.ErrorHandling.Config.TreatAsWithdraw
	options := h.FSM.MarshallingOptions
	h.FSM.Lock.RUnlock()

	m, err := bgp.ParseBGPBody(hd, bodyBuf, options)
	if err != nil {
		handling = h.handlingError(m, err, useRevisedError)
		h.FSM.bgpMessageStateUpdate(0, true)
	} else {
		h.FSM.bgpMessageStateUpdate(m.Header.Type, true)
		err = bgp.ValidateBGPMessage(m)
	}
	h.FSM.Lock.RLock()
	fmsg := &FSMMsg{
		FSM:       h.FSM,
		MsgType:   FSMMsgBGPMessage,
		MsgSrc:    h.FSM.PeerConf.State.NeighborAddress,
		Timestamp: now,
	}
	h.FSM.Lock.RUnlock()

	switch handling {
	case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
		fmsg.MsgData = m
		return fmsg, nil
	case bgp.ERROR_HANDLING_SESSION_RESET:
		h.FSM.Lock.RLock()
		h.FSM.Logger.Warn("Session will be reset due to malformed BGP message",
			log.Fields{
				"Topic": "Peer",
				"Key":   h.FSM.PeerConf.State.NeighborAddress,
				"State": h.FSM.State.String(),
				"Error": err,
			})
		h.FSM.Lock.RUnlock()
		fmsg.MsgData = err
		return fmsg, err
	default:
		fmsg.MsgData = m

		h.FSM.Lock.RLock()
		establishedState := h.FSM.State == bgp.BGP_FSM_ESTABLISHED
		h.FSM.Lock.RUnlock()

		if establishedState {
			switch m.Header.Type {
			case bgp.BGP_MSG_ROUTE_REFRESH:
				fmsg.MsgType = FSMMsgRouteRefresh
			case bgp.BGP_MSG_UPDATE:
				// if the length of h.holdTimerResetCh
				// isn't zero, the timer will be reset
				// soon anyway.
				select {
				case h.HoldTimerResetCh <- true:
				default:
				}
				body := m.Body.(*bgp.BGPUpdate)
				isEBGP := h.FSM.PeerConf.IsEBGPPeer(h.FSM.GlobalConf)
				isConfed := h.FSM.PeerConf.IsConfederationMember(h.FSM.GlobalConf)

				fmsg.Payload = make([]byte, len(headerBuf)+len(bodyBuf))
				copy(fmsg.Payload, headerBuf)
				copy(fmsg.Payload[len(headerBuf):], bodyBuf)

				h.FSM.Lock.RLock()
				rfMap := h.FSM.RFMap
				h.FSM.Lock.RUnlock()

				// Allow updates from host loopback addresses if the BGP connection
				// with the neighbour is both dialed and received on loopback
				// addresses.
				var allowLoopback bool
				if localAddr, peerAddr := h.FSM.PeerInfo.LocalAddress, h.FSM.PeerInfo.Address; localAddr.To4() != nil && peerAddr.To4() != nil {
					allowLoopback = localAddr.IsLoopback() && peerAddr.IsLoopback()
				}
				ok, err := bgp.ValidateUpdateMsg(body, rfMap, isEBGP, isConfed, allowLoopback)
				if !ok {
					handling = h.handlingError(m, err, useRevisedError)
				}
				if handling == bgp.ERROR_HANDLING_SESSION_RESET {
					h.FSM.Lock.RLock()
					h.FSM.Logger.Warn("Session will be reset due to malformed BGP update message",
						log.Fields{
							"Topic": "Peer",
							"Key":   h.FSM.PeerConf.State.NeighborAddress,
							"State": h.FSM.State.String(),
							"error": err,
						})
					h.FSM.Lock.RUnlock()
					fmsg.MsgData = err
					return fmsg, err
				}

				if routes := len(body.WithdrawnRoutes); routes > 0 {
					h.FSM.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
					h.FSM.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
				} else if attr := bgputils.GetPathAttrFromBGPUpdate(body, bgp.BGP_ATTR_TYPE_MP_UNREACH_NLRI); attr != nil {
					mpUnreach := attr.(*bgp.PathAttributeMpUnreachNLRI)
					if routes = len(mpUnreach.Value); routes > 0 {
						h.FSM.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
						h.FSM.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
					}
				}

				table.UpdatePathAttrs4ByteAs(h.FSM.Logger, body)

				if err = table.UpdatePathAggregator4ByteAs(body); err != nil {
					fmsg.MsgData = err
					return fmsg, err
				}

				h.FSM.Lock.RLock()
				peerInfo := h.FSM.PeerInfo
				h.FSM.Lock.RUnlock()
				fmsg.PathList = table.ProcessMessage(m, peerInfo, fmsg.Timestamp)
				fallthrough
			case bgp.BGP_MSG_KEEPALIVE:
				// if the length of h.holdTimerResetCh
				// isn't zero, the timer will be reset
				// soon anyway.
				select {
				case h.HoldTimerResetCh <- true:
				default:
				}
				if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
					return nil, nil
				}
			case bgp.BGP_MSG_NOTIFICATION:
				body := m.Body.(*bgp.BGPNotification)
				if body.ErrorCode == bgp.BGP_ERROR_CEASE && (body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN || body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET) {
					communication, rest := utils.DecodeAdministrativeCommunication(body.Data)
					h.FSM.Lock.RLock()
					h.FSM.Logger.Warn("received notification",
						log.Fields{
							"Topic":               "Peer",
							"Key":                 h.FSM.PeerConf.State.NeighborAddress,
							"Code":                body.ErrorCode,
							"Subcode":             body.ErrorSubcode,
							"Communicated-Reason": communication,
							"Data":                rest,
						})
					h.FSM.Lock.RUnlock()
				} else {
					h.FSM.Lock.RLock()
					h.FSM.Logger.Warn("received notification",
						log.Fields{
							"Topic":   "Peer",
							"Key":     h.FSM.PeerConf.State.NeighborAddress,
							"Code":    body.ErrorCode,
							"Subcode": body.ErrorSubcode,
							"Data":    body.Data,
						})
					h.FSM.Lock.RUnlock()
				}

				h.FSM.Lock.RLock()
				s := h.FSM.PeerConf.GracefulRestart.State
				hardReset := s.Enabled && s.NotificationEnabled && body.ErrorCode == bgp.BGP_ERROR_CEASE && body.ErrorSubcode == bgp.BGP_ERROR_SUB_HARD_RESET
				h.FSM.Lock.RUnlock()
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

func (h *FSMHandler) recvMessage(ctx context.Context, recvChan chan<- any, wg *sync.WaitGroup) error {
	done := make(chan any)

	defer func() {
		wg.Done()
		close(done)
	}()

	go func() {
		select {
		case <-ctx.Done():
			h.Conn.SetReadDeadline(time.Now())
		case <-done:
		}
	}()

	fmsg, _ := h.recvMessageWithError(ctx)
	if fmsg != nil {
		recvChan <- fmsg
	}
	return nil
}

func (h *FSMHandler) sendMessageloop(ctx context.Context, wg *sync.WaitGroup) error {
	sendToStateReasonCh := func(typ FSMStateReasonType, notif *bgp.BGPMessage) {
		reason := *NewfsmStateReason(typ, notif, nil)
		pushed := utils.PushWithContext(ctx, h.StateReasonCh, reason, false)
		if !pushed {
			h.FSM.Logger.Warn("failed to push state reason",
				log.Fields{
					"Topic": "Peer",
					"Key":   h.FSM.PeerConf.State.NeighborAddress,
					"State": h.FSM.State.String(),
					"Data":  reason,
				})
		}
	}

	defer wg.Done()
	conn := h.Conn
	fsm := h.FSM
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

		b, err := m.Serialize(h.FSM.MarshallingOptions)
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
			h.FSM.Lock.RLock()
			options := h.FSM.MarshallingOptions
			h.FSM.Lock.RUnlock()
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
				case o := <-h.Outgoing.Out():
					sendFromChan(o)
				default:
					return nil
				}
			}
		case o := <-h.Outgoing.Out():
			sendFromChan(o)
		case <-ticker.C:
			if err := send(bgp.NewBGPKeepAliveMessage()); err != nil {
				return nil
			}
		}
	}
}

func (h *FSMHandler) recvMessageloop(ctx context.Context, wg *sync.WaitGroup) error {
	done := make(chan any)

	defer func() {
		wg.Done()
		close(done)
	}()

	go func() {
		select {
		case <-ctx.Done():
			h.Conn.SetReadDeadline(time.Now())
		case <-done:
		}
	}()

	for {
		fmsg, err := h.recvMessageWithError(ctx)
		if fmsg != nil && ctx.Err() == nil {
			h.Callback(fmsg)
		}
		if err != nil {
			return nil
		}
	}
}

func (h *FSMHandler) loop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	fsm := h.FSM
	fsm.Lock.RLock()
	oldState := fsm.State
	neighborAddress := fsm.PeerConf.State.NeighborAddress
	fsm.Lock.RUnlock()

	var reason *FSMStateReason
	nextState := bgp.FSMState(-1)

	for ctx.Err() == nil {
		switch oldState {
		case bgp.BGP_FSM_IDLE:
			nextState, reason = h.idle(ctx)
			// case bgp.BGP_FSM_CONNECT:
			// 	nextState = h.connect()
		case bgp.BGP_FSM_ACTIVE:
			nextState, reason = h.active(ctx)
		case bgp.BGP_FSM_OPENSENT:
			nextState, reason = h.opensent(ctx)
		case bgp.BGP_FSM_OPENCONFIRM:
			nextState, reason = h.openconfirm(ctx)
		case bgp.BGP_FSM_ESTABLISHED:
			nextState, reason = h.established(ctx)
		}

		fsm.Lock.Lock()
		fsm.Reason = reason
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
			reason := *reason
			if fsm.Handler.SentNotification != nil {
				reason.Type = FSMNotificationSent
				reason.BGPNotification = fsm.Handler.SentNotification
			}
			fsm.Logger.Info("Peer Down",
				log.Fields{
					"Topic":  "Peer",
					"Key":    neighborAddress,
					"State":  oldState.String(),
					"Reason": reason.String(),
				})
		}

		if ctx.Err() != nil {
			break
		}

		msg := &FSMMsg{
			FSM:         fsm,
			MsgType:     FSMMsgStateChange,
			MsgSrc:      neighborAddress,
			MsgData:     nextState,
			StateReason: reason,
		}

		h.Callback(msg)
		oldState = nextState
	}

	if oldState == bgp.BGP_FSM_ACTIVE {
		select {
		case conn := <-fsm.ConnCh:
			conn.Close()
		default:
		}
		if fsm.Conn != nil {
			err := fsm.Conn.Close()
			if err != nil {
				fsm.Logger.Error("failed to close existing tcp connection",
					log.Fields{
						"Topic": "Peer",
						"Key":   neighborAddress,
						"State": oldState,
					})
			}
		}
	}
	close(fsm.ConnCh)
	fsm.OutgoingCh.Close()
}

func (fsm *fsm) changeadminState(s AdminState) error {
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
