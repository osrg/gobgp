package peering

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/bgputils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
	"github.com/osrg/gobgp/v4/pkg/utils"
	"github.com/pkg/errors"
)

// SetPeerConnTTL sets the TTL (Time To Live) for a peer connection.
// It checks the peer configuration to determine the appropriate TTL value.
func (c *FSMCommon) SetPeerConnTTL(conn net.Conn) error {
	ttl := 0
	ttlMin := 0

	if c.PeerConf.TtlSecurity.Config.Enabled {
		ttl = 255
		ttlMin = int(c.PeerConf.TtlSecurity.Config.TtlMin)
	} else if c.PeerConf.Config.PeerAs != 0 && c.PeerConf.Config.PeerType == oc.PEER_TYPE_EXTERNAL {
		if c.PeerConf.EbgpMultihop.Config.Enabled {
			ttl = int(c.PeerConf.EbgpMultihop.Config.MultihopTtl)
		} else if c.PeerConf.Transport.Config.Ttl != 0 {
			ttl = int(c.PeerConf.Transport.Config.Ttl)
		} else {
			ttl = 1
		}
	} else if c.PeerConf.Transport.Config.Ttl != 0 {
		ttl = int(c.PeerConf.Transport.Config.Ttl)
	}

	if ttl != 0 {
		if err := netutils.SetTCPTTLSockopt(conn, ttl); err != nil {
			return fmt.Errorf("failed to set TTL %d: %w", ttl, err)
		}
	}
	if ttlMin != 0 {
		if err := netutils.SetTCPMinTTLSockopt(conn, ttlMin); err != nil {
			return fmt.Errorf("failed to set minimal TTL %d: %w", ttlMin, err)
		}
	}
	return nil
}

// SetPeerConnMSS sets the Maximum Segment Size (MSS) for a peer connection.
// It retrieves the MSS value from the peer configuration and applies it to the connection.
func (c *FSMCommon) SetPeerConnMSS(conn net.Conn) error {
	mss := c.PeerConf.Transport.Config.TcpMss
	if mss == 0 {
		return nil
	}
	if err := netutils.SetTCPMSSSockopt(conn, mss); err != nil {
		return fmt.Errorf("failed to set MSS %d: %w", mss, err)
	}
	return nil
}

// sendStateTransition sends a state transition message to the FSM's state transition channel.
// It uses a non-blocking send to avoid blocking the FSM's operation if the channel is full.
// However, it should never block, we do that more to avoid surprises in the future if the channel is used differently.
func (fsm *fsm) sendStateTransition(state bgp.FSMState, typ FSMStateReasonType, data any) {
	select {
	case fsm.transitionCh <- NewFSMStateTransition(bgp.BGP_FSM_IDLE, state, typ, data):
	default:
	}
}

// recvMessageWithError reads a BGP message from the connection and handles any errors that occur.
// It returns a FSMMsg containing the message or an error if one occurs.
// The connection gets a deadline when the FSM context get cancelled, so we can return nil.
func (fsm *fsm) recvMessageWithError(conn net.Conn) (*FSMMsg, error) {
	fsm.common.Lock.RLock()
	neighborAddress := fsm.common.PeerConf.State.NeighborAddress
	fsm.common.Lock.RUnlock()

	useRevisedError := fsm.common.PeerConf.ErrorHandling.Config.TreatAsWithdraw
	state := fsm.state.Load()
	options := fsm.marshallingOptions.Load()

	headerBuf, err := netutils.ReadAll(conn, bgp.BGP_HEADER_LENGTH)
	if err != nil {
		return nil, TransitionReadFailed.Copy(WithData(err))
	}

	hd := &bgp.BGPHeader{}
	err = hd.DecodeFromBytes(headerBuf)
	if err != nil {
		fsm.common.bgpMessageStateUpdate(0, true)
		return nil, TransitionHeaderError.Copy(WithData(err))
	}

	bodyBuf, err := netutils.ReadAll(conn, int(hd.Len)-bgp.BGP_HEADER_LENGTH)
	if err != nil {
		return nil, TransitionReadFailed.Copy(WithData(err))
	}

	now := time.Now()
	handling := bgp.ERROR_HANDLING_NONE

	m, err := bgp.ParseBGPBody(hd, bodyBuf, options)
	if err != nil {
		handling = fsm.handlingError(m, err, useRevisedError)
	}

	fsm.common.bgpMessageStateUpdate(m.Header.Type, true)

	fmsg := &FSMMsg{
		Source:    neighborAddress,
		Timestamp: now,
		Message:   m,
	}

	switch handling {
	case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
		return fmsg, nil
	case bgp.ERROR_HANDLING_SESSION_RESET:
		return nil, TransitionMessageError.Copy(WithData(err))
	}

	switch m.Header.Type {
	case bgp.BGP_MSG_KEEPALIVE:
		fsm.timers.holdTimer.Reset(fsm.timers.holdTime)
		if fsm.logger.GetLevel() >= log.DebugLevel {
			fsm.logger.Debug("received keepalive",
				log.Fields{
					"Topic": "Peer",
					"Key":   conn.RemoteAddr().String(),
					"State": state,
				})
		}
	case bgp.BGP_MSG_OPEN:
		if fsm.logger.GetLevel() >= log.DebugLevel {
			fsm.logger.Debug("received open",
				log.Fields{
					"Topic": "Peer",
					"Key":   conn.RemoteAddr().String(),
					"State": state,
				})
		}
	case bgp.BGP_MSG_NOTIFICATION:
		body := m.Body.(*bgp.BGPNotification)
		if body.ErrorCode == bgp.BGP_ERROR_CEASE && (body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN || body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET) {
			communication, rest := utils.DecodeAdministrativeCommunication(body.Data)
			fsm.logger.Warn("received notification",
				log.Fields{
					"Topic":               "Peer",
					"Key":                 conn.RemoteAddr().String(),
					"State":               state,
					"Code":                body.ErrorCode,
					"Subcode":             body.ErrorSubcode,
					"Communicated-Reason": communication,
					"Data":                rest,
				})
		} else {
			fsm.logger.Warn("received notification",
				log.Fields{
					"Topic":   "Peer",
					"Key":     conn.RemoteAddr().String(),
					"State":   state,
					"Code":    body.ErrorCode,
					"Subcode": body.ErrorSubcode,
					"Data":    body.Data,
				})
		}

		fsm.common.Lock.RLock()
		enabled := fsm.common.PeerConf.GracefulRestart.State.Enabled
		notificationEnabled := fsm.common.PeerConf.GracefulRestart.State.NotificationEnabled
		fsm.common.Lock.RUnlock()

		hardReset := enabled && notificationEnabled && body.ErrorCode == bgp.BGP_ERROR_CEASE && body.ErrorSubcode == bgp.BGP_ERROR_SUB_HARD_RESET
		if hardReset {
			return nil, TransitionHardReset.Copy()
		}
		return nil, TransitionNotificationRecv.Copy()
	case bgp.BGP_MSG_UPDATE:
		body := m.Body.(*bgp.BGPUpdate)
		if fsm.logger.GetLevel() >= log.DebugLevel {
			fsm.logger.Debug("received update",
				log.Fields{
					"Topic":       "Peer",
					"Key":         conn.RemoteAddr().String(),
					"State":       state,
					"nlri":        body.NLRI,
					"withdrawals": body.WithdrawnRoutes,
					"attributes":  body.PathAttributes,
				})
		}

		fsm.common.Lock.RLock()
		isEBGP := fsm.common.PeerConf.IsEBGPPeer(fsm.common.GlobalConf)
		isConfed := fsm.common.PeerConf.IsConfederationMember(fsm.common.GlobalConf)
		peerInfo := fsm.common.PeerInfo
		localAddr, peerAddr := peerInfo.LocalAddress, peerInfo.Address
		fsm.common.Lock.RUnlock()

		fmsg.Payload = make([]byte, len(headerBuf)+len(bodyBuf))
		copy(fmsg.Payload, headerBuf)
		copy(fmsg.Payload[len(headerBuf):], bodyBuf)

		// Allow updates from host loopback addresses if the BGP connection
		// with the neighbour is both dialed and received on loopback
		// addresses.
		var allowLoopback bool
		if localAddr.To4() != nil && peerAddr.To4() != nil {
			allowLoopback = localAddr.IsLoopback() && peerAddr.IsLoopback()
		}

		fsm.common.Lock.RLock()
		ok, err := bgp.ValidateUpdateMsg(body, fsm.common.RFMap, isEBGP, isConfed, allowLoopback)
		fsm.common.Lock.RUnlock()

		if !ok {
			handling := fsm.handlingError(m, err, useRevisedError)
			switch handling {
			case bgp.ERROR_HANDLING_SESSION_RESET:
				return nil, TransitionUpdateMsgError.Copy(WithData(err))
			}
		}

		if routes := len(body.WithdrawnRoutes); routes > 0 {
			fsm.common.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
			fsm.common.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
		} else if attr := bgputils.GetPathAttrFromBGPUpdate(body, bgp.BGP_ATTR_TYPE_MP_UNREACH_NLRI); attr != nil {
			mpUnreach := attr.(*bgp.PathAttributeMpUnreachNLRI)
			if routes = len(mpUnreach.Value); routes > 0 {
				fsm.common.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
				fsm.common.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
			}
		}

		table.UpdatePathAttrs4ByteAs(fsm.logger, body)

		if err = table.UpdatePathAggregator4ByteAs(body); err != nil {
			return nil, TransitionUpdateMsgError.Copy(WithData(err))
		}

		fmsg.PathList = table.ProcessMessage(m, peerInfo, fmsg.Timestamp)
		fsm.timers.holdTimer.Reset(fsm.timers.holdTime)
	}
	return fmsg, nil
}

func (fsm *fsm) recvMessage(ctx context.Context, conn net.Conn, recvChan chan<- *FSMMsg, wg *sync.WaitGroup) {
	defer wg.Done()

	fmsg, err := fsm.recvMessageWithError(conn)
	if ctx.Err() != nil {
		// do nothing, we will stop the FSM shortly
		return
	}
	fsm.checkErrorToTransition(err)
	if fmsg != nil {
		recvChan <- fmsg
	}
}

func (fsm *fsm) recvMessageLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	conn := fsm.conn.Load()
	for ctx.Err() == nil {
		fmsg, err := fsm.recvMessageWithError(conn)
		if ctx.Err() != nil {
			// do nothing, we will stop the FSM shortly
			break
		}
		fsm.checkErrorToTransition(err)
		if fmsg != nil {
			fsm.bgpCallback(fmsg)
		}
	}
}

func (fsm *fsm) send(conn net.Conn, m *bgp.BGPMessage) error {
	fsm.common.Lock.RLock()
	gracefulRestartEnabled := fsm.common.PeerConf.GracefulRestart.State.Enabled
	fsm.common.Lock.RUnlock()

	state := fsm.state.Load()
	twoByteAsTrans := fsm.twoByteAsTrans.Load()
	marshallingOptions := fsm.marshallingOptions.Load()
	neighborAddress := conn.RemoteAddr().String()

	if twoByteAsTrans && m.Header.Type == bgp.BGP_MSG_UPDATE {
		fsm.logger.Debug("update for 2byte AS peer",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"State": state.String(),
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
	if gracefulRestartEnabled && m.Header.Type == bgp.BGP_MSG_NOTIFICATION {
		body := m.Body.(*bgp.BGPNotification)
		if body.ErrorCode == bgp.BGP_ERROR_CEASE && bgp.ShouldHardReset(body.ErrorSubcode, false) {
			body.ErrorSubcode = bgp.BGP_ERROR_SUB_HARD_RESET
		}
	}

	b, err := m.Serialize(marshallingOptions)
	if err != nil {
		fsm.common.bgpMessageStateUpdate(0, false)
		return errors.Wrap(err, "failed to serialize message")
	}

	_, err = conn.Write(b)
	if err != nil {
		return errors.Wrap(err, "failed to send message")
	}
	fsm.common.bgpMessageStateUpdate(m.Header.Type, false)

	switch m.Header.Type {
	case bgp.BGP_MSG_NOTIFICATION:
		body := m.Body.(*bgp.BGPNotification)
		if body.ErrorCode == bgp.BGP_ERROR_CEASE && (body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN || body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET) {
			communication, rest := utils.DecodeAdministrativeCommunication(body.Data)
			fsm.logger.Warn("sent notification",
				log.Fields{
					"Topic":               "Peer",
					"Key":                 neighborAddress,
					"State":               state.String(),
					"Code":                body.ErrorCode,
					"Subcode":             body.ErrorSubcode,
					"Communicated-Reason": communication,
					"Data":                rest,
				})
		} else {
			fsm.logger.Warn("sent notification",
				log.Fields{
					"Topic":   "Peer",
					"Key":     neighborAddress,
					"State":   state.String(),
					"Code":    body.ErrorCode,
					"Subcode": body.ErrorSubcode,
					"Data":    string(body.Data),
				})
		}
	case bgp.BGP_MSG_UPDATE:
		update := m.Body.(*bgp.BGPUpdate)
		if fsm.logger.GetLevel() >= log.DebugLevel {
			fsm.logger.Debug("sent update",
				log.Fields{
					"Topic":       "Peer",
					"Key":         neighborAddress,
					"State":       state.String(),
					"nlri":        update.NLRI,
					"withdrawals": update.WithdrawnRoutes,
					"attributes":  update.PathAttributes,
				})
		}
	case bgp.BGP_MSG_OPEN:
		if fsm.logger.GetLevel() >= log.DebugLevel {
			fsm.logger.Debug("sent open",
				log.Fields{
					"Topic": "Peer",
					"Key":   neighborAddress,
					"State": state.String(),
				})
		}
	case bgp.BGP_MSG_KEEPALIVE:
		if fsm.logger.GetLevel() >= log.DebugLevel {
			fsm.logger.Debug("sent keepalive",
				log.Fields{
					"Topic": "Peer",
					"Key":   neighborAddress,
					"State": state.String(),
				})
		}
	default:
		fsm.logger.Debug("sent",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"State": state.String(),
				"data":  m,
			})
	}
	return nil
}

func (fsm *fsm) sendPathsWithError(conn net.Conn, paths []*table.Path) error {
	options := fsm.marshallingOptions.Load()
	for _, msg := range table.CreateUpdateMsgFromPaths(paths, options) {
		if err := fsm.send(conn, msg); err != nil {
			return TransitionWriteFailed.Copy(WithData(err))
		}
	}
	return nil
}

func (fsm *fsm) sendMessageLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	conn := fsm.conn.Load()
	for {
		select {
		case <-ctx.Done():
			// send remaining messages
			// before closing the connection
			// (for example, all the dropped routes)
			for {
				select {
				case o, ok := <-fsm.outgoingCh.Out():
					if !ok {
						return
					}
					p := o.([]*table.Path)
					// ignore the error here
					// we will stop the FSM shortly
					_ = fsm.sendPathsWithError(conn, p)
				default:
					return
				}
			}
		case o, ok := <-fsm.outgoingCh.Out():
			if !ok {
				return
			}
			p := o.([]*table.Path)
			if err := fsm.sendPathsWithError(conn, p); err != nil {
				fsm.checkErrorToTransition(err)
			}
		}
	}
}

func (fsm *fsm) sendNotification(conn net.Conn, code uint8, subcode uint8, data string) {
	m := bgp.NewBGPNotificationMessage(code, subcode, []byte(data))
	_ = fsm.send(conn, m)
}

func (fsm *fsm) sendNotificationToAll(code uint8, subcode uint8, data string) error {
	var errs *multierror.Error
	m := bgp.NewBGPNotificationMessage(code, subcode, []byte(data))

	fsm.tracking.lock.RLock()
	for _, tc := range fsm.tracking.conns {
		errs = multierror.Append(errs, fsm.send(tc, m))
	}
	fsm.tracking.lock.RUnlock()

	conn := fsm.conn.Load()
	if conn != nil {
		errs = multierror.Append(errs, fsm.send(conn, m))
	}
	return errs.ErrorOrNil()
}
