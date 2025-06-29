package peering

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/pkg/bgputils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (fsm *FSM) opensent(ctx context.Context) (bgp.FSMState, *FSMStateReason) {
	fsm.Lock.RLock()
	m := bgputils.BuildOpenMessage(fsm.GlobalConf, fsm.PeerConf)
	fsm.Lock.RUnlock()

	b, _ := m.Serialize()
	fsm.Conn.Write(b)
	fsm.BgpMessageStateUpdate(m.Header.Type, false)

	c, cancel := context.WithCancel(ctx)
	recvWg := &sync.WaitGroup{}
	recvWg.Add(1)

	recvChan := make(chan any, 1)
	reasonChan := make(chan *FSMStateReason, 1)
	go func() {
		err := fsm.recvMessage(c, recvWg, recvChan, reasonChan)
		if err != nil {
			fsm.Lock.RLock()
			fsm.Logger.Error("failed to receive message",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
					"Error": err,
				})
			fsm.Lock.RUnlock()
		}
	}()

	defer func() {
		cancel()
		recvWg.Wait()
		close(recvChan)
		close(reasonChan)
	}()

	// RFC 4271 P.60
	// sets its HoldTimer to a large value
	// A HoldTimer value of 4 minutes is suggested as a "large value"
	// for the HoldTimer
	fsm.Lock.RLock()
	holdTimer := time.NewTimer(time.Second * time.Duration(fsm.OpensentHoldTime))
	fsm.Lock.RUnlock()

	for {
		select {
		case <-ctx.Done():
			return -1, NewFSMStateReason(FSMDying, nil, nil)
		case conn, ok := <-fsm.ConnCh:
			if !ok {
				break
			}
			conn.Close()
			fsm.Lock.RLock()
			fsm.Logger.Warn("Closed an accepted connection",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
				})
			fsm.Lock.RUnlock()
		case <-fsm.GracefulRestartTimer.C:
			fsm.Lock.RLock()
			restarting := fsm.PeerConf.GracefulRestart.State.PeerRestarting
			fsm.Lock.RUnlock()
			if restarting {
				fsm.Lock.RLock()
				fsm.Logger.Warn("graceful restart timer expired",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.PeerConf.State.NeighborAddress,
						"State": fsm.State.String(),
					})
				fsm.Lock.RUnlock()
				return bgp.BGP_FSM_IDLE, NewFSMStateReason(FSMRestartTimerExpired, nil, nil)
			}
		case i := <-recvChan:
			e := i.(*FSMMsg)
			switch m := e.MsgData.(type) {
			case *bgp.BGPMessage:
				if m.Header.Type == bgp.BGP_MSG_OPEN {
					fsm.Lock.Lock()
					fsm.RecvOpen = m
					fsm.Lock.Unlock()

					body := m.Body.(*bgp.BGPOpen)

					fsm.Lock.RLock()
					fsmPeerAS := fsm.PeerConf.Config.PeerAs
					fsm.Lock.RUnlock()
					peerAs, err := bgp.ValidateOpenMsg(body, fsmPeerAS, fsm.PeerInfo.LocalAS, net.ParseIP(fsm.GlobalConf.Config.RouterId))
					if err != nil {
						m, _ := fsm.SendNotificationFromErrorMsg(err.(*bgp.MessageError))
						return bgp.BGP_FSM_IDLE, NewFSMStateReason(FSMInvalidMsg, m, nil)
					}

					// ASN negotiation was skipped
					fsm.Lock.RLock()
					asnNegotiationSkipped := fsm.PeerConf.Config.PeerAs == 0
					fsm.Lock.RUnlock()
					if asnNegotiationSkipped {
						fsm.Lock.Lock()
						typ := oc.PEER_TYPE_EXTERNAL
						if fsm.PeerInfo.LocalAS == peerAs {
							typ = oc.PEER_TYPE_INTERNAL
						}
						fsm.PeerConf.State.PeerType = typ
						fsm.Logger.Info("skipped asn negotiation",
							log.Fields{
								"Topic":    "Peer",
								"Key":      fsm.PeerConf.State.NeighborAddress,
								"State":    fsm.State.String(),
								"Asn":      peerAs,
								"PeerType": typ,
							})
						fsm.Lock.Unlock()
					} else {
						fsm.Lock.Lock()
						fsm.PeerConf.State.PeerType = fsm.PeerConf.Config.PeerType
						fsm.Lock.Unlock()
					}
					fsm.Lock.Lock()
					fsm.PeerConf.State.PeerAs = peerAs
					fsm.PeerInfo.AS = peerAs
					fsm.PeerInfo.ID = body.ID
					fsm.CapMap, fsm.RfMap = bgputils.Open2Cap(body, fsm.PeerConf)

					if _, y := fsm.CapMap[bgp.BGP_CAP_ADD_PATH]; y {
						fsm.MarshallingOptions = &bgp.MarshallingOption{
							AddPath: fsm.RfMap,
						}
					} else {
						fsm.MarshallingOptions = nil
					}

					// calculate HoldTime
					// RFC 4271 P.13
					// a BGP speaker MUST calculate the value of the Hold Timer
					// by using the smaller of its configured Hold Time and the Hold Time
					// received in the OPEN message.
					holdTime := float64(body.HoldTime)
					myHoldTime := fsm.PeerConf.Timers.Config.HoldTime
					fsm.PeerConf.Timers.State.NegotiatedHoldTime = min(holdTime, myHoldTime)

					keepalive := fsm.PeerConf.Timers.Config.KeepaliveInterval
					if n := fsm.PeerConf.Timers.State.NegotiatedHoldTime; n < myHoldTime {
						keepalive = n / 3
					}
					fsm.PeerConf.Timers.State.KeepaliveInterval = keepalive

					gr, ok := fsm.CapMap[bgp.BGP_CAP_GRACEFUL_RESTART]
					if fsm.PeerConf.GracefulRestart.Config.Enabled && ok {
						state := &fsm.PeerConf.GracefulRestart.State
						state.Enabled = true
						cap := gr[len(gr)-1].(*bgp.CapGracefulRestart)
						state.PeerRestartTime = cap.Time

						for _, t := range cap.Tuples {
							n := bgp.AddressFamilyNameMap[bgp.AfiSafiToFamily(t.AFI, t.SAFI)]
							for i, a := range fsm.PeerConf.AfiSafis {
								if string(a.Config.AfiSafiName) == n {
									fsm.PeerConf.AfiSafis[i].MpGracefulRestart.State.Enabled = true
									fsm.PeerConf.AfiSafis[i].MpGracefulRestart.State.Received = true
									break
								}
							}
						}

						// RFC 4724 4.1
						// To re-establish the session with its peer, the Restarting Speaker
						// MUST set the "Restart State" bit in the Graceful Restart Capability
						// of the OPEN message.
						if fsm.PeerConf.GracefulRestart.State.PeerRestarting && cap.Flags&0x08 == 0 {
							fsm.Logger.Warn("restart flag is not set",
								log.Fields{
									"Topic": "Peer",
									"Key":   fsm.PeerConf.State.NeighborAddress,
									"State": fsm.State.String(),
								})
							// just ignore
						}

						// RFC 4724 3
						// The most significant bit is defined as the Restart State (R)
						// bit, ...(snip)... When set (value 1), this bit
						// indicates that the BGP speaker has restarted, and its peer MUST
						// NOT wait for the End-of-RIB marker from the speaker before
						// advertising routing information to the speaker.
						if fsm.PeerConf.GracefulRestart.State.LocalRestarting && cap.Flags&0x08 != 0 {
							fsm.Logger.Debug("peer has restarted, skipping wait for EOR",
								log.Fields{
									"Topic": "Peer",
									"Key":   fsm.PeerConf.State.NeighborAddress,
									"State": fsm.State.String(),
								})
							for i := range fsm.PeerConf.AfiSafis {
								fsm.PeerConf.AfiSafis[i].MpGracefulRestart.State.EndOfRibReceived = true
							}
						}
						if fsm.PeerConf.GracefulRestart.Config.NotificationEnabled && cap.Flags&0x04 > 0 {
							fsm.PeerConf.GracefulRestart.State.NotificationEnabled = true
						}
					}
					llgr, ok2 := fsm.CapMap[bgp.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART]
					if fsm.PeerConf.GracefulRestart.Config.LongLivedEnabled && ok && ok2 {
						fsm.PeerConf.GracefulRestart.State.LongLivedEnabled = true
						cap := llgr[len(llgr)-1].(*bgp.CapLongLivedGracefulRestart)
						for _, t := range cap.Tuples {
							n := bgp.AddressFamilyNameMap[bgp.AfiSafiToFamily(t.AFI, t.SAFI)]
							for i, a := range fsm.PeerConf.AfiSafis {
								if string(a.Config.AfiSafiName) == n {
									fsm.PeerConf.AfiSafis[i].LongLivedGracefulRestart.State.Enabled = true
									fsm.PeerConf.AfiSafis[i].LongLivedGracefulRestart.State.Received = true
									fsm.PeerConf.AfiSafis[i].LongLivedGracefulRestart.State.PeerRestartTime = t.RestartTime
									break
								}
							}
						}
					}

					fsm.Lock.Unlock()
					msg := bgp.NewBGPKeepAliveMessage()
					b, _ := msg.Serialize()
					fsm.Conn.Write(b)
					fsm.BgpMessageStateUpdate(msg.Header.Type, false)
					return bgp.BGP_FSM_OPENCONFIRM, NewFSMStateReason(FSMOpenMsgReceived, nil, nil)
				} else {
					// send notification?
					return bgp.BGP_FSM_IDLE, NewFSMStateReason(FSMInvalidMsg, nil, nil)
				}
			case *bgp.MessageError:
				msg, _ := fsm.SendNotificationFromErrorMsg(m)
				return bgp.BGP_FSM_IDLE, NewFSMStateReason(FSMInvalidMsg, msg, nil)
			default:
				fsm.Logger.Panic("unknown msg type",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.PeerConf.State.NeighborAddress,
						"State": fsm.State.String(),
						"Data":  e.MsgData,
					})
			}
		case err := <-reasonChan:
			return bgp.BGP_FSM_IDLE, err
		case <-holdTimer.C:
			m, _ := fsm.SendNotification(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil, "hold timer expired")
			return bgp.BGP_FSM_IDLE, NewFSMStateReason(FSMHoldTimerExpired, m, nil)
		case stateOp := <-fsm.AdminStateCh:
			err := fsm.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case AdminStateDown:
					return bgp.BGP_FSM_IDLE, NewFSMStateReason(FSMAdminDown, m, nil)
				case AdminStateUp:
					fsm.Logger.Panic("code logic bug",
						log.Fields{
							"Topic":      "Peer",
							"Key":        fsm.PeerConf.State.NeighborAddress,
							"State":      fsm.State.String(),
							"AdminState": stateOp.State.String(),
						})
				}
			}
		}
	}
}
