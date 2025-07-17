package peering

import (
	"github.com/osrg/gobgp/v4/pkg/bgputils"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (fsm *fsm) handlingError(m *bgp.BGPMessage, e error, useRevisedError bool) (handling bgp.ErrorHandling) {
	if m.Header.Type != bgp.BGP_MSG_UPDATE || !useRevisedError {
		return bgp.ERROR_HANDLING_SESSION_RESET
	}

	fsm.common.Lock.RLock()
	neighborAddress := fsm.common.PeerConf.State.NeighborAddress
	fsm.common.Lock.RUnlock()

	state := fsm.state.Load()

	factor := e.(*bgp.MessageError)
	handling = factor.ErrorHandling
	switch handling {
	case bgp.ERROR_HANDLING_ATTRIBUTE_DISCARD:
		fsm.logger.Warn("Some attributes were discarded",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"State": state.String(),
				"Error": e,
			})
	case bgp.ERROR_HANDLING_TREAT_AS_WITHDRAW:
		m.Body = bgp.TreatAsWithdraw(m.Body.(*bgp.BGPUpdate))
		fsm.logger.Warn("the received Update message was treated as withdraw",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"State": state.String(),
				"Error": e,
			})
	case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
		rf := bgputils.ExtractFamily(factor.ErrorAttribute)
		if rf != nil {
			n := fsm.common.afiSafiDisable(*rf)
			fsm.logger.Warn("Capability was disabled",
				log.Fields{
					"Topic": "Peer",
					"Key":   neighborAddress,
					"State": state.String(),
					"Error": e,
					"Cap":   n,
				})
		}
	}
	return
}

func (fsm *fsm) handleErrorForConn(tc *trackedConn, data any) {
	switch data := data.(type) {
	// an error occurred and explain the state transition
	case *bgp.MessageError:
		if data.ErrorHandling == bgp.ERROR_HANDLING_SESSION_RESET {
			fsm.sendNotification(tc, data.TypeCode, data.SubTypeCode, data.Message)
		}
	default:
	}
}

func (fsm *fsm) handleError(data any) {
	switch data := data.(type) {
	// an error occurred and explain the state transition
	case *bgp.MessageError:
		if data.ErrorHandling == bgp.ERROR_HANDLING_SESSION_RESET {
			conn := fsm.conn.Load()
			if conn != nil {
				fsm.sendNotification(conn, data.TypeCode, data.SubTypeCode, data.Message)
			}
			fsm.killConns()
		}
	case error:
		fsm.common.Lock.RLock()
		neighborAddress := fsm.common.PeerConf.State.NeighborAddress
		fsm.common.Lock.RUnlock()
		fsm.logger.Error("An error occurred",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"State": fsm.state.Load().String(),
				"Error": data.Error(),
			})
	default:
	}
}

func (fsm *fsm) checkErrorToTransition(err error) {
	if err == nil {
		return
	}

	switch e := err.(type) {
	case *bgp.MessageError:
		fsm.sendStateTransition(bgp.BGP_FSM_IDLE, FSMUnexpectedMsg, err)
	case *FSMStateTransition:
		fsm.sendStateTransition(e.NewState, e.Reason, e.Data)
	default:
		fsm.common.Lock.RLock()
		neighborAddress := fsm.common.PeerConf.State.NeighborAddress
		fsm.common.Lock.RUnlock()
		fsm.logger.Warn("An error occurred, not transitioning state",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"State": fsm.state.Load().String(),
				"Error": e,
			})
	}
}
