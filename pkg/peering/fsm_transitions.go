package peering

import (
	"errors"
	"fmt"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (r FSMStateReasonType) String() string {
	switch r {
	case FSMDying:
		return "dying"
	case FSMAdminDown:
		return "admin-down"
	case FSMAdminPfxCt:
		return "admin-prefix-limit"
	case FSMReadFailed:
		return "read-failed"
	case FSMConnectFailed:
		return "connect-failed"
	case FSMWriteFailed:
		return "write-failed"
	case FSMNotificationSent:
		return "notification-sent"
	case FSMNotificationRecv:
		return "notification-received"
	case FSMHoldTimerExpired:
		return "hold-timer-expired"
	case FSMIdleTimerExpired:
		return "idle-hold-timer-expired"
	case FSMRestartTimerExpired:
		return "restart-timer-expired"
	case FSMConnectRetryTimerExpired:
		return "connect-retry-timer-expired"
	case FSMGracefulRestart:
		return "graceful-restart"
	case FSMUnexpectedMsg:
		return "invalid-msg"
	case FSMNewConnection:
		return "new-connection"
	case FSMOpenMsgReceived:
		return "open-msg-received"
	case FSMOpenMsgNegotiated:
		return "open-msg-negotiated"
	case FSMHardReset:
		return "hard-reset"
	default:
		return "unknown"
	}
}

func NewFSMStateTransition(oldState, newState bgp.FSMState, reason FSMStateReasonType, data ...any) *FSMStateTransition {
	var d any
	if len(data) > 0 {
		d = data[0]
	}
	return &FSMStateTransition{
		OldState: oldState,
		NewState: newState,
		Reason:   reason,
		Data:     d,
	}
}

// IsAdvancing checks if the transition is advancing to a new state.
// A transition is considered advancing if the new state is greater than the old state.
func (r *FSMStateTransition) IsAdvancing() bool {
	return r.NewState > r.OldState
}

// IsStable checks if the transition is stable.
// A transition is considered stable if the new state is equal to the old state.
func (r *FSMStateTransition) IsStable() bool {
	return r.NewState == r.OldState
}

// Error returns a string representation of the FSMStateTransition.
// This is used to implement the error interface.
func (r *FSMStateTransition) Error() string {
	return r.String()
}

func (r *FSMStateTransition) String() string {
	s := fmt.Sprintf("%s -> %s: %s", r.OldState, r.NewState, r.Reason)
	if r.Data != nil {
		s += fmt.Sprintf("\n%s", r.Data)
	}
	return s
}

// WithData creates a function that can be used to set the Data field
// of FSMStateTransition.
func WithData(data any) func(*FSMStateTransition) {
	return func(t *FSMStateTransition) {
		t.Data = data
	}
}

// WithNewState creates a function that can be used to set the NewState field
// of FSMStateTransition.
func WithNewState(state bgp.FSMState) func(*FSMStateTransition) {
	return func(t *FSMStateTransition) {
		t.NewState = state
	}
}

// Copy creates a copy of the FSMStateTransition with optional modifications.
func (r *FSMStateTransition) Copy(ofunc ...func(*FSMStateTransition)) *FSMStateTransition {
	t := &FSMStateTransition{
		OldState: r.OldState,
		NewState: r.NewState,
		Reason:   r.Reason,
		Data:     r.Data,
	}
	for _, f := range ofunc {
		f(t)
	}
	return t
}

// oldState has no meaning there, it is update by the fsm when receiving the transition
var (
	// TransitionDying is used when the FSM context is done.
	TransitionDying = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMDying)
	// TransitionAdminDown is used when the FSM is administratively shut down.
	TransitionAdminDown = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMAdminDown)
	// TransitionAdminPfxCt is used when the FSM is administratively shut down due to prefix count.
	TransitionAdminPfxCt = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMAdminPfxCt)
	// TransitionConnectFailed is used when the FSM fails to accept a connection to the peer.
	TransitionConnectFailed = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMConnectFailed)
	// TransitionReadFailed is used when the FSM fails to read from the peer's connection.
	TransitionReadFailed = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMReadFailed)
	// TransitionWriteFailed is used when the FSM fails to write to the peer's connection.
	TransitionWriteFailed = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMWriteFailed)
	// TransitionHeaderError is used when the FSM receives a malformed BGP header.
	TransitionHeaderError = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMHeaderError)
	// TransitionMessageError is used when the FSM receives a malformed BGP message.
	TransitionMessageError = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMMessageError)
	// TransitionUnexpectedMsg is used when the FSM receives an unexpected message.
	TransitionUnexpectedMsg = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMUnexpectedMsg)
	// TransitionSerializationError is used when the FSM fails to serialize a BGP message.
	TransitionSerializationError = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMSerializationError)
	// TransitionNewConnection is used when the FSM accepts a new connection to the peer.
	TransitionNewConnection = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_OPENSENT, FSMNewConnection)
	// TransitionGracefulRestartTimerExpired is used when the FSM's graceful restart timer expires.
	TransitionGracefulRestartTimerExpired = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMRestartTimerExpired)
	// TransitionConnectRetryExpired is used when the FSM's connect retry timer expires.
	TransitionConnectRetryExpired = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_CONNECT, FSMConnectRetryTimerExpired)
	// TransitionIdleHoldTimerExpired is used when the FSM's idle hold timer expires.
	TransitionIdleHoldTimerExpired = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_CONNECT, FSMIdleTimerExpired)
	// TransitionPassiveIdleHoldTimerExpired is used when the FSM's passive idle hold timer expires.
	TransitionPassiveIdleHoldTimerExpired = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_ACTIVE, FSMIdleTimerExpired)
	// TransitionHoldTimerExpired is used when the FSM's hold timer expires.
	TransitionHoldTimerExpired = NewFSMStateTransition(bgp.BGP_FSM_OPENSENT, bgp.BGP_FSM_IDLE, FSMHoldTimerExpired, bgp.NewMessageError(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil, "hold timer expired"))
	// TransitionHardReset is used when the FSM needs to perform a hard reset.
	TransitionHardReset = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMHardReset)
	// TransitionNotificationRecv is used when the FSM receives a notification message from the peer.
	TransitionNotificationRecv = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMNotificationRecv)
	// TransitionUpdateMsgError is used when the FSM encounters an error while processing an update message.
	TransitionUpdateMsgError = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMUpdateMsgError)
	// TrnasitionOpenMsgSendFailed is used when the FSM fails to send an open message to the peer.
	TransitionOpenMsgReceived = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_OPENCONFIRM, FSMOpenMsgReceived)
	// TransitionCollisionDetected is used when the FSM detects a collision with another connection.
	TransitionCollisionDetected = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMCollisionDetected, bgp.NewMessageError(bgp.BGP_ERROR_CEASE, 0, nil, "collision detected, not best connection"))
	// TransitionOpenMsgNegotiated is used when the FSM successfully negotiates an open message with the peer.
	TransitionOpenMsgNegotiated = NewFSMStateTransition(bgp.BGP_FSM_OPENCONFIRM, bgp.BGP_FSM_ESTABLISHED, FSMOpenMsgNegotiated)
	// TransitionGracefulRestart is used when the FSM detects a graceful restart condition.
	TransitionGracefulRestart = NewFSMStateTransition(bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, FSMGracefulRestart, bgp.NewMessageError(bgp.BGP_ERROR_CEASE, 0, nil, "graceful restart"))
)

func (r *FSMStateTransition) Unwrap() error {
	// Unwrap the data if it is an error.
	if err, ok := r.Data.(error); ok {
		return err
	}
	// If the data is not an error, return nil.
	return nil
}

func (r *FSMStateTransition) Is(err error) bool {
	t, ok := err.(*FSMStateTransition)
	if ok {
		// Check if the reason matches the FSMStateReasonType.
		return r.Reason == t.Reason
	}
	for werr := errors.Unwrap(err); werr != nil; {
		if errors.Is(err, werr) {
			return true
		}
	}
	return false
}
