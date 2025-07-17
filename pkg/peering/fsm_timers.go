package peering

import "time"

func newFSMTimers(common *FSMCommon) *fsmTimers {
	connectRetryTime := time.Second * time.Duration(common.PeerConf.Timers.Config.ConnectRetry)
	holdTime := time.Second * time.Duration(common.PeerConf.Timers.Config.HoldTime)
	// we want to directly transition to the next state the first time we enter idle
	idleTime := 0 * time.Second
	keepAliveTime := time.Second * time.Duration(common.PeerConf.Timers.Config.KeepaliveInterval)
	gracefulRestartTime := time.Hour

	connectRetryTimer := time.NewTimer(connectRetryTime)
	holdTimer := time.NewTimer(holdTime)
	idleTimer := time.NewTimer(idleTime)
	keepAliveTimer := time.NewTimer(keepAliveTime)
	gracefulRestartTimer := time.NewTimer(gracefulRestartTime)

	connectRetryTimer.Stop()
	holdTimer.Stop()
	idleTimer.Stop()
	keepAliveTimer.Stop()
	gracefulRestartTimer.Stop()

	return &fsmTimers{
		connectRetryTime:     connectRetryTime,
		connectRetryTimer:    connectRetryTimer,
		holdTime:             holdTime,
		holdTimer:            holdTimer,
		keepAliveInterval:    keepAliveTime,
		keepAliveTimer:       keepAliveTimer,
		idleHoldTime:         idleTime,
		idleHoldTimer:        idleTimer,
		gracefulRestartTime:  gracefulRestartTime,
		gracefulRestartTimer: gracefulRestartTimer,
	}
}
