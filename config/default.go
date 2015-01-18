package config

const (
	DEFAULT_HOLDTIME                  = 90
	DEFAULT_IDLE_HOLDTIME_AFTER_RESET = 30
)

func setTimersTypeDefault(timersT *TimersType) {
	if timersT.HoldTime == 0 {
		timersT.HoldTime = float64(DEFAULT_HOLDTIME)
	}
	if timersT.KeepaliveInterval == 0 {
		timersT.KeepaliveInterval = timersT.HoldTime / 3
	}
	if timersT.IdleHoldTImeAfterReset == 0 {
		timersT.IdleHoldTImeAfterReset = float64(DEFAULT_IDLE_HOLDTIME_AFTER_RESET)
	}
}

func SetNeighborTypeDefault(neighborT *NeighborType) {
	setTimersTypeDefault(&neighborT.Timers)
}
