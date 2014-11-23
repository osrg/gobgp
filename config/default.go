package config

const (
	DEFAULT_HOLDTIME = 90
)

func setTimersTypeDefault(timersT *TimersType) {
	if timersT.HoldTime == 0 {
		timersT.HoldTime = float64(DEFAULT_HOLDTIME)
	}
	if timersT.KeepaliveInterval == 0 {
		timersT.KeepaliveInterval = timersT.HoldTime / 3
	}
}

func SetNeighborTypeDefault(neighborT *NeighborType) {
	setTimersTypeDefault(&neighborT.Timers)
}
