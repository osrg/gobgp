package peering

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/eapache/channels"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const (
	MinConnectRetryInterval = 1
	HoldtimeOpensent        = 240
	HoldtimeIdle            = 5
	FlopThreshold           = time.Second * 30
)

type FSMStateReasonType uint8

const (
	FSMDying FSMStateReasonType = iota
	FSMAdminDown
	FSMReadFailed
	FSMWriteFailed
	FSMNotificationSent
	FSMNotificationRecv
	FSMHoldTimerExpired
	FSMIdleTimerExpired
	FSMRestartTimerExpired
	FSMGracefulRestart
	FSMInvalidMsg
	FSMNewConnection
	FSMOpenMsgReceived
	FSMOpenMsgNegotiated
	FSMHardReset
	FSMDeconfigured
)

type FSMStateReason struct {
	Type            FSMStateReasonType
	BGPNotification *bgp.BGPMessage
	Data            []byte
}

type FSMMsgType int

const (
	_ FSMMsgType = iota
	FSMMsgStateChange
	FSMMsgBGPMessage
	FSMMsgRouteRefresh
)

type FSMMessageStateTransition struct {
	OldState  bgp.FSMState
	NextState bgp.FSMState
}

type FSMMsg struct {
	MsgType     FSMMsgType
	MsgSrc      string
	MsgData     any
	StateReason *FSMStateReason
	PathList    []*table.Path
	Timestamp   time.Time
	Payload     []byte
}

type FSMOutgoingMsg struct {
	Paths        []*table.Path
	Notification *bgp.BGPMessage
	StayIdle     bool
}

type AdminStateType int

const (
	AdminStateUp AdminStateType = iota
	AdminStateDown
	AdminStatePfxCt
)

type AdminStateOperation struct {
	State         AdminStateType
	Communication []byte
}

type FSM struct {
	GlobalConf           *oc.Global
	PeerConf             *oc.Neighbor
	Lock                 sync.RWMutex
	State                bgp.FSMState
	OutgoingCh           chan any
	IncomingCh           *channels.InfiniteChannel
	Reason               *FSMStateReason
	Conn                 net.Conn
	ConnCh               chan net.Conn
	IdleHoldTime         float64
	OpensentHoldTime     float64
	AdminState           AdminStateType
	AdminStateCh         chan AdminStateOperation
	RfMap                map[bgp.Family]bgp.BGPAddPathMode
	CapMap               map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface
	RecvOpen             *bgp.BGPMessage
	PeerInfo             *table.PeerInfo
	GracefulRestartTimer *time.Timer
	TwoByteAsTrans       bool
	MarshallingOptions   *bgp.MarshallingOption
	Notification         chan *bgp.BGPMessage
	Logger               log.Logger
	LongLivedRunning     bool

	holdTimerResetCh chan bool
	sentNotification *bgp.BGPMessage
}

type PeerGroup struct {
	Conf             *oc.PeerGroup
	Members          map[string]oc.Neighbor
	DynamicNeighbors map[string]*oc.DynamicNeighbor
}

type Peer struct {
	TableId           string
	FSM               *FSM
	AdjRibIn          *table.AdjRib
	Policy            *table.RoutingPolicy
	LocalRib          *table.TableManager
	PrefixLimitWarned map[bgp.Family]bool
	// map of path local identifiers sent for that prefix
	SentPaths           map[table.PathDestLocalKey]map[uint32]struct{}
	SendMaxPathFiltered map[table.PathLocalKey]struct{}
	LLGREndChs          []chan struct{}

	ctx    context.Context
	cancel context.CancelFunc
	wg     *sync.WaitGroup
}
