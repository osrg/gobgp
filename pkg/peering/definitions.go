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
	FlopThreshold           = time.Second * 30
	HoldTimeOpenSent        = 240
	HoldTimeIdle            = 5
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

type FSMStateTransition struct {
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
	sending      chan any
}

type AdminState int

const (
	AdminStateUp AdminState = iota
	AdminStateDown
	AdminStatePfxCt
)

type AdminStateOperation struct {
	State         AdminState
	Communication []byte
}

type FSMCallback func(*FSMMsg)

type fsm struct {
	Lock                 sync.RWMutex
	GlobalConf           *oc.Global
	PeerConf             *oc.Neighbor
	State                bgp.FSMState
	OutgoingCh           *channels.InfiniteChannel
	Reason               *FSMStateReason
	Conn                 net.Conn
	ConnCh               chan net.Conn
	IdleHoldTime         float64
	OpenSentHoldTime     float64
	AdminState           AdminState
	AdminStateCh         chan AdminStateOperation
	RFMap                map[bgp.Family]bgp.BGPAddPathMode
	CapMap               map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface
	RecvOpen             *bgp.BGPMessage
	PeerInfo             *table.PeerInfo
	GracefulRestartTimer *time.Timer
	TwoByteAsTrans       bool
	MarshallingOptions   *bgp.MarshallingOption
	Notification         chan *bgp.BGPMessage
	LongLivedRunning     bool
	HoldTimerResetCh     chan bool
	SentNotification     *bgp.BGPMessage
	Callback             FSMCallback
	Logger               log.Logger
}

type PeerGroup struct {
	Conf             *oc.PeerGroup
	Members          map[string]oc.Neighbor
	DynamicNeighbors map[string]*oc.DynamicNeighbor
}

type Peer struct {
	TableId           string
	FSM               *fsm
	AdjRibIn          *table.AdjRib
	Policy            *table.RoutingPolicy
	LocalRib          *table.TableManager
	PrefixLimitWarned map[bgp.Family]bool
	// map of path local identifiers sent for that prefix
	SentPaths           map[table.PathDestLocalKey]map[uint32]struct{}
	SendMaxPathFiltered map[table.PathLocalKey]struct{}
	LLGREndChs          []chan struct{}
	Ctx                 context.Context
	CtxCancel           context.CancelFunc
}
