package peering

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eapache/channels"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/utils"
)

var (
	MinConnectRetryInterval = time.Second
	FlopThreshold           = time.Second * 30
	OpenSentHoldTime        = time.Second * 240
	IdleHoldTime            = time.Second * 5
)

type FSMStateReasonType uint8

const (
	FSMDying FSMStateReasonType = iota
	FSMAdminDown
	FSMAdminPfxCt
	FSMLocalResolveFailed
	FSMConnectFailed
	FSMReadFailed
	FSMWriteFailed
	FSMNotificationSent
	FSMNotificationRecv
	FSMHoldTimerExpired
	FSMIdleTimerExpired
	FSMConnectRetryTimerExpired
	FSMRestartTimerExpired
	FSMGracefulRestart
	FSMUnexpectedMsg
	FSMNewConnection
	FSMHeaderError
	FSMMessageError
	FSMSerializationError
	FSMUpdateMsgError
	FSMOpenMsgSendFailed
	FSMOpenMsgSerializedFailed
	FSMOpenMsgReceived
	FSMOpenMsgReceivedFailed
	FSMOpenMsgNegotiated
	FSMCollisionDetected
	FSMHardReset
	FSMDeconfigured
)

type FSMStateTransition struct {
	OldState bgp.FSMState
	NewState bgp.FSMState
	Reason   FSMStateReasonType
	Data     any
}

type FSMMsg struct {
	Source    string
	Message   *bgp.BGPMessage
	PathList  []*table.Path
	Timestamp time.Time
	Payload   []byte
}

type AdminState int

const (
	AdminStateUp AdminState = iota
	AdminStateDown
	AdminStatePfxCt
)

func (s AdminState) String() string {
	switch s {
	case AdminStateUp:
		return "admin-up"
	case AdminStateDown:
		return "admin-down"
	case AdminStatePfxCt:
		return "admin-pfx-ct"
	default:
		return "unknown"
	}
}

type AdminStateOperation struct {
	state         AdminState
	communication string
}

type (
	FSMBGPCallback        func(*FSMMsg)
	FSMTransitionCallback func(*FSMStateTransition)
)

type FSMCommon struct {
	Lock sync.RWMutex
	// OC Config fields are written once at the beginning
	// and never changed. So we can read them without locking.
	// OC State fields can be changed at any time.
	GlobalConf *oc.Global
	PeerConf   *oc.Neighbor
	RFMap      map[bgp.Family]bgp.BGPAddPathMode
	CapMap     map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface
	PeerInfo   *table.PeerInfo
	SentOpen   *bgp.BGPMessage
}

type fsmTimers struct {
	connectRetryTime     time.Duration
	connectRetryTimer    *time.Timer
	holdTime             time.Duration
	holdTimer            *time.Timer
	keepAliveInterval    time.Duration
	keepAliveTimer       *time.Timer
	idleHoldTime         time.Duration
	idleHoldTimer        *time.Timer
	gracefulRestartTime  time.Duration
	gracefulRestartTimer *time.Timer
}

type fsmStats struct {
	// connectRetryCounter uint32
	establishedCounter uint32
	upSince            time.Time
}

type trackedConn struct {
	net.Conn
	common *FSMCommon

	recvdOpen         *bgp.BGPOpen
	peerAs            uint32
	holdTime          time.Duration
	keepAliveInterval time.Duration
	closed            atomic.Bool
}

type connTracking struct {
	lock   sync.RWMutex
	conns  map[net.Addr]*trackedConn
	connCh chan net.Conn
	bestCh chan *trackedConn
	best   *trackedConn
}

// https://datatracker.ietf.org/doc/html/rfc4271#section-8
type fsm struct {
	common *FSMCommon

	adminState         *utils.Atomic[AdminState]
	adminStateCh       chan *AdminStateOperation
	tracking           *connTracking
	conn               atomic.Pointer[trackedConn]
	timers             *fsmTimers
	outgoingCh         *channels.InfiniteChannel
	state              *utils.Atomic[bgp.FSMState]
	transitionCh       chan *FSMStateTransition
	stats              *fsmStats
	twoByteAsTrans     atomic.Bool
	marshallingOptions atomic.Pointer[bgp.MarshallingOption]
	bgpCallback        FSMBGPCallback
	transitionCallback FSMTransitionCallback
	endNotificationCh  chan *bgp.BGPMessage
	logger             log.Logger
}

type PeerGroup struct {
	Conf             *oc.PeerGroup
	Members          map[string]oc.Neighbor
	DynamicNeighbors map[string]*oc.DynamicNeighbor
}

type Peer struct {
	Common *FSMCommon

	Lock              sync.RWMutex
	TableId           string
	AdjRibIn          *table.AdjRib
	Policy            *table.RoutingPolicy
	LocalRib          *table.TableManager
	PrefixLimitWarned map[bgp.Family]bool
	// map of path local identifiers sent for that prefix
	SentPaths           map[table.PathDestLocalKey]map[uint32]struct{}
	SendMaxPathFiltered map[table.PathLocalKey]struct{}
	LLGREndChs          []chan struct{}
	LongLivedRunning    bool
	Logger              log.Logger

	fsm    *fsm
	ctx    context.Context
	cancel context.CancelFunc
}
