package server

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// familyCountingAction accepts every path and counts the paths the export
// policy was evaluated on, per family.
type familyCountingAction struct {
	mu    sync.Mutex
	count map[bgp.Family]int
}

func (a *familyCountingAction) Type() table.ActionType { return table.ACTION_ROUTING }

func (a *familyCountingAction) Apply(path *table.Path, _ *table.PolicyOptions) (*table.Path, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.count[path.GetFamily()]++
	return path, nil
}

func (a *familyCountingAction) String() string { return "count" }

func (a *familyCountingAction) reset() map[bgp.Family]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.count
	a.count = make(map[bgp.Family]int)
	return c
}

// TestAdjRibOutReadEvaluatesRequestedFamilyOnly checks that an adj-out read
// of one family, a path listing or a summary, runs the export policy on the
// paths of that family only, not on those of every family configured on the
// peer.
func TestAdjRibOutReadEvaluatesRequestedFamilyOnly(t *testing.T) {
	const v6Paths = 100
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65001, RouterId: "1.1.1.1", ListenPort: -1},
	}))

	action := &familyCountingAction{count: make(map[bgp.Family]int)}
	require.NoError(t, s.policy.AddPolicy(&table.Policy{
		Name:       "count",
		Statements: []*table.Statement{{Name: "count", RouteAction: action}},
	}, false))
	require.NoError(t, s.policy.AddPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT,
		[]*oc.PolicyDefinition{{Name: "count"}}, table.ROUTE_TYPE_ACCEPT))

	addr := netip.MustParseAddr("10.0.0.1")
	p := newPeerandInfo(t, 65001, 65002, addr.String(), s.globalRib)
	p.policy = s.policy
	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	conf.AfiSafis = []oc.AfiSafi{
		{State: oc.AfiSafiState{Family: bgp.RF_IPv4_UC}},
		{State: oc.AfiSafiState{Family: bgp.RF_IPv6_UC}},
	}
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE,
		bgp.RF_IPv6_UC: bgp.BGP_ADD_PATH_NONE,
	})
	t.Cleanup(func() {
		_ = s.mgmtOperation(func() error {
			delete(s.neighborMap, addr)
			return nil
		}, false)
		cleanInfiniteChannel(p.fsm.outgoingCh)
		s.Stop()
	})

	paths := []*table.Path{makePath(t, "10.1.0.0/24", "10.0.0.254", 0)}
	for i := range v6Paths {
		prefix := netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, byte(i)}), 48)
		nlri, err := bgp.NewIPAddrPrefix(prefix)
		require.NoError(t, err)
		mp, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr("2001:db8::254"))
		require.NoError(t, err)
		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65001})}),
			mp,
		}
		paths = append(paths, table.NewPath(bgp.RF_IPv6_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false))
	}
	require.NoError(t, s.mgmtOperation(func() error {
		s.neighborMap[addr] = p
		s.propagateUpdate(nil, paths)
		return nil
	}, true))
	action.reset()

	for _, enableFiltered := range []bool{false, true} {
		dests := 0
		require.NoError(t, s.ListPath(apiutil.ListPathRequest{
			TableType:      api.TableType_TABLE_TYPE_ADJ_OUT,
			Name:           addr.String(),
			Family:         bgp.RF_IPv4_UC,
			EnableFiltered: enableFiltered,
		}, func(bgp.NLRI, []*apiutil.Path) { dests++ }))
		assert.Equal(t, 1, dests, "enableFiltered=%v", enableFiltered)
		assert.Equal(t, map[bgp.Family]int{bgp.RF_IPv4_UC: 1}, action.reset(), "enableFiltered=%v", enableFiltered)
	}

	rsp, err := s.GetTable(context.Background(), &api.GetTableRequest{
		TableType: api.TableType_TABLE_TYPE_ADJ_OUT,
		Name:      addr.String(),
		Family:    &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), rsp.NumDestination)
	assert.Equal(t, uint64(1), rsp.NumPath)
	assert.Equal(t, map[bgp.Family]int{bgp.RF_IPv4_UC: 1}, action.reset())

	// The other family is still read in full.
	dests := 0
	require.NoError(t, s.ListPath(apiutil.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_ADJ_OUT,
		Name:      addr.String(),
		Family:    bgp.RF_IPv6_UC,
	}, func(bgp.NLRI, []*apiutil.Path) { dests++ }))
	assert.Equal(t, v6Paths, dests)
	assert.Equal(t, map[bgp.Family]int{bgp.RF_IPv6_UC: v6Paths}, action.reset())

	rsp, err = s.GetTable(context.Background(), &api.GetTableRequest{
		TableType: api.TableType_TABLE_TYPE_ADJ_OUT,
		Name:      addr.String(),
		Family:    &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST},
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(v6Paths), rsp.NumDestination)
	assert.Equal(t, map[bgp.Family]int{bgp.RF_IPv6_UC: v6Paths}, action.reset())
}
