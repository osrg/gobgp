// Copyright (C) 2014-2021 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgryski/go-farm"
	"github.com/eapache/channels"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/internal/pkg/version"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
	"github.com/osrg/gobgp/v4/pkg/zebra"
)

type FSMOperation uint

const (
	FSMMgmtOp FSMOperation = iota
	FSMAccept
	FSMROAEvent
	FSMMessage

	FSMOperationTypeCount
)

type FSMTimingHook interface {
	Observe(op FSMOperation, tOp, tWait time.Duration)
}

type nopTimingHook struct{}

func (n nopTimingHook) Observe(op FSMOperation, tOp, tWait time.Duration) {}

type options struct {
	grpcAddress string
	grpcOption  []grpc.ServerOption
	logger      *slog.Logger
	logLevelVar *slog.LevelVar
	timingHook  FSMTimingHook
}

type ServerOption func(*options)

func GrpcListenAddress(addr string) ServerOption {
	return func(o *options) {
		o.grpcAddress = addr
	}
}

func GrpcOption(opt []grpc.ServerOption) ServerOption {
	return func(o *options) {
		o.grpcOption = opt
	}
}

func LoggerOption(logger *slog.Logger, levelVar *slog.LevelVar) ServerOption {
	return func(o *options) {
		o.logger = logger
		o.logLevelVar = levelVar
	}
}

func TimingHookOption(hook FSMTimingHook) ServerOption {
	return func(o *options) {
		o.timingHook = hook
	}
}

type sharedData struct {
	mu sync.Mutex
}

func newSharedData() *sharedData {
	return &sharedData{
		mu: sync.Mutex{},
	}
}

type BgpServer struct {
	shared       *sharedData
	apiServer    *server
	bgpConfig    oc.Bgp
	acceptCh     chan net.Conn
	mgmtCh       chan *mgmtOp
	policy       *table.RoutingPolicy
	listeners    []*netutils.TCPListener
	neighborMap  map[netip.Addr]*peer
	peerGroupMap map[string]*peerGroup
	globalRib    *table.TableManager
	rsRib        *table.TableManager
	roaManager   *roaManager
	watcherMap   map[watchEventType][]*watcher
	zclient      *zebraClient
	bmpManager   *bmpClientManager
	mrtManager   *mrtManager
	roaTable     *table.ROATable
	uuidMap      map[string]uuid.UUID
	logger       *slog.Logger
	logLevelVar  *slog.LevelVar
	timingHook   FSMTimingHook
	// manage lifecycle of the server
	isServing     atomic.Bool
	shutdownWG    *sync.WaitGroup
	runningCtx    context.Context
	runningCancel context.CancelFunc
}

func NewBgpServer(opt ...ServerOption) *BgpServer {
	opts := options{
		timingHook: nopTimingHook{},
	}
	for _, o := range opt {
		o(&opts)
	}
	logger := opts.logger
	lvl := opts.logLevelVar
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
		lvl = nil
	}
	roaTable := table.NewROATable(logger)
	shared := newSharedData()

	s := &BgpServer{
		shared:       shared,
		neighborMap:  make(map[netip.Addr]*peer),
		peerGroupMap: make(map[string]*peerGroup),
		policy:       table.NewRoutingPolicy(logger),
		mgmtCh:       make(chan *mgmtOp, 1),
		watcherMap:   make(map[watchEventType][]*watcher),
		uuidMap:      make(map[string]uuid.UUID),
		roaManager:   newROAManager(roaTable, logger),
		roaTable:     roaTable,
		logger:       logger,
		logLevelVar:  lvl,
		timingHook:   opts.timingHook,
		shutdownWG:   &sync.WaitGroup{},
	}
	s.bmpManager = newBmpClientManager(s)
	s.mrtManager = newMrtManager(s)
	if len(opts.grpcAddress) != 0 {
		grpc.EnableTracing = false
		s.apiServer = newAPIserver(s, shared, grpc.NewServer(opts.grpcOption...), opts.grpcAddress)
		go func() {
			if err := s.apiServer.serve(); err != nil {
				logger.Error("failed to listen grpc port", slog.String("Error", err.Error()))
			}
		}()
	}
	return s
}

func (s *BgpServer) Stop() {
	if err := s.StopBgp(context.Background(), &api.StopBgpRequest{}); err != nil {
		s.logger.Error("failed to stop BGP server",
			slog.String("Topic", "BgpServer"),
			slog.Any("Error", err),
		)
	}

	if s.apiServer != nil {
		s.apiServer.grpcServer.Stop()
	}
}

func (s *BgpServer) listListeners(addr string) []*net.TCPListener {
	list := make([]*net.TCPListener, 0, len(s.listeners))
	rhs := net.ParseIP(addr).To4() != nil
	for _, l := range s.listeners {
		host, _, _ := net.SplitHostPort(l.Addr().String())
		lhs := net.ParseIP(host).To4() != nil
		if lhs == rhs {
			list = append(list, l.Listener())
		}
	}
	return list
}

func (s *BgpServer) active() error {
	if s.bgpConfig.Global.Config.As == 0 {
		return fmt.Errorf("bgp server hasn't started yet")
	}
	return nil
}

type mgmtOp struct {
	f           func() error
	errCh       chan error
	checkActive bool // check BGP global setting is configured before calling f()
	timestamp   time.Time
}

func (s *BgpServer) handleMGMTOp(op *mgmtOp) {
	if op.checkActive {
		if err := s.active(); err != nil {
			op.errCh <- err
			return
		}
	}
	op.errCh <- op.f()
}

func (s *BgpServer) mgmtOperation(f func() error, checkActive bool) (err error) {
	ch := make(chan error)
	defer func() { err = <-ch }()
	s.mgmtCh <- &mgmtOp{
		f:           f,
		errCh:       ch,
		checkActive: checkActive,
		timestamp:   time.Now(),
	}
	return err
}

func (s *BgpServer) startFsmHandler(peer *peer) {
	callback := func(e *fsmMsg) {
		s.handleFSMMessage(peer, e)
	}
	peer.startFSM(s.shutdownWG, callback)
}

func (s *BgpServer) passConnToPeer(conn net.Conn) {
	remoteAddr := conn.RemoteAddr()
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		s.logger.Warn("Failed to get TCPAddr from RemoteAddr",
			slog.String("Topic", "Server"),
			slog.String("Remote Addr", remoteAddr.String()),
		)
		conn.Close()
		return
	}
	addr, _ := netip.AddrFromSlice(tcpAddr.IP)
	addr = addr.WithZone(tcpAddr.Zone)

	peer, found := s.neighborMap[addr]
	if found {
		peer.fsm.lock.Lock()
		adminStateNotUp := peer.AdminState() != adminStateUp
		peer.fsm.lock.Unlock()
		if adminStateNotUp {
			peer.fsm.logger.Debug("New connection for non admin-state-up peer", slog.String("Admin State", peer.AdminState().String()))
			conn.Close()
			return
		}
		peer.fsm.lock.Lock()
		localAddr := peer.fsm.pConf.Transport.Config.LocalAddress
		bindInterface := peer.fsm.pConf.Transport.Config.BindInterface
		peer.fsm.lock.Unlock()
		localAddrValid := func(laddr string) bool {
			if laddr == "0.0.0.0" || laddr == "::" {
				return true
			}
			l := conn.LocalAddr()
			if l == nil {
				// already closed
				return false
			}

			host, _, _ := net.SplitHostPort(l.String())
			if host != laddr && bindInterface == "" {
				peer.fsm.logger.Info("Mismatched local address",
					slog.String("Configured addr", laddr),
					slog.String("Addr", host),
					slog.String("BindInterface", bindInterface))
				return false
			}
			return true
		}(localAddr.String())

		if !localAddrValid {
			conn.Close()
			return
		}

		peer.fsm.logger.Debug("Accepted a new passive connection")
		peer.PassConn(conn)
	} else if pg := s.matchLongestDynamicNeighborPrefix(addr.WithZone("").String()); pg != nil {
		s.logger.Debug("Accepted a new dynamic neighbor",
			slog.String("Topic", "Peer"),
			slog.String("Key", addr.String()),
		)
		rib := s.globalRib
		if pg.Conf.RouteServer.Config.RouteServerClient {
			rib = s.rsRib
		}
		peer := newDynamicPeer(&s.bgpConfig.Global, addr.String(), pg.Conf, rib, s.policy, s.logger)
		if peer == nil {
			s.logger.Info("Can't create new Dynamic Peer",
				slog.String("Topic", "Peer"),
				slog.String("Key", addr.String()),
			)
			conn.Close()
			return
		}
		peer.fsm.lock.Lock()
		policy := peer.fsm.pConf.ApplyPolicy
		peer.fsm.lock.Unlock()
		if err := s.policy.SetPeerPolicy(peer.ID(), policy); err != nil {
			peer.fsm.logger.Error("Failed to set peer policy for dynamic peer", slog.Any("Error", err))
			conn.Close()
			return
		}

		s.neighborMap[addr] = peer
		s.startFsmHandler(peer)
		s.broadcastPeerState(peer, bgp.BGP_FSM_ACTIVE, nil)
		peer.PassConn(conn)
	} else {
		s.logger.Info("Can't find configuration for a new passive connection",
			slog.String("Topic", "Server"),
			slog.String("Key", addr.String()),
		)
		conn.Close()
	}
}

func (s *BgpServer) Serve() {
	if s.isServing.Swap(true) {
		s.logger.Warn("server is already serving",
			slog.String("Topic", "BgpServer"),
		)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.runningCtx = ctx
	s.runningCancel = cancel
	s.shutdownWG.Add(1)
	s.listeners = make([]*netutils.TCPListener, 0, 2)

	defer func() {
		s.shutdownWG.Done()
		s.isServing.Store(false)
	}()

	for {
		tStart := time.Now()
		select {
		case <-s.runningCtx.Done():
			s.logger.Info("shutting down",
				slog.String("Topic", "BgpServer"))
			return
		case op := <-s.mgmtCh:
			tWait := tStart.Sub(op.timestamp)
			s.shared.mu.Lock()
			s.handleMGMTOp(op)
			s.shared.mu.Unlock()
			s.timingHook.Observe(FSMMgmtOp, time.Since(tStart), tWait)
		case conn := <-s.acceptCh:
			// NOTE: it would be useful to use kernel metrics such as SO_TIMESTAMPING to record time we got
			// first SYN packet in TCP connection. For now we skip tWait for accept events, message/mgmt op
			// delays should be enough to analyze FSM loop.
			s.shared.mu.Lock()
			s.passConnToPeer(conn)
			s.shared.mu.Unlock()
			s.timingHook.Observe(FSMAccept, time.Since(tStart), 0)
		case ev := <-s.roaManager.ReceiveROA():
			tWait := tStart.Sub(ev.timestamp)
			s.shared.mu.Lock()
			s.roaManager.HandleROAEvent(ev)
			s.shared.mu.Unlock()
			s.timingHook.Observe(FSMROAEvent, time.Since(tStart), tWait)
		}
	}
}

func (s *BgpServer) matchLongestDynamicNeighborPrefix(a string) *peerGroup {
	ipAddr := net.ParseIP(a)
	longestMask := net.CIDRMask(0, 32).String()
	var longestPG *peerGroup
	for _, pg := range s.peerGroupMap {
		for _, d := range pg.dynamicNeighbors {
			_, netAddr, _ := net.ParseCIDR(d.Config.Prefix.String())
			if netAddr.Contains(ipAddr) {
				if netAddr.Mask.String() > longestMask ||
					netAddr.Mask.String() == longestMask && longestMask == net.CIDRMask(0, 32).String() {
					longestMask = netAddr.Mask.String()
					longestPG = pg
				}
			}
		}
	}
	return longestPG
}

func sendfsmOutgoingMsg(peer *peer, paths []*table.Path) {
	peer.fsm.outgoingCh.In() <- &fsmOutgoingMsg{
		Paths: paths,
	}
}

func isASLoop(peer *peer, path *table.Path) bool {
	return slices.Contains(path.GetAsList(), peer.AS())
}

func filterpath(peer *peer, path, old *table.Path) *table.Path {
	if path == nil {
		return nil
	}

	if y := peer.IsFamilyEnabled(path.GetFamily()); !y {
		return nil
	}

	// RFC4684 Constrained Route Distribution
	if y := peer.IsFamilyEnabled(bgp.RF_RTC_UC); y && path.GetFamily() != bgp.RF_RTC_UC {
		if !peer.interestedIn(path) {
			peer.fsm.logger.Debug("Filtered by Route Target Constraint, ignore", slog.Any("Path", path))
			if old == nil {
				return nil
			}
			if !peer.interestedIn(old) {
				peer.fsm.logger.Debug("Old path filtered by Route Target Constraint, ignore", slog.Any("Path", old))
				return nil
			}
			path = old.Clone(true)
			old = nil
		}
	}

	// iBGP handling
	if peer.isIBGPPeer() {
		ignore := false
		if !path.IsLocal() {
			ignore = true
			info := path.GetSource()
			// if the path comes from eBGP peer
			if info.AS != peer.AS() {
				ignore = false
			}
			if info.RouteReflectorClient {
				ignore = false
			}
			if peer.isRouteReflectorClient() {
				// RFC4456 8. Avoiding Routing Information Loops
				// If the local CLUSTER_ID is found in the CLUSTER_LIST,
				// the advertisement received SHOULD be ignored.
				for _, clusterID := range path.GetClusterList() {
					peer.fsm.lock.Lock()
					rrClusterID := net.ParseIP(peer.fsm.pConf.RouteReflector.State.RouteReflectorClusterId.String())
					peer.fsm.lock.Unlock()
					if slices.Equal(clusterID.AsSlice(), rrClusterID.To4()) {
						peer.fsm.logger.Debug("cluster list path attribute has local cluster id, ignore",
							slog.String("ClusterID", clusterID.String()),
							slog.Any("Path", path))
						return nil
					}
				}
				ignore = false
			}
		}

		if ignore {
			if !path.IsWithdraw && old != nil {
				oldSource := old.GetSource()
				if old.IsLocal() || oldSource.Address.String() != peer.ID() && oldSource.AS != peer.AS() {
					// In this case, we suppose this peer has the same prefix
					// received from another iBGP peer.
					// So we withdraw the old best which was injected locally
					// (from CLI or gRPC for example) in order to avoid the
					// old best left on peers.
					// Also, we withdraw the eBGP route which is the old best.
					// When we got the new best from iBGP, we don't advertise
					// the new best and need to withdraw the old best.
					return old.Clone(true)
				}
			}
			peer.fsm.logger.Debug("From same AS, ignore", slog.Any("Path", path))
			return nil
		}
	}

	if path = peer.filterPathFromSourcePeer(path, old); path == nil {
		return nil
	}

	if !peer.isRouteServerClient() && isASLoop(peer, path) {
		// Do not filter local (static) routes with as-path loop
		// if configured to bypass these checks in the peer
		// as-path options config.
		if !path.IsLocal() || !peer.allowAsPathLoopLocal() {
			if !path.IsWithdraw && old != nil {
				// A new best path was selected, but we cannot advertise it to this peer
				// due to as-loop. In this case, we MUST explicitly withdraw the
				// old path we previously advertised to prevent a stucked route
				// on the peer, which would lead to a traffic blackhole.
				//
				// Example: routers from AS A: A1 and A2, AS B: B1
				// A1 <eBGP> B1, A2 <eBGP> B1, no iBGP
				// All of them announce prefix P
				// Paths on A1, A2: [local, B1]
				// Paths on B1: [local, A1, A2]
				// When B1 receive local prefix withdraw it choose new best
				// for example from A1. Then it send. explicit withdraw for A1
				// and try to implicit withdraw for other peers. But we have AS-Loop for
				// A2 and path stuck. So in this case B1 should send explicit withdraw for old path.
				return old.Clone(true)
			}
			return nil
		}
	}
	return path
}

func (s *BgpServer) prePolicyFilterpath(peer *peer, path, old *table.Path) (*table.Path, *table.PolicyOptions, bool) {
	// Special handling for RTM NLRI.
	if path != nil && path.GetFamily() == bgp.RF_RTC_UC && !path.IsWithdraw {
		// If the given "path" is locally generated and the same with "old", we
		// assumes "path" was already sent before. This assumption avoids the
		// infinite UPDATE loop between Route Reflector and its clients.
		if path.IsLocal() && path.Equal(old) {
			s.logger.Debug("given rtm nlri is already sent, skipping to advertise", slog.Any("Path", path))
			return nil, nil, true
		}

		if old != nil && old.IsLocal() {
			// If it is vrf or rtc route deleting, it will work via explicitWithdraw
			// and make old.Clone(true). The only way to get path != nil and old != nil
			// is to change the path without changing rt. Then we need to update path or
			// do nothing if path == old.
		} else if peer.isRouteReflectorClient() {
			// We need to send the path even if the peer is originator of the
			// path in order to signal that the client should distribute route
			// with the given RT.
		} else {
			// We send a path even if it is not the best path. See comments in
			// (*Destination) GetChanges().
			dst := peer.localRib.GetDestination(path)
			path = nil
			for _, p := range dst.GetKnownPathList(peer.TableID(), peer.AS()) {
				srcPeer := p.GetSource()
				if peer.ID() != srcPeer.Address.String() {
					if srcPeer.RouteReflectorClient {
						// The path from a RR client is preferred than others
						// for the case that RR and non RR client peering
						// (e.g., peering of different RR clusters).
						path = p
						break
					} else if path == nil {
						path = p
					}
				}
			}
		}
	}

	// only allow vpnv4 and vpnv6 paths to be advertised to VRFed neighbors.
	// also check we can import this path using table.CanImportToVrf()
	// if we can, make it local path by calling (*Path).ToLocal()
	peer.fsm.lock.Lock()
	peerVrf := peer.fsm.pConf.Config.Vrf
	peer.fsm.lock.Unlock()
	if path != nil && peerVrf != "" {
		if f := path.GetFamily(); f != bgp.RF_IPv4_VPN && f != bgp.RF_IPv6_VPN && f != bgp.RF_FS_IPv4_VPN && f != bgp.RF_FS_IPv6_VPN {
			return nil, nil, true
		}
		vrf := peer.localRib.Vrfs[peerVrf]
		if table.CanImportToVrf(vrf, path) {
			path = path.ToLocal()
		} else {
			return nil, nil, true
		}
	}

	// replace-peer-as handling
	peer.fsm.lock.Lock()
	if path != nil && !path.IsWithdraw && peer.fsm.pConf.AsPathOptions.State.ReplacePeerAs {
		path = path.ReplaceAS(peer.fsm.pConf.Config.LocalAs, peer.fsm.pConf.Config.PeerAs)
	}
	peer.fsm.lock.Unlock()

	if path = filterpath(peer, path, old); path == nil {
		return nil, nil, true
	}

	options := &table.PolicyOptions{
		Info: peer.peerInfo,
	}
	peer.fsm.lock.Lock()
	if path.IsLocal() && path.GetNexthop().IsUnspecified() {
		// We need a special treatment for the locally-originated path
		// with unspecified nexthop (0.0.0.0 or ::). In this case, the
		// OldNextHop option should be set to the local address.
		// Otherwise, we advertise the unspecified nexthop as is when
		// nexthop-unchanged is configured.
		options.OldNextHop = net.ParseIP(peer.fsm.pConf.Transport.State.LocalAddress.String())
	} else {
		options.OldNextHop = path.GetNexthop().AsSlice()
	}
	path = table.UpdatePathAttrs(peer.fsm.logger, peer.fsm.gConf, peer.fsm.pConf, peer.peerInfo, path)
	peer.fsm.lock.Unlock()

	return path, options, false
}

func (s *BgpServer) postFilterpath(peer *peer, path *table.Path) *table.Path {
	// draft-uttaro-idr-bgp-persistence-02
	// 4.3.  Processing LLGR_STALE Routes
	//
	// The route SHOULD NOT be advertised to any neighbor from which the
	// Long-lived Graceful Restart Capability has not been received.  The
	// exception is described in the Optional Partial Deployment
	// Procedure section (Section 4.7).  Note that this requirement
	// implies that such routes should be withdrawn from any such neighbor.
	if path != nil && !path.IsWithdraw && !peer.isLLGREnabledFamily(path.GetFamily()) && path.IsLLGRStale() {
		// we send unnecessary withdrawn even if we didn't
		// sent the route.
		path = path.Clone(true)
	}

	// remove local-pref attribute
	// we should do this after applying export policy since policy may
	// set local-preference
	if path != nil && !peer.isIBGPPeer() && !peer.isRouteServerClient() {
		path.RemoveLocalPref()
	}

	return path
}

func (s *BgpServer) filterpath(peer *peer, path, old *table.Path) *table.Path {
	path, options, stop := s.prePolicyFilterpath(peer, path, old)
	if stop {
		return nil
	}
	options.Validate = s.roaTable.Validate
	path = peer.policy.ApplyPolicy(peer.TableID(), table.POLICY_DIRECTION_EXPORT, path, options)
	// When 'path' is filtered (path == nil), check 'old' has been sent to this peer.
	// If it has, send withdrawal to the peer.
	if path == nil && old != nil {
		o := peer.policy.ApplyPolicy(peer.TableID(), table.POLICY_DIRECTION_EXPORT, old, options)
		if o != nil {
			path = old.Clone(true)
		}
	}

	return s.postFilterpath(peer, path)
}

func clonePathList(pathList []*table.Path) []*table.Path {
	l := make([]*table.Path, 0, len(pathList))
	for _, p := range pathList {
		if p != nil {
			l = append(l, p.Clone(p.IsWithdraw))
		}
	}
	return l
}

func (s *BgpServer) setPathVrfIdMap(paths []*table.Path, m map[uint32]bool) {
	for _, p := range paths {
		switch p.GetFamily() {
		case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
			for _, vrf := range s.globalRib.Vrfs {
				if vrf.Id != 0 && table.CanImportToVrf(vrf, p) {
					m[vrf.Id] = true
				}
			}
		default:
			m[zebra.DefaultVrf] = true
		}
	}
}

// Note: the destination would be the same for all the paths passed here
// The wather (only zapi) needs a unique list of vrf IDs
func (s *BgpServer) notifyBestWatcher(best []*table.Path, multipath [][]*table.Path) {
	if table.SelectionOptions.DisableBestPathSelection {
		// Note: If best path selection disabled, no best path to notify.
		return
	}
	m := make(map[uint32]bool)
	clonedM := make([][]*table.Path, len(multipath))
	for i, pathList := range multipath {
		clonedM[i] = clonePathList(pathList)
		if table.UseMultiplePaths.Enabled {
			s.setPathVrfIdMap(clonedM[i], m)
		}
	}
	clonedB := clonePathList(best)
	if !table.UseMultiplePaths.Enabled {
		s.setPathVrfIdMap(clonedB, m)
	}
	w := &watchEventBestPath{PathList: clonedB, MultiPathList: clonedM, Timestamp: time.Now()}
	if len(m) > 0 {
		w.Vrf = m
	}
	s.notifyWatcher(watchEventTypeBestPath, w)
}

func (s *BgpServer) toConfig(peer *peer, getAdvertised bool) *oc.Neighbor {
	// create copy which can be access to without mutex
	peer.fsm.lock.Lock()
	conf := *peer.fsm.pConf
	peerAfiSafis := peer.fsm.pConf.AfiSafis
	peerCapMap := peer.fsm.capMap
	peer.fsm.lock.Unlock()

	conf.AfiSafis = make([]oc.AfiSafi, len(peerAfiSafis))
	for i, af := range peerAfiSafis {
		conf.AfiSafis[i] = af
		conf.AfiSafis[i].AddPaths.State.Receive = peer.isAddPathReceiveEnabled(af.State.Family)
		if peer.isAddPathSendEnabled(af.State.Family) {
			conf.AfiSafis[i].AddPaths.State.SendMax = af.AddPaths.State.SendMax
		} else {
			conf.AfiSafis[i].AddPaths.State.SendMax = 0
		}
	}

	remoteCap := make([]bgp.ParameterCapabilityInterface, 0, len(peerCapMap))
	for _, caps := range peerCapMap {
		for _, m := range caps {
			// need to copy all values here
			buf, _ := m.Serialize()
			c, _ := bgp.DecodeCapability(buf)
			remoteCap = append(remoteCap, c)
		}
	}

	conf.State.RemoteCapabilityList = remoteCap

	peer.fsm.lock.Lock()
	conf.State.LocalCapabilityList = capabilitiesFromConfig(peer.fsm.pConf)
	peer.fsm.lock.Unlock()

	state := peer.State()

	peer.fsm.lock.Lock()
	conf.State.SessionState = oc.IntToSessionStateMap[int(state)]
	conf.State.AdminState = oc.IntToAdminStateMap[int(peer.AdminState())]
	conf.State.Flops = peer.fsm.pConf.State.Flops
	peer.fsm.lock.Unlock()

	if state == bgp.BGP_FSM_ESTABLISHED {
		peer.fsm.lock.Lock()
		buf, _ := peer.fsm.recvOpen.Serialize()
		// need to copy all values here
		conf.State.ReceivedOpenMessage, _ = bgp.ParseBGPMessage(buf)
		conf.State.RemoteRouterId = peer.fsm.pConf.State.RemoteRouterId
		peer.fsm.lock.Unlock()
	}
	return &conf
}

func (s *BgpServer) notifyPrePolicyUpdateWatcher(peer *peer, pathList []*table.Path, msg *bgp.BGPMessage, timestamp time.Time, payload []byte) {
	if !s.isWatched(watchEventTypePreUpdate) || peer == nil {
		return
	}

	cloned := clonePathList(pathList)
	if len(cloned) == 0 {
		return
	}
	n := s.toConfig(peer, false)
	peer.fsm.lock.Lock()
	_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
	ev := &watchEventUpdate{
		Message:      msg,
		PeerAS:       peer.fsm.pConf.State.PeerAs,
		LocalAS:      peer.fsm.pConf.Config.LocalAs,
		PeerAddress:  net.ParseIP(peer.fsm.pConf.State.NeighborAddress.String()),
		LocalAddress: net.ParseIP(peer.fsm.pConf.Transport.State.LocalAddress.String()),
		PeerID:       net.ParseIP(peer.fsm.pConf.State.RemoteRouterId.String()).To4(),
		FourBytesAs:  y,
		Timestamp:    timestamp,
		Payload:      payload,
		PostPolicy:   false,
		PathList:     cloned,
		Neighbor:     n,
	}
	peer.fsm.lock.Unlock()
	s.notifyWatcher(watchEventTypePreUpdate, ev)
}

func (s *BgpServer) notifyPostPolicyUpdateWatcher(peer *peer, pathList []*table.Path) {
	if !s.isWatched(watchEventTypePostUpdate) || peer == nil {
		return
	}

	cloned := clonePathList(pathList)
	if len(cloned) == 0 {
		return
	}
	n := s.toConfig(peer, false)
	peer.fsm.lock.Lock()
	_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
	ev := &watchEventUpdate{
		PeerAS:       peer.fsm.pConf.State.PeerAs,
		LocalAS:      peer.fsm.pConf.Config.LocalAs,
		PeerAddress:  net.ParseIP(peer.fsm.pConf.State.NeighborAddress.String()),
		LocalAddress: net.ParseIP(peer.fsm.pConf.Transport.State.LocalAddress.String()),
		PeerID:       net.ParseIP(peer.fsm.pConf.State.RemoteRouterId.String()).To4(),
		FourBytesAs:  y,
		Timestamp:    cloned[0].GetTimestamp(),
		PostPolicy:   true,
		PathList:     cloned,
		Neighbor:     n,
	}
	peer.fsm.lock.Unlock()
	s.notifyWatcher(watchEventTypePostUpdate, ev)
}

func newWatchEventPeer(peer *peer, m *fsmMsg, oldState bgp.FSMState, t apiutil.PeerEventType) *watchEventPeer {
	peer.fsm.lock.Lock()
	sentOpen := buildopen(peer.fsm.gConf, peer.fsm.pConf)
	peer.fsm.lock.Unlock()

	state := peer.State()

	peer.fsm.lock.Lock()
	capList := make([]bgp.ParameterCapabilityInterface, 0, len(peer.fsm.capMap))
	if state >= bgp.BGP_FSM_OPENCONFIRM {
		// Adding peer remote capabilities to the event
		for code, caps := range peer.fsm.capMap {
			if code == bgp.BGP_CAP_FQDN {
				// skip FQDN capability as it generates errors when Marshalling
				continue
			}
			capList = append(capList, caps...)
		}
	}

	recvOpen := peer.fsm.recvOpen
	e := &watchEventPeer{
		Type:          t,
		PeerAS:        peer.fsm.pConf.State.PeerAs,
		LocalAS:       peer.fsm.pConf.Config.LocalAs,
		PeerAddress:   peer.fsm.pConf.State.NeighborAddress,
		LocalAddress:  peer.fsm.pConf.Transport.Config.LocalAddress,
		PeerPort:      peer.fsm.pConf.Transport.State.RemotePort,
		LocalPort:     peer.fsm.pConf.Transport.State.LocalPort,
		PeerID:        peer.fsm.pConf.State.RemoteRouterId,
		SentOpen:      sentOpen,
		RecvOpen:      recvOpen,
		State:         state,
		OldState:      oldState,
		AdminState:    peer.AdminState(),
		Timestamp:     time.Now(),
		PeerInterface: peer.fsm.pConf.Config.NeighborInterface,
		RemoteCap:     capList,
	}
	peer.fsm.lock.Unlock()

	if m != nil {
		e.StateReason = m.StateReason
	}
	return e
}

func (s *BgpServer) broadcastPeerState(peer *peer, oldState bgp.FSMState, e *fsmMsg) {
	s.notifyWatcher(watchEventTypePeerState, newWatchEventPeer(peer, e, oldState, apiutil.PEER_EVENT_STATE))
}

// notifyMessageWatcher notifies recv message to watchers.
// The peer is guaranteed to be in ESTABLISHED state.
func (s *BgpServer) notifyMessageWatcher(peer *peer, timestamp time.Time, msg *bgp.BGPMessage, isSent bool) {
	// validation should be done in the caller of this function
	peer.fsm.lock.Lock()
	_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
	ev := &watchEventMessage{
		Message:      msg,
		PeerAS:       peer.fsm.pConf.State.PeerAs,
		LocalAS:      peer.fsm.pConf.Config.LocalAs,
		PeerAddress:  net.ParseIP(peer.fsm.pConf.State.NeighborAddress.String()),
		LocalAddress: net.ParseIP(peer.fsm.pConf.Transport.State.LocalAddress.String()),
		PeerID:       net.ParseIP(peer.fsm.pConf.State.RemoteRouterId.String()).To4(),
		FourBytesAs:  y,
		Timestamp:    timestamp,
		IsSent:       isSent,
	}
	peer.fsm.lock.Unlock()
	if !isSent {
		s.notifyWatcher(watchEventTypeRecvMsg, ev)
	}
}

func (s *BgpServer) notifyRecvMessageWatcher(peer *peer, timestamp time.Time, msg *bgp.BGPMessage) {
	if peer == nil || !s.isWatched(watchEventTypeRecvMsg) {
		return
	}
	s.notifyMessageWatcher(peer, timestamp, msg, false)
}

func (s *BgpServer) getPossibleBest(peer *peer, family bgp.Family) []*table.Path {
	if peer.isAddPathSendEnabled(family) {
		return peer.localRib.GetPathList(peer.TableID(), peer.AS(), []bgp.Family{family})
	}
	return peer.localRib.GetBestPathList(peer.TableID(), peer.AS(), []bgp.Family{family})
}

func (s *BgpServer) getBestFromLocal(peer *peer, rfList []bgp.Family) ([]*table.Path, []*table.Path) {
	pathList := []*table.Path{}
	filtered := []*table.Path{}

	if peer.isSecondaryRouteEnabled() {
		for _, family := range peer.toGlobalFamilies(rfList) {
			dsts := s.rsRib.Tables[family].GetDestinations()
			dl := make([]*table.Update, 0, len(dsts))
			for _, d := range dsts {
				l := d.GetAllKnownPathList()
				pl := make([]*table.Path, len(l))
				copy(pl, l)
				u := &table.Update{
					KnownPathList: pl,
				}
				dl = append(dl, u)
			}
			pathList = append(pathList, s.sendSecondaryRoutes(peer, nil, dl)...)
		}
		return pathList, filtered
	}

	for _, family := range peer.toGlobalFamilies(rfList) {
		for _, path := range s.getPossibleBest(peer, family) {
			if p := s.filterpath(peer, path, nil); p != nil {
				pathList = append(pathList, p)
			} else {
				filtered = append(filtered, path)
			}
		}
	}
	isGREnabled := peer.isGracefulRestartEnabled()
	for _, family := range rfList {
		// RFC 4684 6
		// As a hint that initial RT membership exchange is complete,
		// implementations SHOULD generate an End-of-RIB marker, as defined in
		// [8], for the Route Target membership (afi, safi), regardless of
		// whether graceful-restart is enabled on the BGP session.
		if isGREnabled || family == bgp.RF_RTC_UC {
			pathList = append(pathList, table.NewEOR(family))
		}
	}
	return pathList, filtered
}

func (s *BgpServer) filterPathListForWithdrawnRT(rt uint64, peer *peer, rfList []bgp.Family) []*table.Path {
	maxLen := s.globalRib.BestPathListForRTMaxLen(rt, rfList)

	filtered := make([]*table.Path, 0, maxLen)
	for _, path := range s.globalRib.GetBestPathListForWithdrawnRT(maxLen, rt, peer.ID(), peer.TableID(), 0, rfList) {
		if p := s.filterpath(peer, path, nil); p == nil {
			filtered = append(filtered, path)
		}
	}
	return filtered
}

func needToAdvertise(peer *peer) bool {
	state := peer.State()
	peer.fsm.lock.Lock()
	notEstablished := state != bgp.BGP_FSM_ESTABLISHED
	localRestarting := peer.fsm.pConf.GracefulRestart.State.LocalRestarting
	peer.fsm.lock.Unlock()
	if notEstablished {
		return false
	}
	if localRestarting {
		peer.fsm.logger.Debug("now syncing, suppress sending updates")
		return false
	}
	return true
}

func (s *BgpServer) sendSecondaryRoutes(peer *peer, newPath *table.Path, dsts []*table.Update) []*table.Path {
	if !needToAdvertise(peer) {
		return nil
	}
	pl := make([]*table.Path, 0, len(dsts))

	f := func(path, old *table.Path) *table.Path {
		path, options, stop := s.prePolicyFilterpath(peer, path, old)
		if stop {
			return nil
		}
		options.Validate = s.roaTable.Validate
		path = peer.policy.ApplyPolicy(peer.TableID(), table.POLICY_DIRECTION_EXPORT, path, options)
		if path != nil {
			return s.postFilterpath(peer, path)
		}
		return nil
	}

	for _, dst := range dsts {
		old := func() *table.Path {
			for _, old := range dst.OldKnownPathList {
				o := f(old, nil)
				if o != nil {
					return o
				}
			}
			return nil
		}()
		path := func() *table.Path {
			for _, known := range dst.KnownPathList {
				path := f(known, old)
				if path != nil {
					return path
				}
			}
			return nil
		}()
		if path != nil {
			pl = append(pl, path)
		} else if old != nil {
			pl = append(pl, old.Clone(true))
		}
	}
	return pl
}

func (s *BgpServer) processOutgoingPaths(peer *peer, paths, olds []*table.Path) []*table.Path {
	if !needToAdvertise(peer) {
		return nil
	}

	outgoing := make([]*table.Path, 0, len(paths))
	for idx, path := range paths {
		var old *table.Path
		if olds != nil {
			old = olds[idx]
		}
		if p := s.filterpath(peer, path, old); p != nil {
			outgoing = append(outgoing, p)
		}
	}
	return outgoing
}

func (s *BgpServer) handleRouteRefresh(peer *peer, e *fsmMsg) []*table.Path {
	m := e.MsgData.(*bgp.BGPMessage)
	rr := m.Body.(*bgp.BGPRouteRefresh)
	rf := bgp.NewFamily(rr.AFI, rr.SAFI)

	if y := peer.IsFamilyEnabled(rf); !y {
		peer.fsm.logger.Warn("Route family isn't supported", slog.String("Family", rf.String()))
		return nil
	}

	peer.fsm.lock.Lock()
	_, ok := peer.fsm.capMap[bgp.BGP_CAP_ROUTE_REFRESH]
	peer.fsm.lock.Unlock()
	if !ok {
		peer.fsm.logger.Warn("ROUTE_REFRESH received but the capability wasn't advertised")
		return nil
	}
	rfList := []bgp.Family{rf}
	accepted, _ := s.getBestFromLocal(peer, rfList)
	return accepted
}

func (s *BgpServer) propagateUpdate(peer *peer, pathList []*table.Path) {
	rs := peer != nil && peer.isRouteServerClient()
	vrf := false
	if peer != nil {
		peer.fsm.lock.Lock()
		vrf = !rs && peer.fsm.pConf.Config.Vrf != ""
		peer.fsm.lock.Unlock()
	}

	tableId := table.GLOBAL_RIB_NAME
	rib := s.globalRib
	if rs {
		tableId = peer.TableID()
		rib = s.rsRib
	}

	for _, path := range pathList {
		if vrf {
			peer.fsm.lock.Lock()
			peerVrf := peer.fsm.pConf.Config.Vrf
			peer.fsm.lock.Unlock()
			path = path.ToGlobal(rib.Vrfs[peerVrf])
			if s.zclient != nil {
				s.zclient.pathVrfMap[path] = rib.Vrfs[peerVrf].Id
			}
		}

		policyOptions := &table.PolicyOptions{
			Validate: s.roaTable.Validate,
		}

		if !rs && peer != nil {
			policyOptions.Info = peer.peerInfo
		}

		if p := s.policy.ApplyPolicy(tableId, table.POLICY_DIRECTION_IMPORT, path, policyOptions); p != nil {
			path = p
		} else {
			path = path.Clone(true)
		}

		if !rs {
			s.notifyPostPolicyUpdateWatcher(peer, []*table.Path{path})

			// RFC4684 Constrained Route Distribution 6. Operation
			//
			// When a BGP speaker receives a BGP UPDATE that advertises or withdraws
			// a given Route Target membership NLRI, it should examine the RIB-OUTs
			// of VPN NLRIs and re-evaluate the advertisement status of routes that
			// match the Route Target in question.
			//
			// A BGP speaker should generate the minimum set of BGP VPN route
			// updates (advertisements and/or withdraws) necessary to transition
			// between the previous and current state of the route distribution
			// graph that is derived from Route Target membership information.
			if peer != nil && path != nil && path.GetFamily() == bgp.RF_RTC_UC {
				nlri, ok := path.GetNlri().(*bgp.RouteTargetMembershipNLRI)
				if !ok {
					s.logger.Debug("Route Target Constraint wrong format, ignore",
						slog.String("Topic", "Peer"),
						slog.String("Key", peer.ID()),
						slog.Any("Data", path.String()))
					continue
				}
				rtHash, err := table.NlriRouteTargetKey(nlri)
				if err != nil {
					s.logger.Warn("Route Target Constraint wrong format, ignore",
						slog.String("Topic", "Peer"),
						slog.String("Key", peer.ID()),
						slog.Any("Data", path.String()))
					continue
				}
				fs := make([]bgp.Family, 0, len(peer.negotiatedRFList()))
				for _, f := range peer.negotiatedRFList() {
					if f != bgp.RF_RTC_UC {
						fs = append(fs, f)
					}
				}
				var paths []*table.Path
				if path.IsWithdraw {
					if rtHash == table.DefaultRT {
						// Note: The paths to be withdrawn are filtered because the
						// given RT on RTM NLRI is already removed from adj-RIB-in.
						_, paths = s.getBestFromLocal(peer, fs)
						withdrawnPaths := make([]*table.Path, 0, len(paths))
						for _, p := range paths {
							withdrawnPaths = append(withdrawnPaths, p.Clone(true))
						}
						paths = withdrawnPaths
					} else {
						paths = s.filterPathListForWithdrawnRT(rtHash, peer, fs)
					}
					// Skips filtering because the paths are already filtered
					// and the withdrawal does not need the path attributes.
					sendfsmOutgoingMsg(peer, paths)
				} else {
					if rtHash == table.DefaultRT {
						paths = s.globalRib.GetBestPathList(peer.TableID(), 0, fs)
					} else {
						paths = s.globalRib.GetBestPathListForAddedRT(rtHash, peer.ID(), peer.TableID(), 0, fs)
					}
					if !peer.getRtcEORWait() {
						paths = s.processOutgoingPaths(peer, paths, nil)
						sendfsmOutgoingMsg(peer, paths)
					} else {
						peer.fsm.logger.Debug("Nothing sent in response to RT received. Waiting for RTC EOR.", slog.Any("Path", path))
					}
				}
			}
		}

		if dsts := rib.Update(path); len(dsts) > 0 {
			s.propagateUpdateToNeighbors(rib, peer, path, dsts, true)
		}
	}
}

func dstsToPaths(id string, as uint32, dsts []*table.Update) ([]*table.Path, []*table.Path, [][]*table.Path) {
	bestList := make([]*table.Path, 0, len(dsts))
	oldList := make([]*table.Path, 0, len(dsts))
	mpathList := make([][]*table.Path, 0, len(dsts))

	for _, dst := range dsts {
		best, old, mpath := dst.GetChanges(id, as, false)
		bestList = append(bestList, best)
		oldList = append(oldList, old)
		if mpath != nil {
			mpathList = append(mpathList, mpath)
		}
	}
	return bestList, oldList, mpathList
}

func (s *BgpServer) propagateUpdateToNeighbors(rib *table.TableManager, source *peer, newPath *table.Path, dsts []*table.Update, needOld bool) {
	if table.SelectionOptions.DisableBestPathSelection {
		return
	}
	var gBestList, gOldList, bestList, oldList []*table.Path
	var mpathList [][]*table.Path
	if source == nil || !source.isRouteServerClient() {
		gBestList, gOldList, mpathList = dstsToPaths(table.GLOBAL_RIB_NAME, 0, dsts)
		s.notifyBestWatcher(gBestList, mpathList)
	}
	family := newPath.GetFamily()
	for _, targetPeer := range s.neighborMap {
		if source == nil && targetPeer.isRouteServerClient() || source != nil && source.isRouteServerClient() != targetPeer.isRouteServerClient() {
			continue
		}
		f := func() bgp.Family {
			targetPeer.fsm.lock.Lock()
			peerVrf := targetPeer.fsm.pConf.Config.Vrf
			targetPeer.fsm.lock.Unlock()
			if peerVrf != "" {
				switch family {
				case bgp.RF_IPv4_VPN:
					return bgp.RF_IPv4_UC
				case bgp.RF_IPv6_VPN:
					return bgp.RF_IPv6_UC
				case bgp.RF_FS_IPv4_VPN:
					return bgp.RF_FS_IPv4_UC
				case bgp.RF_FS_IPv6_VPN:
					return bgp.RF_FS_IPv6_UC
				}
			}
			return family
		}()
		if targetPeer.isAddPathSendEnabled(f) {
			// in case of multiple paths to the same destination, we need to
			// filter the paths before counting the number of paths to be sent.
			if newPath.IsWithdraw {
				bestList = func() []*table.Path {
					l := []*table.Path{}
					for _, d := range dsts {
						toDelete := d.GetWithdrawnPath()
						toActuallyDelete := make([]*table.Path, 0, len(toDelete))
						for _, p := range toDelete {
							// if the path is filtered, there is no need to send the withdrawal
							p := s.filterpath(targetPeer, p, nil)
							// the path was never advertized to the peer
							if p == nil || targetPeer.unsetPathSendMaxFiltered(p) {
								continue
							}
							toActuallyDelete = append(toActuallyDelete, p)
						}

						if len(toActuallyDelete) == 0 {
							continue
						}

						destination := rib.GetDestination(toActuallyDelete[0])
						l = append(l, toActuallyDelete...)

						// the destination has been removed from the table
						// e.g. no more paths to it
						if destination == nil {
							continue
						}

						knownPathList := destination.GetKnownPathList(targetPeer.TableID(), targetPeer.AS())
						toAdd := make([]*table.Path, 0, len(knownPathList))
						for _, p := range knownPathList {
							// If the path is filtered by policies, there is no need to send the path
							// Otherwise, we send only paths that were previously filtered because of the max path limit
							p := s.filterpath(targetPeer, p, nil)
							if p == nil || !targetPeer.isPathSendMaxFiltered(p) {
								continue
							}
							// We unset the flag as the path is not filtered anymore
							targetPeer.unsetPathSendMaxFiltered(p)
							toAdd = append(toAdd, p)
							if len(toAdd) == len(toActuallyDelete) {
								break
							}
						}
						l = append(l, toAdd...)
					}
					targetPeer.updateRoutes(l...)
					return l
				}()
			} else {
				alreadySent := targetPeer.hasPathAlreadyBeenSent(newPath)
				newPath := s.filterpath(targetPeer, newPath, nil)
				// if the path is not filtered and the path has already been sent or land in the limit, we can send it
				if newPath == nil {
					bestList = []*table.Path{}
				} else if alreadySent || targetPeer.getRoutesCount(f, newPath.GetPrefix()) < targetPeer.getAddPathSendMax(f) {
					bestList = []*table.Path{newPath}
					if !alreadySent {
						targetPeer.updateRoutes(newPath)
					}
					if newPath.GetFamily() == bgp.RF_RTC_UC {
						// we assumes that new "path" nlri was already sent before. This assumption avoids the
						// infinite UPDATE loop between Route Reflector and its clients.
						for _, old := range dsts[0].OldKnownPathList {
							if old.IsLocal() {
								bestList = []*table.Path{}
								break
							}
						}
					}
				} else {
					bestList = []*table.Path{}
					targetPeer.sendMaxPathFiltered[newPath.GetLocalKey()] = struct{}{}
					targetPeer.fsm.logger.Warn("exceeding max routes for prefix", slog.String("Prefix", newPath.GetPrefix()))
				}
			}
			if needToAdvertise(targetPeer) && len(bestList) > 0 {
				sendfsmOutgoingMsg(targetPeer, bestList)
			}
		} else {
			if targetPeer.isRouteServerClient() {
				if targetPeer.isSecondaryRouteEnabled() {
					if paths := s.sendSecondaryRoutes(targetPeer, newPath, dsts); len(paths) > 0 {
						sendfsmOutgoingMsg(targetPeer, paths)
					}
					continue
				}
				bestList, oldList, _ = dstsToPaths(targetPeer.TableID(), targetPeer.AS(), dsts)
			} else {
				bestList = gBestList
				oldList = gOldList
			}
			if !needOld {
				oldList = nil
			}
			if paths := s.processOutgoingPaths(targetPeer, bestList, oldList); len(paths) > 0 {
				sendfsmOutgoingMsg(targetPeer, paths)
			}
		}
	}
}

func (s *BgpServer) stopNeighbor(peer *peer, oldState bgp.FSMState, e *fsmMsg) {
	peer.stopPeerRestarting()
	delete(s.neighborMap, netip.MustParseAddr(peer.ID()))
	peer.stopFSM()
	s.broadcastPeerState(peer, oldState, e)
}

func (s *BgpServer) handleFSMMessage(peer *peer, e *fsmMsg) {
	s.shared.mu.Lock()
	defer s.shared.mu.Unlock()

	switch e.MsgType {
	case fsmMsgStateChange:
		nextState := e.MsgData.(bgp.FSMState)
		peer.fsm.lock.Lock()
		oldState := bgp.FSMState(peer.fsm.pConf.State.SessionState.ToInt())
		peer.fsm.pConf.State.SessionState = oc.IntToSessionStateMap[int(nextState)]
		peer.fsm.lock.Unlock()

		peer.fsm.lock.Lock()
		nextStateIdle := peer.fsm.pConf.GracefulRestart.State.PeerRestarting && nextState == bgp.BGP_FSM_IDLE
		peer.fsm.lock.Unlock()

		// PeerDown
		if oldState == bgp.BGP_FSM_ESTABLISHED {
			t := time.Now()
			peer.fsm.lock.Lock()
			if t.Sub(time.Unix(peer.fsm.pConf.Timers.State.Uptime, 0)) < flopThreshold {
				peer.fsm.pConf.State.Flops++
			}
			graceful := e.StateReason.Type == fsmGracefulRestart
			peer.fsm.lock.Unlock()
			var dropFamilies, gracefulFamilies []bgp.Family
			if graceful {
				peer.fsm.lock.Lock()
				peer.fsm.pConf.GracefulRestart.State.PeerRestarting = true
				peer.fsm.lock.Unlock()

				gracefulFamilies, dropFamilies = peer.forwardingPreservedFamilies()
				s.propagateUpdate(peer, peer.StaleAll(gracefulFamilies))
			} else {
				dropFamilies = peer.configuredRFlist()
			}

			// Always clear EndOfRibReceived state on PeerDown
			peer.fsm.lock.Lock()
			for i, af := range peer.fsm.pConf.AfiSafis {
				if slices.Contains(gracefulFamilies, af.State.Family) {
					peer.fsm.pConf.AfiSafis[i].MpGracefulRestart.State.Running = true
				}
				peer.fsm.pConf.AfiSafis[i].MpGracefulRestart.State.EndOfRibReceived = false
			}
			peer.fsm.lock.Unlock()

			peer.prefixLimitWarned = make(map[bgp.Family]bool)
			s.propagateUpdate(peer, peer.DropAll(dropFamilies))

			peer.fsm.lock.Lock()
			if peer.fsm.pConf.Config.PeerAs == 0 {
				peer.fsm.pConf.State.PeerAs = 0
			}
			peer.fsm.lock.Unlock()

			if !graceful && peer.isDynamicNeighbor() {
				s.stopNeighbor(peer, oldState, e)
				return
			}
		} else if nextStateIdle {
			peer.fsm.lock.Lock()
			longLivedEnabled := peer.fsm.pConf.GracefulRestart.State.LongLivedEnabled
			longLivedRunning := peer.longLivedRunning
			peer.fsm.lock.Unlock()
			// We must not restart LLGR timer until we have syncronized with
			// the peer. Routes also need to be marked wit LLGR comm just once.
			// https://datatracker.ietf.org/doc/html/rfc9494#session_resetsnever
			if longLivedEnabled && !longLivedRunning {
				peer.fsm.lock.Lock()
				peer.longLivedRunning = true
				peer.fsm.lock.Unlock()
				llgr, no_llgr := peer.llgrFamilies()

				s.propagateUpdate(peer, peer.DropAll(no_llgr))

				// attach LLGR_STALE community to paths in peer's adj-rib-in
				// paths with NO_LLGR are deleted
				pathList := peer.markLLGRStale(llgr)

				// calculate again
				// wheh path with LLGR_STALE chosen as best,
				// peer which doesn't support LLGR will drop the path
				// if it is in adj-rib-out, do withdrawal
				s.propagateUpdate(peer, pathList)

				for _, f := range llgr {
					endCh := make(chan struct{})
					peer.llgrEndChs = append(peer.llgrEndChs, endCh)
					go func(family bgp.Family, endCh chan struct{}) {
						peer.llgrRestartTimerStarted(family)
						t := peer.llgrRestartTime(family)
						timer := time.NewTimer(time.Second * time.Duration(t))

						peer.fsm.logger.Info("LLGR restart timer started", slog.String("Family", family.String()), slog.Any("Duration", t))

						select {
						case <-timer.C:
							err := s.mgmtOperation(func() error {
								peer.fsm.logger.Info("LLGR restart timer expired", slog.String("Family", family.String()), slog.Any("Duration", t))

								s.propagateUpdate(peer, peer.DropAll([]bgp.Family{family}))

								// when all llgr restart timer expired, stop PeerRestarting
								if peer.llgrRestartTimerExpired(family) {
									peer.stopPeerRestarting()
								}
								return nil
							}, false)
							if err != nil {
								// this would not happen, but handle the error just in case
								// the above operation changes in the future
								peer.fsm.logger.Error("LLGR restart timer expired but failed to propagate update",
									slog.String("Family", family.String()),
									slog.Any("Duration", t))
							}
						case <-endCh:
							peer.fsm.logger.Info("LLGR restart timer stopped",
								slog.String("Family", family.String()),
								slog.Any("Duration", t))
						}
					}(f, endCh)
				}
			} else if !longLivedEnabled {
				// RFC 4724 4.2
				// If the session does not get re-established within the "Restart Time"
				// that the peer advertised previously, the Receiving Speaker MUST
				// delete all the stale routes from the peer that it is retaining.
				peer.fsm.lock.Lock()
				peer.fsm.pConf.GracefulRestart.State.PeerRestarting = false
				for i := range peer.fsm.pConf.AfiSafis {
					peer.fsm.pConf.AfiSafis[i].MpGracefulRestart.State.Running = false
				}
				peer.fsm.lock.Unlock()

				s.propagateUpdate(peer, peer.DropAll(peer.configuredRFlist()))

				if peer.isDynamicNeighbor() {
					s.stopNeighbor(peer, oldState, e)
					return
				}
			}
		}

		drainChannel(peer.fsm.outgoingCh.Out())

		if nextState == bgp.BGP_FSM_ESTABLISHED {
			peer.fsm.lock.Lock()

			peer.peerInfo = table.NewPeerInfo(peer.fsm.gConf, peer.fsm.pConf,
				peer.fsm.pConf.State.PeerAs, peer.fsm.pConf.Config.LocalAs,
				peer.fsm.pConf.State.RemoteRouterId,
				peer.fsm.gConf.Config.RouterId, peer.fsm.pConf.Transport.State.RemoteAddress, peer.fsm.pConf.Transport.State.LocalAddress)

			neighborAddress := peer.fsm.pConf.State.NeighborAddress

			peer.fsm.lock.Unlock()
			deferralExpiredFunc := func(family bgp.Family) func() {
				//nolint: errcheck // ignore error
				return func() {
					s.mgmtOperation(func() error {
						return s.softResetOut(neighborAddress.String(), family, true)
					}, false)
				}
			}
			peer.fsm.lock.Lock()
			notLocalRestarting := !peer.fsm.pConf.GracefulRestart.State.LocalRestarting
			peer.fsm.lock.Unlock()
			if notLocalRestarting {
				// When graceful-restart cap (which means intention
				// of sending EOR) and route-target address family are negotiated,
				// send route-target NLRIs first, and wait to send others
				// till receiving EOR of route-target address family.
				// This prevents sending uninterested routes to peers.
				//
				// However, when the peer is graceful restarting, give up
				// waiting sending non-route-target NLRIs since the peer won't send
				// any routes (and EORs) before we send ours (or deferral-timer expires).
				var pathList []*table.Path
				peer.fsm.lock.Lock()
				c := peer.fsm.pConf.GetAfiSafi(bgp.RF_RTC_UC)
				notPeerRestarting := !peer.fsm.pConf.GracefulRestart.State.PeerRestarting
				peer.fsm.lock.Unlock()
				if y := peer.IsFamilyEnabled(bgp.RF_RTC_UC); y && notPeerRestarting && c.RouteTargetMembership.Config.DeferralTime > 0 {
					peer.setRtcEORWait(true)
					pathList, _ = s.getBestFromLocal(peer, []bgp.Family{bgp.RF_RTC_UC})
					t := c.RouteTargetMembership.Config.DeferralTime
					for _, f := range peer.negotiatedRFList() {
						if f != bgp.RF_RTC_UC {
							time.AfterFunc(time.Second*time.Duration(t), deferralExpiredFunc(f))
						}
					}
				} else {
					pathList, _ = s.getBestFromLocal(peer, peer.negotiatedRFList())
				}

				if len(pathList) > 0 {
					sendfsmOutgoingMsg(peer, pathList)
				}
			} else {
				// RFC 4724 4.1
				// Once the session between the Restarting Speaker and the Receiving
				// Speaker is re-established, ...snip... it MUST defer route
				// selection for an address family until it either (a) receives the
				// End-of-RIB marker from all its peers (excluding the ones with the
				// "Restart State" bit set in the received capability and excluding the
				// ones that do not advertise the graceful restart capability) or (b)
				// the Selection_Deferral_Timer referred to below has expired.
				allEnd := func() bool {
					for _, p := range s.neighborMap {
						if !p.recvedAllEOR() {
							return false
						}
					}
					return true
				}()
				if allEnd {
					for _, p := range s.neighborMap {
						p.fsm.lock.Lock()
						peerLocalRestarting := p.fsm.pConf.GracefulRestart.State.LocalRestarting
						p.fsm.pConf.GracefulRestart.State.LocalRestarting = false
						p.fsm.lock.Unlock()
						if !p.isGracefulRestartEnabled() && !peerLocalRestarting {
							continue
						}
						paths, _ := s.getBestFromLocal(p, p.configuredRFlist())
						if len(paths) > 0 {
							sendfsmOutgoingMsg(p, paths)
						}
					}
					peer.fsm.logger.Info("sync finished")
				} else {
					peer.fsm.lock.Lock()
					deferral := peer.fsm.pConf.GracefulRestart.Config.DeferralTime
					peer.fsm.lock.Unlock()
					peer.fsm.logger.Debug("Now syncing, suppress sending updates. start deferral timer", slog.Any("Duration", deferral))

					time.AfterFunc(time.Second*time.Duration(deferral), deferralExpiredFunc(bgp.Family(0)))
				}
			}
		} else {
			peer.fsm.lock.Lock()
			peer.fsm.pConf.Timers.State.Downtime = time.Now().Unix()
			peer.fsm.lock.Unlock()
		}
		// clear counter
		if peer.AdminState() == adminStateDown {
			peer.fsm.lock.Lock()
			peer.fsm.pConf.State = oc.NeighborState{}
			peer.fsm.pConf.State.NeighborAddress = peer.fsm.pConf.Config.NeighborAddress
			peer.fsm.pConf.State.PeerAs = peer.fsm.pConf.Config.PeerAs
			peer.fsm.pConf.Timers.State = oc.TimersState{}
			peer.fsm.lock.Unlock()
		}
		s.broadcastPeerState(peer, oldState, e)
	case fsmMsgRouteRefresh:
		notEstablished := peer.State() != bgp.BGP_FSM_ESTABLISHED
		peer.fsm.lock.Lock()
		beforeUptime := e.timestamp.Unix() < peer.fsm.pConf.Timers.State.Uptime
		peer.fsm.lock.Unlock()
		if notEstablished || beforeUptime {
			return
		}
		if paths := s.handleRouteRefresh(peer, e); len(paths) > 0 {
			sendfsmOutgoingMsg(peer, paths)
			return
		}
	case fsmMsgBGPMessage:
		switch m := e.MsgData.(type) {
		case *bgp.MessageError:
			peer.sendNotification(bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data))
			return
		case *bgp.BGPMessage:
			s.notifyRecvMessageWatcher(peer, e.timestamp, m)
			notEstablished := peer.State() != bgp.BGP_FSM_ESTABLISHED
			peer.fsm.lock.Lock()
			beforeUptime := e.timestamp.Unix() < peer.fsm.pConf.Timers.State.Uptime
			peer.fsm.lock.Unlock()
			if notEstablished || beforeUptime {
				return
			}
			pathList, eor, isLimit := peer.handleUpdate(e)
			if isLimit {
				_ = s.setAdminState(peer.ID(), "", adminStatePfxCt)
				return
			}
			if m.Header.Type == bgp.BGP_MSG_UPDATE {
				s.notifyPrePolicyUpdateWatcher(peer, pathList, m, e.timestamp, e.payload)
			}

			if len(pathList) > 0 {
				s.propagateUpdate(peer, pathList)
			}

			peer.fsm.lock.Lock()
			peerAfiSafis := peer.fsm.pConf.AfiSafis
			peer.fsm.lock.Unlock()
			if len(eor) > 0 {
				rtc := false
				for _, f := range eor {
					if f == bgp.RF_RTC_UC {
						rtc = true
					}
					peerInfo := *peer.peerInfo
					ev := &watchEventEor{
						Family:   f,
						PeerInfo: &peerInfo,
					}
					s.notifyWatcher(watchEventTypeEor, ev)
					for i, a := range peerAfiSafis {
						if a.State.Family == f {
							peer.fsm.lock.Lock()
							peer.fsm.pConf.AfiSafis[i].MpGracefulRestart.State.EndOfRibReceived = true
							peer.fsm.lock.Unlock()
						}
					}
				}

				// RFC 4724 4.1
				// Once the session between the Restarting Speaker and the Receiving
				// Speaker is re-established, ...snip... it MUST defer route
				// selection for an address family until it either (a) receives the
				// End-of-RIB marker from all its peers (excluding the ones with the
				// "Restart State" bit set in the received capability and excluding the
				// ones that do not advertise the graceful restart capability) or ...snip...

				peer.fsm.lock.Lock()
				localRestarting := peer.fsm.pConf.GracefulRestart.State.LocalRestarting
				peer.fsm.lock.Unlock()
				if localRestarting {
					allEnd := func() bool {
						for _, p := range s.neighborMap {
							if !p.recvedAllEOR() {
								return false
							}
						}
						return true
					}()
					if allEnd {
						for _, p := range s.neighborMap {
							p.fsm.lock.Lock()
							peerLocalRestarting := p.fsm.pConf.GracefulRestart.State.LocalRestarting
							p.fsm.pConf.GracefulRestart.State.LocalRestarting = false
							p.fsm.lock.Unlock()
							if !p.isGracefulRestartEnabled() && !peerLocalRestarting {
								continue
							}
							paths, _ := s.getBestFromLocal(p, p.negotiatedRFList())
							if len(paths) > 0 {
								sendfsmOutgoingMsg(p, paths)
							}
						}
						s.logger.Info("sync finished",
							slog.String("Topic", "Server"),
						)
					}

					// we don't delay non-route-target NLRIs when local-restarting
					peer.setRtcEORWait(false)
				}
				peer.fsm.lock.Lock()
				peerRestarting := peer.fsm.pConf.GracefulRestart.State.PeerRestarting
				peer.fsm.lock.Unlock()
				if peerRestarting {
					if peer.recvedAllEOR() {
						peer.stopPeerRestarting()
						pathList := peer.adjRibIn.DropStale(peer.configuredRFlist())

						peer.fsm.logger.Debug("withdraw stale routes", slog.Int("Numbers", len(pathList)))

						s.propagateUpdate(peer, pathList)
					}
					// we don't delay non-route-target NLRIs when peer is restarting
					peer.setRtcEORWait(false)
				}

				// received EOR of route-target address family
				// outbound filter is now ready, let's flash non-route-target NLRIs
				if rtc && peer.getRtcEORWait() {
					peer.setRtcEORWait(false)
					peer.fsm.logger.Debug("received route-target eor. flash non-route-target NLRIs")

					families := make([]bgp.Family, 0, len(peer.negotiatedRFList()))
					for _, f := range peer.negotiatedRFList() {
						if f != bgp.RF_RTC_UC {
							families = append(families, f)
						}
					}
					if paths, _ := s.getBestFromLocal(peer, families); len(paths) > 0 {
						sendfsmOutgoingMsg(peer, paths)
					}
				}
			}
		default:
			peer.fsm.logger.Error("unknown msg type", slog.Any("Data", e.MsgData))
		}
	}
}

func (s *BgpServer) EnableZebra(ctx context.Context, r *api.EnableZebraRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		if s.zclient != nil {
			return fmt.Errorf("already connected to Zebra")
		}
		software := zebra.NewSoftware(uint8(r.Version), r.SoftwareName)
		for _, p := range r.RouteTypes {
			if _, err := zebra.RouteTypeFromString(p, uint8(r.Version), software); err != nil {
				return err
			}
		}

		protos := make([]string, 0, len(r.RouteTypes))
		protos = append(protos, r.RouteTypes...)
		var err error
		s.zclient, err = newZebraClient(s, r.Url, protos, uint8(r.Version), r.NexthopTriggerEnable, uint8(r.NexthopTriggerDelay), r.MplsLabelRangeSize, software)
		return err
	}, false)
}

func (s *BgpServer) AddBmp(ctx context.Context, r *api.AddBmpRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		_, ok := api.AddBmpRequest_MonitoringPolicy_name[int32(r.Policy)]
		if !ok {
			return fmt.Errorf("invalid bmp route monitoring policy: %v", r.Policy)
		}
		port := r.Port
		if port == 0 {
			port = bmp.BMP_DEFAULT_PORT
		}
		sysname := r.SysName
		if sysname == "" {
			sysname = "GoBGP"
		}
		sysDescr := r.SysDescr
		if sysDescr == "" {
			sysDescr = version.Version()
		}
		s.logger.Debug("add bmp server",
			slog.String("Topic", "Server"),
			slog.String("Key", r.Address),
			slog.Int("Port", int(port)),
			slog.String("Policy", r.Policy.String()))

		return s.bmpManager.addServer(&oc.BmpServerConfig{
			Address:               netip.MustParseAddr(r.Address),
			Port:                  port,
			SysName:               sysname,
			SysDescr:              sysDescr,
			RouteMonitoringPolicy: oc.IntToBmpRouteMonitoringPolicyTypeMap[int(r.Policy)],
			StatisticsTimeout:     uint16(r.StatisticsTimeout),
		})
	}, true)
}

func (s *BgpServer) DeleteBmp(ctx context.Context, r *api.DeleteBmpRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.bmpManager.deleteServer(&oc.BmpServerConfig{
			Address: netip.MustParseAddr(r.Address),
			Port:    r.Port,
		})
	}, true)
}

func (s *BgpServer) ListBmp(ctx context.Context, req *api.ListBmpRequest, fn func(*api.ListBmpResponse_BmpStation)) error {
	if req == nil {
		return fmt.Errorf("null request")
	}
	var stations []*api.ListBmpResponse_BmpStation
	err := s.mgmtOperation(func() error {
		for _, s := range s.bmpManager.clientMap {
			stations = append(stations, &api.ListBmpResponse_BmpStation{
				Conf: &api.ListBmpResponse_BmpStation_Conf{
					Address: s.c.Address.String(),
					Port:    s.c.Port,
				},
				State: &api.ListBmpResponse_BmpStation_State{
					Uptime:   oc.ProtoTimestamp(atomic.LoadInt64(&s.uptime)),
					Downtime: oc.ProtoTimestamp(atomic.LoadInt64(&s.downtime)),
				},
			})
		}
		return nil
	}, false)
	if err == nil {
		for _, rsp := range stations {
			select {
			case <-ctx.Done():
				return nil
			default:
				fn(rsp)
			}
		}
	}
	return err
}

func (s *BgpServer) StopBgp(ctx context.Context, r *api.StopBgpRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	err := s.mgmtOperation(func() error {
		defer s.runningCancel()

		for address, neighbor := range s.neighborMap {
			c := &oc.Neighbor{Config: oc.NeighborConfig{
				NeighborAddress: address,
			}}
			neighbor.fsm.lock.Lock()
			sendNotification := !r.AllowGracefulRestart || !neighbor.fsm.pConf.GracefulRestart.Config.Enabled
			neighbor.fsm.lock.Unlock()
			if err := s.deleteNeighbor(c, bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED, sendNotification); err != nil {
				return err
			}
		}
		for _, l := range s.listeners {
			l.Close()
		}
		s.bgpConfig.Global = oc.Global{}
		return nil
	}, false)
	if err != nil {
		return err
	}

	s.shutdownWG.Wait()
	return nil
}

func (s *BgpServer) SetPolicies(ctx context.Context, r *api.SetPoliciesRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	rp, err := newRoutingPolicyFromApiStruct(r)
	if err != nil {
		return err
	}

	getConfig := func(id string) (*oc.ApplyPolicy, error) {
		f := func(id string, dir table.PolicyDirection) (oc.DefaultPolicyType, []string, error) {
			rt, policies, err := s.policy.GetPolicyAssignment(id, dir)
			if err != nil {
				return oc.DEFAULT_POLICY_TYPE_REJECT_ROUTE, nil, err
			}
			names := make([]string, 0, len(policies))
			for _, p := range policies {
				names = append(names, p.Name)
			}
			t := oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE
			if rt == table.ROUTE_TYPE_REJECT {
				t = oc.DEFAULT_POLICY_TYPE_REJECT_ROUTE
			}
			return t, names, nil
		}

		c := &oc.ApplyPolicy{}
		rt, policies, err := f(id, table.POLICY_DIRECTION_IMPORT)
		if err != nil {
			return nil, err
		}
		c.Config.ImportPolicyList = policies
		c.Config.DefaultImportPolicy = rt
		rt, policies, err = f(id, table.POLICY_DIRECTION_EXPORT)
		if err != nil {
			return nil, err
		}
		c.Config.ExportPolicyList = policies
		c.Config.DefaultExportPolicy = rt
		return c, nil
	}

	return s.mgmtOperation(func() error {
		ap := make(map[string]oc.ApplyPolicy, len(s.neighborMap)+1)
		a, err := getConfig(table.GLOBAL_RIB_NAME)
		if err != nil {
			return err
		}
		ap[table.GLOBAL_RIB_NAME] = *a
		for _, peer := range s.neighborMap {
			peer.fsm.logger.Info("call set policy")

			a, err := getConfig(peer.ID())
			if err != nil {
				return err
			}
			ap[peer.ID()] = *a
		}
		return s.policy.Reset(rp, ap)
	}, false)
}

// EVPN MAC MOBILITY HANDLING
//
// We don't have multihoming function now, so ignore
// ESI comparison.
//
// RFC7432 15. MAC Mobility
//
// A PE detecting a locally attached MAC address for which it had
// previously received a MAC/IP Advertisement route with the same zero
// Ethernet segment identifier (single-homed scenarios) advertises it
// with a MAC Mobility extended community attribute with the sequence
// number set properly.  In the case of single-homed scenarios, there
// is no need for ESI comparison.

func getMacMobilityExtendedCommunity(etag uint32, mac net.HardwareAddr, evpnPaths []*table.Path) *bgp.MacMobilityExtended {
	seqs := make([]struct {
		seq     int
		isLocal bool
	}, 0)

	for _, path := range evpnPaths {
		if path == nil {
			continue
		}
		nlri := path.GetNlri().(*bgp.EVPNNLRI)
		target, ok := nlri.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
		if !ok {
			continue
		}
		if target.ETag == etag && bytes.Equal(target.MacAddress, mac) {
			found := false
			for _, ec := range path.GetExtCommunities() {
				if t, st := ec.GetTypes(); t == bgp.EC_TYPE_EVPN && st == bgp.EC_SUBTYPE_MAC_MOBILITY {
					seqs = append(seqs, struct {
						seq     int
						isLocal bool
					}{int(ec.(*bgp.MacMobilityExtended).Sequence), path.IsLocal()})
					found = true
					break
				}
			}

			if !found {
				seqs = append(seqs, struct {
					seq     int
					isLocal bool
				}{-1, path.IsLocal()})
			}
		}
	}

	if len(seqs) > 0 {
		newSeq := -2
		var isLocal bool
		for _, seq := range seqs {
			if seq.seq > newSeq {
				newSeq = seq.seq
				isLocal = seq.isLocal
			}
		}

		if !isLocal {
			newSeq += 1
		}

		if newSeq != -1 {
			return &bgp.MacMobilityExtended{
				Sequence: uint32(newSeq),
			}
		}
	}
	return nil
}

func (s *BgpServer) fixupApiPath(vrfId string, pathList []*table.Path) error {
	for _, path := range pathList {
		if !path.IsWithdraw {
			if _, err := path.GetOrigin(); err != nil {
				return err
			}
		}

		if vrfId != "" {
			vrf := s.globalRib.Vrfs[vrfId]
			if vrf == nil {
				return fmt.Errorf("vrf %s not found", vrfId)
			}
			if err := vrf.ToGlobalPath(path); err != nil {
				return err
			}
		}

		// Address Family specific Handling
		switch nlri := path.GetNlri().(type) {
		case *bgp.EVPNNLRI:
			switch r := nlri.RouteTypeData.(type) {
			case *bgp.EVPNMacIPAdvertisementRoute:
				// MAC Mobility Extended Community
				var paths []*table.Path
				for _, ec := range path.GetRouteTargets() {
					paths = append(paths, s.globalRib.GetPathListWithMac(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_EVPN}, ec, r.MacAddress)...)
				}
				if m := getMacMobilityExtendedCommunity(r.ETag, r.MacAddress, paths); m != nil {
					pm := getMacMobilityExtendedCommunity(r.ETag, r.MacAddress, []*table.Path{path})
					if pm == nil {
						path.SetExtCommunities([]bgp.ExtendedCommunityInterface{m}, false)
					} else if pm != nil && pm.Sequence < m.Sequence {
						return fmt.Errorf("invalid MAC mobility sequence number")
					}
				}
			case *bgp.EVPNEthernetSegmentRoute:
				// RFC7432: BGP MPLS-Based Ethernet VPN
				// 7.6. ES-Import Route Target
				// The value is derived automatically for the ESI Types 1, 2,
				// and 3, by encoding the high-order 6-octet portion of the 9-octet ESI
				// Value, which corresponds to a MAC address, in the ES-Import Route
				// Target.
				// Note: If the given path already has the ES-Import Route Target,
				// skips deriving a new one.
				found := false
				for _, extComm := range path.GetExtCommunities() {
					if _, found = extComm.(*bgp.ESImportRouteTarget); found {
						break
					}
				}
				if !found {
					switch r.ESI.Type {
					case bgp.ESI_LACP, bgp.ESI_MSTP, bgp.ESI_MAC:
						mac := net.HardwareAddr(r.ESI.Value[:6])
						rt := &bgp.ESImportRouteTarget{ESImport: mac}
						path.SetExtCommunities([]bgp.ExtendedCommunityInterface{rt}, false)
					}
				}
			}
		}
	}
	return nil
}

func pathTokey(path *table.Path) string {
	return fmt.Sprintf("%d:%s", path.RemoteID(), path.GetPrefix())
}

func apiutilPathTokey(path *apiutil.Path) string {
	return fmt.Sprintf("%d:%s", path.RemoteID, path.Nlri.String())
}

func (s *BgpServer) addPathList(vrfId string, pathList []*table.Path) error {
	err := s.fixupApiPath(vrfId, pathList)
	if err == nil {
		s.propagateUpdate(nil, pathList)
	}
	return err
}

func (s *BgpServer) addPathStream(vrfId string, pathList []*table.Path) error {
	err := s.mgmtOperation(func() error {
		return s.addPathList(vrfId, pathList)
	}, true)
	return err
}

func apiutil2Path(path *apiutil.Path, isVRFTable bool, isWithdraw ...bool) (*table.Path, error) {
	var source *table.PeerInfo
	if path.PeerASN != 0 {
		source = &table.PeerInfo{
			AS:      path.PeerASN,
			ID:      path.PeerID,
			Address: path.PeerAddress,
		}
	}

	// TODO (sbezverk) At this poinnt nlri and path attributes are converted to native mode
	// need to check if update with SR Policy nlri comes with mandatory route distinguisher
	// extended community or NO_ADVERTISE community, with Tunnel Encapsulation Attribute 23
	// and tunnel type 15. If it is not the case ignore update and log an error.
	var nexthop netip.Addr
	isMPFlowSpec := false
	pattrs := make([]bgp.PathAttributeInterface, 0)
	seen := make(map[bgp.BGPAttrType]struct{})
	for _, a := range path.Attrs {
		aType := a.GetType()
		if _, ok := seen[aType]; ok {
			return nil, fmt.Errorf("duplicate path attribute %s", aType)
		}
		seen[aType] = struct{}{}
		switch aType {
		case bgp.BGP_ATTR_TYPE_NEXT_HOP:
			nexthop = a.(*bgp.PathAttributeNextHop).Value
		case bgp.BGP_ATTR_TYPE_MP_REACH_NLRI:
			mp := a.(*bgp.PathAttributeMpReachNLRI)
			if len(mp.Value) == 0 {
				return nil, fmt.Errorf("mp reach nlri value is empty")
			}
			isMPFlowSpec = mp.SAFI == bgp.SAFI_FLOW_SPEC_UNICAST || mp.SAFI == bgp.SAFI_FLOW_SPEC_VPN
			nexthop = mp.Nexthop
		default:
			pattrs = append(pattrs, a)
		}
	}
	if !path.Withdrawal && !nexthop.IsValid() && !isMPFlowSpec {
		return nil, fmt.Errorf("nexthop not found")
	}

	if !isVRFTable && path.Family == bgp.RF_IPv4_UC && nexthop.Is4() {
		attr, _ := bgp.NewPathAttributeNextHop(nexthop)
		pattrs = append(pattrs, attr)
	} else {
		attr, _ := bgp.NewPathAttributeMpReachNLRI(path.Family, []bgp.PathNLRI{{NLRI: path.Nlri}}, nexthop)
		pattrs = append(pattrs, attr)
	}

	doWithdraw := len(isWithdraw) > 0 && isWithdraw[0] || path.Withdrawal
	p := table.NewPath(path.Family, source, bgp.PathNLRI{NLRI: path.Nlri, ID: path.RemoteID}, doWithdraw, pattrs, time.Unix(path.Age, 0), path.NoImplicitWithdraw)
	if p == nil {
		return nil, fmt.Errorf("invalid path: %v", path)
	}
	if !doWithdraw {
		total := bytes.NewBuffer(make([]byte, 0))
		for _, a := range pattrs {
			if a.GetType() == bgp.BGP_ATTR_TYPE_MP_REACH_NLRI {
				continue
			}
			b, _ := a.Serialize()
			total.Write(b)
		}
		p.SetHash(farm.Hash64(total.Bytes()))
	}
	p.SetIsFromExternal(path.IsFromExternal)
	return p, nil
}

func (s *BgpServer) AddPath(req apiutil.AddPathRequest) ([]apiutil.AddPathResponse, error) {
	if len(req.Paths) == 0 {
		return []apiutil.AddPathResponse{}, fmt.Errorf("no path(s) to add")
	}
	isVRF := false
	if req.VRFID != "" {
		if vrf := s.globalRib.Vrfs[req.VRFID]; vrf == nil {
			return []apiutil.AddPathResponse{}, fmt.Errorf("vrf %s not found", req.VRFID)
		}
		isVRF = true
	}

	resps := make([]apiutil.AddPathResponse, len(req.Paths))
	var lastErr error
	err := s.mgmtOperation(func() error {
		for i, p := range req.Paths {
			if p == nil {
				lastErr = errors.New("path is nil")
				resps[i].Error = lastErr
				continue
			}
			path, err := apiutil2Path(p, isVRF)
			if err != nil {
				lastErr = err
				resps[i].Error = err
				continue
			}

			err = s.addPathList(req.VRFID, []*table.Path{path})
			if err != nil {
				lastErr = err
				resps[i].Error = err
				continue
			}

			id, err := uuid.NewRandom()
			if err != nil {
				lastErr = err
				resps[i].Error = err
				continue
			}
			s.uuidMap[pathTokey(path)] = id
			resps[i].UUID = id
		}
		return lastErr
	}, true)
	if err != nil {
		return []apiutil.AddPathResponse{}, err
	}
	return resps, err
}

// if deleteAll is true, it will delete all locally generated paths, if deleteFamily is set, then the whole family will be deleted
// if uuids is not empty, it will delete paths with the given UUIDs otherwise it will delete specified paths
// deleteAll == false and uuids is empty, paths must contain at least one path
func (s *BgpServer) DeletePath(req apiutil.DeletePathRequest) error {
	isVRF := false
	if req.VRFID != "" {
		if vrf := s.globalRib.Vrfs[req.VRFID]; vrf == nil {
			return fmt.Errorf("vrf %s not found", req.VRFID)
		}
		isVRF = true
	}
	return s.mgmtOperation(func() error {
		deletePathList := make([]*table.Path, 0)
		// delete by uuid
		if len(req.UUIDs) > 0 {
			for k, v := range s.uuidMap {
				if slices.Contains(req.UUIDs, v) {
					for _, path := range s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, s.globalRib.GetRFlist()) {
						if path.IsLocal() && k == pathTokey(path) {
							delete(s.uuidMap, k)
							deletePathList = append(deletePathList, path.Clone(true))
						}
					}
				}
			}
			if len(deletePathList) == 0 {
				return fmt.Errorf("can't find a specified path(s) with the given UUID(s)")
			}
		} else if req.DeleteAll {
			// Delete all locally generated paths
			families := s.globalRib.GetRFlist()
			if req.DeleteFamily != nil {
				families = []bgp.Family{*req.DeleteFamily}
			}
			for _, path := range s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, families) {
				if path.IsLocal() {
					deletePathList = append(deletePathList, path.Clone(true))
				}
			}
			s.uuidMap = make(map[string]uuid.UUID)
		} else {
			// Delete specified path(s)
			if len(req.Paths) == 0 {
				return errors.New("no path(s) to delete")
			}
			for _, p := range req.Paths {
				path, err := apiutil2Path(p, isVRF, true)
				if err != nil {
					return err
				}
				if err := s.fixupApiPath(req.VRFID, []*table.Path{path}); err != nil {
					return err
				}
				delete(s.uuidMap, pathTokey(path))
				deletePathList = append(deletePathList, path)
			}
		}
		s.propagateUpdate(nil, deletePathList)
		return nil
	}, true)
}

func (s *BgpServer) updatePath(vrfId string, pathList []*table.Path) error {
	err := s.mgmtOperation(func() error {
		if err := s.fixupApiPath(vrfId, pathList); err != nil {
			return err
		}
		s.propagateUpdate(nil, pathList)
		return nil
	}, true)
	return err
}

func (s *BgpServer) StartBgp(ctx context.Context, r *api.StartBgpRequest) error {
	if r == nil || r.Global == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		g := r.Global
		if net.ParseIP(g.RouterId) == nil {
			return fmt.Errorf("invalid router-id format: %s", g.RouterId)
		}

		c := newGlobalFromAPIStruct(g)
		if err := oc.SetDefaultGlobalConfigValues(c); err != nil {
			return err
		}

		if c.Config.Port > 0 {
			acceptCh := make(chan net.Conn, 32)
			for _, addr := range c.Config.LocalAddressList {
				l, err := netutils.NewTCPListener(s.logger, addr.String(), uint32(c.Config.Port), g.BindToDevice, acceptCh)
				if err != nil {
					return err
				}
				s.listeners = append(s.listeners, l)
			}
			s.acceptCh = acceptCh
		}

		rfs, _ := oc.AfiSafis(c.AfiSafis).ToRfList()
		s.globalRib = table.NewTableManager(s.logger, rfs)
		s.rsRib = table.NewTableManager(s.logger, rfs)

		if err := s.policy.Initialize(); err != nil {
			return err
		}
		s.bgpConfig.Global = *c
		// update route selection options
		table.SelectionOptions = c.RouteSelectionOptions.Config
		table.UseMultiplePaths = c.UseMultiplePaths.Config
		return nil
	}, false)
}

func (s *BgpServer) ListVrf(ctx context.Context, r *api.ListVrfRequest, fn func(*api.Vrf)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	toApi := func(v *table.Vrf) *api.Vrf {
		d, _ := apiutil.MarshalRD(v.Rd)
		irt, _ := apiutil.MarshalRTs(v.ImportRt.ToSlice())
		ert, _ := apiutil.MarshalRTs(v.ExportRt)
		return &api.Vrf{
			Name:     v.Name,
			Rd:       d,
			Id:       v.Id,
			ImportRt: irt,
			ExportRt: ert,
		}
	}
	var l []*api.Vrf
	err := s.mgmtOperation(func() error {
		l = make([]*api.Vrf, 0, len(s.globalRib.Vrfs))
		for name, vrf := range s.globalRib.Vrfs {
			if r.Name != "" && r.Name != name {
				continue
			}
			l = append(l, toApi(vrf.Clone()))
		}
		return nil
	}, true)
	if err != nil {
		return err
	}
	for _, v := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(v)
		}
	}
	return nil
}

func (s *BgpServer) AddVrf(ctx context.Context, r *api.AddVrfRequest) error {
	if r == nil || r.Vrf == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		name := r.Vrf.Name
		id := r.Vrf.Id

		rd, err := apiutil.UnmarshalRD(r.Vrf.Rd)
		if err != nil {
			return err
		}
		im, err := apiutil.UnmarshalRTs(r.Vrf.ImportRt)
		if err != nil {
			return err
		}
		ex, err := apiutil.UnmarshalRTs(r.Vrf.ExportRt)
		if err != nil {
			return err
		}

		pi := &table.PeerInfo{
			AS:      s.bgpConfig.Global.Config.As,
			LocalID: s.bgpConfig.Global.Config.RouterId,
		}

		if pathList, err := s.globalRib.AddVrf(name, id, rd, im, ex, pi); err != nil {
			return err
		} else if len(pathList) > 0 {
			s.propagateUpdate(nil, pathList)
		}
		if vrf, ok := s.globalRib.Vrfs[name]; ok {
			if s.zclient != nil && s.zclient.mplsLabel.rangeSize > 0 {
				if err := s.zclient.assignAndSendVrfMplsLabel(vrf); err != nil {
					return fmt.Errorf("failed to assign MPLS label for VRF %s: %w", name, err)
				}
			}
		}
		return nil
	}, true)
}

func (s *BgpServer) DeleteVrf(ctx context.Context, r *api.DeleteVrfRequest) error {
	if r == nil || r.Name == "" {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		name := r.Name
		for _, n := range s.neighborMap {
			n.fsm.lock.Lock()
			peerVrf := n.fsm.pConf.Config.Vrf
			n.fsm.lock.Unlock()
			if peerVrf == name {
				return fmt.Errorf("failed to delete VRF %s: neighbor %s is in use", name, n.ID())
			}
		}

		if vrf, ok := s.globalRib.Vrfs[name]; ok {
			if vrf.MplsLabel > 0 {
				s.zclient.releaseMplsLabel(vrf.MplsLabel)
			}
		}
		pathList, err := s.globalRib.DeleteVrf(name)
		if err != nil {
			return err
		}
		if len(pathList) > 0 {
			s.propagateUpdate(nil, pathList)
		}
		return nil
	}, true)
}

func familiesForSoftreset(peer *peer, family bgp.Family) []bgp.Family {
	if family == bgp.Family(0) {
		configured := peer.configuredRFlist()
		families := make([]bgp.Family, 0, len(configured))
		for _, f := range configured {
			if f != bgp.RF_RTC_UC {
				families = append(families, f)
			}
		}
		return families
	}
	return []bgp.Family{family}
}

func (s *BgpServer) softResetIn(addr string, family bgp.Family) error {
	peers, err := s.addrToPeers(addr)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		s.propagateUpdate(peer, peer.adjRibIn.PathList(familiesForSoftreset(peer, family), true))
	}
	return err
}

func (s *BgpServer) softResetOut(addr string, family bgp.Family, deferral bool) error {
	peers, err := s.addrToPeers(addr)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		notEstablished := peer.State() != bgp.BGP_FSM_ESTABLISHED
		if notEstablished {
			continue
		}
		families := familiesForSoftreset(peer, family)

		if deferral {
			if family == bgp.Family(0) {
				families = peer.configuredRFlist()
			}
			peer.fsm.lock.Lock()
			c := peer.fsm.pConf.GetAfiSafi(bgp.RF_RTC_UC)
			restarting := peer.fsm.pConf.GracefulRestart.State.LocalRestarting
			peer.fsm.lock.Unlock()
			if restarting {
				peer.fsm.lock.Lock()
				peer.fsm.pConf.GracefulRestart.State.LocalRestarting = false
				peer.fsm.lock.Unlock()
				peer.fsm.logger.Debug("deferral timer expired", slog.Any("Families", families))
			} else if peer.IsFamilyEnabled(bgp.RF_RTC_UC) && !c.MpGracefulRestart.State.EndOfRibReceived {
				peer.setRtcEORWait(false)
				peer.fsm.logger.Debug("route-target deferral timer expired", slog.Any("Families", families))
			} else {
				continue
			}
		}

		pathList, _ := s.getBestFromLocal(peer, families)
		if len(pathList) > 0 {
			if deferral {
				pathList = func() []*table.Path {
					l := make([]*table.Path, 0, len(pathList))
					for _, p := range pathList {
						if !p.IsWithdraw {
							l = append(l, p)
						}
					}
					return l
				}()
			}
			sendfsmOutgoingMsg(peer, pathList)
		}
	}
	return nil
}

func (s *BgpServer) sResetIn(addr string, family bgp.Family) error {
	s.logger.Info("Neighbor soft reset in",
		slog.String("Topic", "Operation"),
		slog.String("Key", addr))
	return s.softResetIn(addr, family)
}

func (s *BgpServer) sResetOut(addr string, family bgp.Family) error {
	s.logger.Info("Neighbor soft reset out",
		slog.String("Topic", "Operation"),
		slog.String("Key", addr))
	return s.softResetOut(addr, family, false)
}

func (s *BgpServer) sReset(addr string, family bgp.Family) error {
	s.logger.Info("Neighbor soft reset",
		slog.String("Topic", "Operation"),
		slog.String("Key", addr))
	err := s.softResetIn(addr, family)
	if err != nil {
		return err
	}
	return s.softResetOut(addr, family, false)
}

func (s *BgpServer) validateTable(r *table.Table) (v map[*table.Path]*table.Validation) {
	if s.roaManager.enabled() {
		v = make(map[*table.Path]*table.Validation, len(r.GetDestinations()))
		for _, d := range r.GetDestinations() {
			for _, p := range d.GetAllKnownPathList() {
				v[p] = s.roaTable.Validate(p)
			}
		}
	}
	return v
}

func (s *BgpServer) getRib(addr string, family bgp.Family, prefixes []*apiutil.LookupPrefix) (rib *table.Table, v map[*table.Path]*table.Validation, err error) {
	err = s.mgmtOperation(func() error {
		m := s.globalRib
		id := table.GLOBAL_RIB_NAME
		as := uint32(0)
		if len(addr) > 0 {
			remoteAddr, err := netip.ParseAddr(addr)
			if err != nil {
				return fmt.Errorf("failed to parse address: %v", err)
			}
			peer, ok := s.neighborMap[remoteAddr]
			if !ok {
				return fmt.Errorf("neighbor that has %v doesn't exist", addr)
			}
			if !peer.isRouteServerClient() {
				return fmt.Errorf("neighbor %v doesn't have local rib", addr)
			}
			id = peer.ID()
			as = peer.AS()
			m = s.rsRib
		}
		af := family
		tbl, ok := m.Tables[af]
		if !ok {
			return fmt.Errorf("address family: %s not supported", af)
		}
		rib, err = tbl.Select(table.TableSelectOption{ID: id, AS: as, LookupPrefixes: prefixes})
		if err != nil {
			return err
		}
		v = s.validateTable(rib)
		return nil
	}, true)
	return rib, v, err
}

func (s *BgpServer) getVrfRib(name string, family bgp.Family, prefixes []*apiutil.LookupPrefix) (rib *table.Table, err error) {
	err = s.mgmtOperation(func() error {
		m := s.globalRib
		vrfs := m.Vrfs
		if _, ok := vrfs[name]; !ok {
			return fmt.Errorf("vrf %s not found", name)
		}
		var af bgp.Family
		switch family {
		case bgp.RF_IPv4_UC:
			af = bgp.RF_IPv4_VPN
		case bgp.RF_IPv6_UC:
			af = bgp.RF_IPv6_VPN
		case bgp.RF_FS_IPv4_UC:
			af = bgp.RF_FS_IPv4_VPN
		case bgp.RF_FS_IPv6_UC:
			af = bgp.RF_FS_IPv6_VPN
		case bgp.RF_EVPN:
			af = bgp.RF_EVPN
		}
		tbl, ok := m.Tables[af]
		if !ok {
			return fmt.Errorf("address family: %s not supported", af)
		}
		rib, err = tbl.Select(table.TableSelectOption{VRF: vrfs[name], LookupPrefixes: prefixes})
		return err
	}, true)
	return rib, err
}

func (s *BgpServer) getAdjRib(addr string, family bgp.Family, in bool, enableFiltered bool, prefixes []*apiutil.LookupPrefix) (rib *table.Table, filtered map[table.PathLocalKey]table.FilteredType, v map[*table.Path]*table.Validation, err error) {
	err = s.mgmtOperation(func() error {
		remoteAddr, err := netip.ParseAddr(addr)
		if err != nil {
			return fmt.Errorf("failed to parse address: %v", err)
		}
		peer, ok := s.neighborMap[remoteAddr]
		if !ok {
			return fmt.Errorf("neighbor that has %v doesn't exist", addr)
		}
		id := peer.ID()
		as := peer.AS()

		var adjRib *table.AdjRib
		var toUpdate []*table.Path
		filtered = make(map[table.PathLocalKey]table.FilteredType)
		if in {
			adjRib = peer.adjRibIn
			if enableFiltered {
				toUpdate = make([]*table.Path, 0)
				for _, path := range peer.adjRibIn.PathList([]bgp.Family{family}, true) {
					pathLocalKey := path.GetLocalKey()
					options := &table.PolicyOptions{
						Validate: s.roaTable.Validate,
					}
					p := s.policy.ApplyPolicy(peer.TableID(), table.POLICY_DIRECTION_IMPORT, path, options)
					if p == nil {
						filtered[pathLocalKey] = table.PolicyFiltered
					} else {
						toUpdate = append(toUpdate, p)
					}
				}
			}
		} else {
			adjRib = table.NewAdjRib(s.logger, peer.configuredRFlist())
			pathList := []*table.Path{}
			if enableFiltered {
				for _, path := range s.getPossibleBest(peer, family) {
					pathLocalKey := path.GetLocalKey()
					p, options, stop := s.prePolicyFilterpath(peer, path, nil)
					if stop {
						continue
					}
					options.Validate = s.roaTable.Validate
					if p = peer.policy.ApplyPolicy(peer.TableID(), table.POLICY_DIRECTION_EXPORT, p, options); p == nil {
						filtered[pathLocalKey] = table.PolicyFiltered
					}
					pathList = append(pathList, path)
				}
			} else {
				pathList, _ = s.getBestFromLocal(peer, peer.configuredRFlist())
			}
			toUpdate = make([]*table.Path, 0, len(pathList))
			for _, path := range pathList {
				if path.IsEOR() {
					continue
				}
				pathLocalKey := path.GetLocalKey()
				if peer.isPathSendMaxFiltered(path) {
					filtered[pathLocalKey] = filtered[pathLocalKey] | table.SendMaxFiltered
				}
				toUpdate = append(toUpdate, path)
			}
		}
		adjRib.Update(toUpdate)
		rib, err = adjRib.Select(family, false, table.TableSelectOption{ID: id, AS: as, LookupPrefixes: prefixes})
		v = s.validateTable(rib)
		return err
	}, true)
	return rib, filtered, v, err
}

func (s *BgpServer) ListPath(r apiutil.ListPathRequest, fn func(prefix bgp.NLRI, paths []*apiutil.Path)) error {
	in := false
	family := r.Family

	var filtered map[table.PathLocalKey]table.FilteredType
	var v map[*table.Path]*table.Validation
	var tbl *table.Table
	var err error
	switch r.TableType {
	case api.TableType_TABLE_TYPE_UNSPECIFIED:
		return errors.New("unspecified table type")
	case api.TableType_TABLE_TYPE_LOCAL, api.TableType_TABLE_TYPE_GLOBAL:
		tbl, v, err = s.getRib(r.Name, family, r.Prefixes)
	case api.TableType_TABLE_TYPE_ADJ_IN:
		in = true
		fallthrough
	case api.TableType_TABLE_TYPE_ADJ_OUT:
		tbl, filtered, v, err = s.getAdjRib(r.Name, family, in, r.EnableFiltered, r.Prefixes)
	case api.TableType_TABLE_TYPE_VRF:
		tbl, err = s.getVrfRib(r.Name, family, []*apiutil.LookupPrefix{})
	default:
		return fmt.Errorf("unknown table type %d", r.TableType)
	}
	if err != nil {
		return err
	}

	err = func() error {
		for _, dst := range tbl.GetDestinations() {
			prefix := dst.GetNlri()
			knownPathList := dst.GetAllKnownPathList()
			paths := make([]*apiutil.Path, len(knownPathList))

			for i, path := range knownPathList {
				p := toPathApiUtil(path)
				if validation := getValidation(v, path); validation != nil {
					p.Validation = newValidationFromTableStruct(validation)
				}
				if !table.SelectionOptions.DisableBestPathSelection {
					if i == 0 {
						switch r.TableType {
						case api.TableType_TABLE_TYPE_LOCAL, api.TableType_TABLE_TYPE_GLOBAL:
							p.Best = true
						}
					} else if s.bgpConfig.Global.UseMultiplePaths.Config.Enabled && path.Equal(knownPathList[i-1]) {
						p.Best = true
					}
				}
				if r.EnableFiltered && filtered[path.GetLocalKey()]&table.PolicyFiltered > 0 {
					p.Filtered = true
				}
				// we always want to know that some paths are filtered out
				// by send-max attribute
				if filtered[path.GetLocalKey()]&table.SendMaxFiltered > 0 {
					p.SendMaxFiltered = true
				}
				paths[i] = p
			}

			fn(prefix, paths)
		}
		return nil
	}()
	return err
}

func (s *BgpServer) getRibInfo(addr string, family bgp.Family) (info *table.TableInfo, err error) {
	err = s.mgmtOperation(func() error {
		m := s.globalRib
		id := table.GLOBAL_RIB_NAME
		as := uint32(0)
		if len(addr) > 0 {
			remoteAddr, err := netip.ParseAddr(addr)
			if err != nil {
				return fmt.Errorf("failed to parse address: %v", err)
			}
			peer, ok := s.neighborMap[remoteAddr]
			if !ok {
				return fmt.Errorf("neighbor that has %v doesn't exist", remoteAddr)
			}
			if !peer.isRouteServerClient() {
				return fmt.Errorf("neighbor %v doesn't have local rib", remoteAddr)
			}
			id = peer.ID()
			as = peer.AS()
			m = s.rsRib
		}

		af := family
		tbl, ok := m.Tables[af]
		if !ok {
			return fmt.Errorf("address family: %s not supported", af)
		}

		info = tbl.Info(table.TableInfoOptions{ID: id, AS: as})

		return err
	}, true)
	return info, err
}

func (s *BgpServer) getAdjRibInfo(addr string, family bgp.Family, in bool) (info *table.TableInfo, err error) {
	err = s.mgmtOperation(func() error {
		remoteAddr, err := netip.ParseAddr(addr)
		if err != nil {
			return fmt.Errorf("failed to parse address: %v", err)
		}
		peer, ok := s.neighborMap[remoteAddr]
		if !ok {
			return fmt.Errorf("neighbor that has %v doesn't exist", remoteAddr)
		}

		var adjRib *table.AdjRib
		if in {
			adjRib = peer.adjRibIn
		} else {
			adjRib = table.NewAdjRib(s.logger, peer.configuredRFlist())
			accepted, _ := s.getBestFromLocal(peer, peer.configuredRFlist())
			adjRib.UpdateAdjRibOut(accepted)
		}
		info, err = adjRib.TableInfo(family)
		return err
	}, true)
	return info, err
}

func (s *BgpServer) getVrfRibInfo(name string, family bgp.Family) (info *table.TableInfo, err error) {
	err = s.mgmtOperation(func() error {
		m := s.globalRib
		vrfs := m.Vrfs
		if _, ok := vrfs[name]; !ok {
			return fmt.Errorf("vrf %s not found", name)
		}

		var af bgp.Family
		switch family {
		case bgp.RF_IPv4_UC:
			af = bgp.RF_IPv4_VPN
		case bgp.RF_IPv6_UC:
			af = bgp.RF_IPv6_VPN
		case bgp.RF_FS_IPv4_UC:
			af = bgp.RF_FS_IPv4_VPN
		case bgp.RF_FS_IPv6_UC:
			af = bgp.RF_FS_IPv6_VPN
		case bgp.RF_EVPN:
			af = bgp.RF_EVPN
		}

		tbl, ok := m.Tables[af]
		if !ok {
			return fmt.Errorf("address family: %s not supported", af)
		}

		info = tbl.Info(table.TableInfoOptions{VRF: vrfs[name]})

		return err
	}, true)
	return info, err
}

func (s *BgpServer) GetTable(ctx context.Context, r *api.GetTableRequest) (*api.GetTableResponse, error) {
	if r == nil || r.Family == nil {
		return nil, fmt.Errorf("nil request")
	}
	family := bgp.Family(0)
	if r.Family != nil {
		family = bgp.NewFamily(uint16(r.Family.Afi), uint8(r.Family.Safi))
	}
	var in bool
	var err error
	var info *table.TableInfo
	switch r.TableType {
	case api.TableType_TABLE_TYPE_UNSPECIFIED:
		return nil, status.Error(codes.InvalidArgument, "unspecified table type")
	case api.TableType_TABLE_TYPE_GLOBAL, api.TableType_TABLE_TYPE_LOCAL:
		info, err = s.getRibInfo(r.Name, family)
	case api.TableType_TABLE_TYPE_ADJ_IN:
		in = true
		fallthrough
	case api.TableType_TABLE_TYPE_ADJ_OUT:
		info, err = s.getAdjRibInfo(r.Name, family, in)
	case api.TableType_TABLE_TYPE_VRF:
		info, err = s.getVrfRibInfo(r.Name, family)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown table type %d", r.TableType)
	}

	if err != nil {
		return nil, err
	}

	return &api.GetTableResponse{
		NumDestination: uint64(info.NumDestination),
		NumPath:        uint64(info.NumPath),
		NumAccepted:    uint64(info.NumAccepted),
	}, nil
}

func (s *BgpServer) GetBgp(ctx context.Context, r *api.GetBgpRequest) (rsp *api.GetBgpResponse, err error) {
	if r == nil {
		return nil, fmt.Errorf("nil request")
	}
	err = s.mgmtOperation(func() error {
		g := s.bgpConfig.Global
		l := make([]string, 0, len(g.Config.LocalAddressList))
		for _, addr := range g.Config.LocalAddressList {
			l = append(l, addr.String())
		}
		rsp = &api.GetBgpResponse{
			Global: &api.Global{
				Asn:              g.Config.As,
				RouterId:         g.Config.RouterId.String(),
				ListenPort:       g.Config.Port,
				ListenAddresses:  l,
				UseMultiplePaths: g.UseMultiplePaths.Config.Enabled,
			},
		}
		return nil
	}, false)
	return rsp, err
}

func (s *BgpServer) ListDynamicNeighbor(ctx context.Context, r *api.ListDynamicNeighborRequest, fn func(neighbor *api.DynamicNeighbor)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	toApi := func(dn *oc.DynamicNeighbor) *api.DynamicNeighbor {
		return &api.DynamicNeighbor{
			Prefix:    dn.Config.Prefix.String(),
			PeerGroup: dn.Config.PeerGroup,
		}
	}
	var l []*api.DynamicNeighbor
	err := s.mgmtOperation(func() error {
		peerGroupName := r.PeerGroup
		for k, group := range s.peerGroupMap {
			if peerGroupName != "" && peerGroupName != k {
				continue
			}
			for _, dn := range group.dynamicNeighbors {
				l = append(l, toApi(dn))
			}
		}
		return nil
	}, false)
	if err != nil {
		return err
	}
	for _, dn := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(dn)
		}
	}
	return nil
}

func (s *BgpServer) ListPeerGroup(ctx context.Context, r *api.ListPeerGroupRequest, fn func(*api.PeerGroup)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var l []*api.PeerGroup
	err := s.mgmtOperation(func() error {
		peerGroupName := r.PeerGroupName
		l = make([]*api.PeerGroup, 0, len(s.peerGroupMap))
		for k, group := range s.peerGroupMap {
			if peerGroupName != "" && peerGroupName != k {
				continue
			}
			pg := oc.NewPeerGroupFromConfigStruct(group.Conf)
			l = append(l, pg)
		}
		return nil
	}, false)
	if err != nil {
		return err
	}
	for _, pg := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(pg)
		}
	}
	return nil
}

func (s *BgpServer) ListPeer(ctx context.Context, r *api.ListPeerRequest, fn func(*api.Peer)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var l []*api.Peer
	err := s.mgmtOperation(func() error {
		address := r.Address
		getAdvertised := r.EnableAdvertised
		l = make([]*api.Peer, 0, len(s.neighborMap))
		for k, peer := range s.neighborMap {
			peer.fsm.lock.Lock()
			neighborIface := peer.fsm.pConf.Config.NeighborInterface
			peer.fsm.lock.Unlock()
			if address != "" && address != k.String() && address != neighborIface {
				continue
			}
			// FIXME: should remove toConfig() conversion
			p := oc.NewPeerFromConfigStruct(s.toConfig(peer, getAdvertised))
			for _, family := range peer.configuredRFlist() {
				for i, afisafi := range p.AfiSafis {
					if !afisafi.Config.Enabled {
						continue
					}
					c := afisafi.Config
					if c.Family != nil && c.Family.Afi == api.Family_Afi(family.Afi()) && c.Family.Safi == api.Family_Safi(family.Safi()) {
						flist := []bgp.Family{family}
						sesstionState := peer.State()

						received := uint64(0)
						accepted := uint64(0)
						advertised := uint64(0)
						if sesstionState == bgp.BGP_FSM_ESTABLISHED {
							received = uint64(peer.adjRibIn.Count(flist))
							accepted = uint64(peer.adjRibIn.Accepted(flist))
							if getAdvertised {
								pathList, _ := s.getBestFromLocal(peer, flist)
								advertised = uint64(len(pathList))
							}
						}
						p.AfiSafis[i].State = &api.AfiSafiState{
							Family:     c.Family,
							Enabled:    true,
							Received:   received,
							Accepted:   accepted,
							Advertised: advertised,
						}
					}
				}
			}
			l = append(l, p)
		}
		return nil
	}, false)
	if err != nil {
		return err
	}
	for _, p := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(p)
		}
	}
	return nil
}

func (s *BgpServer) addPeerGroup(c *oc.PeerGroup) error {
	name := c.Config.PeerGroupName
	if _, y := s.peerGroupMap[name]; y {
		return fmt.Errorf("can't overwrite the existing peer-group: %s", name)
	}

	s.logger.Info("Add a peer group configuration",
		slog.String("Topic", "Peer"),
		slog.String("Name", name))

	s.peerGroupMap[c.Config.PeerGroupName] = newPeerGroup(c)

	return nil
}

func (s *BgpServer) addNeighbor(c *oc.Neighbor) error {
	addr, err := c.ExtractNeighborAddress()
	if err != nil {
		return err
	}

	if _, y := s.neighborMap[netip.MustParseAddr(addr)]; y {
		return fmt.Errorf("can't overwrite the existing peer: %s", addr)
	}

	var pgConf *oc.PeerGroup
	if c.Config.PeerGroup != "" {
		pg, ok := s.peerGroupMap[c.Config.PeerGroup]
		if !ok {
			return fmt.Errorf("no such peer-group: %s", c.Config.PeerGroup)
		}
		pgConf = pg.Conf
	}

	if err := oc.SetDefaultNeighborConfigValues(c, pgConf, &s.bgpConfig.Global); err != nil {
		return err
	}

	if vrf := c.Config.Vrf; vrf != "" {
		if c.RouteServer.Config.RouteServerClient {
			return fmt.Errorf("route server client can't be enslaved to VRF")
		}
		families, _ := oc.AfiSafis(c.AfiSafis).ToRfList()
		for _, f := range families {
			if f != bgp.RF_IPv4_UC && f != bgp.RF_IPv6_UC && f != bgp.RF_FS_IPv4_UC && f != bgp.RF_FS_IPv6_UC {
				return fmt.Errorf("%s is not supported for VRF enslaved neighbor", f)
			}
		}
		_, y := s.globalRib.Vrfs[vrf]
		if !y {
			return fmt.Errorf("VRF not found: %s", vrf)
		}
	}

	if c.RouteServer.Config.RouteServerClient && c.RouteReflector.Config.RouteReflectorClient {
		return fmt.Errorf("can't be both route-server-client and route-reflector-client")
	}

	if s.bgpConfig.Global.Config.Port > 0 {
		for _, l := range s.listListeners(addr) {
			if c.Config.AuthPassword != "" {
				if err := netutils.SetTCPMD5SigSockopt(l, addr, c.Config.AuthPassword); err != nil {
					s.logger.Warn("failed to set md5",
						slog.String("Topic", "Peer"),
						slog.String("Key", addr),
						slog.String("Err", err.Error()))
				}
			}
		}
	}
	s.logger.Info("Add a peer configuration",
		slog.String("Topic", "Peer"),
		slog.String("Key", addr))

	rib := s.globalRib
	if c.RouteServer.Config.RouteServerClient {
		rib = s.rsRib
	}
	peer := newPeer(&s.bgpConfig.Global, c, bgp.BGP_FSM_IDLE, rib, s.policy, s.logger)
	if err := s.policy.SetPeerPolicy(peer.ID(), c.ApplyPolicy); err != nil {
		return fmt.Errorf("failed to set peer policy for %s: %v", addr, err)
	}
	s.neighborMap[netip.MustParseAddr(addr)] = peer
	if name := c.Config.PeerGroup; name != "" {
		s.peerGroupMap[name].AddMember(*c)
	}
	s.startFsmHandler(peer)
	s.broadcastPeerState(peer, bgp.BGP_FSM_IDLE, nil)
	return nil
}

func (s *BgpServer) AddPeerGroup(ctx context.Context, r *api.AddPeerGroupRequest) error {
	if r == nil || r.PeerGroup == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		c, err := newPeerGroupFromAPIStruct(r.PeerGroup)
		if err != nil {
			return err
		}
		return s.addPeerGroup(c)
	}, true)
}

func (s *BgpServer) AddPeer(ctx context.Context, r *api.AddPeerRequest) error {
	if r == nil || r.Peer == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		c, err := newNeighborFromAPIStruct(r.Peer)
		if err != nil {
			return err
		}
		return s.addNeighbor(c)
	}, true)
}

func (s *BgpServer) AddDynamicNeighbor(ctx context.Context, r *api.AddDynamicNeighborRequest) error {
	if r == nil || r.DynamicNeighbor == nil {
		return fmt.Errorf("nil request")
	}
	p, err := netip.ParsePrefix(r.DynamicNeighbor.Prefix)
	if err != nil {
		return fmt.Errorf("invalid prefix: %v", err)
	}

	return s.mgmtOperation(func() error {
		c := &oc.DynamicNeighbor{
			Config: oc.DynamicNeighborConfig{
				Prefix:    p,
				PeerGroup: r.DynamicNeighbor.PeerGroup,
			},
		}
		s.peerGroupMap[c.Config.PeerGroup].AddDynamicNeighbor(c)

		pConf := s.peerGroupMap[c.Config.PeerGroup].Conf
		if pConf.Config.AuthPassword != "" {
			prefix := r.DynamicNeighbor.Prefix
			addr, _, _ := net.ParseCIDR(prefix)
			for _, l := range s.listListeners(addr.String()) {
				if err := netutils.SetTCPMD5SigSockopt(l, prefix, pConf.Config.AuthPassword); err != nil {
					s.logger.Warn("failed to set md5",
						slog.String("Topic", "Peer"),
						slog.String("Key", prefix),
						slog.String("Err", err.Error()))
				} else {
					s.logger.Info("successfully set md5 for dynamic peer",
						slog.String("Topic", "Peer"),
						slog.String("Key", prefix),
					)
				}
			}
		}
		return nil
	}, true)
}

func (s *BgpServer) deletePeerGroup(name string) error {
	if _, y := s.peerGroupMap[name]; !y {
		return fmt.Errorf("can't delete a peer-group %s which does not exist", name)
	}

	s.logger.Info("Delete a peer group configuration",
		slog.String("Topic", "Server"),
		slog.String("Name", name))

	delete(s.peerGroupMap, name)
	return nil
}

func (s *BgpServer) deleteNeighbor(c *oc.Neighbor, code, subcode uint8, sendNotification bool) error {
	if c.Config.PeerGroup != "" {
		_, y := s.peerGroupMap[c.Config.PeerGroup]
		if y {
			s.peerGroupMap[c.Config.PeerGroup].DeleteMember(*c)
		}
	}

	addr, err := c.ExtractNeighborAddress()
	if err != nil {
		return err
	}

	if intf := c.Config.NeighborInterface; intf != "" {
		var err error
		addr, err = oc.GetIPv6LinkLocalNeighborAddress(intf)
		if err != nil {
			return err
		}
	}
	n, y := s.neighborMap[netip.MustParseAddr(addr)]
	if !y {
		return fmt.Errorf("can't delete a peer configuration for %s", addr)
	}
	for _, l := range s.listListeners(addr) {
		if c.Config.AuthPassword != "" {
			if err := netutils.SetTCPMD5SigSockopt(l, addr, ""); err != nil {
				n.fsm.logger.Warn("failed to unset md5", slog.String("Err", err.Error()))
			}
		}
	}
	n.fsm.logger.Info("Delete a peer configuration")

	if sendNotification {
		n.fsm.deconfiguredNotification <- bgp.NewBGPNotificationMessage(code, subcode, nil)
	}
	s.propagateUpdate(n, n.DropAll(n.configuredRFlist()))
	s.stopNeighbor(n, -1, nil)
	return nil
}

func (s *BgpServer) DeletePeerGroup(ctx context.Context, r *api.DeletePeerGroupRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		name := r.Name
		for _, n := range s.neighborMap {
			n.fsm.lock.Lock()
			peerGroup := n.fsm.pConf.Config.PeerGroup
			n.fsm.lock.Unlock()
			if peerGroup == name {
				return fmt.Errorf("failed to delete peer-group %s: neighbor %s is in use", name, n.ID())
			}
		}
		return s.deletePeerGroup(name)
	}, true)
}

func (s *BgpServer) DeletePeer(ctx context.Context, r *api.DeletePeerRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		c := &oc.Neighbor{Config: oc.NeighborConfig{
			NeighborAddress:   netip.MustParseAddr(r.Address),
			NeighborInterface: r.Interface,
		}}
		return s.deleteNeighbor(c, bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED, true)
	}, true)
}

func (s *BgpServer) DeleteDynamicNeighbor(ctx context.Context, r *api.DeleteDynamicNeighborRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		s.peerGroupMap[r.PeerGroup].DeleteDynamicNeighbor(r.Prefix)

		if pg, ok := s.peerGroupMap[r.PeerGroup]; ok {
			pConf := pg.Conf
			if pConf.Config.AuthPassword != "" {
				prefix := r.Prefix
				addr, _, perr := net.ParseCIDR(prefix)
				if perr == nil {
					for _, l := range s.listListeners(addr.String()) {
						if err := netutils.SetTCPMD5SigSockopt(l, prefix, ""); err != nil {
							s.logger.Warn("failed to clear md5",
								slog.String("Topic", "Peer"),
								slog.String("Key", prefix),
								slog.String("Err", err.Error()))
						}
					}
				} else {
					s.logger.Warn("Cannot clear up dynamic MD5, invalid prefix",
						slog.String("Topic", "Peer"),
						slog.String("Key", prefix),
						slog.String("Err", perr.Error()),
					)
				}
			}
		}
		return nil
	}, true)
}

func (s *BgpServer) updatePeerGroup(pg *oc.PeerGroup) (needsSoftResetIn bool, err error) {
	name := pg.Config.PeerGroupName

	_, ok := s.peerGroupMap[name]
	if !ok {
		return false, fmt.Errorf("peer-group %s doesn't exist", name)
	}
	s.peerGroupMap[name].Conf = pg

	for _, n := range s.peerGroupMap[name].members {
		u, err := s.updateNeighbor(&n)
		if err != nil {
			return needsSoftResetIn, err
		}
		needsSoftResetIn = needsSoftResetIn || u
	}
	return needsSoftResetIn, nil
}

func (s *BgpServer) UpdatePeerGroup(ctx context.Context, r *api.UpdatePeerGroupRequest) (rsp *api.UpdatePeerGroupResponse, err error) {
	if r == nil || r.PeerGroup == nil {
		return nil, fmt.Errorf("nil request")
	}
	doSoftreset := false
	err = s.mgmtOperation(func() error {
		pg, err := newPeerGroupFromAPIStruct(r.PeerGroup)
		if err != nil {
			return err
		}
		doSoftreset, err = s.updatePeerGroup(pg)
		return err
	}, true)
	return &api.UpdatePeerGroupResponse{NeedsSoftResetIn: doSoftreset}, err
}

func (s *BgpServer) updateNeighbor(c *oc.Neighbor) (needsSoftResetIn bool, err error) {
	var pgConf *oc.PeerGroup
	if c.Config.PeerGroup != "" {
		if pg, ok := s.peerGroupMap[c.Config.PeerGroup]; ok {
			pgConf = pg.Conf
		} else {
			return needsSoftResetIn, fmt.Errorf("no such peer-group: %s", c.Config.PeerGroup)
		}
	}
	if err := oc.SetDefaultNeighborConfigValues(c, pgConf, &s.bgpConfig.Global); err != nil {
		return needsSoftResetIn, err
	}

	addr, err := c.ExtractNeighborAddress()
	if err != nil {
		return needsSoftResetIn, err
	}

	peer, ok := s.neighborMap[netip.MustParseAddr(addr)]
	if !ok {
		return needsSoftResetIn, fmt.Errorf("neighbor that has %v doesn't exist", addr)
	}

	if !peer.fsm.pConf.ApplyPolicy.Equal(&c.ApplyPolicy) {
		peer.fsm.logger.Info("Update ApplyPolicy")

		err := s.policy.SetPeerPolicy(peer.ID(), c.ApplyPolicy)
		if err != nil {
			return false, fmt.Errorf("failed to set peer policy: %w", err)
		}
		peer.fsm.pConf.ApplyPolicy = c.ApplyPolicy
		needsSoftResetIn = true
	}
	original := peer.fsm.pConf

	if !original.AsPathOptions.Config.Equal(&c.AsPathOptions.Config) {
		peer.fsm.logger.Info("Update aspath options")

		needsSoftResetIn = true
	}

	if original.NeedsResendOpenMessage(c) {
		sub := uint8(bgp.BGP_ERROR_SUB_OTHER_CONFIGURATION_CHANGE)
		if original.Config.AdminDown != c.Config.AdminDown {
			sub = bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN
			state := "Admin Down"

			if !c.Config.AdminDown {
				state = "Admin Up"
			}
			peer.fsm.logger.Info("Update admin-state configuration", slog.String("State", state))
		} else if original.Config.PeerAs != c.Config.PeerAs {
			sub = bgp.BGP_ERROR_SUB_PEER_DECONFIGURED
		}
		if err = s.deleteNeighbor(peer.fsm.pConf, bgp.BGP_ERROR_CEASE, sub, true); err != nil {
			peer.fsm.logger.Error("failed to delete neighbor", slog.String("Err", err.Error()))
			return needsSoftResetIn, err
		}
		err = s.addNeighbor(c)
		if err != nil {
			peer.fsm.logger.Error("failed to add neighbor", slog.String("Err", err.Error()))
		}
		return needsSoftResetIn, err
	}

	if !original.Timers.Config.Equal(&c.Timers.Config) {
		peer.fsm.logger.Info("Update timer configuration", slog.String("Err", err.Error()))
		peer.fsm.pConf.Timers.Config = c.Timers.Config
	}

	isLimit, err := peer.updatePrefixLimitConfig(c.AfiSafis)
	if isLimit && err == nil {
		err = s.setAdminState(addr, "", adminStatePfxCt)
	}
	if err != nil {
		peer.fsm.logger.Error("failed to update prefixLimit", slog.String("Err", err.Error()))
		// rollback to original state
		peer.fsm.pConf = original
		return needsSoftResetIn, err
	}

	setTTL := false
	if !original.EbgpMultihop.Config.Equal(&c.EbgpMultihop.Config) {
		peer.fsm.pConf.EbgpMultihop.Config = c.EbgpMultihop.Config
		setTTL = true
	}
	if !original.TtlSecurity.Config.Equal(&c.TtlSecurity.Config) {
		peer.fsm.pConf.TtlSecurity.Config = c.TtlSecurity.Config
		setTTL = true
	}

	if setTTL {
		if err := setPeerConnTTL(peer.fsm); err != nil {
			peer.fsm.logger.Error("failed to set peer connection TTL", slog.String("Err", err.Error()))
			// rollback to original state
			peer.fsm.pConf = original
			if err := setPeerConnTTL(peer.fsm); err != nil {
				peer.fsm.logger.Error("failed to rollback peer connection TTL", slog.String("Err", err.Error()))
			}
			return needsSoftResetIn, err
		}
	}

	return needsSoftResetIn, err
}

func (s *BgpServer) UpdatePeer(ctx context.Context, r *api.UpdatePeerRequest) (rsp *api.UpdatePeerResponse, err error) {
	if r == nil || r.Peer == nil {
		return nil, fmt.Errorf("nil request")
	}
	doSoftReset := false
	err = s.mgmtOperation(func() error {
		c, err := newNeighborFromAPIStruct(r.Peer)
		if err != nil {
			return err
		}
		doSoftReset, err = s.updateNeighbor(c)
		return err
	}, true)
	return &api.UpdatePeerResponse{NeedsSoftResetIn: doSoftReset}, err
}

func (s *BgpServer) addrToPeers(addr string) (l []*peer, err error) {
	if len(addr) == 0 {
		for _, p := range s.neighborMap {
			l = append(l, p)
		}
		return l, nil
	}
	remoteAddr, err := netip.ParseAddr(addr)
	if err != nil {
		return l, fmt.Errorf("failed to parse address: %v", err)
	}
	p, found := s.neighborMap[remoteAddr]
	if !found {
		return l, fmt.Errorf("neighbor that has %v doesn't exist", addr)
	}
	return []*peer{p}, nil
}

func (s *BgpServer) sendNotification(op, addr string, subcode uint8, data []byte) error {
	s.logger.Info("Send operation notification",
		slog.String("Topic", "Operation"),
		slog.String("Key", addr),
		slog.String("Op", op))

	peers, err := s.addrToPeers(addr)
	if err == nil {
		m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, subcode, data)
		for _, peer := range peers {
			peer.sendNotification(m)
		}
	}
	return err
}

func (s *BgpServer) ShutdownPeer(ctx context.Context, r *api.ShutdownPeerRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.sendNotification("Neighbor shutdown", r.Address, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, newAdministrativeCommunication(r.Communication))
	}, true)
}

func (s *BgpServer) ResetPeer(ctx context.Context, r *api.ResetPeerRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		addr := r.Address
		comm := r.Communication
		if r.Soft {
			var err error
			if addr == "all" {
				addr = ""
			}
			family := bgp.Family(0)
			switch r.Direction {
			case api.ResetPeerRequest_DIRECTION_IN:
				err = s.sResetIn(addr, family)
			case api.ResetPeerRequest_DIRECTION_OUT:
				err = s.sResetOut(addr, family)
			case api.ResetPeerRequest_DIRECTION_BOTH:
				err = s.sReset(addr, family)
			default:
				err = status.Errorf(codes.InvalidArgument, "unknown direction")
			}
			return err
		}

		return s.sendNotification("Neighbor reset", addr, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET, newAdministrativeCommunication(comm))
	}, true)
}

func (s *BgpServer) setAdminState(addr, communication string, state adminState) error {
	peers, err := s.addrToPeers(addr)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		f := func(stateOp *adminStateOperation, message string) {
			select {
			case peer.fsm.adminStateCh <- *stateOp:
				peer.fsm.logger.Debug("set admin state", slog.String("Message", message))
			default:
				peer.fsm.logger.Warn("previous setting admin state request is still remaining")
			}
		}
		switch state {
		case adminStateUp:
			f(&adminStateOperation{adminStateUp, nil}, "adminStateUp requested")
		case adminStateDown:
			f(&adminStateOperation{adminStateDown, newAdministrativeCommunication(communication)}, "adminStateDown requested")
		case adminStatePfxCt:
			f(&adminStateOperation{adminStatePfxCt, nil}, "adminStatePfxCt requested")
		}
	}
	return nil
}

func (s *BgpServer) EnablePeer(ctx context.Context, r *api.EnablePeerRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.setAdminState(r.Address, "", adminStateUp)
	}, true)
}

func (s *BgpServer) DisablePeer(ctx context.Context, r *api.DisablePeerRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.setAdminState(r.Address, r.Communication, adminStateDown)
	}, true)
}

func (s *BgpServer) ListDefinedSet(ctx context.Context, r *api.ListDefinedSetRequest, fn func(*api.DefinedSet)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var dt table.DefinedType
	switch r.DefinedType {
	case api.DefinedType_DEFINED_TYPE_UNSPECIFIED:
		return status.Error(codes.InvalidArgument, "unspecified defined type")
	case api.DefinedType_DEFINED_TYPE_PREFIX:
		dt = table.DEFINED_TYPE_PREFIX
	case api.DefinedType_DEFINED_TYPE_NEIGHBOR:
		dt = table.DEFINED_TYPE_NEIGHBOR
	case api.DefinedType_DEFINED_TYPE_AS_PATH:
		dt = table.DEFINED_TYPE_AS_PATH
	case api.DefinedType_DEFINED_TYPE_COMMUNITY:
		dt = table.DEFINED_TYPE_COMMUNITY
	case api.DefinedType_DEFINED_TYPE_EXT_COMMUNITY:
		dt = table.DEFINED_TYPE_EXT_COMMUNITY
	case api.DefinedType_DEFINED_TYPE_LARGE_COMMUNITY:
		dt = table.DEFINED_TYPE_LARGE_COMMUNITY
	default:
		return status.Errorf(codes.InvalidArgument, "unknown defined type %d", r.DefinedType)
	}
	var cd *oc.DefinedSets
	var err error
	err = s.mgmtOperation(func() error {
		cd, err = s.policy.GetDefinedSet(dt, r.Name)
		return err
	}, false)
	if err != nil {
		return err
	}
	exec := func(d *api.DefinedSet) bool {
		select {
		case <-ctx.Done():
			return true
		default:
			fn(d)
		}
		return false
	}

	for _, cs := range cd.PrefixSets {
		ad := &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
			Name:        cs.PrefixSetName,
			Prefixes: func() []*api.Prefix {
				l := make([]*api.Prefix, 0, len(cs.PrefixList))
				for _, p := range cs.PrefixList {
					elems := _regexpPrefixMaskLengthRange.FindStringSubmatch(p.MasklengthRange)
					min, _ := strconv.ParseUint(elems[1], 10, 32)
					max, _ := strconv.ParseUint(elems[2], 10, 32)

					l = append(l, &api.Prefix{IpPrefix: p.IpPrefix.String(), MaskLengthMin: uint32(min), MaskLengthMax: uint32(max)})
				}
				return l
			}(),
		}
		if exec(ad) {
			return nil
		}
	}
	for _, cs := range cd.NeighborSets {
		ad := &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR,
			Name:        cs.NeighborSetName,
			List:        cs.NeighborInfoList,
		}
		if exec(ad) {
			return nil
		}
	}
	for _, cs := range cd.BgpDefinedSets.CommunitySets {
		ad := &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY,
			Name:        cs.CommunitySetName,
			List:        cs.CommunityList,
		}
		if exec(ad) {
			return nil
		}
	}
	for _, cs := range cd.BgpDefinedSets.ExtCommunitySets {
		ad := &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_EXT_COMMUNITY,
			Name:        cs.ExtCommunitySetName,
			List:        cs.ExtCommunityList,
		}
		if exec(ad) {
			return nil
		}
	}
	for _, cs := range cd.BgpDefinedSets.LargeCommunitySets {
		ad := &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_LARGE_COMMUNITY,
			Name:        cs.LargeCommunitySetName,
			List:        cs.LargeCommunityList,
		}
		if exec(ad) {
			return nil
		}
	}
	for _, cs := range cd.BgpDefinedSets.AsPathSets {
		ad := &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_AS_PATH,
			Name:        cs.AsPathSetName,
			List:        cs.AsPathList,
		}
		if exec(ad) {
			return nil
		}
	}
	return nil
}

func (s *BgpServer) AddDefinedSet(ctx context.Context, r *api.AddDefinedSetRequest) error {
	if r == nil || r.DefinedSet == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		set, err := newDefinedSetFromApiStruct(r.DefinedSet)
		if err != nil {
			return err
		}
		return s.policy.AddDefinedSet(set, r.GetReplace())
	}, false)
}

func (s *BgpServer) DeleteDefinedSet(ctx context.Context, r *api.DeleteDefinedSetRequest) error {
	if r == nil || r.DefinedSet == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		set, err := newDefinedSetFromApiStruct(r.DefinedSet)
		if err != nil {
			return err
		}
		return s.policy.DeleteDefinedSet(set, r.All)
	}, false)
}

func (s *BgpServer) ListStatement(ctx context.Context, r *api.ListStatementRequest, fn func(*api.Statement)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var l []*api.Statement
	err := s.mgmtOperation(func() error {
		s := s.policy.GetStatement(r.Name)
		l = make([]*api.Statement, 0, len(s))
		for _, st := range s {
			l = append(l, toStatementApi(st))
		}
		return nil
	}, false)
	if err != nil {
		return err
	}
	for _, s := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(s)
		}
	}
	return nil
}

func (s *BgpServer) AddStatement(ctx context.Context, r *api.AddStatementRequest) error {
	if r == nil || r.Statement == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		st, err := newStatementFromApiStruct(r.Statement)
		if err != nil {
			return err
		}
		return s.policy.AddStatement(st)
	}, false)
}

func (s *BgpServer) DeleteStatement(ctx context.Context, r *api.DeleteStatementRequest) error {
	if r == nil || r.Statement == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		st, err := newStatementFromApiStruct(r.Statement)
		if err == nil {
			err = s.policy.DeleteStatement(st, r.All)
		}
		return err
	}, false)
}

func (s *BgpServer) ListPolicy(ctx context.Context, r *api.ListPolicyRequest, fn func(*api.Policy)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var l []*api.Policy
	err := s.mgmtOperation(func() error {
		pl := s.policy.GetPolicy(r.Name)
		l = make([]*api.Policy, 0, len(pl))
		for _, p := range pl {
			l = append(l, table.ToPolicyApi(p))
		}
		return nil
	}, false)
	if err != nil {
		return err
	}
	for _, p := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(p)
		}
	}
	return nil
}

func (s *BgpServer) AddPolicy(ctx context.Context, r *api.AddPolicyRequest) error {
	if r == nil || r.Policy == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		p, err := newPolicyFromApiStruct(r.Policy)
		if err == nil {
			err = s.policy.AddPolicy(p, r.ReferExistingStatements)
		}
		return err
	}, false)
}

func (s *BgpServer) DeletePolicy(ctx context.Context, r *api.DeletePolicyRequest) error {
	if r == nil || r.Policy == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		p, err := newPolicyFromApiStruct(r.Policy)
		if err != nil {
			return err
		}

		l := make([]string, 0, len(s.neighborMap)+1)
		for _, peer := range s.neighborMap {
			l = append(l, peer.ID())
		}
		l = append(l, table.GLOBAL_RIB_NAME)

		return s.policy.DeletePolicy(p, r.All, r.PreserveStatements, l)
	}, false)
}

func (s *BgpServer) toPolicyInfo(name string, dir api.PolicyDirection) (string, table.PolicyDirection, error) {
	if name == "" {
		return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("empty table name")
	}

	if name == table.GLOBAL_RIB_NAME {
		name = table.GLOBAL_RIB_NAME
	} else {
		remoteAddr, err := netip.ParseAddr(name)
		if err != nil {
			return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("failed to parse address: %v", err)
		}
		peer, ok := s.neighborMap[remoteAddr]
		if !ok {
			return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("not found peer %s", name)
		}
		if !peer.isRouteServerClient() {
			return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("non-rs-client peer %s doesn't have per peer policy", name)
		}
		name = peer.ID()
	}
	switch dir {
	case api.PolicyDirection_POLICY_DIRECTION_IMPORT:
		return name, table.POLICY_DIRECTION_IMPORT, nil
	case api.PolicyDirection_POLICY_DIRECTION_EXPORT:
		return name, table.POLICY_DIRECTION_EXPORT, nil
	}
	return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("invalid policy type")
}

func (s *BgpServer) ListPolicyAssignment(ctx context.Context, r *api.ListPolicyAssignmentRequest, fn func(*api.PolicyAssignment)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var a []*api.PolicyAssignment
	err := s.mgmtOperation(func() error {
		names := make([]string, 0, len(s.neighborMap)+1)
		if r.Name == "" {
			names = append(names, table.GLOBAL_RIB_NAME)
			for name, peer := range s.neighborMap {
				if peer.isRouteServerClient() {
					names = append(names, name.String())
				}
			}
		} else {
			names = append(names, r.Name)
		}
		dirs := make([]api.PolicyDirection, 0, 2)
		if r.Direction == api.PolicyDirection_POLICY_DIRECTION_UNSPECIFIED {
			dirs = []api.PolicyDirection{api.PolicyDirection_POLICY_DIRECTION_EXPORT, api.PolicyDirection_POLICY_DIRECTION_IMPORT}
		} else {
			dirs = append(dirs, r.Direction)
		}

		a = make([]*api.PolicyAssignment, 0, len(names))
		for _, name := range names {
			for _, dir := range dirs {
				id, dir, err := s.toPolicyInfo(name, dir)
				if err != nil {
					return err
				}
				rt, policies, err := s.policy.GetPolicyAssignment(id, dir)
				if err != nil {
					return err
				}
				t := &table.PolicyAssignment{
					Name:     name,
					Type:     dir,
					Default:  rt,
					Policies: policies,
				}
				a = append(a, table.NewAPIPolicyAssignmentFromTableStruct(t))
			}
		}
		return nil
	}, false)
	if err == nil {
		for _, p := range a {
			select {
			case <-ctx.Done():
				return nil
			default:
				fn(p)
			}
		}
	}
	return err
}

func (s *BgpServer) AddPolicyAssignment(ctx context.Context, r *api.AddPolicyAssignmentRequest) error {
	if r == nil || r.Assignment == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		id, dir, err := s.toPolicyInfo(r.Assignment.Name, r.Assignment.Direction)
		if err != nil {
			return err
		}
		return s.policy.AddPolicyAssignment(id, dir, toPolicyDefinition(r.Assignment.Policies), defaultRouteType(r.Assignment.DefaultAction))
	}, false)
}

func (s *BgpServer) DeletePolicyAssignment(ctx context.Context, r *api.DeletePolicyAssignmentRequest) error {
	if r == nil || r.Assignment == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		id, dir, err := s.toPolicyInfo(r.Assignment.Name, r.Assignment.Direction)
		if err != nil {
			return err
		}
		return s.policy.DeletePolicyAssignment(id, dir, toPolicyDefinition(r.Assignment.Policies), r.All)
	}, false)
}

func (s *BgpServer) SetPolicyAssignment(ctx context.Context, r *api.SetPolicyAssignmentRequest) error {
	if r == nil || r.Assignment == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		id, dir, err := s.toPolicyInfo(r.Assignment.Name, r.Assignment.Direction)
		if err != nil {
			return err
		}
		return s.policy.SetPolicyAssignment(id, dir, toPolicyDefinition(r.Assignment.Policies), defaultRouteType(r.Assignment.DefaultAction))
	}, false)
}

func (s *BgpServer) EnableMrt(ctx context.Context, r *api.EnableMrtRequest) error {
	if r == nil {
		return status.Errorf(codes.InvalidArgument, "null request")
	}

	var dump_type oc.MrtType
	switch r.DumpType {
	case api.EnableMrtRequest_DUMP_TYPE_UNSPECIFIED:
		return status.Errorf(codes.InvalidArgument, "unspecified type")
	case api.EnableMrtRequest_DUMP_TYPE_UPDATES:
		dump_type = oc.MRT_TYPE_UPDATES
	case api.EnableMrtRequest_DUMP_TYPE_TABLE:
		dump_type = oc.MRT_TYPE_TABLE
	}

	return s.mgmtOperation(func() error {
		return s.mrtManager.enable(&oc.MrtConfig{
			DumpInterval:     r.DumpInterval,
			RotationInterval: r.RotationInterval,
			DumpType:         dump_type,
			FileName:         r.Filename,
		})
	}, false)
}

func (s *BgpServer) DisableMrt(ctx context.Context, r *api.DisableMrtRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.mrtManager.disable(&oc.MrtConfig{})
	}, false)
}

func (s *BgpServer) ListRpki(ctx context.Context, r *api.ListRpkiRequest, fn func(*api.Rpki)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var l []*api.Rpki
	err := s.mgmtOperation(func() error {
		for _, r := range s.roaManager.GetServers() {
			received := &r.State.RpkiMessages.RpkiReceived
			sent := &r.State.RpkiMessages.RpkiSent
			rpki := &api.Rpki{
				Conf: &api.RPKIConf{
					Address:    r.Config.Address.String(),
					RemotePort: r.Config.Port,
				},
				State: &api.RPKIState{
					Uptime:        oc.ProtoTimestamp(r.State.Uptime),
					Downtime:      oc.ProtoTimestamp(r.State.Downtime),
					Up:            r.State.Up,
					RecordIpv4:    r.State.RecordsV4,
					RecordIpv6:    r.State.RecordsV6,
					PrefixIpv4:    r.State.PrefixesV4,
					PrefixIpv6:    r.State.PrefixesV6,
					Serial:        r.State.SerialNumber,
					ReceivedIpv4:  received.Ipv4Prefix,
					ReceivedIpv6:  received.Ipv6Prefix,
					SerialNotify:  received.SerialNotify,
					CacheReset:    received.CacheReset,
					CacheResponse: received.CacheResponse,
					EndOfData:     received.EndOfData,
					Error:         received.Error,
					SerialQuery:   sent.SerialQuery,
					ResetQuery:    sent.ResetQuery,
				},
			}
			l = append(l, rpki)
		}
		return nil
	}, false)
	if err != nil {
		return err
	}
	for _, r := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(r)
		}
	}
	return nil
}

func (s *BgpServer) ListRpkiTable(ctx context.Context, r *api.ListRpkiTableRequest, fn func(*api.Roa)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var l []*api.Roa
	err := s.mgmtOperation(func() error {
		family := bgp.Family(0)
		if r.Family != nil {
			family = bgp.NewFamily(uint16(r.Family.Afi), uint8(r.Family.Safi))
		}
		roas, err := s.roaTable.List(family)
		if err != nil {
			return err
		}
		l = append(l, newRoaListFromTableStructList(roas)...)
		return nil
	}, false)
	if err != nil {
		return err
	}
	for _, roa := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(roa)
		}
	}
	return nil
}

func (s *BgpServer) AddRpki(ctx context.Context, r *api.AddRpkiRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.roaManager.AddServer(net.JoinHostPort(r.Address, strconv.Itoa(int(r.Port))), r.Lifetime)
	}, false)
}

func (s *BgpServer) DeleteRpki(ctx context.Context, r *api.DeleteRpkiRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.roaManager.DeleteServer(r.Address)
	}, false)
}

func (s *BgpServer) EnableRpki(ctx context.Context, r *api.EnableRpkiRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.roaManager.Enable(r.Address)
	}, false)
}

func (s *BgpServer) DisableRpki(ctx context.Context, r *api.DisableRpkiRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.roaManager.Disable(r.Address)
	}, false)
}

func (s *BgpServer) ResetRpki(ctx context.Context, r *api.ResetRpkiRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		if r.Soft {
			return s.roaManager.SoftReset(r.Address)
		}
		return s.roaManager.Reset(r.Address)
	}, false)
}

// convertFSMStateReasonToAPI converts FSM state reason to API disconnect reason and message
func convertFSMStateReasonToAPI(stateReason *fsmStateReason) (api.PeerState_DisconnectReason, string) {
	if stateReason == nil {
		return api.PeerState_DISCONNECT_REASON_UNSPECIFIED, ""
	}

	var disconnectReason api.PeerState_DisconnectReason
	switch stateReason.Type {
	case fsmAdminDown:
		disconnectReason = api.PeerState_DISCONNECT_REASON_ADMIN_DOWN
	case fsmHoldTimerExpired:
		disconnectReason = api.PeerState_DISCONNECT_REASON_HOLD_TIMER_EXPIRED
	case fsmNotificationSent:
		disconnectReason = api.PeerState_DISCONNECT_REASON_NOTIFICATION_SENT
	case fsmNotificationRecv:
		disconnectReason = api.PeerState_DISCONNECT_REASON_NOTIFICATION_RECEIVED
	case fsmReadFailed:
		disconnectReason = api.PeerState_DISCONNECT_REASON_READ_FAILED
	case fsmWriteFailed:
		disconnectReason = api.PeerState_DISCONNECT_REASON_WRITE_FAILED
	case fsmIdleTimerExpired:
		disconnectReason = api.PeerState_DISCONNECT_REASON_IDLE_TIMER_EXPIRED
	case fsmRestartTimerExpired:
		disconnectReason = api.PeerState_DISCONNECT_REASON_RESTART_TIMER_EXPIRED
	case fsmGracefulRestart:
		disconnectReason = api.PeerState_DISCONNECT_REASON_GRACEFUL_RESTART
	case fsmInvalidMsg:
		disconnectReason = api.PeerState_DISCONNECT_REASON_INVALID_MSG
	case fsmHardReset:
		disconnectReason = api.PeerState_DISCONNECT_REASON_HARD_RESET
	case fsmDeConfigured:
		disconnectReason = api.PeerState_DISCONNECT_REASON_DECONFIGURED
	case fsmBadPeerAS:
		disconnectReason = api.PeerState_DISCONNECT_REASON_BAD_PEER_AS
	default:
		disconnectReason = api.PeerState_DISCONNECT_REASON_UNSPECIFIED
	}

	return disconnectReason, stateReason.String()
}

func toPathApiUtil(path *table.Path) *apiutil.Path {
	// Best and SendMaxFiltered are set in ListPath API
	p := &apiutil.Path{
		Family:             path.GetFamily(),
		Nlri:               path.GetNlri(),
		Age:                path.GetTimestamp().Unix(),
		Attrs:              path.GetPathAttrs(),
		Stale:              path.IsStale(),
		Withdrawal:         path.IsWithdraw,
		IsFromExternal:     path.IsFromExternal(),
		NoImplicitWithdraw: path.NoImplicitWithdraw(),
		IsNexthopInvalid:   path.IsNexthopInvalid,
		RemoteID:           path.RemoteID(),
		LocalID:            path.LocalID(),
	}
	if s := path.GetSource(); s != nil {
		p.PeerASN = s.AS
		p.PeerID = s.ID
		p.PeerAddress = s.Address
	}
	return p
}

type WatchEventMessageCallbacks struct {
	OnPathUpdate func([]*apiutil.Path, time.Time)
	OnBestPath   func([]*apiutil.Path, time.Time)
	OnPathEor    func(*apiutil.Path, time.Time)
	OnPeerUpdate func(*apiutil.WatchEventMessage_PeerEvent, time.Time)
}

func (s *BgpServer) WatchEvent(ctx context.Context, callbacks WatchEventMessageCallbacks, opts ...WatchOption) error {
	if len(opts) == 0 {
		return fmt.Errorf("no events to watch")
	}
	w := s.watch(opts...)

	go func() {
		defer w.Stop()

		for {
			select {
			case ev := <-w.Event():
				switch msg := ev.(type) {
				case *watchEventUpdate:
					if callbacks.OnPathUpdate != nil {
						paths := make([]*apiutil.Path, len(msg.PathList))
						for i, path := range msg.PathList {
							paths[i] = toPathApiUtil(path)
						}
						callbacks.OnPathUpdate(paths, msg.Timestamp)
					}

				case *watchEventBestPath:
					if callbacks.OnBestPath != nil {
						callback := func(paths []*table.Path) {
							p := make([]*apiutil.Path, len(paths))
							for i, path := range paths {
								p[i] = toPathApiUtil(path)
							}
							callbacks.OnBestPath(p, msg.Timestamp)
						}

						if len(msg.MultiPathList) > 0 {
							plen := 0
							for _, pa := range msg.MultiPathList {
								plen += len(pa)
							}
							paths := make([]*table.Path, plen)
							i := 0
							for _, pa := range msg.MultiPathList {
								for _, path := range pa {
									paths[i] = path
									i++
								}
							}
							callback(paths)
						} else {
							callback(msg.PathList)
						}
					}

				case *watchEventEor:
					if callbacks.OnPathEor != nil {
						eor := table.NewEOR(msg.Family)
						eor.SetSource(msg.PeerInfo)
						callbacks.OnPathEor(toPathApiUtil(eor), msg.Timestamp)
					}

				case *watchEventPeer:
					if callbacks.OnPeerUpdate != nil {
						var admin_state api.PeerState_AdminState
						switch msg.AdminState {
						case adminStateUp:
							admin_state = api.PeerState_ADMIN_STATE_UP
						case adminStateDown:
							admin_state = api.PeerState_ADMIN_STATE_DOWN
						case adminStatePfxCt:
							admin_state = api.PeerState_ADMIN_STATE_PFX_CT
						}

						disconnectReason, disconnectMessage := convertFSMStateReasonToAPI(msg.StateReason)

						callbacks.OnPeerUpdate(&apiutil.WatchEventMessage_PeerEvent{
							Type: msg.Type,
							Peer: apiutil.Peer{
								Conf: apiutil.PeerConf{
									PeerASN:           msg.PeerAS,
									LocalASN:          msg.LocalAS,
									NeighborAddress:   msg.PeerAddress,
									NeighborInterface: msg.PeerInterface,
								},
								State: apiutil.PeerState{
									PeerASN:           msg.PeerAS,
									LocalASN:          msg.LocalAS,
									NeighborAddress:   msg.PeerAddress,
									SessionState:      msg.State,
									AdminState:        admin_state,
									RouterID:          msg.PeerID,
									RemoteCap:         msg.RemoteCap,
									DisconnectReason:  disconnectReason,
									DisconnectMessage: disconnectMessage,
								},
								Transport: apiutil.Transport{
									LocalAddress: msg.LocalAddress,
									LocalPort:    uint32(msg.LocalPort),
									RemotePort:   uint32(msg.PeerPort),
								},
							},
						}, msg.Timestamp)
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}

func (s *BgpServer) SetLogLevel(ctx context.Context, r *api.SetLogLevelRequest) error {
	var newLevel slog.Level
	switch r.Level {
	case api.SetLogLevelRequest_LEVEL_ERROR:
		newLevel = slog.LevelError
	case api.SetLogLevelRequest_LEVEL_WARN:
		newLevel = slog.LevelWarn
	case api.SetLogLevelRequest_LEVEL_INFO:
		newLevel = slog.LevelInfo
	case api.SetLogLevelRequest_LEVEL_DEBUG:
		newLevel = slog.LevelDebug
	default:
		return status.Errorf(codes.InvalidArgument, "Unknown log level %s", r.Level)
	}

	if s.logLevelVar != nil {
		lvl := s.logLevelVar.Level()
		if lvl == newLevel {
			s.logger.Info("Logging level unchanged",
				slog.String("Topic", "Config"),
				slog.String("OldLevel", lvl.String()),
				slog.String("NewLevel", newLevel.String()))
		} else {
			s.logLevelVar.Set(newLevel)
			s.logger.Warn("Logging level changed",
				slog.String("Topic", "Config"),
				slog.String("OldLevel", lvl.String()),
				slog.String("NewLevel", newLevel.String()))
		}
		return nil
	}
	return nil
}

func (s *BgpServer) Log() *slog.Logger {
	return s.logger
}

type watchEventType string

const (
	watchEventTypeBestPath   watchEventType = "bestpath"
	watchEventTypePreUpdate  watchEventType = "preupdate"
	watchEventTypePostUpdate watchEventType = "postupdate"
	watchEventTypePeerState  watchEventType = "peerstate"
	watchEventTypeRecvMsg    watchEventType = "receivedmessage"
	watchEventTypeEor        watchEventType = "eor"
)

type watchEvent any

type watchEventUpdate struct {
	Message      *bgp.BGPMessage
	PeerAS       uint32
	LocalAS      uint32
	PeerAddress  net.IP
	LocalAddress net.IP
	PeerID       net.IP
	FourBytesAs  bool
	Timestamp    time.Time
	Payload      []byte
	PostPolicy   bool
	Init         bool
	PathList     []*table.Path
	Neighbor     *oc.Neighbor
}

type watchEventPeer struct {
	Type          apiutil.PeerEventType
	PeerAS        uint32
	LocalAS       uint32
	PeerAddress   netip.Addr
	LocalAddress  netip.Addr
	PeerPort      uint16
	LocalPort     uint16
	PeerID        netip.Addr
	SentOpen      *bgp.BGPMessage
	RecvOpen      *bgp.BGPMessage
	State         bgp.FSMState
	OldState      bgp.FSMState
	StateReason   *fsmStateReason
	AdminState    adminState
	Timestamp     time.Time
	PeerInterface string
	RemoteCap     []bgp.ParameterCapabilityInterface
}

type watchEventBestPath struct {
	PathList      []*table.Path
	MultiPathList [][]*table.Path
	Vrf           map[uint32]bool
	Timestamp     time.Time
}

type watchEventMessage struct {
	Message      *bgp.BGPMessage
	PeerAS       uint32
	LocalAS      uint32
	PeerAddress  net.IP
	LocalAddress net.IP
	PeerID       net.IP
	FourBytesAs  bool
	Timestamp    time.Time
	IsSent       bool
}

type watchEventEor struct {
	Family    bgp.Family
	PeerInfo  *table.PeerInfo
	Timestamp time.Time
}

type watchOptions struct {
	bestPath         bool
	preUpdate        bool
	preUpdateFilter  func(w watchEvent) bool
	postUpdate       bool
	postUpdateFilter func(w watchEvent) bool

	peerState      bool
	initBest       bool
	initUpdate     bool
	initPostUpdate bool
	recvMessage    bool
	initEor        bool
	eor            bool
}

type WatchOption func(*watchOptions)

func WatchBestPath(current bool) WatchOption {
	return func(o *watchOptions) {
		o.bestPath = true
		if current {
			o.initBest = true
		}
	}
}

func WatchUpdate(current bool, peerAddress string, peerGroup string) WatchOption {
	return func(o *watchOptions) {
		o.preUpdate = true
		if current {
			o.initUpdate = true
		}
		if peerAddress != "" || peerGroup != "" {
			o.preUpdateFilter = func(w watchEvent) bool {
				ev, ok := w.(*watchEventUpdate)
				if !ok || ev == nil {
					return false
				}
				if len(peerAddress) > 0 && ev.Neighbor.State.NeighborAddress == netip.MustParseAddr(peerAddress) {
					return true
				}
				if len(peerGroup) > 0 && ev.Neighbor.State.PeerGroup == peerGroup {
					return true
				}
				return false
			}
		}
	}
}

func WatchPostUpdate(current bool, peerAddress string, peerGroup string) WatchOption {
	return func(o *watchOptions) {
		o.postUpdate = true
		if current {
			o.initPostUpdate = true
		}
		if peerAddress != "" || peerGroup != "" {
			o.postUpdateFilter = func(w watchEvent) bool {
				ev, ok := w.(*watchEventUpdate)
				if !ok || ev == nil {
					return false
				}
				if len(peerAddress) > 0 && ev.Neighbor.State.NeighborAddress == netip.MustParseAddr(peerAddress) {
					return true
				}
				if len(peerGroup) > 0 && ev.Neighbor.State.PeerGroup == peerGroup {
					return true
				}
				return false
			}
		}
	}
}

func WatchEor(current bool) WatchOption {
	return func(o *watchOptions) {
		o.eor = true
		if current {
			o.initEor = true
		}
	}
}

func WatchPeer() WatchOption {
	return func(o *watchOptions) {
		o.peerState = true
	}
}

func watchMessage(isSent bool) WatchOption {
	return func(o *watchOptions) {
		if isSent {
			// log.WithFields(log.Fields{
			// 	"Topic": "Server",
			// }).Warn("watch event for sent messages is not implemented yet")
			// o.sentMessage = true
		} else {
			o.recvMessage = true
		}
	}
}

type watcher struct {
	opts   watchOptions
	realCh chan watchEvent
	ch     *channels.InfiniteChannel
	s      *BgpServer
	// filters are used for notifyWatcher by using the filter for the given watchEvent,
	// call notify method for skipping filtering.
	filters map[watchEventType]func(w watchEvent) bool
}

func (w *watcher) Event() <-chan watchEvent {
	return w.realCh
}

func (w *watcher) notify(v watchEvent) {
	w.ch.In() <- v
}

func (w *watcher) loop() {
	for ev := range w.ch.Out() {
		if ev == nil {
			break
		}
		w.realCh <- ev.(watchEvent)
	}
	close(w.realCh)
}

//nolint:errcheck // we don't care about the error here.
func (w *watcher) Stop() {
	w.s.mgmtOperation(func() error {
		for k, l := range w.s.watcherMap {
			for i, v := range l {
				if w == v {
					w.s.watcherMap[k] = append(l[:i], l[i+1:]...)
					break
				}
			}
		}

		cleanInfiniteChannel(w.ch)
		// the loop function goroutine might be blocked for
		// writing to realCh. make sure it finishes.
		for range w.realCh {
		}
		return nil
	}, false)
}

func (s *BgpServer) isWatched(typ watchEventType) bool {
	return len(s.watcherMap[typ]) != 0
}

// notifyWatcher notifies all watchers of the watchEventType about the event.
// If the filter is set(and not nil) for the watchEventType, it will be used for filtering.
// Otherwise, all events will be processed without any filtering.
func (s *BgpServer) notifyWatcher(typ watchEventType, ev watchEvent) {
	for _, w := range s.watcherMap[typ] {
		if f := w.filters[typ]; f != nil && !f(ev) {
			// Filter is set and the event doesn't pass it.
			continue
		}
		w.notify(ev)
	}
}

func (s *BgpServer) watch(opts ...WatchOption) (w *watcher) {
	// TODO: return error
	_ = s.mgmtOperation(func() error {
		w = &watcher{
			s:       s,
			realCh:  make(chan watchEvent, 8),
			ch:      channels.NewInfiniteChannel(),
			filters: make(map[watchEventType]func(w watchEvent) bool),
		}

		for _, opt := range opts {
			opt(&w.opts)
		}

		register := func(t watchEventType, w *watcher) {
			s.watcherMap[t] = append(s.watcherMap[t], w)
		}

		if w.opts.bestPath {
			register(watchEventTypeBestPath, w)
		}
		if w.opts.preUpdate {
			if w.opts.preUpdateFilter != nil {
				w.filters[watchEventTypePreUpdate] = w.opts.preUpdateFilter
			}
			register(watchEventTypePreUpdate, w)
		}
		if w.opts.postUpdate {
			if w.opts.postUpdateFilter != nil {
				w.filters[watchEventTypePostUpdate] = w.opts.postUpdateFilter
			}
			register(watchEventTypePostUpdate, w)
		}
		if w.opts.eor {
			register(watchEventTypeEor, w)
		}
		if w.opts.peerState {
			for _, p := range s.neighborMap {
				state := p.State()
				w.notify(newWatchEventPeer(p, nil, state, apiutil.PEER_EVENT_INIT))
			}
			w.notify(&watchEventPeer{Type: apiutil.PEER_EVENT_END_OF_INIT})

			register(watchEventTypePeerState, w)
		}

		if w.opts.initBest && s.active() == nil {
			w.notify(&watchEventBestPath{
				PathList:      s.globalRib.GetBestPathList(table.GLOBAL_RIB_NAME, 0, nil),
				MultiPathList: s.globalRib.GetBestMultiPathList(table.GLOBAL_RIB_NAME, nil),
				Timestamp:     time.Now(),
			})
		}
		if w.opts.initEor && s.active() == nil {
			now := time.Now()
			for _, p := range s.neighborMap {
				func() {
					p.fsm.lock.Lock()
					defer p.fsm.lock.Unlock()
					for _, a := range p.fsm.pConf.AfiSafis {
						if s := a.MpGracefulRestart.State; s.EndOfRibReceived {
							family := a.State.Family
							peerInfo := *p.peerInfo
							w.notify(&watchEventEor{
								Family:    family,
								PeerInfo:  &peerInfo,
								Timestamp: now,
							})
						}
					}
				}()
			}
		}
		if w.opts.initUpdate {
			for _, peer := range s.neighborMap {
				state := peer.State()
				if state != bgp.BGP_FSM_ESTABLISHED {
					continue
				}
				configNeighbor := w.s.toConfig(peer, false)
				if w.opts.preUpdateFilter != nil {
					ev := &watchEventUpdate{ // use fake event to check filter.
						Neighbor: configNeighbor,
					}
					if !w.opts.preUpdateFilter(ev) {
						continue
					}
				}
				for _, rf := range peer.configuredRFlist() {
					peer.fsm.lock.Lock()
					_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
					l := net.ParseIP(peer.fsm.pConf.Transport.State.LocalAddress.String())
					update := &watchEventUpdate{
						PeerAS:       peer.fsm.pConf.State.PeerAs,
						LocalAS:      peer.fsm.pConf.Config.LocalAs,
						PeerAddress:  net.ParseIP(peer.fsm.pConf.State.NeighborAddress.String()),
						LocalAddress: l,
						PeerID:       net.ParseIP(peer.fsm.pConf.State.RemoteRouterId.String()).To4(),
						FourBytesAs:  y,
						Init:         true,
						PostPolicy:   false,
						Neighbor:     configNeighbor,
						PathList:     peer.adjRibIn.PathList([]bgp.Family{rf}, false),
					}
					peer.fsm.lock.Unlock()
					w.notify(update)

					eor := bgp.NewEndOfRib(rf)
					eorBuf, _ := eor.Serialize()
					peer.fsm.lock.Lock()
					update = &watchEventUpdate{
						Message:      eor,
						PeerAS:       peer.fsm.pConf.State.PeerAs,
						LocalAS:      peer.fsm.pConf.Config.LocalAs,
						PeerAddress:  net.ParseIP(peer.fsm.pConf.State.NeighborAddress.String()),
						LocalAddress: l,
						PeerID:       net.ParseIP(peer.fsm.pConf.State.RemoteRouterId.String()).To4(),
						FourBytesAs:  y,
						Timestamp:    time.Now(),
						Init:         true,
						Payload:      eorBuf,
						PostPolicy:   false,
						Neighbor:     configNeighbor,
					}
					peer.fsm.lock.Unlock()
					w.notify(update)
				}
			}
		}
		if w.opts.initPostUpdate && s.active() == nil {
			for _, rf := range s.globalRib.GetRFlist() {
				if len(s.globalRib.Tables[rf].GetDestinations()) == 0 {
					continue
				}
				pathsByPeer := make(map[*table.PeerInfo][]*table.Path)
				for _, path := range s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{rf}) {
					pathsByPeer[path.GetSource()] = append(pathsByPeer[path.GetSource()], path)
				}
				for peerInfo, paths := range pathsByPeer {
					// create copy which can be access to without mutex
					var configNeighbor *oc.Neighbor
					peerAddress := peerInfo.Address
					if peer, ok := s.neighborMap[peerAddress]; ok {
						configNeighbor = w.s.toConfig(peer, false)
					}
					ev := &watchEventUpdate{
						PeerAS:      peerInfo.AS,
						PeerAddress: net.IP(peerInfo.Address.AsSlice()),
						PeerID:      net.IP(peerInfo.ID.AsSlice()),
						PostPolicy:  true,
						Neighbor:    configNeighbor,
						PathList:    paths,
						Init:        true,
					}
					if w.opts.postUpdateFilter != nil && !w.opts.postUpdateFilter(ev) {
						continue
					}

					w.notify(ev)

					eor := bgp.NewEndOfRib(rf)
					eorBuf, _ := eor.Serialize()
					w.notify(&watchEventUpdate{
						Message:     eor,
						PeerAS:      peerInfo.AS,
						PeerAddress: net.IP(peerInfo.Address.AsSlice()),
						PeerID:      net.IP(peerInfo.ID.AsSlice()),
						Timestamp:   time.Now(),
						Payload:     eorBuf,
						PostPolicy:  true,
						Neighbor:    configNeighbor,
						Init:        true,
					})
				}
			}
		}
		if w.opts.recvMessage {
			register(watchEventTypeRecvMsg, w)
		}

		go w.loop()
		return nil
	}, false)
	return w
}
