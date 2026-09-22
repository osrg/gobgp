package metrics

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

type fsmTimingsCollector struct {
	timingHistograms, waitHistograms []prometheus.Histogram
}

type FSMTimingsCollector interface {
	server.FSMTimingHook
	prometheus.Collector
}

var (
	fsmOperationInfixes = [server.FSMOperationTypeCount]string{
		"mgmt_op",
		"accept",
		"event",
		"message",
	}

	fsmOperationDescriptions = [server.FSMOperationTypeCount]string{
		"management operation",
		"TCP accept",
		"event",
		"BGP message",
	}
)

func NewFSMTimingsCollector() FSMTimingsCollector {
	const namespace = "fsm_loop"
	c := &fsmTimingsCollector{
		timingHistograms: make([]prometheus.Histogram, server.FSMOperationTypeCount),
		waitHistograms:   make([]prometheus.Histogram, server.FSMOperationTypeCount),
	}

	fsmHistograms := make([]prometheus.Histogram, server.FSMOperationTypeCount)
	for i := range fsmHistograms {
		c.timingHistograms[i] = prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    prometheus.BuildFQName(namespace, fsmOperationInfixes[i], "timing_sec"),
			Help:    fmt.Sprintf("Histogram of %s timings", fsmOperationDescriptions[i]),
			Buckets: prometheus.DefBuckets,
		})
		c.waitHistograms[i] = prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    prometheus.BuildFQName(namespace, fsmOperationInfixes[i], "wait_sec"),
			Help:    fmt.Sprintf("Histogram of %s channel delays", fsmOperationDescriptions[i]),
			Buckets: prometheus.DefBuckets,
		})
	}
	return c
}

func (f *fsmTimingsCollector) Observe(op server.FSMOperation, tOp, tWait time.Duration) {
	f.timingHistograms[op].Observe(tOp.Seconds())
	if tWait != 0 {
		f.waitHistograms[op].Observe(tWait.Seconds())
	}
}

func (f *fsmTimingsCollector) Describe(descs chan<- *prometheus.Desc) {
	for _, histogramList := range [][]prometheus.Histogram{f.timingHistograms, f.waitHistograms} {
		for _, h := range histogramList {
			h.Describe(descs)
		}
	}
}

func (f *fsmTimingsCollector) Collect(metrics chan<- prometheus.Metric) {
	for _, histogramList := range [][]prometheus.Histogram{f.timingHistograms, f.waitHistograms} {
		for _, h := range histogramList {
			h.Collect(metrics)
		}
	}
}

type bgpCollector struct {
	server *server.BgpServer
}

const (
	// Global namespace of the metrics
	namespace = "bgp"
)

// enumValues lists the values of an API enum, so that the help text of a
// metric reporting one cannot drift from what is reported.
func enumValues(names map[int32]string, prefix string) string {
	codes := slices.Sorted(maps.Keys(names))
	values := make([]string, 0, len(codes))
	for _, code := range codes {
		values = append(values, fmt.Sprintf("%s (%d)", strings.TrimPrefix(names[code], prefix), code))
	}
	return strings.Join(values, ", ")
}

var (
	// Labels appended to the metrics. peerLabels is on every peer-scoped metric;
	// the others extend it.
	peerLabels         = []string{"peer", "peer_group", "description"}
	peerRouterIdLabels = slices.Concat(peerLabels, []string{"router_id"})
	rfLabels           = slices.Concat(peerLabels, []string{"route_family"})

	bgpReceivedUpdateTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "update_total"),
		"Number of received BGP UPDATE messages from peer",
		peerLabels, nil,
	)
	bgpReceivedNotificationTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "notification_total"),
		"Number of received BGP NOTIFICATION messages from peer",
		peerLabels, nil,
	)
	bgpReceivedOpenTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "open_total"),
		"Number of received BGP OPEN messages from peer",
		peerLabels, nil,
	)
	bgpReceivedRefreshTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "refresh_total"),
		"Number of received BGP REFRESH messages from peer",
		peerLabels, nil,
	)
	bgpReceivedKeepaliveTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "keepalive_total"),
		"Number of received BGP KEEPALIVE messages from peer",
		peerLabels, nil,
	)
	bgpReceivedWithdrawUpdateTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "withdraw_update_total"),
		"Number of received BGP WITHDRAW-UPDATE messages from peer",
		peerLabels, nil,
	)
	bgpReceivedWithdrawPrefixTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "withdraw_prefix_total"),
		"Number of received BGP WITHDRAW-PREFIX messages from peer",
		peerLabels, nil,
	)
	bgpReceivedDiscardedTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "discarded_total"),
		"Number of discarded BGP messages from peer",
		peerLabels, nil,
	)
	bgpReceivedMessageTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "received", "message_total"),
		"Number of received BGP messages from peer",
		peerLabels, nil,
	)

	bgpSentUpdateTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "update_total"),
		"Number of sent BGP UPDATE messages from peer",
		peerLabels, nil,
	)
	bgpSentNotificationTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "notification_total"),
		"Number of sent BGP NOTIFICATION messages from peer",
		peerLabels, nil,
	)
	bgpSentOpenTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "open_total"),
		"Number of sent BGP OPEN messages from peer",
		peerLabels, nil,
	)
	bgpSentRefreshTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "refresh_total"),
		"Number of sent BGP REFRESH messages from peer",
		peerLabels, nil,
	)
	bgpSentKeepaliveTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "keepalive_total"),
		"Number of sent BGP KEEPALIVE messages from peer",
		peerLabels, nil,
	)
	bgpSentWithdrawUpdateTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "withdraw_update_total"),
		"Number of sent BGP WITHDRAW-UPDATE messages from peer",
		peerLabels, nil,
	)
	bgpSentWithdrawPrefixTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "withdraw_prefix_total"),
		"Number of sent BGP WITHDRAW-PREFIX messages from peer",
		peerLabels, nil,
	)
	bgpSentDiscardedTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "discarded_total"),
		"Number of discarded BGP messages to peer", peerLabels,
		nil,
	)
	bgpSentMessageTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sent", "message_total"),
		"Number of sent BGP messages from peer", peerLabels,
		nil,
	)

	bgpPeerOutQueueDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "out_queue_count"),
		"Length of the outgoing message queue",
		peerLabels, nil,
	)
	bgpPeerFlopsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "flop_count"),
		"Number of flops with the peer",
		peerLabels, nil,
	)
	bgpPeerUptimeDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "uptime"),
		"Unix time at which the BGP session with the peer last came up",
		peerLabels, nil,
	)
	bgpPeerSendCommunityFlagDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "send_community"),
		"BGP community with the peer",
		peerLabels, nil,
	)
	bgpPeerRemovePrivateAsFlagDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "remove_private_as"),
		"Do we remove private ASNs from the paths sent to the peer",
		peerLabels, nil,
	)
	bgpPeerPasswordSetFlagDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "password_set"),
		"Whether the GoBGP peer has been configured (1) for authentication or not (0)",
		peerLabels, nil,
	)
	bgpPeerTypeDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "type"),
		"Type of the BGP peer: "+enumValues(api.PeerType_name, "PEER_TYPE_"),
		peerLabels, nil,
	)
	bgpPeerAsnDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "asn"),
		"What is the AS number of the peer",
		peerRouterIdLabels, nil,
	)
	bgpPeerLocalAsnDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "local_asn"),
		"What is the AS number presented to the peer by this router",
		peerRouterIdLabels, nil,
	)
	bgpPeerSessionStateDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "session_state"),
		"Session state of the BGP peer: "+enumValues(api.PeerState_SessionState_name, "SESSION_STATE_"),
		peerLabels, nil,
	)
	bgpPeerAdminStateDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "admin_state"),
		"Administrative state of the BGP peer: "+enumValues(api.PeerState_AdminState_name, "ADMIN_STATE_"),
		peerLabels, nil,
	)

	bgpRoutesReceivedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "routes", "received"),
		"Number of routes received from peer",
		rfLabels, nil,
	)
	bgpRoutesAcceptedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "routes", "accepted"),
		"Number of routes accepted from peer",
		rfLabels, nil,
	)
	bgpRoutesAdvertisedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "routes", "advertised"),
		"Number of routes advertised to peer",
		rfLabels, nil,
	)
)

func NewBgpCollector(server *server.BgpServer) prometheus.Collector {
	return &bgpCollector{server: server}
}

func (c *bgpCollector) Describe(out chan<- *prometheus.Desc) {
	out <- bgpReceivedUpdateTotalDesc
	out <- bgpReceivedNotificationTotalDesc
	out <- bgpReceivedOpenTotalDesc
	out <- bgpReceivedRefreshTotalDesc
	out <- bgpReceivedKeepaliveTotalDesc
	out <- bgpReceivedWithdrawUpdateTotalDesc
	out <- bgpReceivedWithdrawPrefixTotalDesc
	out <- bgpReceivedDiscardedTotalDesc
	out <- bgpReceivedMessageTotalDesc

	out <- bgpSentUpdateTotalDesc
	out <- bgpSentNotificationTotalDesc
	out <- bgpSentOpenTotalDesc
	out <- bgpSentRefreshTotalDesc
	out <- bgpSentKeepaliveTotalDesc
	out <- bgpSentWithdrawUpdateTotalDesc
	out <- bgpSentWithdrawPrefixTotalDesc
	out <- bgpSentDiscardedTotalDesc
	out <- bgpSentMessageTotalDesc

	out <- bgpPeerOutQueueDesc
	out <- bgpPeerFlopsDesc
	out <- bgpPeerUptimeDesc
	out <- bgpPeerSendCommunityFlagDesc
	out <- bgpPeerRemovePrivateAsFlagDesc
	out <- bgpPeerPasswordSetFlagDesc
	out <- bgpPeerTypeDesc
	out <- bgpPeerAsnDesc
	out <- bgpPeerLocalAsnDesc
	out <- bgpPeerSessionStateDesc
	out <- bgpPeerAdminStateDesc

	out <- bgpRoutesReceivedDesc
	out <- bgpRoutesAcceptedDesc
	out <- bgpRoutesAdvertisedDesc
}

func (c *bgpCollector) Collect(out chan<- prometheus.Metric) {
	bgpServer, err := c.server.GetBgp(context.Background(), &api.GetBgpRequest{})
	if err != nil {
		out <- prometheus.NewInvalidMetric(prometheus.NewDesc("error", "error during metric collection", nil, nil), err)
		return
	}

	req := &api.ListPeerRequest{EnableAdvertised: true}
	err = c.server.ListPeer(context.Background(), req, func(p *api.Peer) {
		peerState := p.GetState()
		peerAddr := peerState.GetNeighborAddress()
		peerPg := peerState.GetPeerGroup()
		peerDesc := peerState.GetDescription()
		peerTimers := p.GetTimers()
		msg := peerState.GetMessages()

		sendCounter := func(desc *prometheus.Desc, cnt uint64) {
			out <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(cnt), peerAddr, peerPg, peerDesc)
		}
		sendGauge := func(desc *prometheus.Desc, v float64) {
			out <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, v, peerAddr, peerPg, peerDesc)
		}

		// Statistics about BGP announcements we've received from our peers
		sendCounter(bgpReceivedUpdateTotalDesc, msg.Received.Update)
		sendCounter(bgpReceivedNotificationTotalDesc, msg.Received.Notification)
		sendCounter(bgpReceivedOpenTotalDesc, msg.Received.Open)
		sendCounter(bgpReceivedRefreshTotalDesc, msg.Received.Refresh)
		sendCounter(bgpReceivedKeepaliveTotalDesc, msg.Received.Keepalive)
		sendCounter(bgpReceivedWithdrawUpdateTotalDesc, msg.Received.WithdrawUpdate)
		sendCounter(bgpReceivedWithdrawPrefixTotalDesc, msg.Received.WithdrawPrefix)
		sendCounter(bgpReceivedDiscardedTotalDesc, msg.Received.Discarded)
		sendCounter(bgpReceivedMessageTotalDesc, msg.Received.Total)

		// Statistics about BGP announcements we've sent to our peers
		sendCounter(bgpSentUpdateTotalDesc, msg.Sent.Update)
		sendCounter(bgpSentNotificationTotalDesc, msg.Sent.Notification)
		sendCounter(bgpSentOpenTotalDesc, msg.Sent.Open)
		sendCounter(bgpSentRefreshTotalDesc, msg.Sent.Refresh)
		sendCounter(bgpSentKeepaliveTotalDesc, msg.Sent.Keepalive)
		sendCounter(bgpSentWithdrawUpdateTotalDesc, msg.Sent.WithdrawUpdate)
		sendCounter(bgpSentWithdrawPrefixTotalDesc, msg.Sent.WithdrawPrefix)
		sendCounter(bgpSentDiscardedTotalDesc, msg.Sent.Discarded)
		sendCounter(bgpSentMessageTotalDesc, msg.Sent.Total)

		// The outbound queue message size
		sendGauge(bgpPeerOutQueueDesc, float64(peerState.GetOutQ()))
		// The number of neighbor flops
		sendCounter(bgpPeerFlopsDesc, uint64(peerState.GetFlops()))
		// Unix time at which the session came up
		sendGauge(bgpPeerUptimeDesc, float64(peerTimers.GetState().GetUptime().GetSeconds()))
		// Whether BGP community is being sent
		sendGauge(bgpPeerSendCommunityFlagDesc, float64(peerState.GetSendCommunity()))
		// Whether BGP Private AS is being removed (1) or not (0)
		sendGauge(bgpPeerRemovePrivateAsFlagDesc, float64(peerState.GetRemovePrivate()))
		sendGauge(bgpPeerTypeDesc, float64(peerState.GetType()))

		// Whether authentication password is being set (1) or not (0)
		passwordSetFlag := 0
		if peerState.GetAuthPassword() != "" {
			passwordSetFlag = 1
		}
		sendGauge(bgpPeerPasswordSetFlagDesc, float64(passwordSetFlag))

		// Remote peer router ID and ASN
		out <- prometheus.MustNewConstMetric(
			bgpPeerAsnDesc,
			prometheus.GaugeValue,
			float64(peerState.GetPeerAsn()),
			peerAddr,
			peerPg,
			peerDesc,
			peerState.GetRouterId(),
		)

		// Local router ID and ASN advertised to peer
		out <- prometheus.MustNewConstMetric(
			bgpPeerLocalAsnDesc,
			prometheus.GaugeValue,
			float64(peerState.GetLocalAsn()),
			peerAddr,
			peerPg,
			peerDesc,
			bgpServer.Global.RouterId,
		)

		sendGauge(bgpPeerSessionStateDesc, float64(peerState.GetSessionState()))
		sendGauge(bgpPeerAdminStateDesc, float64(peerState.GetAdminState()))

		for _, afiSafi := range p.GetAfiSafis() {
			if !afiSafi.GetConfig().GetEnabled() {
				continue
			}
			afiState := afiSafi.GetState()
			family := bgp.NewFamily(
				uint16(afiState.GetFamily().GetAfi()),
				uint8(afiState.GetFamily().GetSafi()),
			).String()
			labelValues := []string{peerAddr, peerPg, peerDesc, family}
			out <- prometheus.MustNewConstMetric(
				bgpRoutesReceivedDesc,
				prometheus.GaugeValue,
				float64(afiState.GetReceived()),
				labelValues...,
			)
			out <- prometheus.MustNewConstMetric(
				bgpRoutesAcceptedDesc,
				prometheus.GaugeValue,
				float64(afiState.GetAccepted()),
				labelValues...,
			)
			out <- prometheus.MustNewConstMetric(
				bgpRoutesAdvertisedDesc,
				prometheus.GaugeValue,
				float64(afiState.GetAdvertised()),
				labelValues...,
			)
		}
	})
	if err != nil {
		out <- prometheus.NewInvalidMetric(prometheus.NewDesc("error", "error during metric collection", nil, nil), err)
	}
}
