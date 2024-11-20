package metrics

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/server"
)

type bgpCollector struct {
	server *server.BgpServer
}

const (
	// Global namespace of the metrics
	namespace = "bgp"
)

var (
	// Labels appended to the metrics
	peerLabels         = []string{"peer"}
	peerRouterIdLabels = []string{"peer", "router_id"}
	peerStateLabels    = []string{"peer", "session_state", "admin_state"}
	rfLabels           = []string{"peer", "route_family"}

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
		"For how long the peer has been in its current state",
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
		"Type of the BGP peer, internal (0) or external (1)",
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
	bgpPeerStateDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "peer", "state"),
		"State of the BGP session with peer and its administrative state",
		peerStateLabels, nil,
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
	out <- bgpPeerStateDesc

	out <- bgpRoutesReceivedDesc
	out <- bgpRoutesAcceptedDesc
	out <- bgpRoutesAdvertisedDesc
}

func (c *bgpCollector) Collect(out chan<- prometheus.Metric) {
	req := &api.ListPeerRequest{EnableAdvertised: true}
	err := c.server.ListPeer(context.Background(), req, func(p *api.Peer) {
		peerState := p.GetState()
		peerAddr := peerState.GetNeighborAddress()
		peerTimers := p.GetTimers()
		msg := peerState.GetMessages()

		send := func(desc *prometheus.Desc, cnt uint64) {
			out <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(cnt), peerAddr)
		}

		// Statistics about BGP announcements we've received from our peers
		send(bgpReceivedUpdateTotalDesc, msg.Received.Update)
		send(bgpReceivedNotificationTotalDesc, msg.Received.Notification)
		send(bgpReceivedOpenTotalDesc, msg.Received.Open)
		send(bgpReceivedRefreshTotalDesc, msg.Received.Refresh)
		send(bgpReceivedKeepaliveTotalDesc, msg.Received.Keepalive)
		send(bgpReceivedWithdrawUpdateTotalDesc, uint64(msg.Received.WithdrawUpdate))
		send(bgpReceivedWithdrawPrefixTotalDesc, uint64(msg.Received.WithdrawPrefix))
		send(bgpReceivedDiscardedTotalDesc, msg.Received.Discarded)
		send(bgpReceivedMessageTotalDesc, msg.Received.Total)

		// Statistics about BGP announcements we've sent to our peers
		send(bgpSentUpdateTotalDesc, msg.Sent.Update)
		send(bgpSentNotificationTotalDesc, msg.Sent.Notification)
		send(bgpSentOpenTotalDesc, msg.Sent.Open)
		send(bgpSentRefreshTotalDesc, msg.Sent.Refresh)
		send(bgpSentKeepaliveTotalDesc, msg.Sent.Keepalive)
		send(bgpSentWithdrawUpdateTotalDesc, msg.Sent.WithdrawUpdate)
		send(bgpSentWithdrawPrefixTotalDesc, msg.Sent.WithdrawPrefix)
		send(bgpSentDiscardedTotalDesc, msg.Sent.Discarded)
		send(bgpSentMessageTotalDesc, msg.Sent.Total)

		// The outbound queue message size
		send(bgpPeerOutQueueDesc, uint64(peerState.GetOutQ()))
		// The number of neighbor flops
		send(bgpPeerFlopsDesc, uint64(peerState.GetFlops()))
		// Uptime in seconds of the session
		send(bgpPeerUptimeDesc, uint64(peerTimers.GetState().GetUptime().GetSeconds()))
		// Whether BGP community is being sent
		send(bgpPeerSendCommunityFlagDesc, uint64(peerState.GetSendCommunity()))
		// Whether BGP Private AS is being removed (1) or not (0)
		send(bgpPeerRemovePrivateAsFlagDesc, uint64(peerState.GetRemovePrivate()))
		// Peer Type (0) for internal, (1) for external
		send(bgpPeerTypeDesc, uint64(peerState.GetType()))

		// Whether authentication password is being set (1) or not (0)
		passwordSetFlag := 0
		if peerState.GetAuthPassword() != "" {
			passwordSetFlag = 1
		}
		send(bgpPeerPasswordSetFlagDesc, uint64(passwordSetFlag))

		// Remote peer router ID and ASN
		out <- prometheus.MustNewConstMetric(
			bgpPeerAsnDesc,
			prometheus.GaugeValue,
			float64(peerState.GetPeerAsn()),
			peerAddr,
			peerState.GetRouterId(),
		)

		// Local router ID and ASN advertised to peer
		out <- prometheus.MustNewConstMetric(
			bgpPeerLocalAsnDesc,
			prometheus.GaugeValue,
			float64(peerState.GetLocalAsn()),
			peerAddr,
			p.Transport.GetLocalAddress(),
		)

		// Session and administrative state of the peer
		out <- prometheus.MustNewConstMetric(
			bgpPeerStateDesc,
			prometheus.GaugeValue,
			1.0,
			peerAddr,
			peerState.GetSessionState().String(),
			peerState.GetAdminState().String(),
		)

		for _, afiSafi := range p.GetAfiSafis() {
			if !afiSafi.GetConfig().GetEnabled() {
				continue
			}
			afiState := afiSafi.GetState()
			family := bgp.AfiSafiToRouteFamily(
				uint16(afiState.GetFamily().GetAfi()),
				uint8(afiState.GetFamily().GetSafi()),
			).String()
			labelValues := []string{peerAddr, family}
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
