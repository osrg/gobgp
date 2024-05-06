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

var (
	peerLabels      = []string{"peer"}
	peerStateLabels = []string{"peer", "session_state", "admin_state"}
	rfLabels        = []string{"peer", "route_family"}

	bgpReceivedUpdateTotalDesc         = prometheus.NewDesc("bgp_received_update_total", "Number of received BGP UPDATE messages from peer", peerLabels, nil)
	bgpReceivedNotificationTotalDesc   = prometheus.NewDesc("bgp_received_notification_total", "Number of received BGP NOTIFICATION messages from peer", peerLabels, nil)
	bgpReceivedOpenTotalDesc           = prometheus.NewDesc("bgp_received_open_total", "Number of received BGP OPEN messages from peer", peerLabels, nil)
	bgpReceivedRefreshTotalDesc        = prometheus.NewDesc("bgp_received_refresh_total", "Number of received BGP REFRESH messages from peer", peerLabels, nil)
	bgpReceivedKeepaliveTotalDesc      = prometheus.NewDesc("bgp_received_keepalive_total", "Number of received BGP KEEPALIVE messages from peer", peerLabels, nil)
	bgpReceivedWithdrawUpdateTotalDesc = prometheus.NewDesc("bgp_received_withdraw_update_total", "Number of received BGP WITHDRAW-UPDATE messages from peer", peerLabels, nil)
	bgpReceivedWithdrawPrefixTotalDesc = prometheus.NewDesc("bgp_received_withdraw_prefix_total", "Number of received BGP WITHDRAW-PREFIX messages from peer", peerLabels, nil)
	bgpReceivedDiscardedTotalDesc      = prometheus.NewDesc("bgp_received_discarded_total", "Number of discarded BGP messages from peer", peerLabels, nil)
	bgpReceivedMessageTotalDesc        = prometheus.NewDesc("bgp_received_message_total", "Number of received BGP messages from peer", peerLabels, nil)

	bgpSentUpdateTotalDesc         = prometheus.NewDesc("bgp_sent_update_total", "Number of sent BGP UPDATE messages from peer", peerLabels, nil)
	bgpSentNotificationTotalDesc   = prometheus.NewDesc("bgp_sent_notification_total", "Number of sent BGP NOTIFICATION messages from peer", peerLabels, nil)
	bgpSentOpenTotalDesc           = prometheus.NewDesc("bgp_sent_open_total", "Number of sent BGP OPEN messages from peer", peerLabels, nil)
	bgpSentRefreshTotalDesc        = prometheus.NewDesc("bgp_sent_refresh_total", "Number of sent BGP REFRESH messages from peer", peerLabels, nil)
	bgpSentKeepaliveTotalDesc      = prometheus.NewDesc("bgp_sent_keepalive_total", "Number of sent BGP KEEPALIVE messages from peer", peerLabels, nil)
	bgpSentWithdrawUpdateTotalDesc = prometheus.NewDesc("bgp_sent_withdraw_update_total", "Number of sent BGP WITHDRAW-UPDATE messages from peer", peerLabels, nil)
	bgpSentWithdrawPrefixTotalDesc = prometheus.NewDesc("bgp_sent_withdraw_prefix_total", "Number of sent BGP WITHDRAW-PREFIX messages from peer", peerLabels, nil)
	bgpSentDiscardedTotalDesc      = prometheus.NewDesc("bgp_sent_discarded_total", "Number of discarded BGP messages from peer", peerLabels, nil)
	bgpSentMessageTotalDesc        = prometheus.NewDesc("bgp_sent_message_total", "Number of sent BGP messages from peer", peerLabels, nil)

	bgpPeerStateDesc = prometheus.NewDesc("bgp_peer_state", "State of the BGP session with peer", peerStateLabels, nil)

	bgpRoutesReceivedDesc = prometheus.NewDesc(
		"bgp_routes_received",
		"Number of routes received from peer",
		rfLabels, nil,
	)
	bgpRoutesAcceptedDesc = prometheus.NewDesc(
		"bgp_routes_accepted",
		"Number of routes accepted from peer",
		rfLabels, nil,
	)
	bgpRoutesAdvertisedDesc = prometheus.NewDesc(
		"bgp_routes_advertised",
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
		msg := peerState.GetMessages()

		send := func(desc *prometheus.Desc, cnt uint64) {
			out <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(cnt), peerAddr)
		}

		send(bgpReceivedUpdateTotalDesc, msg.Received.Update)
		send(bgpReceivedNotificationTotalDesc, msg.Received.Notification)
		send(bgpReceivedOpenTotalDesc, msg.Received.Open)
		send(bgpReceivedRefreshTotalDesc, msg.Received.Refresh)
		send(bgpReceivedKeepaliveTotalDesc, msg.Received.Keepalive)
		send(bgpReceivedWithdrawUpdateTotalDesc, uint64(msg.Received.WithdrawUpdate))
		send(bgpReceivedWithdrawPrefixTotalDesc, uint64(msg.Received.WithdrawPrefix))
		send(bgpReceivedDiscardedTotalDesc, msg.Received.Discarded)
		send(bgpReceivedMessageTotalDesc, msg.Received.Total)

		send(bgpSentUpdateTotalDesc, msg.Sent.Update)
		send(bgpSentNotificationTotalDesc, msg.Sent.Notification)
		send(bgpSentOpenTotalDesc, msg.Sent.Open)
		send(bgpSentRefreshTotalDesc, msg.Sent.Refresh)
		send(bgpSentKeepaliveTotalDesc, msg.Sent.Keepalive)
		send(bgpSentWithdrawUpdateTotalDesc, uint64(msg.Sent.WithdrawUpdate))
		send(bgpSentWithdrawPrefixTotalDesc, uint64(msg.Sent.WithdrawPrefix))
		send(bgpSentDiscardedTotalDesc, msg.Sent.Discarded)
		send(bgpSentMessageTotalDesc, msg.Sent.Total)

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
