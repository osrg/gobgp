package server

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/osrg/gobgp/v3/internal/pkg/config"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

type peerMetricsCollector struct {
	server *BgpServer
	peer   *peer
}

var _ prometheus.Collector = &peerMetricsCollector{}

var (
	bgpReceivedUpdateTotalDesc         = prometheus.NewDesc("bgp_received_update_total", "Number of received BGP UPDATE messages from peer", nil, nil)
	bgpReceivedNotificationTotalDesc   = prometheus.NewDesc("bgp_received_notification_total", "Number of received BGP NOTIFICATION messages from peer", nil, nil)
	bgpReceivedOpenTotalDesc           = prometheus.NewDesc("bgp_received_open_total", "Number of received BGP OPEN messages from peer", nil, nil)
	bgpReceivedRefreshTotalDesc        = prometheus.NewDesc("bgp_received_refresh_total", "Number of received BGP REFRESH messages from peer", nil, nil)
	bgpReceivedKeepaliveTotalDesc      = prometheus.NewDesc("bgp_received_keepalive_total", "Number of received BGP KEEPALIVE messages from peer", nil, nil)
	bgpReceivedDynamicCapTotalDesc     = prometheus.NewDesc("bgp_received_dynamic_cap_total", "Number of received BGP DYNAMIC-CAP messages from peer", nil, nil)
	bgpReceivedWithdrawUpdateTotalDesc = prometheus.NewDesc("bgp_received_withdraw_update_total", "Number of received BGP WITHDRAW-UPDATE messages from peer", nil, nil)
	bgpReceivedWithdrawPrefixTotalDesc = prometheus.NewDesc("bgp_received_withdraw_prefix_total", "Number of received BGP WITHDRAW-PREFIX messages from peer", nil, nil)
	bgpReceivedDiscardedTotalDesc      = prometheus.NewDesc("bgp_received_discarded_total", "Number of discarded BGP messages from peer", nil, nil)
	bgpReceivedMessageTotalDesc        = prometheus.NewDesc("bgp_received_message_total", "Number of received BGP messages from peer", nil, nil)

	bgpSentUpdateTotalDesc         = prometheus.NewDesc("bgp_sent_update_total", "Number of sent BGP UPDATE messages from peer", nil, nil)
	bgpSentNotificationTotalDesc   = prometheus.NewDesc("bgp_sent_notification_total", "Number of sent BGP NOTIFICATION messages from peer", nil, nil)
	bgpSentOpenTotalDesc           = prometheus.NewDesc("bgp_sent_open_total", "Number of sent BGP OPEN messages from peer", nil, nil)
	bgpSentRefreshTotalDesc        = prometheus.NewDesc("bgp_sent_refresh_total", "Number of sent BGP REFRESH messages from peer", nil, nil)
	bgpSentKeepaliveTotalDesc      = prometheus.NewDesc("bgp_sent_keepalive_total", "Number of sent BGP KEEPALIVE messages from peer", nil, nil)
	bgpSentDynamicCapTotalDesc     = prometheus.NewDesc("bgp_sent_dynamic_cap_total", "Number of sent BGP DYNAMIC-CAP messages from peer", nil, nil)
	bgpSentWithdrawUpdateTotalDesc = prometheus.NewDesc("bgp_sent_withdraw_update_total", "Number of sent BGP WITHDRAW-UPDATE messages from peer", nil, nil)
	bgpSentWithdrawPrefixTotalDesc = prometheus.NewDesc("bgp_sent_withdraw_prefix_total", "Number of sent BGP WITHDRAW-PREFIX messages from peer", nil, nil)
	bgpSentDiscardedTotalDesc      = prometheus.NewDesc("bgp_sent_discarded_total", "Number of discarded BGP messages from peer", nil, nil)
	bgpSentMessageTotalDesc        = prometheus.NewDesc("bgp_sent_message_total", "Number of sent BGP messages from peer", nil, nil)

	bgpRoutesReceivedDesc = prometheus.NewDesc(
		"bgp_routes_received",
		"Number of routes received from peer",
		[]string{"route_family"}, nil,
	)
	bgpRoutesAcceptedDesc = prometheus.NewDesc(
		"bgp_routes_accepted",
		"Number of routes accepted from peer",
		[]string{"route_family"}, nil,
	)
)

func (m *peerMetricsCollector) Describe(out chan<- *prometheus.Desc) {
	out <- bgpReceivedUpdateTotalDesc
	out <- bgpReceivedNotificationTotalDesc
	out <- bgpReceivedOpenTotalDesc
	out <- bgpReceivedRefreshTotalDesc
	out <- bgpReceivedKeepaliveTotalDesc
	out <- bgpReceivedDynamicCapTotalDesc
	out <- bgpReceivedWithdrawUpdateTotalDesc
	out <- bgpReceivedWithdrawPrefixTotalDesc
	out <- bgpReceivedDiscardedTotalDesc
	out <- bgpReceivedMessageTotalDesc

	out <- bgpSentUpdateTotalDesc
	out <- bgpSentNotificationTotalDesc
	out <- bgpSentOpenTotalDesc
	out <- bgpSentRefreshTotalDesc
	out <- bgpSentKeepaliveTotalDesc
	out <- bgpSentDynamicCapTotalDesc
	out <- bgpSentWithdrawUpdateTotalDesc
	out <- bgpSentWithdrawPrefixTotalDesc
	out <- bgpSentDiscardedTotalDesc
	out <- bgpSentMessageTotalDesc

	out <- bgpRoutesReceivedDesc
	out <- bgpRoutesAcceptedDesc
}

func (m *peerMetricsCollector) Collect(out chan<- prometheus.Metric) {
	var msg config.Messages
	type familyCnt struct {
		received, accepted int
	}
	routeCnt := make(map[bgp.RouteFamily]familyCnt)

	m.server.mgmtOperation(func() error {
		msg = m.collectMessageCounters()

		for _, family := range m.peer.configuredRFlist() {
			flist := []bgp.RouteFamily{family}
			routeCnt[family] = familyCnt{
				received: m.peer.adjRibIn.Count(flist),
				accepted: m.peer.adjRibIn.Accepted(flist),
			}
		}
		return nil
	}, false)

	send := func(desc *prometheus.Desc, cnt uint64) {
		out <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(cnt))
	}

	send(bgpReceivedUpdateTotalDesc, msg.Received.Update)
	send(bgpReceivedNotificationTotalDesc, msg.Received.Notification)
	send(bgpReceivedOpenTotalDesc, msg.Received.Open)
	send(bgpReceivedRefreshTotalDesc, msg.Received.Refresh)
	send(bgpReceivedKeepaliveTotalDesc, msg.Received.Keepalive)
	send(bgpReceivedDynamicCapTotalDesc, msg.Received.DynamicCap)
	send(bgpReceivedWithdrawUpdateTotalDesc, uint64(msg.Received.WithdrawUpdate))
	send(bgpReceivedWithdrawPrefixTotalDesc, uint64(msg.Received.WithdrawPrefix))
	send(bgpReceivedDiscardedTotalDesc, msg.Received.Discarded)
	send(bgpReceivedMessageTotalDesc, msg.Received.Total)

	send(bgpSentUpdateTotalDesc, msg.Sent.Update)
	send(bgpSentNotificationTotalDesc, msg.Sent.Notification)
	send(bgpSentOpenTotalDesc, msg.Sent.Open)
	send(bgpSentRefreshTotalDesc, msg.Sent.Refresh)
	send(bgpSentKeepaliveTotalDesc, msg.Sent.Keepalive)
	send(bgpSentDynamicCapTotalDesc, msg.Sent.DynamicCap)
	send(bgpSentWithdrawUpdateTotalDesc, uint64(msg.Sent.WithdrawUpdate))
	send(bgpSentWithdrawPrefixTotalDesc, uint64(msg.Sent.WithdrawPrefix))
	send(bgpSentDiscardedTotalDesc, msg.Sent.Discarded)
	send(bgpSentMessageTotalDesc, msg.Sent.Total)

	for family, cnt := range routeCnt {
		out <- prometheus.MustNewConstMetric(
			bgpRoutesReceivedDesc,
			prometheus.GaugeValue,
			float64(cnt.received),
			family.String(),
		)
		out <- prometheus.MustNewConstMetric(
			bgpRoutesAcceptedDesc,
			prometheus.GaugeValue,
			float64(cnt.accepted),
			family.String(),
		)
	}
}

func (m *peerMetricsCollector) collectMessageCounters() config.Messages {
	m.peer.fsm.lock.RLock()
	defer m.peer.fsm.lock.RUnlock()

	return m.peer.fsm.pConf.State.Messages
}
