package peering

import (
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
)

func (c *FSMCommon) bgpMessageStateUpdate(MessageType uint8, isIn bool) {
	c.Lock.Lock()
	defer c.Lock.Unlock()
	state := &c.PeerConf.State.Messages
	timer := &c.PeerConf.Timers
	if isIn {
		state.Received.Total++
	} else {
		state.Sent.Total++
	}
	switch MessageType {
	case bgp.BGP_MSG_OPEN:
		if isIn {
			state.Received.Open++
		} else {
			state.Sent.Open++
		}
	case bgp.BGP_MSG_UPDATE:
		if isIn {
			state.Received.Update++
			timer.State.UpdateRecvTime = time.Now().Unix()
		} else {
			state.Sent.Update++
		}
	case bgp.BGP_MSG_NOTIFICATION:
		if isIn {
			state.Received.Notification++
		} else {
			state.Sent.Notification++
		}
	case bgp.BGP_MSG_KEEPALIVE:
		if isIn {
			state.Received.Keepalive++
		} else {
			state.Sent.Keepalive++
		}
	case bgp.BGP_MSG_ROUTE_REFRESH:
		if isIn {
			state.Received.Refresh++
		} else {
			state.Sent.Refresh++
		}
	default:
		if isIn {
			state.Received.Discarded++
		} else {
			state.Sent.Discarded++
		}
	}
}

func (c *FSMCommon) bmpStatsUpdate(statType uint16, increment int) {
	c.Lock.Lock()
	defer c.Lock.Unlock()
	stats := &c.PeerConf.State.Messages.Received
	switch statType {
	// TODO
	// Support other stat types.
	case bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE:
		stats.WithdrawUpdate += uint32(increment)
	case bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX:
		stats.WithdrawPrefix += uint32(increment)
	}
}
