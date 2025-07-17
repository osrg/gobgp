package peering

import (
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
)

func NewPeerGroup(c *oc.PeerGroup) *PeerGroup {
	return &PeerGroup{
		Conf:             c,
		Members:          make(map[string]oc.Neighbor),
		DynamicNeighbors: make(map[string]*oc.DynamicNeighbor),
	}
}

func (pg *PeerGroup) AddMember(c oc.Neighbor) {
	pg.Members[c.State.NeighborAddress] = c
}

func (pg *PeerGroup) DeleteMember(c oc.Neighbor) {
	delete(pg.Members, c.State.NeighborAddress)
}

func (pg *PeerGroup) AddDynamicNeighbor(c *oc.DynamicNeighbor) {
	pg.DynamicNeighbors[c.Config.Prefix] = c
}

func (pg *PeerGroup) DeleteDynamicNeighbor(prefix string) {
	delete(pg.DynamicNeighbors, prefix)
}

func NewDynamicPeer(g *oc.Global, neighborAddress string, pg *oc.PeerGroup, loc *table.TableManager, policy *table.RoutingPolicy, logger log.Logger) *Peer {
	conf := oc.Neighbor{
		Config: oc.NeighborConfig{
			PeerGroup: pg.Config.PeerGroupName,
		},
		State: oc.NeighborState{
			NeighborAddress: neighborAddress,
		},
		Transport: oc.Transport{
			Config: oc.TransportConfig{
				PassiveMode: true,
			},
		},
	}
	if err := oc.OverwriteNeighborConfigWithPeerGroup(&conf, pg); err != nil {
		logger.Debug("Can't overwrite neighbor config",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"Error": err,
			})
		return nil
	}
	if err := oc.SetDefaultNeighborConfigValues(&conf, pg, g); err != nil {
		logger.Debug("Can't set default config",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"Error": err,
			})
		return nil
	}
	return NewPeer(g, &conf, loc, policy, logger)
}
