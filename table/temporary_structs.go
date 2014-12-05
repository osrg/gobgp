// core.go
package table

import (
	"github.com/osrg/gobgp/packet"
	"net"
)

type CoreService struct {
	CommonConf    *Commons
	NeighborsConf *Neighbors
}
type Neighbors struct {
	//need to define a structure
}
type Commons struct {
	//need to define a structure
}
type Peer struct {
	//need to define a structure
	RemoteAs      uint32
	VersionNum    int
	RemoteAddress net.IP
	protocol      *BgpProtocol
}
type SentRoute struct {
	path Path
	peer *Peer
}
type BgpProtocol struct {
	//need to define a structure
	recvOpenMsg *bgp.BGPOpen
	sentOpenMsg *bgp.BGPOpen
}
