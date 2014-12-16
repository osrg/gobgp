// core.go
package table

import (
	"github.com/osrg/gobgp/packet"
	"net"
)

type Peer struct {
	//need to define a structure
	RemoteAs      uint32
	VersionNum    int
	RemoteAddress net.IP
	protocol      *BgpProtocol
}

type BgpProtocol struct {
	//need to define a structure
	recvOpenMsg *bgp.BGPOpen
	sentOpenMsg *bgp.BGPOpen
}
