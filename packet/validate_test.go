package bgp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func update1() *BGPMessage {
	aspath := []AsPathParamInterface{
		NewAsPathParam(2, []uint16{65001}),
	}

	p := []PathAttributeInterface{
		NewPathAttributeOrigin(1),
		NewPathAttributeAsPath(aspath),
		NewPathAttributeNextHop("192.168.1.1"),
	}

	n := []NLRInfo{*NewNLRInfo(24, "10.10.10.0")}
	return NewBGPUpdateMessage(nil, p, n)
}

func Test_Validate_OK(t *testing.T) {
	message := update1().Body.(*BGPUpdate)
	res, err := ValidateUpdateMsg(message)
	assert.Equal(t, true, res)
	assert.NoError(t, err)

}
