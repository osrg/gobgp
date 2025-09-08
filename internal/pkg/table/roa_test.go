package table

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

func strToASParam(str string) *bgp.PathAttributeAsPath {
	toList := func(asstr, sep string) []uint32 {
		as := make([]uint32, 0)
		l := strings.Split(asstr, sep)
		for _, s := range l {
			v, _ := strconv.ParseUint(s, 10, 32)
			as = append(as, uint32(v))
		}
		return as
	}
	var atype uint8
	var as []uint32
	if strings.HasPrefix(str, "{") {
		atype = bgp.BGP_ASPATH_ATTR_TYPE_SET
		as = toList(str[1:len(str)-1], ",")
	} else if strings.HasPrefix(str, "(") {
		atype = bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET
		as = toList(str[1:len(str)-1], " ")
	} else {
		atype = bgp.BGP_ASPATH_ATTR_TYPE_SEQ
		as = toList(str, " ")
	}

	return bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(atype, as)})
}

func validateOne(rt *ROATable, cidr, aspathStr string) oc.RpkiValidationResultType {
	ip, r, _ := net.ParseCIDR(cidr)
	length, _ := r.Mask.Size()
	var family bgp.Family
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(fmt.Sprintf("%s/%d", ip.String(), length)))
	if ip.To4() == nil {
		family = bgp.RF_IPv6_UC
	} else {
		family = bgp.RF_IPv4_UC
	}
	attrs := []bgp.PathAttributeInterface{strToASParam(aspathStr)}
	path := NewPath(family, &PeerInfo{LocalAS: 65500}, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
	ret := rt.Validate(path)
	return ret.Status
}

func TestValidate0(t *testing.T) {
	assert := assert.New(t)

	table := NewROATable(logger)
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("192.168.0.0").To4(), 24, 32, 100, ""))
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("192.168.0.0").To4(), 24, 24, 200, ""))

	r := validateOne(table, "192.168.0.0/24", "100")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)

	r = validateOne(table, "192.168.0.0/24", "100 200")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)

	r = validateOne(table, "192.168.0.0/24", "300")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)

	r = validateOne(table, "192.168.0.0/25", "100")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)

	r = validateOne(table, "192.168.0.0/25", "200")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)

	r = validateOne(table, "192.168.0.0/25", "300")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)
}

func TestValidate1(t *testing.T) {
	assert := assert.New(t)

	table := NewROATable(logger)
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 16, 16, 65000, ""))

	r := validateOne(table, "10.0.0.0/16", "65000")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)

	r = validateOne(table, "10.0.0.0/16", "65001")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)
}

func TestValidate2(t *testing.T) {
	assert := assert.New(t)

	table := NewROATable(logger)

	var r oc.RpkiValidationResultType

	r = validateOne(table, "10.0.0.0/16", "65000")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)

	r = validateOne(table, "10.0.0.0/16", "65001")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)
}

func TestValidate3(t *testing.T) {
	assert := assert.New(t)

	table := NewROATable(logger)
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 16, 16, 65000, ""))

	r := validateOne(table, "10.0.0.0/8", "65000")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)

	r = validateOne(table, "10.0.0.0/17", "65000")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)

	table = NewROATable(logger)
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 16, 24, 65000, ""))

	r = validateOne(table, "10.0.0.0/17", "65000")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)
}

func TestValidate4(t *testing.T) {
	assert := assert.New(t)

	table := NewROATable(logger)
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 16, 16, 65000, ""))
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 16, 16, 65001, ""))

	r := validateOne(table, "10.0.0.0/16", "65000")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)

	r = validateOne(table, "10.0.0.0/16", "65001")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)
}

func TestValidate5(t *testing.T) {
	assert := assert.New(t)

	table := NewROATable(logger)
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 17, 17, 65000, ""))
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("10.0.128.0").To4(), 17, 17, 65000, ""))

	r := validateOne(table, "10.0.0.0/16", "65000")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)
}

func TestValidate6(t *testing.T) {
	assert := assert.New(t)

	table := NewROATable(logger)
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 8, 32, 0, ""))

	r := validateOne(table, "10.0.0.0/7", "65000")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)

	r = validateOne(table, "10.0.0.0/8", "65000")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)

	r = validateOne(table, "10.0.0.0/24", "65000")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)
}

func TestValidate7(t *testing.T) {
	assert := assert.New(t)

	table := NewROATable(logger)
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 16, 24, 65000, ""))

	r := validateOne(table, "10.0.0.0/24", "{65000}")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)

	r = validateOne(table, "10.0.0.0/24", "{65001}")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)

	r = validateOne(table, "10.0.0.0/24", "{65000,65001}")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)
}

func TestValidate8(t *testing.T) {
	assert := assert.New(t)

	table := NewROATable(logger)
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 16, 24, 0, ""))
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 16, 24, 65000, ""))

	r := validateOne(table, "10.0.0.0/24", "65000")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)

	r = validateOne(table, "10.0.0.0/24", "65001")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)
}

func TestValidate9(t *testing.T) {
	assert := assert.New(t)

	table := NewROATable(logger)
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 24, 24, 65000, ""))
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 16, 24, 65001, ""))

	r := validateOne(table, "10.0.0.0/24", "65000")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)

	r = validateOne(table, "10.0.0.0/24", "65001")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)
}

func TestValidate10(t *testing.T) {
	assert := assert.New(t)

	table := NewROATable(logger)
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 24, 24, 0, ""))
	table.Add(NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 16, 24, 65001, ""))

	r := validateOne(table, "10.0.0.0/24", "65000")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_INVALID)

	r = validateOne(table, "10.0.0.0/24", "65001")
	assert.Equal(r, oc.RPKI_VALIDATION_RESULT_TYPE_VALID)
}
