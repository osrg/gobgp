// Code generated by "stringer -type=NEXTHOP_TYPE"; DO NOT EDIT.

package zebra

import "strconv"

const _NEXTHOP_TYPE_name = "NEXTHOP_IFINDEXNEXTHOP_IFNAMENEXTHOP_IPV4NEXTHOP_IPV4_IFINDEXNEXTHOP_IPV4_IFNAMENEXTHOP_IPV6NEXTHOP_IPV6_IFINDEXNEXTHOP_IPV6_IFNAMENEXTHOP_BLACKHOLE"

var _NEXTHOP_TYPE_index = [...]uint8{0, 15, 29, 41, 61, 80, 92, 112, 131, 148}

func (i NEXTHOP_TYPE) String() string {
	i -= 1
	if i >= NEXTHOP_TYPE(len(_NEXTHOP_TYPE_index)-1) {
		return "NEXTHOP_TYPE(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _NEXTHOP_TYPE_name[_NEXTHOP_TYPE_index[i]:_NEXTHOP_TYPE_index[i+1]]
}
