// Code generated by "stringer -type=LSP_TYPE"; DO NOT EDIT.

package zebra

import "strconv"

const _LSP_TYPE_name = "FRR5_LSP_NONEFRR5_LSP_STATICFRR5_LSP_LDPFRR5_LSP_BGPFRR5_LSP_SRFRR5_LSP_SHARP"

var _LSP_TYPE_index = [...]uint8{0, 13, 28, 40, 52, 63, 77}

func (i LSP_TYPE) String() string {
	if i >= LSP_TYPE(len(_LSP_TYPE_index)-1) {
		return "LSP_TYPE(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _LSP_TYPE_name[_LSP_TYPE_index[i]:_LSP_TYPE_index[i+1]]
}