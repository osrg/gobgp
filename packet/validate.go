package bgp

import (
	"strconv"
)

// validator for PathAttribute
func ValidateFlags(t BGPAttrType, flags uint8) (bool, string) {

	/*
	 * RFC 4271 P.17 For well-known attributes, the Transitive bit MUST be set to 1.
	 */
	if flags&BGP_ATTR_FLAG_OPTIONAL == 0 && flags&BGP_ATTR_FLAG_TRANSITIVE == 0 {
		eMsg := "well-known attribute must have transitive flag 1"
		return false, eMsg
	}
	/*
	 * RFC 4271 P.17 For well-known attributes and for optional non-transitive attributes,
	 * the Partial bit MUST be set to 0.
	 */
	if flags&BGP_ATTR_FLAG_OPTIONAL == 0 && flags&BGP_ATTR_FLAG_PARTIAL != 0 {
		eMsg := "well-known attribute must have partial bit 0"
		return false, eMsg
	}
	if flags&BGP_ATTR_FLAG_OPTIONAL != 0 && flags&BGP_ATTR_FLAG_TRANSITIVE == 0 && flags&BGP_ATTR_FLAG_PARTIAL != 0 {
		eMsg := "optional non-transitive attribute must have partial bit 0"
		return false, eMsg
	}

	// check flags are correct

	if f, ok := pathAttrFlags[t]; ok {
		if f != flags {
			eMsg := "flags are invalid. attribtue type : " + strconv.Itoa(int(t))
			return false, eMsg
		}
	}
	return true, ""
}
