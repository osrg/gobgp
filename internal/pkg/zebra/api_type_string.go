// Code generated by "stringer -type=API_TYPE"; DO NOT EDIT.

package zebra

import "strconv"

const _API_TYPE_name = "FRR_ZAPI5_INTERFACE_ADDFRR_ZAPI5_INTERFACE_DELETEFRR_ZAPI5_INTERFACE_ADDRESS_ADDFRR_ZAPI5_INTERFACE_ADDRESS_DELETEFRR_ZAPI5_INTERFACE_UPFRR_ZAPI5_INTERFACE_DOWNFRR_ZAPI5_INTERFACE_SET_MASTERFRR_ZAPI5_ROUTE_ADDFRR_ZAPI5_ROUTE_DELETEFRR_ZAPI5_ROUTE_NOTIFY_OWNERFRR_ZAPI5_IPV4_ROUTE_ADDFRR_ZAPI5_IPV4_ROUTE_DELETEFRR_ZAPI5_IPV6_ROUTE_ADDFRR_ZAPI5_IPV6_ROUTE_DELETEFRR_ZAPI5_REDISTRIBUTE_ADDFRR_ZAPI5_REDISTRIBUTE_DELETEFRR_ZAPI5_REDISTRIBUTE_DEFAULT_ADDFRR_ZAPI5_REDISTRIBUTE_DEFAULT_DELETEFRR_ZAPI5_ROUTER_ID_ADDFRR_ZAPI5_ROUTER_ID_DELETEFRR_ZAPI5_ROUTER_ID_UPDATEFRR_ZAPI5_HELLOFRR_ZAPI5_CAPABILITIESFRR_ZAPI5_NEXTHOP_REGISTERFRR_ZAPI5_NEXTHOP_UNREGISTERFRR_ZAPI5_NEXTHOP_UPDATEFRR_ZAPI5_INTERFACE_NBR_ADDRESS_ADDFRR_ZAPI5_INTERFACE_NBR_ADDRESS_DELETEFRR_ZAPI5_INTERFACE_BFD_DEST_UPDATEFRR_ZAPI5_IMPORT_ROUTE_REGISTERFRR_ZAPI5_IMPORT_ROUTE_UNREGISTERFRR_ZAPI5_IMPORT_CHECK_UPDATEFRR_ZAPI5_IPV4_ROUTE_IPV6_NEXTHOP_ADDFRR_ZAPI5_BFD_DEST_REGISTERFRR_ZAPI5_BFD_DEST_DEREGISTERFRR_ZAPI5_BFD_DEST_UPDATEFRR_ZAPI5_BFD_DEST_REPLAYFRR_ZAPI5_REDISTRIBUTE_ROUTE_ADDFRR_ZAPI5_REDISTRIBUTE_ROUTE_DELFRR_ZAPI5_VRF_UNREGISTERFRR_ZAPI5_VRF_ADDFRR_ZAPI5_VRF_DELETEFRR_ZAPI5_VRF_LABELFRR_ZAPI5_INTERFACE_VRF_UPDATEFRR_ZAPI5_BFD_CLIENT_REGISTERFRR_ZAPI5_INTERFACE_ENABLE_RADVFRR_ZAPI5_INTERFACE_DISABLE_RADVFRR_ZAPI5_IPV4_NEXTHOP_LOOKUP_MRIBFRR_ZAPI5_INTERFACE_LINK_PARAMSFRR_ZAPI5_MPLS_LABELS_ADDFRR_ZAPI5_MPLS_LABELS_DELETEFRR_ZAPI5_IPMR_ROUTE_STATSFRR_ZAPI5_LABEL_MANAGER_CONNECTFRR_ZAPI5_GET_LABEL_CHUNKFRR_ZAPI5_RELEASE_LABEL_CHUNKFRR_ZAPI5_FEC_REGISTERFRR_ZAPI5_FEC_UNREGISTERFRR_ZAPI5_FEC_UPDATEFRR_ZAPI5_ADVERTISE_DEFAULT_GWFRR_ZAPI5_ADVERTISE_SUBNETFRR_ZAPI5_ADVERTISE_ALL_VNIFRR_ZAPI5_VNI_ADDFRR_ZAPI5_VNI_DELFRR_ZAPI5_L3VNI_ADDFRR_ZAPI5_L3VNI_DELFRR_ZAPI5_REMOTE_VTEP_ADDFRR_ZAPI5_REMOTE_VTEP_DELFRR_ZAPI5_MACIP_ADDFRR_ZAPI5_MACIP_DELFRR_ZAPI5_IP_PREFIX_ROUTE_ADDFRR_ZAPI5_IP_PREFIX_ROUTE_DELFRR_ZAPI5_REMOTE_MACIP_ADDFRR_ZAPI5_REMOTE_MACIP_DELFRR_ZAPI5_PW_ADDFRR_ZAPI5_PW_DELETEFRR_ZAPI5_PW_SETFRR_ZAPI5_PW_UNSETFRR_ZAPI5_PW_STATUS_UPDATEFRR_ZAPI5_RULE_ADDFRR_ZAPI5_RULE_DELETEFRR_ZAPI5_RULE_NOTIFY_OWNERFRR_ZAPI5_TABLE_MANAGER_CONNECTFRR_ZAPI5_GET_TABLE_CHUNKFRR_ZAPI5_RELEASE_TABLE_CHUNKFRR_ZAPI5_IPSET_CREATEFRR_ZAPI5_IPSET_DESTROYFRR_ZAPI5_IPSET_ENTRY_ADDFRR_ZAPI5_IPSET_ENTRY_DELETEFRR_ZAPI5_IPSET_NOTIFY_OWNERFRR_ZAPI5_IPSET_ENTRY_NOTIFY_OWNERFRR_ZAPI5_IPTABLE_ADDFRR_ZAPI5_IPTABLE_DELETEFRR_ZAPI5_IPTABLE_NOTIFY_OWNER"

var _API_TYPE_index = [...]uint16{0, 23, 49, 80, 114, 136, 160, 190, 209, 231, 259, 283, 310, 334, 361, 387, 416, 450, 487, 510, 536, 562, 577, 599, 625, 653, 677, 712, 750, 785, 816, 849, 878, 915, 942, 971, 996, 1021, 1053, 1085, 1109, 1126, 1146, 1165, 1195, 1224, 1255, 1287, 1321, 1352, 1377, 1405, 1431, 1462, 1487, 1516, 1538, 1562, 1582, 1612, 1638, 1665, 1682, 1699, 1718, 1737, 1762, 1787, 1806, 1825, 1854, 1883, 1909, 1935, 1951, 1970, 1986, 2004, 2030, 2048, 2069, 2096, 2127, 2152, 2181, 2203, 2226, 2251, 2279, 2307, 2341, 2362, 2386, 2416}

func (i API_TYPE) String() string {
	if i >= API_TYPE(len(_API_TYPE_index)-1) {
		return "API_TYPE(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _API_TYPE_name[_API_TYPE_index[i]:_API_TYPE_index[i+1]]
}
