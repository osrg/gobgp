// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import "net"
import "time"

// typedef for typedef bgp:peer-type
type PeerTypeDef int

const (
	PEER_TYPE_INTERNAL = iota
	PEER_TYPE_EXTERNAL
)

// typedef for typedef bgp:rr-cluster-id-type
type RrClusterIdType string

// typedef for typedef bgp:percentage
type Percentage uint8

// typedef for typedef bgp:remove-private-as-option
type RemovePrivateAsOption int

const (
	REMOVE_PRIVATE_AS_OPTION_ALL = iota
	REMOVE_PRIVATE_AS_OPTION_REPLACE
)

// typedef for typedef bgp-policy:bgp-next-hop-type
type BgpNextHopType string

// typedef for typedef bgp-policy:as-path-prepend-option-repeat
type AsPathPrependOptionRepeat uint32

// typedef for typedef bgp-policy:std-community-attr-type
type StdCommunityAttrType string

// typedef for typedef bgp-policy:match-set-options-type
type MatchSetOptionsType int

const (
	MATCH_SET_OPTIONS_TYPE_ANY = iota
	MATCH_SET_OPTIONS_TYPE_ALL
	MATCH_SET_OPTIONS_TYPE_INVERT
)

// typedef for typedef bgp-policy:set-community-option-type
type SetCommunityOptionType int

const (
	SET_COMMUNITY_OPTION_TYPE_ADD = iota
	SET_COMMUNITY_OPTION_TYPE_REMOVE
	SET_COMMUNITY_OPTION_TYPE_REPLACE
	SET_COMMUNITY_OPTION_TYPE_NULL
)

// typedef for typedef bgp-policy:community-regexp-type
type CommunityRegexpType string

// typedef for typedef bgp-policy:ext-community-attr-type
type ExtCommunityAttrType string

// typedef for typedef bgp-policy:bgp-origin-attr-type
type BgpOriginAttrType int

const (
	BGP_ORIGIN_ATTR_TYPE_IGP        = 0
	BGP_ORIGIN_ATTR_TYPE_EGP        = 1
	BGP_ORIGIN_ATTR_TYPE_INCOMPLETE = 2
)

// typedef for typedef bgp-policy:well-known-community-attr
type WellKnownCommunityAttr int

const (
	WELL_KNOWN_COMMUNITY_ATTR_INTERNET = iota
	WELL_KNOWN_COMMUNITY_ATTR_NO_EXPORT
	WELL_KNOWN_COMMUNITY_ATTR_NO_ADVERTISE
	WELL_KNOWN_COMMUNITY_ATTR_NO_EXPORT_SUBCONFED
)

// typedef for identity bgp-policy:attribute-le
type AttributeLe struct {
	// base_type -> bgp-attribute-comparison
	BgpAttributeComparison
}

// typedef for identity bgp-policy:attribute-ge
type AttributeGe struct {
	// base_type -> bgp-attribute-comparison
	BgpAttributeComparison
}

// typedef for identity bgp-policy:attribute-eq
type AttributeEq struct {
	// base_type -> bgp-attribute-comparison
	BgpAttributeComparison
}

// typedef for identity bgp-policy:bgp-attribute-comparison
type BgpAttributeComparison struct {
}

// typedef for identity bgp-mp:multicast-vpn-safi
type MulticastVpnSafi struct {
	// base_type -> safi-type
	SafiTypeDef
}

// typedef for identity bgp-mp:ipv4-afi
type Ipv4Afi struct {
	// base_type -> bgp-mp:afi-type
	AfiTypeDef
}

// typedef for identity bgp-mp:safi-type
type SafiTypeDef struct {
}

// typedef for identity bgp-mp:multicast-safi
type MulticastSafi struct {
	// base_type -> safi-type
	SafiTypeDef
}

// typedef for identity bgp-mp:l3vpn-unicast-safi
type L3vpnUnicastSafi struct {
	// base_type -> safi-type
	SafiTypeDef
}

// typedef for identity bgp-mp:labeled-unicast-safi
type LabeledUnicastSafi struct {
	// base_type -> safi-type
	SafiTypeDef
}

// typedef for identity bgp-mp:afi-type
type AfiTypeDef struct {
}

// typedef for identity bgp-mp:ipv6-afi
type Ipv6Afi struct {
	// base_type -> bgp-mp:afi-type
	AfiTypeDef
}

// typedef for identity bgp-mp:l2vpn-vpls-afi
type L2vpnVplsAfi struct {
	// base_type -> afi-type
	AfiTypeDef
}

// typedef for identity bgp-mp:unicast-safi
type UnicastSafi struct {
	// base_type -> bgp-mp:safi-type
	SafiTypeDef
}

// typedef for identity bgp-mp:l2vpn-vpls-safi
type L2vpnVplsSafi struct {
	// base_type -> safi-type
	SafiTypeDef
}

//struct for container set-ext-community
type SetExtCommunityType struct {
	// original -> bgp-policy:communities
	//original type is list of union
	Communities []string
	// original -> bgp-policy:options
	Options SetCommunityOptionType
}

//struct for container set-community
type SetCommunityType struct {
	// original -> bgp-policy:communities
	//original type is list of union
	Communities []string
	// original -> bgp-policy:options
	Options SetCommunityOptionType
}

//struct for container set-as-path-prepend
type SetAsPathPrependType struct {
	// original -> bgp-policy:repeat-n
	RepeatN uint8
}

//struct for container actions
type ActionsType struct {
	// original -> bgp-policy:set-as-path-prepend
	SetAsPathPrepend SetAsPathPrependType
	// original -> bgp-policy:set-community
	SetCommunity SetCommunityType
	// original -> bgp-policy:set-ext-community
	SetExtCommunity SetExtCommunityType
	// original -> bgp-policy:set-route-origin
	SetRouteOrigin BgpOriginAttrType
	// original -> bgp-policy:set-local-pref
	SetLocalPref uint32
	// original -> bgp-policy:set-next-hop
	SetNextHop BgpNextHopType
	// original -> bgp-policy:set-med
	SetMed uint32
	// original -> bgp-policy:accept-route
	//accept-route's original type is empty
	AcceptRoute bool
	// original -> bgp-policy:reject-route
	//reject-route's original type is empty
	RejectRoute bool
	// original -> bgp-policy:goto-next
	//goto-next's original type is empty
	GotoNext bool
	// original -> bgp-policy:goto-policy
	GotoPolicy string
}

//struct for container as-path-length
type AsPathLengthType struct {
	// original -> bgp-policy:operator
	Operator BgpAttributeComparison
	// original -> bgp-policy:value
	Value uint32
}

//struct for container community-count
type CommunityCountType struct {
	// original -> bgp-policy:operator
	Operator BgpAttributeComparison
	// original -> bgp-policy:value
	Value uint32
}

//struct for container conditions
type ConditionsType struct {
	// original -> bgp-policy:call-policy
	CallPolicy string
	// original -> bgp-policy:match-community-set
	MatchCommunitySet string
	// original -> bgp-policy:match-ext-community-set
	MatchExtCommunitySet string
	// original -> bgp-policy:match-as-path-set
	MatchAsPathSet string
	// original -> bgp-policy:match-prefix-set
	MatchPrefixSet string
	// original -> bgp-policy:match-set-options
	MatchSetOptions MatchSetOptionsType
	// original -> bgp-policy:med-eq
	MedEq uint32
	// original -> bgp-policy:origin-eq
	OriginEq BgpOriginAttrType
	// original -> bgp-policy:next-hop-in
	//original type is list of inet:ip-address
	NextHopIn []net.IP
	// original -> bgp-policy:local-pref-eq
	LocalPrefEq uint32
	// original -> bgp-policy:community-count
	CommunityCount CommunityCountType
	// original -> bgp-policy:as-path-length
	AsPathLength AsPathLengthType
	// original -> bgp-policy:route-type
	//route-type's original type is enumeration
	RouteType string
}

//struct for container statements
type StatementsType struct {
	// original -> bgp-policy:name
	Name string
	// original -> bgp-policy:conditions
	Conditions ConditionsType
	// original -> bgp-policy:actions
	Actions ActionsType
}

//struct for container policy-definition
type PolicyDefinitionType struct {
	// original -> bgp-policy:name
	Name string
	// original -> bgp-policy:statements
	StatementsList []StatementsType
}

//struct for container policy-definitions
type PolicyDefinitionsType struct {
	// original -> bgp-policy:policy-definition
	PolicyDefinitionList []PolicyDefinitionType
}

//struct for container as-path-set
type AsPathSetType struct {
	// original -> bgp-policy:as-path-set-name
	AsPathSetName string
	// original -> bgp-policy:as-path-set-members
	AsPathSetMembers []string
}

//struct for container ext-community-set
type ExtCommunitySetType struct {
	// original -> bgp-policy:ext-community-set-name
	ExtCommunitySetName string
	// original -> bgp-policy:ext-community-members
	//original type is list of union
	ExtCommunityMembers []string
}

//struct for container community-set
type CommunitySetType struct {
	// original -> bgp-policy:community-set-name
	CommunitySetName string
	// original -> bgp-policy:community-members
	//original type is list of union
	CommunityMembers []string
}

//struct for container prefix
type PrefixType struct {
	// original -> bgp-policy:address
	//address's original type is inet:ip-address
	Address net.IP
	// original -> bgp-policy:masklength
	Masklength uint8
	// original -> bgp-policy:masklength-range
	MasklengthRange string
}

//struct for container prefix-set
type PrefixSetType struct {
	// original -> bgp-policy:prefix-set-name
	PrefixSetName string
	// original -> bgp-policy:prefix
	PrefixList []PrefixType
}

//struct for container defined-sets
type DefinedSetsType struct {
	// original -> bgp-policy:prefix-set
	PrefixSetList []PrefixSetType
	// original -> bgp-policy:community-set
	CommunitySetList []CommunitySetType
	// original -> bgp-policy:ext-community-set
	ExtCommunitySetList []ExtCommunitySetType
	// original -> bgp-policy:as-path-set
	AsPathSetList []AsPathSetType
}

//struct for container policy
type PolicyType struct {
	// original -> bgp-policy:defined-sets
	DefinedSets DefinedSetsType
	// original -> bgp-policy:policy-definitions
	PolicyDefinitions PolicyDefinitionsType
}

//struct for container bgp-neighbor-common-state
type BgpNeighborCommonStateType struct {
	// peer-state
	State uint32
	// peer-uptime
	Uptime   time.Time
	Downtime time.Time

	// BGP statistics
	// Open message input count
	OpenIn uint32
	// Open message output count
	OpenOut uint32
	// Update message input count
	UpdateIn uint32
	// Update message ouput count
	UpdateOut uint32
	// Update message received time
	UpdateRecvTime time.Time
	// Keepalive input count
	KeepaliveIn uint32
	// Keepalive output count
	KeepaliveOut uint32
	// Notify input count
	NotifyIn uint32
	// Notify output count
	NotifyOut uint32
	// Route Refresh input count
	RefreshIn uint32
	// Route Refresh output count
	RefreshOut uint32
	// Dynamic Capability input count
	DynamicCapIn uint32
	// Dynamic Capability output count
	DynamicCapOut uint32

	DiscardedOut uint32
	DiscardedIn  uint32

	TotalIn  uint32
	TotalOut uint32

	// BGP state count
	// Established
	EstablishedCount uint32
	// Dropped
	DroppedCount uint32
	Flops        uint32
}

//struct for container transport-options
type TransportOptionsType struct {
	// original -> bgp:tcp-mss
	TcpMss uint16
	// original -> bgp:mtu-discovery
	//mtu-discovery's original type is boolean
	MtuDiscovery bool
	// original -> bgp:passive-mode
	//passive-mode's original type is boolean
	PassiveMode bool
}

//struct for container bgp-logging-options
type BgpLoggingOptionsType struct {
	// original -> bgp:log-neighbor-state-changes
	//log-neighbor-state-changes's original type is boolean
	LogNeighborStateChanges bool
}

//struct for container route-reflector
type RouteReflectorType struct {
	// original -> bgp:route-reflector-cluster-id
	//route-reflector-cluster-id's original type is rr-cluster-id-type
	RouteReflectorClusterId uint32
	// original -> bgp:route-reflector-client
	//route-reflector-client's original type is boolean
	RouteReflectorClient bool
}

//struct for container ebgp-multihop
type EbgpMultihopType struct {
	// original -> bgp:multihop-ttl
	MultihopTtl uint8
}

//struct for container timers
type TimersType struct {
	// original -> bgp:connect-retry
	//connect-retry's original type is decimal64
	ConnectRetry float64
	// original -> bgp:hold-time
	//hold-time's original type is decimal64
	HoldTime float64
	// original -> bgp:keepalive-interval
	//keepalive-interval's original type is decimal64
	KeepaliveInterval float64
	// original -> bgp:minimum-advertisement-interval
	//minimum-advertisement-interval's original type is decimal64
	MinimumAdvertisementInterval float64
	// original -> bgp:send-update-delay
	//send-update-delay's original type is decimal64
	SendUpdateDelay float64

	IdleHoldTImeAfterReset float64
}

//struct for container bgp-af-common-state
type BgpAfCommonStateType struct {
	// received prefix count
	Pcount int64
	// sent prefix count
	Scount int64
}

//struct for container apply-policy
type ApplyPolicyType struct {
	// original -> bgp-policy:import-policies
	ImportPolicies []string
	// original -> bgp-policy:export-policies
	ExportPolicies []string
}

//struct for container prefix-limit
type PrefixLimitType struct {
	// original -> bgp-mp:max-prefixes
	MaxPrefixes uint32
	// original -> bgp-mp:shutdown-threshold-pct
	ShutdownThresholdPct Percentage
	// original -> bgp-mp:restart-timer
	//restart-timer's original type is decimal64
	RestartTimer float64
}

//struct for container ipv6-multicast-vpn
type Ipv6MulticastVpnType struct {
}

//struct for container ipv4-multicast-vpn
type Ipv4MulticastVpnType struct {
}

//struct for container l2vpn
type L2vpnType struct {
}

//struct for container ipv4-labeled-unicast
type Ipv4LabeledUnicastType struct {
}

//struct for container ipv6-l3vpn-unicast
type Ipv6L3vpnUnicastType struct {
}

//struct for container vrfs
type VrfsType struct {
	// original -> bgp-mp:name
	Name string
	// original -> bgp-mp:route-distinguisher
	RouteDistinguisher uint64
	// original -> bgp-policy:apply-policy
	ApplyPolicy ApplyPolicyType
}

//struct for container ipv4-l3vpn-unicast
type Ipv4L3vpnUnicastType struct {
	// original -> bgp-mp:vrfs
	VrfsList []VrfsType
}

//struct for container ipv4-ipv6-unicast
type Ipv4Ipv6UnicastType struct {
	// original -> bgp-mp:send-default-route
	//send-default-route's original type is boolean
	SendDefaultRoute bool
}

//struct for container safi
type SafiType struct {
	// original -> bgp-mp:safi-name
	SafiName SafiTypeDef
	// original -> bgp-mp:ipv4-ipv6-unicast
	Ipv4Ipv6Unicast Ipv4Ipv6UnicastType
	// original -> bgp-mp:ipv4-l3vpn-unicast
	Ipv4L3vpnUnicast Ipv4L3vpnUnicastType
	// original -> bgp-mp:ipv6-l3vpn-unicast
	Ipv6L3vpnUnicast Ipv6L3vpnUnicastType
	// original -> bgp-mp:ipv4-labeled-unicast
	Ipv4LabeledUnicast Ipv4LabeledUnicastType
	// original -> bgp-mp:l2vpn
	L2vpn L2vpnType
	// original -> bgp-mp:ipv4-multicast-vpn
	Ipv4MulticastVpn Ipv4MulticastVpnType
	// original -> bgp-mp:ipv6-multicast-vpn
	Ipv6MulticastVpn Ipv6MulticastVpnType
	// original -> bgp-mp:prefix-limit
	PrefixLimit PrefixLimitType
	// original -> bgp-policy:apply-policy
	ApplyPolicy ApplyPolicyType
}

//struct for container afi
type AfiType struct {
	// original -> bgp-mp:afi-name
	AfiName AfiTypeDef
	// original -> bgp-mp:safi
	SafiList []SafiType
	// original -> bgp-op:bgp-af-common-state
	BgpAfCommonState BgpAfCommonStateType
}

//struct for container graceful-restart
type GracefulRestartType struct {
	// original -> bgp:restart-time
	RestartTime uint16
	// original -> bgp:stale-routes-time
	//stale-routes-time's original type is decimal64
	StaleRoutesTime float64
}

//struct for container eibgp
type EibgpType struct {
	// original -> bgp:maximum-paths
	MaximumPaths uint32
}

//struct for container ibgp
type IbgpType struct {
	// original -> bgp:maximum-paths
	MaximumPaths uint32
}

//struct for container ebgp
type EbgpType struct {
	// original -> bgp:allow-multiple-as
	//allow-multiple-as's original type is boolean
	AllowMultipleAs bool
	// original -> bgp:maximum-paths
	MaximumPaths uint32
}

//struct for container use-multiple-paths
type UseMultiplePathsType struct {
	// original -> bgp:ebgp
	Ebgp EbgpType
	// original -> bgp:ibgp
	Ibgp IbgpType
	// original -> bgp:eibgp
	Eibgp EibgpType
}

//struct for container route-selection-options
type RouteSelectionOptionsType struct {
	// original -> bgp:always-compare-med
	//always-compare-med's original type is boolean
	AlwaysCompareMed bool
	// original -> bgp:ignore-as-path-length
	//ignore-as-path-length's original type is boolean
	IgnoreAsPathLength bool
	// original -> bgp:external-compare-router-id
	//external-compare-router-id's original type is boolean
	ExternalCompareRouterId bool
	// original -> bgp:advertise-inactive-routes
	//advertise-inactive-routes's original type is boolean
	AdvertiseInactiveRoutes bool
	// original -> bgp:enable-aigp
	//enable-aigp's original type is empty
	EnableAigp bool
}

//struct for container neighbor
type NeighborType struct {
	// original -> bgp:neighbor-address
	//neighbor-address's original type is inet:ip-address
	NeighborAddress net.IP
	// original -> bgp:peer-as
	//peer-as's original type is inet:as-number
	PeerAs uint32
	// original -> bgp:description
	Description string
	// original -> bgp:route-selection-options
	RouteSelectionOptions RouteSelectionOptionsType
	// original -> bgp:use-multiple-paths
	UseMultiplePaths UseMultiplePathsType
	// original -> bgp:graceful-restart
	GracefulRestart GracefulRestartType
	// original -> bgp-policy:apply-policy
	ApplyPolicy ApplyPolicyType
	// original -> bgp-mp:afi
	AfiList []AfiType
	// original -> bgp:auth-password
	AuthPassword string
	// original -> bgp:peer-type
	PeerType PeerTypeDef
	// original -> bgp:timers
	Timers TimersType
	// original -> bgp:ebgp-multihop
	EbgpMultihop EbgpMultihopType
	// original -> bgp:route-reflector
	RouteReflector RouteReflectorType
	// original -> bgp:remove-private-as
	RemovePrivateAs RemovePrivateAsOption
	// original -> bgp:bgp-logging-options
	BgpLoggingOptions BgpLoggingOptionsType
	// original -> bgp:transport-options
	TransportOptions TransportOptionsType
	// original -> bgp:local-address
	//local-address's original type is inet:ip-address
	LocalAddress net.IP
	// original -> bgp:route-flap-damping
	//route-flap-damping's original type is boolean
	RouteFlapDamping bool
	// original -> bgp-op:bgp-neighbor-common-state
	BgpNeighborCommonState BgpNeighborCommonStateType
}

//struct for container bgp-group-common-state
type BgpGroupCommonStateType struct {
}

//struct for container peer-group
type PeerGroupType struct {
	// original -> bgp:group-name
	GroupName string
	// original -> bgp-op:bgp-group-common-state
	BgpGroupCommonState BgpGroupCommonStateType
	// original -> bgp:description
	Description string
	// original -> bgp:route-selection-options
	RouteSelectionOptions RouteSelectionOptionsType
	// original -> bgp:use-multiple-paths
	UseMultiplePaths UseMultiplePathsType
	// original -> bgp:graceful-restart
	GracefulRestart GracefulRestartType
	// original -> bgp-policy:apply-policy
	ApplyPolicy ApplyPolicyType
	// original -> bgp-mp:afi
	AfiList []AfiType
	// original -> bgp:auth-password
	AuthPassword string
	// original -> bgp:peer-type
	PeerType PeerTypeDef
	// original -> bgp:timers
	Timers TimersType
	// original -> bgp:ebgp-multihop
	EbgpMultihop EbgpMultihopType
	// original -> bgp:route-reflector
	RouteReflector RouteReflectorType
	// original -> bgp:remove-private-as
	RemovePrivateAs RemovePrivateAsOption
	// original -> bgp:bgp-logging-options
	BgpLoggingOptions BgpLoggingOptionsType
	// original -> bgp:transport-options
	TransportOptions TransportOptionsType
	// original -> bgp:local-address
	//local-address's original type is inet:ip-address
	LocalAddress net.IP
	// original -> bgp:route-flap-damping
	//route-flap-damping's original type is boolean
	RouteFlapDamping bool
	// original -> bgp:neighbor
	NeighborList []NeighborType
}

//struct for container bgp-global-state
type BgpGlobalStateType struct {
	// start time
	StartTime time.Time
}

//struct for container confederation
type ConfederationType struct {
	// original -> bgp:identifier
	//identifier's original type is inet:as-number
	Identifier uint32
	// original -> bgp:member-as
	//original type is list of inet:as-number
	MemberAs []uint32
}

//struct for container default-route-distance
type DefaultRouteDistanceType struct {
	// original -> bgp:external-route-distance
	ExternalRouteDistance uint8
	// original -> bgp:internal-route-distance
	InternalRouteDistance uint8
}

//struct for container global
type GlobalType struct {
	// original -> bgp:as
	//as's original type is inet:as-number
	As uint32
	// original -> bgp:router-id
	//router-id's original type is inet:ipv4-address
	RouterId net.IP
	// original -> bgp:default-route-distance
	DefaultRouteDistance DefaultRouteDistanceType
	// original -> bgp:confederation
	Confederation ConfederationType
	// original -> bgp-op:bgp-global-state
	BgpGlobalState BgpGlobalStateType
}

//struct for container bgp
type BgpType struct {
	// original -> bgp:global
	Global GlobalType
	// original -> bgp-mp:afi
	AfiList []AfiType
	// original -> bgp:peer-group
	PeerGroupList []PeerGroupType
	// original -> bgp:neighbor
	NeighborList []NeighborType
	// original -> bgp-policy:policy
	Policy PolicyType
}
