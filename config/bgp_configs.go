// Copyright (C) 2014,2015 Nippon Telegraph and Telephone Corporation.
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

// typedef for typedef bgp:remove-private-as-option
type RemovePrivateAsOption int

const (
	REMOVE_PRIVATE_AS_OPTION_ALL = iota
	REMOVE_PRIVATE_AS_OPTION_REPLACE
)

// typedef for typedef bgp:community-type
type CommunityType int

const (
	COMMUNITY_TYPE_STANDARD = iota
	COMMUNITY_TYPE_EXTENDED
	COMMUNITY_TYPE_BOTH
	COMMUNITY_TYPE_NONE
)

// typedef for typedef bgp:rr-cluster-id-type
type RrClusterIdType string

// typedef for typedef bgp:peer-type
type PeerTypeDef int

const (
	PEER_TYPE_INTERNAL = iota
	PEER_TYPE_EXTERNAL
)

// typedef for typedef bgp:percentage
type Percentage uint8

// typedef for typedef bgp:bgp-origin-attr-type
type BgpOriginAttrType int

const (
	BGP_ORIGIN_ATTR_TYPE_IGP        = 0
	BGP_ORIGIN_ATTR_TYPE_EGP        = 1
	BGP_ORIGIN_ATTR_TYPE_INCOMPLETE = 2
)

// typedef for typedef rpol:install-protocol-type
type InstallProtocolType int

const (
	INSTALL_PROTOCOL_TYPE_ISIS = iota
	INSTALL_PROTOCOL_TYPE_OSPF
	INSTALL_PROTOCOL_TYPE_OSPF3
	INSTALL_PROTOCOL_TYPE_STATIC
	INSTALL_PROTOCOL_TYPE_DIRECTLY_CONNECTED
)

// typedef for typedef rpol:default-policy-type
type DefaultPolicyType int

const (
	DEFAULT_POLICY_TYPE_ACCEPT_ROUTE = iota
	DEFAULT_POLICY_TYPE_REJECT_ROUTE
)

//struct for container apply-policy
type ApplyPolicy struct {
	// original -> rpol:import-policies
	ImportPolicies []string
	// original -> rpol:default-import-policy
	DefaultImportPolicy DefaultPolicyType
	// original -> rpol:export-policies
	ExportPolicies []string
	// original -> rpol:default-export-policy
	DefaultExportPolicy DefaultPolicyType
}

//struct for container bgp-neighbor-common-state
type BgpNeighborCommonState struct {
	// original -> bgp-op:state
	State uint32
	// original -> bgp-op:uptime
	Uptime int64
	// original -> bgp-op:downtime
	Downtime int64
	// original -> bgp-op:open-in
	OpenIn uint32
	// original -> bgp-op:open-out
	OpenOut uint32
	// original -> bgp-op:update-in
	UpdateIn uint32
	// original -> bgp-op:update-out
	UpdateOut uint32
	// original -> bgp-op:update-recv-time
	UpdateRecvTime int64
	// original -> bgp-op:keepalive-in
	KeepaliveIn uint32
	// original -> bgp-op:keepalive-out
	KeepaliveOut uint32
	// original -> bgp-op:notify-in
	NotifyIn uint32
	// original -> bgp-op:notify-out
	NotifyOut uint32
	// original -> bgp-op:refresh-in
	RefreshIn uint32
	// original -> bgp-op:refresh-out
	RefreshOut uint32
	// original -> bgp-op:dynamic-cap-in
	DynamicCapIn uint32
	// original -> bgp-op:dynamic-cap-out
	DynamicCapOut uint32
	// original -> bgp-op:discarded-in
	DiscardedIn uint32
	// original -> bgp-op:discarded-out
	DiscardedOut uint32
	// original -> bgp-op:total-in
	TotalIn uint32
	// original -> bgp-op:total-out
	TotalOut uint32
	// original -> bgp-op:established-count
	EstablishedCount uint32
	// original -> bgp-op:flops
	Flops uint32
}

//struct for container add-paths
type AddPaths struct {
	// original -> bgp:receive
	//receive's original type is empty
	Receive bool
	// original -> bgp:send-max
	SendMax uint8
}

//struct for container as-path-options
type AsPathOptions struct {
	// original -> bgp:allow-own-as
	//allow-own-as's original type is boolean
	AllowOwnAs bool
	// original -> bgp:replace-peer-as
	//replace-peer-as's original type is boolean
	ReplacePeerAs bool
}

//struct for container error-handling
type ErrorHandling struct {
	// original -> bgp:treat-as-withdraw
	//treat-as-withdraw's original type is boolean
	TreatAsWithdraw bool
}

//struct for container transport-options
type TransportOptions struct {
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
type BgpLoggingOptions struct {
	// original -> bgp:log-neighbor-state-changes
	//log-neighbor-state-changes's original type is boolean
	LogNeighborStateChanges bool
}

//struct for container route-server
type RouteServer struct {
	// original -> bgp:route-server-client
	//route-server-client's original type is boolean
	RouteServerClient bool
}

//struct for container route-reflector
type RouteReflector struct {
	// original -> bgp:route-reflector-cluster-id
	//route-reflector-cluster-id's original type is rr-cluster-id-type
	RouteReflectorClusterId uint32
	// original -> bgp:route-reflector-client
	//route-reflector-client's original type is boolean
	RouteReflectorClient bool
}

//struct for container ebgp-multihop
type EbgpMultihop struct {
	// original -> bgp:multihop-ttl
	MultihopTtl uint8
}

//struct for container timers
type Timers struct {
	// original -> bgp:connect-retry
	//connect-retry's original type is decimal64
	ConnectRetry float64
	// original -> bgp:hold-time
	//hold-time's original type is decimal64
	HoldTime float64
	// original -> bgp:idle-hold-time-after-reset
	//idle-hold-time-after-reset's original type is decimal64
	IdleHoldTimeAfterReset float64
	// original -> bgp:keepalive-interval
	//keepalive-interval's original type is decimal64
	KeepaliveInterval float64
	// original -> bgp:minimum-advertisement-interval
	//minimum-advertisement-interval's original type is decimal64
	MinimumAdvertisementInterval float64
	// original -> bgp:send-update-delay
	//send-update-delay's original type is decimal64
	SendUpdateDelay float64
}

//struct for container prefix-limit
type PrefixLimit struct {
	// original -> bgp-mp:max-prefixes
	MaxPrefixes uint32
	// original -> bgp-mp:shutdown-threshold-pct
	ShutdownThresholdPct Percentage
	// original -> bgp-mp:restart-timer
	//restart-timer's original type is decimal64
	RestartTimer float64
}

//struct for container l2vpn-evpn
type L2vpnEvpn struct {
	// original -> rpol:apply-policy
	ApplyPolicy ApplyPolicy
	// original -> bgp-mp:prefix-limit
	PrefixLimit PrefixLimit
}

//struct for container l2vpn-vpls
type L2vpnVpls struct {
	// original -> bgp-mp:enabled
	//enabled's original type is boolean
	Enabled bool
	// original -> rpol:apply-policy
	ApplyPolicy ApplyPolicy
	// original -> bgp-mp:prefix-limit
	PrefixLimit PrefixLimit
}

//struct for container l3vpn-ipv6-multicast
type L3vpnIpv6Multicast struct {
	// original -> bgp-mp:enabled
	//enabled's original type is boolean
	Enabled bool
	// original -> rpol:apply-policy
	ApplyPolicy ApplyPolicy
	// original -> bgp-mp:prefix-limit
	PrefixLimit PrefixLimit
}

//struct for container l3vpn-ipv4-multicast
type L3vpnIpv4Multicast struct {
	// original -> bgp-mp:enabled
	//enabled's original type is boolean
	Enabled bool
	// original -> rpol:apply-policy
	ApplyPolicy ApplyPolicy
	// original -> bgp-mp:prefix-limit
	PrefixLimit PrefixLimit
}

//struct for container l3vpn-ipv6-unicast
type L3vpnIpv6Unicast struct {
	// original -> bgp-mp:enabled
	//enabled's original type is boolean
	Enabled bool
	// original -> rpol:apply-policy
	ApplyPolicy ApplyPolicy
	// original -> bgp-mp:prefix-limit
	PrefixLimit PrefixLimit
}

//struct for container l3vpn-ipv4-unicast
type L3vpnIpv4Unicast struct {
	// original -> bgp-mp:enabled
	//enabled's original type is boolean
	Enabled bool
	// original -> rpol:apply-policy
	ApplyPolicy ApplyPolicy
	// original -> bgp-mp:prefix-limit
	PrefixLimit PrefixLimit
}

//struct for container ipv6-labelled-unicast
type Ipv6LabelledUnicast struct {
	// original -> bgp-mp:enabled
	//enabled's original type is boolean
	Enabled bool
	// original -> rpol:apply-policy
	ApplyPolicy ApplyPolicy
	// original -> bgp-mp:prefix-limit
	PrefixLimit PrefixLimit
}

//struct for container ipv4-labelled-unicast
type Ipv4LabelledUnicast struct {
	// original -> bgp-mp:enabled
	//enabled's original type is boolean
	Enabled bool
	// original -> rpol:apply-policy
	ApplyPolicy ApplyPolicy
	// original -> bgp-mp:prefix-limit
	PrefixLimit PrefixLimit
}

//struct for container ipv6-multicast
type Ipv6Multicast struct {
	// original -> bgp-mp:enabled
	//enabled's original type is boolean
	Enabled bool
	// original -> rpol:apply-policy
	ApplyPolicy ApplyPolicy
	// original -> bgp-mp:prefix-limit
	PrefixLimit PrefixLimit
}

//struct for container ipv4-multicast
type Ipv4Multicast struct {
	// original -> bgp-mp:enabled
	//enabled's original type is boolean
	Enabled bool
	// original -> rpol:apply-policy
	ApplyPolicy ApplyPolicy
	// original -> bgp-mp:prefix-limit
	PrefixLimit PrefixLimit
}

//struct for container ipv6-unicast
type Ipv6Unicast struct {
	// original -> bgp-mp:enabled
	//enabled's original type is boolean
	Enabled bool
	// original -> rpol:apply-policy
	ApplyPolicy ApplyPolicy
	// original -> bgp-mp:prefix-limit
	PrefixLimit PrefixLimit
	// original -> bgp-mp:send-default-route
	//send-default-route's original type is boolean
	SendDefaultRoute bool
}

//struct for container ipv4-unicast
type Ipv4Unicast struct {
	// original -> bgp-mp:enabled
	//enabled's original type is boolean
	Enabled bool
	// original -> rpol:apply-policy
	ApplyPolicy ApplyPolicy
	// original -> bgp-mp:prefix-limit
	PrefixLimit PrefixLimit
	// original -> bgp-mp:send-default-route
	//send-default-route's original type is boolean
	SendDefaultRoute bool
}

//struct for container afi-safi
type AfiSafi struct {
	// original -> bgp-mp:afi-safi-name
	AfiSafiName string
	// original -> bgp-mp:ipv4-unicast
	Ipv4Unicast Ipv4Unicast
	// original -> bgp-mp:ipv6-unicast
	Ipv6Unicast Ipv6Unicast
	// original -> bgp-mp:ipv4-multicast
	Ipv4Multicast Ipv4Multicast
	// original -> bgp-mp:ipv6-multicast
	Ipv6Multicast Ipv6Multicast
	// original -> bgp-mp:ipv4-labelled-unicast
	Ipv4LabelledUnicast Ipv4LabelledUnicast
	// original -> bgp-mp:ipv6-labelled-unicast
	Ipv6LabelledUnicast Ipv6LabelledUnicast
	// original -> bgp-mp:l3vpn-ipv4-unicast
	L3vpnIpv4Unicast L3vpnIpv4Unicast
	// original -> bgp-mp:l3vpn-ipv6-unicast
	L3vpnIpv6Unicast L3vpnIpv6Unicast
	// original -> bgp-mp:l3vpn-ipv4-multicast
	L3vpnIpv4Multicast L3vpnIpv4Multicast
	// original -> bgp-mp:l3vpn-ipv6-multicast
	L3vpnIpv6Multicast L3vpnIpv6Multicast
	// original -> bgp-mp:l2vpn-vpls
	L2vpnVpls L2vpnVpls
	// original -> bgp-mp:l2vpn-evpn
	L2vpnEvpn L2vpnEvpn
}

//struct for container graceful-restart
type GracefulRestart struct {
	// original -> bgp:restart-time
	RestartTime uint16
	// original -> bgp:stale-routes-time
	//stale-routes-time's original type is decimal64
	StaleRoutesTime float64
}

//struct for container neighbor
type Neighbor struct {
	// original -> bgp:neighbor-address
	//neighbor-address's original type is inet:ip-address
	NeighborAddress net.IP
	// original -> bgp:peer-as
	//peer-as's original type is inet:as-number
	PeerAs uint32
	// original -> bgp:description
	Description string
	// original -> bgp:graceful-restart
	GracefulRestart GracefulRestart
	// original -> rpol:apply-policy
	ApplyPolicy ApplyPolicy
	// original -> bgp-mp:afi-safi
	AfiSafiList []AfiSafi
	// original -> bgp:auth-password
	AuthPassword string
	// original -> bgp:peer-type
	PeerType PeerTypeDef
	// original -> bgp:timers
	Timers Timers
	// original -> bgp:ebgp-multihop
	EbgpMultihop EbgpMultihop
	// original -> bgp:route-reflector
	RouteReflector RouteReflector
	// original -> bgp:route-server
	RouteServer RouteServer
	// original -> bgp:remove-private-as
	RemovePrivateAs RemovePrivateAsOption
	// original -> bgp:bgp-logging-options
	BgpLoggingOptions BgpLoggingOptions
	// original -> bgp:transport-options
	TransportOptions TransportOptions
	// original -> bgp:local-address
	//local-address's original type is inet:ip-address
	LocalAddress net.IP
	// original -> bgp:route-flap-damping
	//route-flap-damping's original type is boolean
	RouteFlapDamping bool
	// original -> bgp:send-community
	SendCommunity CommunityType
	// original -> bgp:error-handling
	ErrorHandling ErrorHandling
	// original -> bgp:as-path-options
	AsPathOptions AsPathOptions
	// original -> bgp:add-paths
	AddPaths AddPaths
	// original -> bgp-op:bgp-neighbor-common-state
	BgpNeighborCommonState BgpNeighborCommonState
}

//struct for container ibgp
type Ibgp struct {
	// original -> bgp-mp:maximum-paths
	MaximumPaths uint32
}

//struct for container ebgp
type Ebgp struct {
	// original -> bgp-mp:allow-multiple-as
	//allow-multiple-as's original type is boolean
	AllowMultipleAs bool
	// original -> bgp-mp:maximum-paths
	MaximumPaths uint32
}

//struct for container use-multiple-paths
type UseMultiplePaths struct {
	// original -> bgp-mp:ebgp
	Ebgp Ebgp
	// original -> bgp-mp:ibgp
	Ibgp Ibgp
}

//struct for container bgp-group-common-state
type BgpGroupCommonState struct {
}

//struct for container peer-group
type PeerGroup struct {
	// original -> bgp:group-name
	GroupName string
	// original -> bgp-op:bgp-group-common-state
	BgpGroupCommonState BgpGroupCommonState
	// original -> bgp:description
	Description string
	// original -> bgp:graceful-restart
	GracefulRestart GracefulRestart
	// original -> rpol:apply-policy
	ApplyPolicy ApplyPolicy
	// original -> bgp-mp:afi-safi
	AfiSafiList []AfiSafi
	// original -> bgp:auth-password
	AuthPassword string
	// original -> bgp:peer-type
	PeerType PeerTypeDef
	// original -> bgp:timers
	Timers Timers
	// original -> bgp:ebgp-multihop
	EbgpMultihop EbgpMultihop
	// original -> bgp:route-reflector
	RouteReflector RouteReflector
	// original -> bgp:route-server
	RouteServer RouteServer
	// original -> bgp:remove-private-as
	RemovePrivateAs RemovePrivateAsOption
	// original -> bgp:bgp-logging-options
	BgpLoggingOptions BgpLoggingOptions
	// original -> bgp:transport-options
	TransportOptions TransportOptions
	// original -> bgp:local-address
	//local-address's original type is inet:ip-address
	LocalAddress net.IP
	// original -> bgp:route-flap-damping
	//route-flap-damping's original type is boolean
	RouteFlapDamping bool
	// original -> bgp:send-community
	SendCommunity CommunityType
	// original -> bgp:error-handling
	ErrorHandling ErrorHandling
	// original -> bgp:as-path-options
	AsPathOptions AsPathOptions
	// original -> bgp:add-paths
	AddPaths AddPaths
	// original -> bgp-mp:use-multiple-paths
	UseMultiplePaths UseMultiplePaths
	// original -> bgp:neighbor
	NeighborList []Neighbor
}

//struct for container bgp-global-state
type BgpGlobalState struct {
}

//struct for container route-selection-options
type RouteSelectionOptions struct {
	// original -> bgp-mp:always-compare-med
	//always-compare-med's original type is boolean
	AlwaysCompareMed bool
	// original -> bgp-mp:ignore-as-path-length
	//ignore-as-path-length's original type is boolean
	IgnoreAsPathLength bool
	// original -> bgp-mp:external-compare-router-id
	//external-compare-router-id's original type is boolean
	ExternalCompareRouterId bool
	// original -> bgp-mp:advertise-inactive-routes
	//advertise-inactive-routes's original type is boolean
	AdvertiseInactiveRoutes bool
	// original -> bgp-mp:enable-aigp
	//enable-aigp's original type is empty
	EnableAigp bool
	// original -> bgp-mp:ignore-next-hop-igp-metric
	//ignore-next-hop-igp-metric's original type is boolean
	IgnoreNextHopIgpMetric bool
}

//struct for container confederation
type Confederation struct {
	// original -> bgp:identifier
	//identifier's original type is inet:as-number
	Identifier uint32
	// original -> bgp:member-as
	//original type is list of inet:as-number
	MemberAs []uint32
}

//struct for container default-route-distance
type DefaultRouteDistance struct {
	// original -> bgp:external-route-distance
	ExternalRouteDistance uint8
	// original -> bgp:internal-route-distance
	InternalRouteDistance uint8
}

//struct for container global
type Global struct {
	// original -> bgp:as
	//as's original type is inet:as-number
	As uint32
	// original -> bgp:router-id
	//router-id's original type is inet:ipv4-address
	RouterId net.IP
	// original -> bgp:default-route-distance
	DefaultRouteDistance DefaultRouteDistance
	// original -> bgp:confederation
	Confederation Confederation
	// original -> bgp-mp:use-multiple-paths
	UseMultiplePaths UseMultiplePaths
	// original -> bgp-mp:afi-safi
	AfiSafiList []AfiSafi
	// original -> bgp-op:bgp-global-state
	BgpGlobalState BgpGlobalState
}

//struct for container bgp
type Bgp struct {
	// original -> bgp:global
	Global Global
	// original -> bgp:peer-group
	PeerGroupList []PeerGroup
	// original -> bgp:neighbor
	NeighborList []Neighbor
	// original -> rpol:apply-policy
	ApplyPolicy ApplyPolicy
}
