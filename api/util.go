// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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

package api

var AF_IPV4_UC *AddressFamily = &AddressFamily{AFI_IP, SAFI_UNICAST}
var AF_IPV6_UC *AddressFamily = &AddressFamily{AFI_IP6, SAFI_UNICAST}
var AF_EVPN *AddressFamily = &AddressFamily{AFI_L2VPN, SAFI_EVPN}
var AF_ENCAP *AddressFamily = &AddressFamily{AFI_IP, SAFI_ENCAP}
var AF_RTC *AddressFamily = &AddressFamily{AFI_IP, SAFI_ROUTE_TARGET_CONSTRAINTS}

func (lhs *AddressFamily) Equal(rhs *AddressFamily) bool {
	return lhs.Afi == rhs.Afi && lhs.Safi == rhs.Safi
}
