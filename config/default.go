package config

import (
	"fmt"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/packet/bmp"
	"github.com/osrg/gobgp/packet/rtr"
	"github.com/spf13/viper"
	"net"
	"reflect"
)

const (
	DEFAULT_HOLDTIME                  = 90
	DEFAULT_IDLE_HOLDTIME_AFTER_RESET = 30
	DEFAULT_CONNECT_RETRY             = 120
)

var forcedOverwrittenConfig = []string{
	"neighbor.config.peer-as",
	"neighbor.timers.config.minimum-advertisement-interval",
}

var configuredFields map[string]interface{}

func RegisterConfiguredFields(addr string, n interface{}) {
	if configuredFields == nil {
		configuredFields = make(map[string]interface{}, 0)
	}
	configuredFields[addr] = n
}

func defaultAfiSafi(typ AfiSafiType, enable bool) AfiSafi {
	return AfiSafi{
		Config: AfiSafiConfig{
			AfiSafiName: typ,
			Enabled:     enable,
		},
		State: AfiSafiState{
			AfiSafiName: typ,
		},
	}
}

// yaml is decoded as []interface{}
// but toml is decoded as []map[string]interface{}.
// currently, viper can't hide this difference.
// handle the difference here.
func extractArray(intf interface{}) ([]interface{}, error) {
	if intf != nil {
		list, ok := intf.([]interface{})
		if ok {
			return list, nil
		}
		l, ok := intf.([]map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid configuration: neither []interface{} nor []map[string]interface{}")
		}
		list = make([]interface{}, 0, len(l))
		for _, m := range l {
			list = append(list, m)
		}
		return list, nil
	}
	return nil, nil
}

func getIPv6LinkLocalAddress(ifname string) (string, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return "", err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		ip := addr.(*net.IPNet).IP
		if ip.To4() == nil && ip.IsLinkLocalUnicast() {
			return fmt.Sprintf("%s%%%s", ip.String(), ifname), nil
		}
	}
	return "", fmt.Errorf("no ipv6 link local address for %s", ifname)
}

func isLocalLinkLocalAddress(ifindex int, addr net.IP) (bool, error) {
	ifi, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return false, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return false, err
	}
	for _, a := range addrs {
		if ip, _, _ := net.ParseCIDR(a.String()); addr.Equal(ip) {
			return true, nil
		}
	}
	return false, nil
}

func SetDefaultNeighborConfigValues(n *Neighbor, asn uint32) error {
	return setDefaultNeighborConfigValuesWithViper(nil, n, asn)
}

func setDefaultNeighborConfigValuesWithViper(v *viper.Viper, n *Neighbor, asn uint32) error {
	if v == nil {
		// Determines this function is called against the same Neighbor struct,
		// and if already called, returns immediately.
		if n.State.LocalAs != 0 {
			return nil
		}
		v = viper.New()
	}

	if n.Config.LocalAs == 0 {
		n.Config.LocalAs = asn
	}
	n.State.LocalAs = n.Config.LocalAs

	if n.Config.PeerAs != n.Config.LocalAs {
		n.Config.PeerType = PEER_TYPE_EXTERNAL
		n.State.PeerType = PEER_TYPE_EXTERNAL
		n.State.RemovePrivateAs = n.Config.RemovePrivateAs
		n.AsPathOptions.State.ReplacePeerAs = n.AsPathOptions.Config.ReplacePeerAs
	} else {
		n.Config.PeerType = PEER_TYPE_INTERNAL
		n.State.PeerType = PEER_TYPE_INTERNAL
		if string(n.Config.RemovePrivateAs) != "" {
			return fmt.Errorf("can't set remove-private-as for iBGP peer")
		}
		if n.AsPathOptions.Config.ReplacePeerAs {
			return fmt.Errorf("can't set replace-peer-as for iBGP peer")
		}
	}

	if n.State.NeighborAddress == "" {
		n.State.NeighborAddress = n.Config.NeighborAddress
	}

	n.State.PeerAs = n.Config.PeerAs
	n.AsPathOptions.State.AllowOwnAs = n.AsPathOptions.Config.AllowOwnAs

	if !v.IsSet("neighbor.timers.config.connect-retry") && n.Timers.Config.ConnectRetry == 0 {
		n.Timers.Config.ConnectRetry = float64(DEFAULT_CONNECT_RETRY)
	}
	if !v.IsSet("neighbor.timers.config.hold-time") && n.Timers.Config.HoldTime == 0 {
		n.Timers.Config.HoldTime = float64(DEFAULT_HOLDTIME)
	}
	if !v.IsSet("neighbor.timers.config.keepalive-interval") && n.Timers.Config.KeepaliveInterval == 0 {
		n.Timers.Config.KeepaliveInterval = n.Timers.Config.HoldTime / 3
	}
	if !v.IsSet("neighbor.timers.config.idle-hold-time-after-reset") && n.Timers.Config.IdleHoldTimeAfterReset == 0 {
		n.Timers.Config.IdleHoldTimeAfterReset = float64(DEFAULT_IDLE_HOLDTIME_AFTER_RESET)
	}

	if n.Config.NeighborInterface != "" {
		if n.RouteServer.Config.RouteServerClient {
			return fmt.Errorf("configuring route server client as unnumbered peer is not supported")
		}
		addr, err := GetIPv6LinkLocalNeighborAddress(n.Config.NeighborInterface)
		if err != nil {
			return err
		}
		n.State.NeighborAddress = addr
	}

	if n.Transport.Config.LocalAddress == "" {
		if n.State.NeighborAddress == "" {
			return fmt.Errorf("no neighbor address/interface specified")
		}
		ipAddr, err := net.ResolveIPAddr("ip", n.State.NeighborAddress)
		if err != nil {
			return err
		}
		localAddress := "0.0.0.0"
		if ipAddr.IP.To4() == nil {
			localAddress = "::"
			if ipAddr.Zone != "" {
				localAddress, err = getIPv6LinkLocalAddress(ipAddr.Zone)
				if err != nil {
					return err
				}
			}
		}
		n.Transport.Config.LocalAddress = localAddress
	}

	if len(n.AfiSafis) == 0 {
		if n.Config.NeighborInterface != "" {
			n.AfiSafis = []AfiSafi{
				defaultAfiSafi(AFI_SAFI_TYPE_IPV4_UNICAST, true),
				defaultAfiSafi(AFI_SAFI_TYPE_IPV6_UNICAST, true),
			}
		} else if ipAddr, err := net.ResolveIPAddr("ip", n.State.NeighborAddress); err != nil {
			return fmt.Errorf("invalid neighbor address: %s", n.State.NeighborAddress)
		} else if ipAddr.IP.To4() != nil {
			n.AfiSafis = []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV4_UNICAST, true)}
		} else {
			n.AfiSafis = []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV6_UNICAST, true)}
		}
	} else {
		afs, err := extractArray(v.Get("neighbor.afi-safis"))
		if err != nil {
			return err
		}
		for i := range n.AfiSafis {
			vv := viper.New()
			if len(afs) > i {
				vv.Set("afi-safi", afs[i])
			}
			if _, err := bgp.GetRouteFamily(string(n.AfiSafis[i].Config.AfiSafiName)); err != nil {
				return err
			}
			n.AfiSafis[i].State.AfiSafiName = n.AfiSafis[i].Config.AfiSafiName
			if !vv.IsSet("afi-safi.config.enabled") {
				n.AfiSafis[i].Config.Enabled = true
			}
			n.AfiSafis[i].MpGracefulRestart.State.Enabled = n.AfiSafis[i].MpGracefulRestart.Config.Enabled
		}
	}

	n.State.Description = n.Config.Description
	n.State.AdminDown = n.Config.AdminDown

	if n.GracefulRestart.Config.Enabled {
		if !v.IsSet("neighbor.graceful-restart.config.restart-time") && n.GracefulRestart.Config.RestartTime == 0 {
			// RFC 4724 4. Operation
			// A suggested default for the Restart Time is a value less than or
			// equal to the HOLDTIME carried in the OPEN.
			n.GracefulRestart.Config.RestartTime = uint16(n.Timers.Config.HoldTime)
		}
		if !v.IsSet("neighbor.graceful-restart.config.deferral-time") && n.GracefulRestart.Config.DeferralTime == 0 {
			// RFC 4724 4.1. Procedures for the Restarting Speaker
			// The value of this timer should be large
			// enough, so as to provide all the peers of the Restarting Speaker with
			// enough time to send all the routes to the Restarting Speaker
			n.GracefulRestart.Config.DeferralTime = uint16(360)
		}
	}

	if n.EbgpMultihop.Config.Enabled && n.TtlSecurity.Config.Enabled {
		return fmt.Errorf("ebgp-multihop and ttl-security are mututally exclusive")
	}

	return nil
}

func SetDefaultGlobalConfigValues(g *Global) error {
	if len(g.AfiSafis) == 0 {
		g.AfiSafis = []AfiSafi{}
		for k, _ := range AfiSafiTypeToIntMap {
			g.AfiSafis = append(g.AfiSafis, defaultAfiSafi(k, true))
		}
	}

	if g.Config.Port == 0 {
		g.Config.Port = bgp.BGP_PORT
	}

	if len(g.Config.LocalAddressList) == 0 {
		g.Config.LocalAddressList = []string{"0.0.0.0", "::"}
	}
	return nil
}

func SetDefaultConfigValues(b *BgpConfigSet) error {
	return setDefaultConfigValuesWithViper(nil, b)
}

func setDefaultPolicyConfigValuesWithViper(v *viper.Viper, p *PolicyDefinition) error {
	stmts, err := extractArray(v.Get("policy.statements"))
	if err != nil {
		return err
	}
	for i, _ := range p.Statements {
		vv := viper.New()
		if len(stmts) > i {
			vv.Set("statement", stmts[i])
		}
		if !vv.IsSet("statement.actions.route-disposition") {
			p.Statements[i].Actions.RouteDisposition = ROUTE_DISPOSITION_NONE
		}
	}
	return nil
}

func validatePeerGroupConfig(n *Neighbor, b *BgpConfigSet) error {
	name := n.Config.PeerGroup
	if name == "" {
		return nil
	}

	pg, err := getPeerGroup(name, b)
	if err != nil {
		return err
	}

	if pg.Config.PeerAs != 0 && n.Config.PeerAs != 0 {
		return fmt.Errorf("Cannot configure remote-as for members. PeerGroup AS %d.", pg.Config.PeerAs)
	}
	return nil
}

func getPeerGroup(n string, b *BgpConfigSet) (*PeerGroup, error) {
	if n == "" {
		return nil, fmt.Errorf("peer-group name is not configured")
	}
	for _, pg := range b.PeerGroups {
		if n == pg.Config.PeerGroupName {
			return &pg, nil
		}
	}
	return nil, fmt.Errorf("No such peer-group: %s", n)
}

func validateDynamicNeighborConfig(d *DynamicNeighborConfig, b *BgpConfigSet) error {
	if _, err := getPeerGroup(d.PeerGroup, b); err != nil {
		return err
	}
	if _, _, err := net.ParseCIDR(d.Prefix); err != nil {
		return fmt.Errorf("Invalid Dynamic Neighbor prefix %s", d.Prefix)
	}
	return nil
}

func setDefaultConfigValuesWithViper(v *viper.Viper, b *BgpConfigSet) error {
	if v == nil {
		v = viper.New()
	}

	if err := SetDefaultGlobalConfigValues(&b.Global); err != nil {
		return err
	}

	for idx, server := range b.BmpServers {
		if server.Config.Port == 0 {
			server.Config.Port = bmp.BMP_DEFAULT_PORT
		}
		// statistics-timeout is uint16 value and implicitly less than 65536
		if server.Config.StatisticsTimeout != 0 && server.Config.StatisticsTimeout < 15 {
			return fmt.Errorf("too small statistics-timeout value: %d", server.Config.StatisticsTimeout)
		}
		b.BmpServers[idx] = server
	}

	if b.Zebra.Config.Url == "" {
		b.Zebra.Config.Url = "unix:/var/run/quagga/zserv.api"
	}
	if b.Zebra.Config.Version < 2 || 3 > b.Zebra.Config.Version {
		b.Zebra.Config.Version = 2
	}
	if !v.IsSet("zebra.config.nexthop-trigger-enable") && !b.Zebra.Config.NexthopTriggerEnable && b.Zebra.Config.Version > 2 {
		b.Zebra.Config.NexthopTriggerEnable = true
	}
	if b.Zebra.Config.NexthopTriggerDelay == 0 {
		b.Zebra.Config.NexthopTriggerDelay = 5
	}

	list, err := extractArray(v.Get("neighbors"))
	if err != nil {
		return err
	}

	for idx, n := range b.Neighbors {
		if err := validatePeerGroupConfig(&n, b); err != nil {
			return err
		}

		vv := viper.New()
		if len(list) > idx {
			vv.Set("neighbor", list[idx])
		}
		if err := setDefaultNeighborConfigValuesWithViper(vv, &n, b.Global.Config.As); err != nil {
			return err
		}
		b.Neighbors[idx] = n

		if n.Config.PeerGroup != "" {
			RegisterConfiguredFields(vv.Get("neighbor.config.neighbor-address").(string), list[idx])
		}
	}

	for _, d := range b.DynamicNeighbors {
		if err := validateDynamicNeighborConfig(&d.Config, b); err != nil {
			return err
		}
	}

	for idx, r := range b.RpkiServers {
		if r.Config.Port == 0 {
			b.RpkiServers[idx].Config.Port = rtr.RPKI_DEFAULT_PORT
		}
	}

	list, err = extractArray(v.Get("policy-definitions"))
	if err != nil {
		return err
	}

	for idx, p := range b.PolicyDefinitions {
		vv := viper.New()
		if len(list) > idx {
			vv.Set("policy", list[idx])
		}
		if err := setDefaultPolicyConfigValuesWithViper(vv, &p); err != nil {
			return err
		}
		b.PolicyDefinitions[idx] = p
	}

	return nil
}

func OverwriteNeighborConfigWithPeerGroup(c *Neighbor, pg *PeerGroup) error {
	v := viper.New()

	val, ok := configuredFields[c.State.NeighborAddress]
	if ok {
		v.Set("neighbor", val)
	} else {
		v.Set("neighbor.config.peer-group", c.Config.PeerGroup)
	}

	overwriteConfig(&c.Config, &pg.Config, "neighbor.config", v)
	overwriteConfig(&c.Timers.Config, &pg.Timers.Config, "neighbor.timers.config", v)
	overwriteConfig(&c.Transport.Config, &pg.Transport.Config, "neighbor.transport.config", v)
	overwriteConfig(&c.ErrorHandling.Config, &pg.ErrorHandling.Config, "neighbor.error-handling.config", v)
	overwriteConfig(&c.LoggingOptions.Config, &pg.LoggingOptions.Config, "neighbor.logging-options.config", v)
	overwriteConfig(&c.EbgpMultihop.Config, &pg.EbgpMultihop.Config, "neighbor.ebgp-multihop.config", v)
	overwriteConfig(&c.RouteReflector.Config, &pg.RouteReflector.Config, "neighbor.route-reflector.config", v)
	overwriteConfig(&c.AsPathOptions.Config, &pg.AsPathOptions.Config, "neighbor.as-path-options.config", v)
	overwriteConfig(&c.AddPaths.Config, &pg.AddPaths.Config, "neighbor.add-paths.config", v)
	overwriteConfig(&c.GracefulRestart.Config, &pg.GracefulRestart.Config, "neighbor.gradeful-restart.config", v)
	overwriteConfig(&c.ApplyPolicy.Config, &pg.ApplyPolicy.Config, "neighbor.apply-policy.config", v)
	overwriteConfig(&c.UseMultiplePaths.Config, &pg.UseMultiplePaths.Config, "neighbor.use-multiple-paths.config", v)
	overwriteConfig(&c.RouteServer.Config, &pg.RouteServer.Config, "neighbor.route-server.config", v)
	overwriteConfig(&c.TtlSecurity.Config, &pg.TtlSecurity.Config, "neighbor.ttl-security.config", v)

	if !v.IsSet("neighbor.afi-safis") {
		c.AfiSafis = pg.AfiSafis
	}

	return nil
}

func overwriteConfig(c, pg interface{}, tagPrefix string, v *viper.Viper) {
	nValue := reflect.Indirect(reflect.ValueOf(c))
	nType := reflect.Indirect(nValue).Type()
	pgValue := reflect.Indirect(reflect.ValueOf(pg))
	pgType := reflect.Indirect(pgValue).Type()

	for i := 0; i < pgType.NumField(); i++ {
		field := pgType.Field(i).Name
		tag := tagPrefix + "." + nType.Field(i).Tag.Get("mapstructure")
		if func() bool {
			for _, t := range forcedOverwrittenConfig {
				if t == tag {
					return true
				}
			}
			return false
		}() || !v.IsSet(tag) {
			nValue.FieldByName(field).Set(pgValue.FieldByName(field))
		}
	}
}
