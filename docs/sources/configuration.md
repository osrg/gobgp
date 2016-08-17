# Configuration example

```toml
[global.config]
    as = 1
    router-id = "1.1.1.1"
    # listen port (by default 179)
    port = 1790
    # to disable listening
    # port = -1

    # listen address list (by default "0.0.0.0" and "::")
    local-address-list = ["192.168.10.1", "2001:db8::1"]

    [global.apply-policy.config]
        import-policy-list = ["policy1"]
        default-import-policy = "reject-route"
        export-policy-list = ["policy2"]
        default-export-policy = "accept-route"
    [global.mpls-label-range]
        min-label = 1000
        max-label = 2000

[[rpki-servers]]
    [rpki-servers.config]
        address = "210.173.170.254"
        port = 323

[[bmp-servers]]
    [bmp-servers.config]
        address = "127.0.0.1"
        port = 11019

[[mrt-dump]]
    dump-type = "updates"
    file-name = "/tmp/log/2006/01/02.1504.dump"
    interval = 180

[zebra]
    [zebra.config]
        enabled = true
        url = "unix:/var/run/quagga/zserv.api"
        redistribute-route-type-list = ["connect"]

[[neighbors]]
    [neighbors.config]
        peer-as = 2
        auth-password = "password"
        neighbor-address = "192.168.10.2"
        # override global.config.as value
        local-as = 1000
    [neighbors.timers.config]
        connect-retry = 5
        hold-time = 9
        keepalive-interval = 3
    [neighbors.transport.config]
        passive-mode = true
        local-address = "192.168.10.1"
        remote-port = 2016
    [neighbors.ebgp-multihop.config]
        enabled = true
        multihop-ttl = 100
    [neighbors.route-reflector.config]
        route-reflector-client = true
        route-reflector-cluster-id = "192.168.0.1"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv4-unicast"
        [neighbors.afi-safis.prefix-limit.config]
           max-prefixes = 1000
           shutdown-threshold-pct = 80
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv6-unicast"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv4-labelled-unicast"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv6-labelled-unicast"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "l3vpn-ipv4-unicast"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "l3vpn-ipv6-unicast"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "l2vpn-evpn"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "rtc"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv4-encap"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv6-encap"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv4-flowspec"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv6-flowspec"
    [neighbors.apply-policy.config]
        import-policy-list = ["policy1"]
        default-import-policy = "reject-route"
        export-policy-list = ["policy2"]
        default-export-policy = "accept-route"
        in-policy-list = ["policy3"]
        default-in-policy = "reject-route"
    [neighbors.route-server.config]
        route-server-client = true

[[defined-sets.prefix-sets]]
    prefix-set-name = "ps0"
    [[defined-sets.prefix-sets.prefix-list]]
        ip-prefix = "10.0.0.0/8"
        masklength-range = "24..32"
[[defined-sets.neighbor-sets]]
   neighbor-set-name = "ns0"
   neighbor-info-list = ["192.168.10.2"]
[[defined-sets.bgp-defined-sets.community-sets]]
    community-set-name = "cs0"
    community-list = ["100:100"]
[[defined-sets.bgp-defined-sets.ext-community-sets]]
    ext-community-set-name = "es0"
    ext-community-list = ["rt:100:100", "soo:200:200"]
[[defined-sets.bgp-defined-sets.as-path-sets]]
    as-path-set-name = "as0"
    as-path-list = ["^100", "200$"]

[[policy-definitions]]
    name = "policy1"
    [[policy-definitions.statements]]
        [policy-definitions.statements.conditions.match-prefix-set]
            prefix-set = "ps0"
            match-set-options = "any"
        [policy-definitions.statements.conditions.match-neighbor-set]
            neighbor-set = "ns0"
            match-set-options = "invert"
        [policy-definitions.statements.conditions.bgp-conditions.match-community-set]
            community-set = "cs0"
            match-set-options = "all"
        [policy-definitions.statements.actions.bgp-actions.set-as-path-prepend]
            as = "last-as"
            repeat-n = 5
        [policy-definitions.statements.actions.route-disposition]
            accept-route = true
    [[policy-definitions.statements]]
        [policy-definitions.statements.conditions.bgp-conditions.match-ext-community-set]
            ext-community-set = "es0"
        [policy-definitions.statements.actions.route-disposition]
            accept-route = false

[[policy-definitions]]
    name = "policy2"
    [[policy-definitions.statements]]
        [policy-definitions.statements.conditions.bgp-conditions.match-as-path-set]
            as-path-set = "as0"
        [policy-definitions.statements.actions.route-disposition]
            accept-route = true
        [policy-definitions.statements.actions.bgp-actions.set-community]
            options = "add"
            [policy-definitions.statements.actions.bgp-actions.set-community.set-community-method]
                communities-list = ["100:200"]

[[policy-definitions]]
    name = "policy3"
    [[policy-definitions.statements]]
        [policy-definitions.statements.conditions.bgp-conditions.match-as-path-set]
            as-path-set = "as0"
        [policy-definitions.statements.actions.route-disposition]
            accept-route = true
        [policy-definitions.statements.actions.bgp-actions.set-community]
            options = "add"
            [policy-definitions.statements.actions.bgp-actions.set-community.set-community-method]
                communities-list = ["100:200"]
    [[policy-definitions.statements]]
        [policy-definitions.statements.conditions.match-prefix-set]
            prefix-set = "ps0"
            match-set-options = "invert"
        [policy-definitions.statements.actions.route-disposition]
            accept-route = true
        [policy-definitions.statements.actions.bgp-actions.set-ext-community]
            options = "replace"
            [policy-definitions.statements.actions.bgp-actions.set-ext-community.set-ext-community-method]
                communities-list = ["soo:100:200", "rt:300:400"]
    [[policy-definitions.statements]]
        [policy-definitions.statements.conditions.match-neighbor-set]
            neighbor-set = "ns0"
        [policy-definitions.statements.actions.route-disposition]
            accept-route = true
        [policy-definitions.statements.actions.bgp-actions.set-ext-community]
            options = "remove"
            [policy-definitions.statements.actions.bgp-actions.set-ext-community.set-ext-community-method]
                communities-list = ["soo:500:600", "rt:700:800"]

[[policy-definitions]]
    name = "route-type-policy"
    [[policy-definitions.statements]]
        # this statement matches with locally generated routes 
        [policy-definitions.statements.conditions.bgp-conditions]
            route-type = "local"
        [policy-definitions.statements.actions.route-disposition]
            accept-route = true
    [[policy-definitions.statements]]
        # this statement matches with routes from iBGP peers
        [policy-definitions.statements.conditions.bgp-conditions]
            route-type = "internal"
        [policy-definitions.statements.actions.route-disposition]
            accept-route = true
    [[policy-definitions.statements]]
        # this statement matches with routes from eBGP peers
        [policy-definitions.statements.conditions.bgp-conditions]
            route-type = "external"
        [policy-definitions.statements.actions.route-disposition]
            accept-route = true
```
