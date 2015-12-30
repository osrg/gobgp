# BGP Monitoring Protocol

GoBGP supports [BGP Monitoring Protocol](https://datatracker.ietf.org/doc/draft-ietf-grow-bmp/).

## Prerequisites

Assume you finished [Getting Started](https://github.com/osrg/gobgp/blob/master/docs/sources/getting-started.md).

## Contents
- [Configuration](#config)
- [Verification](#verify)

## <a name="config"> Configuration

Add `[BmpServers]` section under `[Global]` to enable BMP like below.

```toml
[Global]
  [Global.Config]
    As = 64512
    RouterId = "192.168.255.1"
  [Global.BmpServers]
    [[Global.BmpServers.BmpServerList]]
      [Global.BmpServers.BmpServerList.Config]
        Address = "127.0.0.1"
        Port=11019
```

## <a name="verify"> Verification

Let's check if BMP works with a bmp server. GoBGP also supports BMP server (currently, just shows received BMP messages in the json format).

```bash
$ go get github.com/osrg/gobgp/gobmpd
$ gobmpd
```

Once the BMP server accepts a connection from gobgpd, then you see
below on the BMP server side.

```bash
INFO[0013] Accepted a new connection from 127.0.0.1:33685
{"Header":{"Version":3,"Length":6,"Type":4},"PeerHeader":{"PeerType":0,"IsPostPolicy":false,"PeerDistinguisher":0,"PeerAddress":"","PeerAS":0,"PeerBGPID":"","Timestamp":0},"Body":{"Info":null}}
```

You also see below on the BGP server side:

```bash
{"level":"info","msg":"bmp server is connected, 127.0.0.1:11019","time":"2015-09-15T10:29:03+09:00"}
```
