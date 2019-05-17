VERSION=$(shell git describe --match 'v[0-9]*' --always --tags)
PKG=github.com/osrg/gobgp

GO_LDFLAGS=-ldflags '-X $(PKG)/internal/pkg/version.Version=$(VERSION)'

.PHONY: binaries
binaries:
	@go build $(GO_LDFLAGS) -o cmd/gobgp/gobgp github.com/osrg/gobgp/cmd/gobgp
	@go build $(GO_LDFLAGS) -o cmd/gobgpd/gobgpd github.com/osrg/gobgp/cmd/gobgpd

.PHONY: clean
clean:
	@rm -f cmd/gobgp/gobgp cmd/gobgpd/gobgpd
