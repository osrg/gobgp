SHELL := /bin/bash -o pipefail

# go environment
go_path := $(shell go env GOPATH)
export GOPATH = $(go_path)
export BUILDTAGS = ""

gomod.vendor:
	$(Q) >&2 GOPRIVATE=bb.yandex-team.ru go mod tidy
	$(Q) >&2 GOPRIVATE=bb.yandex-team.ru go mod vendor

.PHONY: gobgp.deb
gobgp.deb: gomod.vendor
	debuild --preserve-envvar PATH --preserve-envvar GOPATH --preserve-envvar BUILDTAGS -uc -us -b
	rm -f debian
	for i in ../*.changes; do \
	  dcmd mv $$i ./; \
	done

.PHONY: gobgp.deb.upload
gobgp.deb.upload:
	debrelease -t yandex-cloud

# docker build -t gobgp_builder -f builder.Dockerfile .
# docker run --rm -it -v $PWD:/project gobgp_builder make gobgp.gen
.PHONY: gobgp.gen
gobgp.gen:
	./tools/grpc/genproto.sh
	pyang --plugindir tools/pyang_plugins \
		-p /osrg/yang/standard/ietf/RFC \
		-p /osrg/public/release/models \
		-p /osrg/public/release/models/bgp \
		-p /osrg/public/release/models/policy \
		-f golang \
		/osrg/public/release/models/bgp/openconfig-bgp.yang \
		/osrg/public/release/models/policy/openconfig-routing-policy.yang \
		tools/pyang_plugins/gobgp.yang | gofmt > pkg/config/oc/bgp_configs.go || true

# docker build -t gobgp_builder -f builder.Dockerfile .
# docker run --rm -it -v $PWD:/project gobgp_builder make gobgp.test
.PHONY: gobgp.test
gobgp.test:
	go test ./... -v -race

# docker build -t gobgp_builder -f builder.Dockerfile .
# docker run --rm -it -v $PWD:/project gobgp_builder make gobgp.build
.PHONY: gobgp.build
gobgp.build: gobgp.gen
	go build -buildvcs=false -o build/gobgp ./cmd/gobgp
	go build -buildvcs=false -o build/gobgpd ./cmd/gobgpd
