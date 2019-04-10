EXECUTABLE :=gobgp
SOURCES ?= $(shell find . -name "*.go" -type f)
PACKAGES ?= $(shell go list ./... | grep -v /vendor/)

GOFMT ?= gofmt
GOFILES := $(shell find . ! -name "*_test.go" -name "*.go" -type f -not -path "./vendor/*")
RACE := -race

ifneq ($(shell go env GOARCH), amd64)
	RACE =
endif

all: build

build: $(EXECUTABLE)

$(EXECUTABLE): $(SOURCES)
	go build -v -o bin/$@ ./cmd/gobgp/
	go build -v -o bin/$@d ./cmd/gobgpd/

.PHONY: fmt
fmt:
	$(GOFMT) -w $(GOFILES)

.PHONY: test
test: fmt
	go test $(RACE) $(PACKAGES) -timeout 120s