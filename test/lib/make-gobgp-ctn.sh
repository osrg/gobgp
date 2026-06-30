#!/bin/bash
set -eu

TAG="gobgp"
FROM_IMAGE="osrg/quagga"

usage() {
    echo "Usage: $0 [--tag TAG] [--from-image IMAGE]"
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --tag)
            TAG="$2"
            shift 2
            ;;
        --from-image)
            FROM_IMAGE="$2"
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GOBGP_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$GOBGP_ROOT"

CGO_ENABLED=0 go build "-ldflags=-s -w -buildid=" ./cmd/gobgp
CGO_ENABLED=0 go build "-ldflags=-s -w -buildid=" ./cmd/gobgpd

cat > Dockerfile <<EOF
FROM ${FROM_IMAGE}
COPY gobgpd /go/bin/gobgpd
COPY gobgp /go/bin/gobgp
EOF

docker build -t "$TAG" .
rm Dockerfile
