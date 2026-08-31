#!/bin/bash
set -eu

TAG="gobgp"
FROM_IMAGE="osrg/quagga"
SKIP_COMPILE=0

usage() {
    echo "Usage: $0 [--tag TAG] [--from-image IMAGE] [--skip-compile]"
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
        --skip-compile)
            SKIP_COMPILE=1
            shift
            ;;
        *)
            usage
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GOBGP_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$GOBGP_ROOT"

if [ "$SKIP_COMPILE" -eq 0 ]; then
    # Limit parallelism to reduce peak RAM (OOM -> "signal: killed" in small VMs).
    export GOMAXPROCS="${GOMAXPROCS:-1}"
    CGO_ENABLED=0 go build -p "${GOMAXPROCS}" "-ldflags=-s -w -buildid=" ./cmd/gobgp
    CGO_ENABLED=0 go build -p "${GOMAXPROCS}" "-ldflags=-s -w -buildid=" ./cmd/gobgpd
fi

cat > Dockerfile <<EOF
FROM ${FROM_IMAGE}
COPY gobgpd /go/bin/gobgpd
COPY gobgp /go/bin/gobgp
EOF

docker build -t "$TAG" .
rm Dockerfile
