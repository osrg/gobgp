# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app
# Copy gobgp root go.mod for replace directive
COPY go.mod go.sum ./
COPY api ./api
COPY pkg ./pkg
COPY proto ./proto
COPY internal ./internal
# Copy only bgp-grpc-forwarder source files
COPY cmd/bgp-grpc-forwarder/go.mod cmd/bgp-grpc-forwarder/go.sum ./cmd/bgp-grpc-forwarder/
COPY cmd/bgp-grpc-forwarder/main.go ./cmd/bgp-grpc-forwarder/
COPY cmd/bgp-grpc-forwarder/config.toml ./cmd/bgp-grpc-forwarder/

WORKDIR /app/cmd/bgp-grpc-forwarder

# Install build dependencies
RUN apk add --no-cache git

# Download dependencies
RUN go mod download

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o bgp-grpc-forwarder

# Final stage
FROM alpine:3.18

WORKDIR /app

# Copy the binary and config from builder
COPY --from=builder /app/cmd/bgp-grpc-forwarder/bgp-grpc-forwarder .
COPY --from=builder /app/cmd/bgp-grpc-forwarder/config.toml .

# Create non-root user
RUN adduser -D -u 1000 gobgp && \
    chown -R gobgp:gobgp /app

USER gobgp

ENTRYPOINT ["/app/bgp-grpc-forwarder"]
