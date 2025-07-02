# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY . .

# Install build dependencies
RUN apk add --no-cache git

# Download dependencies
RUN go mod download

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o bgp-http-forwarder

# Final stage
FROM alpine:3.18

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/bgp-http-forwarder .
COPY config.toml .

# Create non-root user
RUN adduser -D -u 1000 gobgp && \
    chown -R gobgp:gobgp /app

USER gobgp

ENTRYPOINT ["/app/bgp-http-forwarder"]
