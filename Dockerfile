# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')" \
    -o snail-shell ./cmd/snail-shell

# Runtime stage - minimal image
FROM alpine:3.20

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata wget

# Create non-root user for security
RUN adduser -D -g '' -u 1000 appuser

# Copy binary from builder
COPY --from=builder /build/snail-shell .

# Set ownership
RUN chown -R appuser:appuser /app

USER appuser

# Expose port
EXPOSE 8080

# Note: DATABASE_URL environment variable is required for PostgreSQL connection

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the server
ENTRYPOINT ["./snail-shell"]

