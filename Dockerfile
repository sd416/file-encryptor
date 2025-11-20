# Multi-stage build for optimal image size
FROM golang:1.25-alpine AS builder

# Install git for version information
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build arguments for version information
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown

# Build the application with version information
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME}" \
    -a -installsuffix cgo \
    -o file-encryptor \
    ./cmd/file-encryptor

# Final stage - minimal runtime image
FROM alpine:latest

# Install ca-certificates for HTTPS requests (if needed)
RUN apk --no-cache add ca-certificates

# Create non-root user for security
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/file-encryptor .

# Copy default configuration
COPY --from=builder /app/file-encryptor.yaml .

# Change ownership to non-root user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Create volume for data
VOLUME ["/data"]

# Set default working directory for file operations
WORKDIR /data

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/file-encryptor", "--version"]

# Default command
ENTRYPOINT ["/app/file-encryptor"]
CMD ["--help"]
