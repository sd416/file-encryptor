.PHONY: build test lint clean install coverage docker help

# Build variables
BINARY_NAME=file-encryptor
BUILD_DIR=bin
VERSION?=dev
GIT_COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Default target
all: build

# Build the application
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) cmd/file-encryptor/main.go cmd/file-encryptor/cli.go cmd/file-encryptor/config.go cmd/file-encryptor/handlers.go cmd/file-encryptor/web_stub.go
	@echo "Built $(BUILD_DIR)/$(BINARY_NAME)"

# Build with web UI
build-web:
	@echo "Building $(BINARY_NAME) with web UI..."
	@mkdir -p $(BUILD_DIR)
	go build -tags web $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-web cmd/file-encryptor/main.go cmd/file-encryptor/cli.go cmd/file-encryptor/config.go cmd/file-encryptor/handlers.go cmd/file-encryptor/web.go
	@echo "Built $(BUILD_DIR)/$(BINARY_NAME)-web"

# Run tests
test:
	@echo "Running tests..."
	sudo go test -v -race ./...

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	sudo go test -v -race -coverprofile=coverage.out ./...
	sudo go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Lint the code
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found. Install it with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		sudo go vet ./...; \
		sudo go fmt ./...; \
	fi

# Security scan
security:
	@echo "Running security scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not found. Install it with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)/ dist/ coverage.out coverage.html
	rm -f *.enc *_test_* test_* key_*

# Install the binary
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "Installed successfully!"

# Build Docker image
docker:
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) .

# Run the test suite script
test-suite:
	@echo "Running comprehensive test suite..."
	./run_tests.sh

# Development setup
dev-setup:
	@echo "Setting up development environment..."
	sudo go mod tidy
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		sudo go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@if ! command -v gosec >/dev/null 2>&1; then \
		echo "Installing gosec..."; \
		sudo go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
	fi

# Release build (optimized)
release:
	@echo "Building release version..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -a -installsuffix cgo $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) cmd/file-encryptor/*.go
	@echo "Release build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Cross-platform builds
build-all:
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 cmd/file-encryptor/*.go
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 cmd/file-encryptor/*.go
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe cmd/file-encryptor/*.go
	@echo "Cross-platform builds complete!"

# Show help
help:
	@echo "Available targets:"
	@echo "  build       - Build the application"
	@echo "  build-web   - Build the application with web UI"
	@echo "  test        - Run tests"
	@echo "  coverage    - Run tests with coverage report"
	@echo "  lint        - Run code linters"
	@echo "  security    - Run security scan"
	@echo "  clean       - Clean build artifacts"
	@echo "  install     - Install binary to /usr/local/bin"
	@echo "  docker      - Build Docker image"
	@echo "  test-suite  - Run comprehensive test suite"
	@echo "  dev-setup   - Set up development environment"
	@echo "  release     - Build optimized release version"
	@echo "  build-all   - Build for multiple platforms"
	@echo "  help        - Show this help message"
