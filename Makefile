.PHONY: build run clean test deps fmt lint docker

# Binary name
BINARY=snail-shell
VERSION=0.1.0

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GORUN=$(GOCMD) run
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt

# Build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

# Default target
all: deps build

# Download dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Build the binary
build:
	$(GOBUILD) $(LDFLAGS) -o bin/$(BINARY) ./cmd/snail-shell

# Run the server
run:
	$(GORUN) ./cmd/snail-shell

# Run with debug logging
run-debug:
	$(GORUN) ./cmd/snail-shell -debug

# Generate test data
test-data:
	$(GORUN) ./cmd/snail-shell -generate-test-data -test-hosts 50

# Generate lots of test data
test-data-large:
	$(GORUN) ./cmd/snail-shell -generate-test-data -test-hosts 200

# Clean build artifacts
clean:
	rm -rf bin/
	rm -rf data/

# Run tests
test:
	$(GOTEST) -v ./...

# Format code
fmt:
	$(GOFMT) -w .

# Lint code (requires golangci-lint)
lint:
	golangci-lint run

# Build Docker image
docker:
	docker build -t snail-shell:$(VERSION) .

# Run with Docker
docker-run:
	docker run -p 8080:8080 -v $(PWD)/data:/app/data snail-shell:$(VERSION)

# Development setup
dev-setup:
	mkdir -p data/reports
	cp config.yaml.example config.yaml

# Show help
help:
	@echo "Available targets:"
	@echo "  deps       - Download dependencies"
	@echo "  build      - Build the binary"
	@echo "  run        - Run the server"
	@echo "  run-debug  - Run with debug logging"
	@echo "  test-data  - Generate 50 test hosts"
	@echo "  test-data-large - Generate 200 test hosts"
	@echo "  test       - Run tests"
	@echo "  fmt        - Format code"
	@echo "  lint       - Lint code"
	@echo "  docker     - Build Docker image"
	@echo "  clean      - Clean build artifacts"
	@echo "  dev-setup  - Setup development environment"

