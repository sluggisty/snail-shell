# 🐚 Snail Shell

Backend service for receiving and storing system reports from [snail-core](../snail-core).

Snail Shell provides a REST API for ingesting system diagnostics data, storing reports, and querying host information.

## Features

- **Report Ingestion**: Receives JSON reports from snail-core clients
- **Gzip Support**: Handles compressed uploads automatically
- **API Key Authentication**: Optional Bearer token authentication
- **File-Based Storage**: Simple JSON file storage with in-memory indexing
- **Host Tracking**: Aggregates reports by hostname
- **RESTful API**: Query reports and host information

## Quick Start

### Build and Run

```bash
# Build the binary
make build

# Run the server
./bin/snail-shell

# Or run directly
make run

# Run with debug logging
make run-debug
```

### Docker

```bash
# Build image
make docker

# Run container
docker run -p 8080:8080 -v $(pwd)/data:/app/data snail-shell:0.1.0
```

## Configuration

Create a `config.yaml` file (or copy from `config.yaml.example`):

```yaml
server:
  listen: ":8080"
  read_timeout: 60
  write_timeout: 60

auth:
  enabled: true
  api_keys:
    - your-secret-api-key

storage:
  type: file
  path: ./data/reports
  max_reports: 1000
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SNAIL_LISTEN` | Server listen address (e.g., `:8080`) |
| `SNAIL_API_KEY` | API key for authentication |
| `SNAIL_STORAGE_PATH` | Path for report storage |
| `SNAIL_TLS_CERT` | Path to TLS certificate |
| `SNAIL_TLS_KEY` | Path to TLS private key |

## API Endpoints

### Health & Info

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Server information |
| GET | `/health` | Health check |

### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/ingest` | Receive report from snail-core |
| GET | `/api/v1/reports` | List all reports |
| GET | `/api/v1/reports/{id}` | Get specific report |
| DELETE | `/api/v1/reports/{id}` | Delete a report |

### Hosts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/hosts` | List all known hosts |
| GET | `/api/v1/hosts/{hostname}` | Get host summary |
| GET | `/api/v1/hosts/{hostname}/reports` | Get all reports for host |

## Usage with snail-core

Configure snail-core to upload to this server:

```bash
# Set environment variables
export SNAIL_UPLOAD_URL="http://localhost:8080/api/v1/ingest"
export SNAIL_API_KEY="your-secret-api-key"

# Run collection and upload
snail run
```

Or in the snail-core config file:

```yaml
upload:
  url: http://localhost:8080/api/v1/ingest
  enabled: true

auth:
  api_key: your-secret-api-key
```

## API Examples

### Ingest a Report

```bash
curl -X POST http://localhost:8080/api/v1/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-api-key" \
  -d '{
    "meta": {
      "hostname": "fedora-workstation",
      "collection_id": "abc-123",
      "timestamp": "2024-01-15T10:30:00Z",
      "snail_version": "0.1.0"
    },
    "data": {
      "system": {"os": {"name": "Fedora Linux 41"}}
    },
    "errors": []
  }'
```

### List Reports

```bash
curl http://localhost:8080/api/v1/reports

# With pagination
curl "http://localhost:8080/api/v1/reports?limit=10&offset=0"

# Filter by hostname
curl "http://localhost:8080/api/v1/reports?hostname=fedora-workstation"
```

### Get Specific Report

```bash
curl http://localhost:8080/api/v1/reports/{report-id}
```

### List Hosts

```bash
curl http://localhost:8080/api/v1/hosts
```

### Get Host Reports

```bash
curl http://localhost:8080/api/v1/hosts/fedora-workstation/reports
```

## Development

```bash
# Setup development environment
make dev-setup

# Format code
make fmt

# Run tests
make test

# Build and run
make build && ./bin/snail-shell --debug
```

## Project Structure

```
snail-shell/
├── cmd/
│   └── snail-shell/
│       └── main.go          # Entry point
├── internal/
│   ├── config/
│   │   └── config.go        # Configuration loading
│   ├── handlers/
│   │   └── handlers.go      # HTTP handlers
│   ├── models/
│   │   └── report.go        # Data models
│   ├── server/
│   │   ├── server.go        # HTTP server setup
│   │   └── middleware.go    # Auth & logging middleware
│   └── storage/
│       ├── storage.go       # Storage interface
│       └── file.go          # File-based storage
├── config.yaml.example
├── Dockerfile
├── Makefile
└── README.md
```

## License

Apache License 2.0

