# Test Data Generation

Snail Shell includes a test data generator to create realistic test data for development and testing.

## Usage

### Command Line

```bash
# Generate 50 test hosts (default)
./bin/snail-shell -generate-test-data

# Generate specific number of hosts
./bin/snail-shell -generate-test-data -test-hosts 100

# Generate 200 hosts for large-scale testing
./bin/snail-shell -generate-test-data -test-hosts 200
```

### Using Make

```bash
# Generate 50 test hosts
make test-data

# Generate 200 test hosts
make test-data-large
```

### Using Docker Compose

```bash
# First, make sure postgres is running
docker compose up -d postgres

# Wait for postgres to be ready (about 10 seconds)
sleep 10

# Generate 50 test hosts
docker compose run --rm snail-shell -generate-test-data

# Generate 100 test hosts
docker compose run --rm snail-shell -generate-test-data -test-hosts 100

# Generate 200 test hosts
docker compose run --rm snail-shell -generate-test-data -test-hosts 200
```

**One-liner:**
```bash
docker compose up -d postgres && sleep 10 && docker compose run --rm snail-shell -generate-test-data -test-hosts 200
```

## What Gets Generated

Each test host includes:

### System Information
- Fedora Linux versions (36-42)
- Kernel versions
- Hostnames (e.g., `web-42-1`, `db-41-5`)
- Uptime information
- Virtualization details

### Hardware Data
- CPU models (Intel/AMD)
- Memory (4GB - 128GB)
- Disk partitions
- Load averages

### Network Data
- Network interfaces
- IP addresses
- MAC addresses
- DNS configuration

### Packages
- Package counts (500-2500 packages)
- Upgradeable packages
- Security updates

### Services
- Running services (sshd, nginx, postgresql, etc.)
- Service status

### Vulnerabilities (85% of hosts)
- 0-8 CVEs per host
- Mix of severities (CRITICAL, HIGH, MEDIUM, LOW)
- Realistic CVE IDs and descriptions
- CVSS scores
- Package information
- Published dates

### Compliance (70% of hosts)
- OpenSCAP scan results
- Compliance scores (60-100)
- Pass/fail rule counts
- Profile information

## Test Data Characteristics

- **Hostnames**: Mix of prefixes (web, db, app, cache, etc.) with Fedora versions
- **Timestamps**: Hosts report at different times (0-30 days ago)
- **Vulnerabilities**: Realistic distribution - some hosts have many CVEs, some have none
- **Compliance**: Varying scores to test different compliance states
- **Variety**: Different Fedora versions, hardware configs, and service setups

## Example Output

```
INFO Generating test data count=50
INFO Storing test data...
INFO Progress progress=10 total=50
INFO Progress progress=20 total=50
INFO Progress progress=30 total=50
INFO Progress progress=40 total=50
INFO Progress progress=50 total=50
INFO Test data generation complete! hosts_created=50
```

## Use Cases

- **Frontend Development**: Test UI with lots of hosts and data
- **Performance Testing**: Test aggregation with many hosts
- **Feature Development**: Have realistic data while building features
- **Demo/Testing**: Quickly populate database for demos

## Notes

- Test data is stored in your configured storage backend
- Existing hosts with the same hostname will be overwritten
- Generated data uses realistic but fake CVE IDs (CVE-2024-12345, etc.)
- All data is randomly generated but follows realistic patterns
