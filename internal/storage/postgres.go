package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/rs/zerolog/log"
	"github.com/sluggisty/snail-shell/internal/models"
)

// PostgresStorage implements Storage using PostgreSQL
type PostgresStorage struct {
	db *sql.DB
}

// NewPostgresStorage creates a new PostgreSQL-backed storage
func NewPostgresStorage(dsn string) (*PostgresStorage, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	ps := &PostgresStorage{
		db: db,
	}

	// Initialize schema
	if err := ps.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	log.Info().Msg("PostgreSQL storage initialized")

	return ps, nil
}

func (ps *PostgresStorage) initSchema() error {
	// Migrate: drop old table if it uses id as primary key, create new one with hostname as primary key
	schema := `
	-- Create hosts table with hostname as primary key (one report per host)
	CREATE TABLE IF NOT EXISTS hosts (
		hostname TEXT PRIMARY KEY,
		received_at TIMESTAMPTZ NOT NULL,
		collection_id TEXT,
		timestamp TEXT,
		snail_version TEXT,
		data JSONB NOT NULL,
		errors TEXT[]
	);

	CREATE INDEX IF NOT EXISTS idx_hosts_received_at ON hosts(received_at DESC);
	`

	_, err := ps.db.Exec(schema)
	return err
}

// SaveHost stores or updates a host's report (replaces any previous report)
func (ps *PostgresStorage) SaveHost(report *models.Report) error {
	query := `
		INSERT INTO hosts (hostname, received_at, collection_id, timestamp, snail_version, data, errors)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (hostname) DO UPDATE SET
			received_at = EXCLUDED.received_at,
			collection_id = EXCLUDED.collection_id,
			timestamp = EXCLUDED.timestamp,
			snail_version = EXCLUDED.snail_version,
			data = EXCLUDED.data,
			errors = EXCLUDED.errors
	`

	var errors []string
	if report.Errors != nil {
		errors = report.Errors
	}

	_, err := ps.db.Exec(query,
		report.Meta.Hostname,
		report.ReceivedAt,
		report.Meta.CollectionID,
		report.Meta.Timestamp,
		report.Meta.SnailVersion,
		report.Data,
		pq.Array(errors),
	)

	if err != nil {
		return fmt.Errorf("failed to save host: %w", err)
	}

	return nil
}

// GetHost returns the full report data for a specific host
func (ps *PostgresStorage) GetHost(hostname string) (*models.Report, error) {
	query := `
		SELECT hostname, received_at, collection_id, timestamp, snail_version, data, errors
		FROM hosts
		WHERE hostname = $1
	`

	report := &models.Report{}
	var errors []string

	err := ps.db.QueryRow(query, hostname).Scan(
		&report.Meta.Hostname,
		&report.ReceivedAt,
		&report.Meta.CollectionID,
		&report.Meta.Timestamp,
		&report.Meta.SnailVersion,
		&report.Data,
		pq.Array(&errors),
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get host: %w", err)
	}

	report.ID = hostname // Use hostname as ID
	report.Errors = errors
	return report, nil
}

// DeleteHost removes a host
func (ps *PostgresStorage) DeleteHost(hostname string) error {
	result, err := ps.db.Exec("DELETE FROM hosts WHERE hostname = $1", hostname)
	if err != nil {
		return fmt.Errorf("failed to delete host: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// ListHosts returns all hosts with summary info
func (ps *PostgresStorage) ListHosts() ([]*models.HostSummary, error) {
	query := `
		SELECT hostname, received_at, data
		FROM hosts
		ORDER BY received_at DESC
	`

	rows, err := ps.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list hosts: %w", err)
	}
	defer rows.Close()

	var hosts []*models.HostSummary

	for rows.Next() {
		var hostname string
		var receivedAt time.Time
		var data json.RawMessage

		if err := rows.Scan(&hostname, &receivedAt, &data); err != nil {
			return nil, fmt.Errorf("failed to scan host: %w", err)
		}

		host := &models.HostSummary{
			Hostname: hostname,
			LastSeen: receivedAt,
		}

		// Parse vulnerability and compliance summaries from data
		host.LatestVulnerabilitySummary = extractVulnerabilitySummary(data)
		host.LatestComplianceSummary = extractComplianceSummary(data)

		hosts = append(hosts, host)
	}

	return hosts, nil
}

// GetAllHosts returns all hosts with their full report data
func (ps *PostgresStorage) GetAllHosts() ([]*models.Report, error) {
	query := `
		SELECT hostname, received_at, collection_id, timestamp, snail_version, data, errors
		FROM hosts
		ORDER BY received_at DESC
	`

	rows, err := ps.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get all hosts: %w", err)
	}
	defer rows.Close()

	var reports []*models.Report
	for rows.Next() {
		report := &models.Report{}
		var errors []string

		if err := rows.Scan(
			&report.Meta.Hostname,
			&report.ReceivedAt,
			&report.Meta.CollectionID,
			&report.Meta.Timestamp,
			&report.Meta.SnailVersion,
			&report.Data,
			pq.Array(&errors),
		); err != nil {
			return nil, fmt.Errorf("failed to scan report: %w", err)
		}

		report.ID = report.Meta.Hostname
		report.Errors = errors
		reports = append(reports, report)
	}

	return reports, nil
}

// Close closes the database connection
func (ps *PostgresStorage) Close() error {
	return ps.db.Close()
}

// extractVulnerabilitySummary parses vulnerability summary from report data
func extractVulnerabilitySummary(data json.RawMessage) *models.VulnerabilitySummary {
	var allData map[string]json.RawMessage
	if err := json.Unmarshal(data, &allData); err != nil {
		return nil
	}

	vulnRaw, ok := allData["vulnerabilities"]
	if !ok {
		return nil
	}

	var vulnData struct {
		ScanCompleted bool                        `json:"scan_completed"`
		Summary       models.VulnerabilitySummary `json:"summary"`
	}

	if err := json.Unmarshal(vulnRaw, &vulnData); err != nil {
		return nil
	}

	if !vulnData.ScanCompleted {
		return nil
	}

	return &vulnData.Summary
}

// extractComplianceSummary parses compliance summary from report data
func extractComplianceSummary(data json.RawMessage) *models.ComplianceSummary {
	var allData map[string]json.RawMessage
	if err := json.Unmarshal(data, &allData); err != nil {
		return nil
	}

	compRaw, ok := allData["compliance"]
	if !ok {
		return nil
	}

	var compData struct {
		ScanCompleted bool                     `json:"scan_completed"`
		Summary       models.ComplianceSummary `json:"summary"`
	}

	if err := json.Unmarshal(compRaw, &compData); err != nil {
		return nil
	}

	if !compData.ScanCompleted {
		return nil
	}

	return &compData.Summary
}
