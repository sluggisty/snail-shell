package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"github.com/rs/zerolog/log"
	"github.com/sluggisty/snail-shell/internal/models"
)

// PostgresStorage implements Storage using PostgreSQL
type PostgresStorage struct {
	db         *sql.DB
	maxReports int
}

// NewPostgresStorage creates a new PostgreSQL-backed storage
func NewPostgresStorage(dsn string, maxReports int) (*PostgresStorage, error) {
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
		db:         db,
		maxReports: maxReports,
	}

	// Initialize schema
	if err := ps.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	log.Info().Msg("PostgreSQL storage initialized")

	return ps, nil
}

func (ps *PostgresStorage) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS reports (
		id TEXT PRIMARY KEY,
		received_at TIMESTAMPTZ NOT NULL,
		hostname TEXT NOT NULL,
		collection_id TEXT,
		timestamp TEXT,
		snail_version TEXT,
		data JSONB NOT NULL,
		errors TEXT[]
	);

	CREATE INDEX IF NOT EXISTS idx_reports_hostname ON reports(hostname);
	CREATE INDEX IF NOT EXISTS idx_reports_received_at ON reports(received_at DESC);
	CREATE INDEX IF NOT EXISTS idx_reports_hostname_received ON reports(hostname, received_at DESC);
	`

	_, err := ps.db.Exec(schema)
	return err
}

// SaveReport stores a new report
func (ps *PostgresStorage) SaveReport(report *models.Report) error {
	query := `
		INSERT INTO reports (id, received_at, hostname, collection_id, timestamp, snail_version, data, errors)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			received_at = EXCLUDED.received_at,
			hostname = EXCLUDED.hostname,
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
		report.ID,
		report.ReceivedAt,
		report.Meta.Hostname,
		report.Meta.CollectionID,
		report.Meta.Timestamp,
		report.Meta.SnailVersion,
		report.Data,
		errors,
	)

	if err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}

	// Enforce max reports limit
	if ps.maxReports > 0 {
		ps.enforceLimit()
	}

	return nil
}

func (ps *PostgresStorage) enforceLimit() {
	if ps.maxReports <= 0 {
		return
	}

	// Delete oldest reports beyond the limit
	query := `
		DELETE FROM reports
		WHERE id IN (
			SELECT id FROM reports
			ORDER BY received_at DESC
			OFFSET $1
		)
	`

	result, err := ps.db.Exec(query, ps.maxReports)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to enforce report limit")
		return
	}

	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Debug().Int64("removed", rows).Msg("Enforced report limit")
	}
}

// GetReport retrieves a report by ID
func (ps *PostgresStorage) GetReport(id string) (*models.Report, error) {
	query := `
		SELECT id, received_at, hostname, collection_id, timestamp, snail_version, data, errors
		FROM reports
		WHERE id = $1
	`

	report := &models.Report{}
	var errors []string

	err := ps.db.QueryRow(query, id).Scan(
		&report.ID,
		&report.ReceivedAt,
		&report.Meta.Hostname,
		&report.Meta.CollectionID,
		&report.Meta.Timestamp,
		&report.Meta.SnailVersion,
		&report.Data,
		(*[]string)(&errors),
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get report: %w", err)
	}

	report.Errors = errors
	return report, nil
}

// DeleteReport removes a report by ID
func (ps *PostgresStorage) DeleteReport(id string) error {
	result, err := ps.db.Exec("DELETE FROM reports WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete report: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// ListReports returns reports with pagination
func (ps *PostgresStorage) ListReports(hostname string, limit, offset int) ([]*models.Report, int, error) {
	var total int
	var reports []*models.Report

	// Get total count
	countQuery := "SELECT COUNT(*) FROM reports"
	countArgs := []interface{}{}

	if hostname != "" {
		countQuery += " WHERE hostname = $1"
		countArgs = append(countArgs, hostname)
	}

	if err := ps.db.QueryRow(countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count reports: %w", err)
	}

	// Get reports
	query := `
		SELECT id, received_at, hostname, collection_id, timestamp, snail_version, data, errors
		FROM reports
	`
	args := []interface{}{}

	if hostname != "" {
		query += " WHERE hostname = $1"
		args = append(args, hostname)
	}

	query += " ORDER BY received_at DESC LIMIT $%d OFFSET $%d"
	if hostname != "" {
		query = fmt.Sprintf(query[:len(query)-24]+" ORDER BY received_at DESC LIMIT $2 OFFSET $3", 2, 3)
		args = append(args, limit, offset)
	} else {
		query = "SELECT id, received_at, hostname, collection_id, timestamp, snail_version, data, errors FROM reports ORDER BY received_at DESC LIMIT $1 OFFSET $2"
		args = append(args, limit, offset)
	}

	rows, err := ps.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list reports: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		report := &models.Report{}
		var errors []string

		if err := rows.Scan(
			&report.ID,
			&report.ReceivedAt,
			&report.Meta.Hostname,
			&report.Meta.CollectionID,
			&report.Meta.Timestamp,
			&report.Meta.SnailVersion,
			&report.Data,
			(*[]string)(&errors),
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan report: %w", err)
		}

		report.Errors = errors
		reports = append(reports, report)
	}

	return reports, total, nil
}

// ListHosts returns all known hosts with their summaries
func (ps *PostgresStorage) ListHosts() ([]*models.HostSummary, error) {
	query := `
		SELECT 
			hostname,
			COUNT(*) as report_count,
			MIN(received_at) as first_seen,
			MAX(received_at) as last_seen
		FROM reports
		GROUP BY hostname
		ORDER BY last_seen DESC
	`

	rows, err := ps.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list hosts: %w", err)
	}
	defer rows.Close()

	var hosts []*models.HostSummary

	for rows.Next() {
		host := &models.HostSummary{}
		if err := rows.Scan(
			&host.Hostname,
			&host.ReportCount,
			&host.FirstSeen,
			&host.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("failed to scan host: %w", err)
		}

		// Get latest report ID and vulnerability summary
		latestQuery := `
			SELECT id, data 
			FROM reports 
			WHERE hostname = $1 
			ORDER BY received_at DESC 
			LIMIT 1
		`
		var latestID string
		var data json.RawMessage
		if err := ps.db.QueryRow(latestQuery, host.Hostname).Scan(&latestID, &data); err == nil {
			host.LatestReport = latestID

			// Parse vulnerability summary from data
			host.LatestVulnerabilitySummary = extractVulnerabilitySummary(data)
		}

		hosts = append(hosts, host)
	}

	return hosts, nil
}

// GetHost returns summary for a specific host
func (ps *PostgresStorage) GetHost(hostname string) (*models.HostSummary, error) {
	query := `
		SELECT 
			hostname,
			COUNT(*) as report_count,
			MIN(received_at) as first_seen,
			MAX(received_at) as last_seen
		FROM reports
		WHERE hostname = $1
		GROUP BY hostname
	`

	host := &models.HostSummary{}
	err := ps.db.QueryRow(query, hostname).Scan(
		&host.Hostname,
		&host.ReportCount,
		&host.FirstSeen,
		&host.LastSeen,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get host: %w", err)
	}

	// Get latest report ID and vulnerability summary
	latestQuery := `
		SELECT id, data 
		FROM reports 
		WHERE hostname = $1 
		ORDER BY received_at DESC 
		LIMIT 1
	`
	var latestID string
	var data json.RawMessage
	if err := ps.db.QueryRow(latestQuery, hostname).Scan(&latestID, &data); err == nil {
		host.LatestReport = latestID
		host.LatestVulnerabilitySummary = extractVulnerabilitySummary(data)
	}

	return host, nil
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
