package storage

import (
	"errors"

	"github.com/sluggisty/snail-shell/internal/config"
	"github.com/sluggisty/snail-shell/internal/models"
)

// Common errors
var (
	ErrNotFound = errors.New("not found")
)

// Storage defines the interface for report storage
type Storage interface {
	// SaveReport stores a new report
	SaveReport(report *models.Report) error

	// GetReport retrieves a report by ID
	GetReport(id string) (*models.Report, error)

	// DeleteReport removes a report by ID
	DeleteReport(id string) error

	// ListReports returns reports with pagination
	// If hostname is empty, returns all reports
	ListReports(hostname string, limit, offset int) ([]*models.Report, int, error)

	// ListHosts returns all known hosts
	ListHosts() ([]*models.HostSummary, error)

	// GetHost returns summary for a specific host
	GetHost(hostname string) (*models.HostSummary, error)

	// Close closes the storage connection
	Close() error
}

// New creates a new storage instance based on configuration
func New(cfg config.StorageConfig) (Storage, error) {
	switch cfg.Type {
	case "file", "":
		return NewFileStorage(cfg.Path, cfg.MaxReports)
	default:
		return NewFileStorage(cfg.Path, cfg.MaxReports)
	}
}
