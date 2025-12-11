package storage

import (
	"errors"
	"fmt"

	"github.com/sluggisty/snail-shell/internal/config"
	"github.com/sluggisty/snail-shell/internal/models"
)

// Common errors
var (
	ErrNotFound = errors.New("not found")
)

// Storage defines the interface for host storage
type Storage interface {
	// SaveHost stores or updates a host's report (replaces any previous data)
	SaveHost(report *models.Report) error

	// GetHost returns the full report data for a specific host
	GetHost(hostname string) (*models.Report, error)

	// DeleteHost removes a host
	DeleteHost(hostname string) error

	// ListHosts returns all hosts with summary info
	ListHosts() ([]*models.HostSummary, error)

	// GetAllHosts returns all hosts with their full report data
	GetAllHosts() ([]*models.Report, error)

	// Close closes the storage connection
	Close() error
}

// New creates a new PostgreSQL storage instance
func New(cfg config.StorageConfig) (Storage, error) {
	if cfg.DSN == "" {
		return nil, fmt.Errorf("DATABASE_URL or storage.dsn is required")
	}
	return NewPostgresStorage(cfg.DSN)
}
