package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stillness/snail-shell/internal/models"
)

// FileStorage implements Storage using the filesystem
type FileStorage struct {
	basePath   string
	maxReports int
	mu         sync.RWMutex

	// In-memory index for fast lookups
	reports    map[string]*models.Report
	hostIndex  map[string][]string // hostname -> report IDs
}

// NewFileStorage creates a new file-based storage
func NewFileStorage(path string, maxReports int) (*FileStorage, error) {
	// Create directories if they don't exist
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, err
	}

	fs := &FileStorage{
		basePath:   path,
		maxReports: maxReports,
		reports:    make(map[string]*models.Report),
		hostIndex:  make(map[string][]string),
	}

	// Load existing reports
	if err := fs.loadExisting(); err != nil {
		log.Warn().Err(err).Msg("Failed to load some existing reports")
	}

	log.Info().
		Str("path", path).
		Int("loaded", len(fs.reports)).
		Msg("File storage initialized")

	return fs, nil
}

func (fs *FileStorage) loadExisting() error {
	entries, err := os.ReadDir(fs.basePath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		path := filepath.Join(fs.basePath, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Warn().Err(err).Str("file", entry.Name()).Msg("Failed to read report file")
			continue
		}

		var report models.Report
		if err := json.Unmarshal(data, &report); err != nil {
			log.Warn().Err(err).Str("file", entry.Name()).Msg("Failed to parse report file")
			continue
		}

		fs.reports[report.ID] = &report
		fs.hostIndex[report.Meta.Hostname] = append(fs.hostIndex[report.Meta.Hostname], report.ID)
	}

	return nil
}

// SaveReport stores a new report
func (fs *FileStorage) SaveReport(report *models.Report) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Serialize to JSON
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	// Write to file
	filename := filepath.Join(fs.basePath, report.ID+".json")
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return err
	}

	// Update in-memory index
	fs.reports[report.ID] = report
	fs.hostIndex[report.Meta.Hostname] = append(fs.hostIndex[report.Meta.Hostname], report.ID)

	// Enforce max reports limit
	fs.enforceLimit()

	return nil
}

func (fs *FileStorage) enforceLimit() {
	if fs.maxReports <= 0 || len(fs.reports) <= fs.maxReports {
		return
	}

	// Sort by received time
	type reportTime struct {
		id   string
		time time.Time
	}
	var times []reportTime
	for id, r := range fs.reports {
		times = append(times, reportTime{id: id, time: r.ReceivedAt})
	}
	sort.Slice(times, func(i, j int) bool {
		return times[i].time.Before(times[j].time)
	})

	// Remove oldest reports
	toRemove := len(fs.reports) - fs.maxReports
	for i := 0; i < toRemove; i++ {
		id := times[i].id
		if report, ok := fs.reports[id]; ok {
			// Remove from host index
			hostname := report.Meta.Hostname
			ids := fs.hostIndex[hostname]
			for j, rid := range ids {
				if rid == id {
					fs.hostIndex[hostname] = append(ids[:j], ids[j+1:]...)
					break
				}
			}

			// Delete file
			os.Remove(filepath.Join(fs.basePath, id+".json"))
			delete(fs.reports, id)
		}
	}

	log.Debug().Int("removed", toRemove).Msg("Enforced report limit")
}

// GetReport retrieves a report by ID
func (fs *FileStorage) GetReport(id string) (*models.Report, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	report, ok := fs.reports[id]
	if !ok {
		return nil, ErrNotFound
	}
	return report, nil
}

// DeleteReport removes a report by ID
func (fs *FileStorage) DeleteReport(id string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	report, ok := fs.reports[id]
	if !ok {
		return ErrNotFound
	}

	// Remove from host index
	hostname := report.Meta.Hostname
	ids := fs.hostIndex[hostname]
	for i, rid := range ids {
		if rid == id {
			fs.hostIndex[hostname] = append(ids[:i], ids[i+1:]...)
			break
		}
	}

	// Delete file
	if err := os.Remove(filepath.Join(fs.basePath, id+".json")); err != nil && !os.IsNotExist(err) {
		return err
	}

	delete(fs.reports, id)
	return nil
}

// ListReports returns reports with pagination
func (fs *FileStorage) ListReports(hostname string, limit, offset int) ([]*models.Report, int, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	// Get relevant report IDs
	var ids []string
	if hostname != "" {
		ids = fs.hostIndex[hostname]
	} else {
		for id := range fs.reports {
			ids = append(ids, id)
		}
	}

	// Sort by received time (newest first)
	sort.Slice(ids, func(i, j int) bool {
		ri := fs.reports[ids[i]]
		rj := fs.reports[ids[j]]
		return ri.ReceivedAt.After(rj.ReceivedAt)
	})

	total := len(ids)

	// Apply pagination
	if offset >= len(ids) {
		return []*models.Report{}, total, nil
	}
	ids = ids[offset:]
	if len(ids) > limit {
		ids = ids[:limit]
	}

	// Collect reports
	reports := make([]*models.Report, len(ids))
	for i, id := range ids {
		reports[i] = fs.reports[id]
	}

	return reports, total, nil
}

// ListHosts returns all known hosts
func (fs *FileStorage) ListHosts() ([]*models.HostSummary, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var hosts []*models.HostSummary

	for hostname, ids := range fs.hostIndex {
		if len(ids) == 0 {
			continue
		}

		summary := &models.HostSummary{
			Hostname:    hostname,
			ReportCount: len(ids),
		}

		// Find first/last seen and latest report
		for _, id := range ids {
			report := fs.reports[id]
			if summary.FirstSeen.IsZero() || report.ReceivedAt.Before(summary.FirstSeen) {
				summary.FirstSeen = report.ReceivedAt
			}
			if report.ReceivedAt.After(summary.LastSeen) {
				summary.LastSeen = report.ReceivedAt
				summary.LatestReport = report.ID
			}
		}

		hosts = append(hosts, summary)
	}

	// Sort by last seen (newest first)
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].LastSeen.After(hosts[j].LastSeen)
	})

	return hosts, nil
}

// GetHost returns summary for a specific host
func (fs *FileStorage) GetHost(hostname string) (*models.HostSummary, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	ids, ok := fs.hostIndex[hostname]
	if !ok || len(ids) == 0 {
		return nil, ErrNotFound
	}

	summary := &models.HostSummary{
		Hostname:    hostname,
		ReportCount: len(ids),
	}

	for _, id := range ids {
		report := fs.reports[id]
		if summary.FirstSeen.IsZero() || report.ReceivedAt.Before(summary.FirstSeen) {
			summary.FirstSeen = report.ReceivedAt
		}
		if report.ReceivedAt.After(summary.LastSeen) {
			summary.LastSeen = report.ReceivedAt
			summary.LatestReport = report.ID
		}
	}

	return summary, nil
}

// Close closes the storage
func (fs *FileStorage) Close() error {
	// Nothing to close for file storage
	return nil
}

