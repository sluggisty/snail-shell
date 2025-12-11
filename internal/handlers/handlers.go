package handlers

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/sluggisty/snail-shell/internal/models"
	"github.com/sluggisty/snail-shell/internal/storage"
)

// Handlers contains HTTP handlers
type Handlers struct {
	storage storage.Storage
}

// New creates a new Handlers instance
func New(store storage.Storage) *Handlers {
	return &Handlers{storage: store}
}

// Health returns server health status
func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// Info returns server information
func (h *Handlers) Info(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"name":        "snail-shell",
		"version":     "0.1.0",
		"description": "Backend service for snail-core system reports",
		"endpoints": map[string]string{
			"health":  "GET /health",
			"ingest":  "POST /api/v1/ingest",
			"reports": "GET /api/v1/reports",
			"hosts":   "GET /api/v1/hosts",
		},
	})
}

// Ingest handles incoming reports from snail-core
func (h *Handlers) Ingest(w http.ResponseWriter, r *http.Request) {
	// Handle gzip-compressed requests
	var reader io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(r.Body)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create gzip reader")
			http.Error(w, `{"error": "failed to decompress request"}`, http.StatusBadRequest)
			return
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Parse the request
	var req models.IngestRequest
	if err := json.NewDecoder(reader).Decode(&req); err != nil {
		log.Error().Err(err).Msg("Failed to parse ingest request")
		http.Error(w, `{"error": "invalid JSON payload"}`, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Meta.Hostname == "" {
		http.Error(w, `{"error": "missing hostname in meta"}`, http.StatusBadRequest)
		return
	}

	// Create report
	now := time.Now().UTC()
	report := &models.Report{
		ID:         uuid.New().String(),
		ReceivedAt: now,
		Meta:       req.Meta,
		Data:       req.Data,
		Errors:     req.Errors,
	}

	// Store the report
	if err := h.storage.SaveReport(report); err != nil {
		log.Error().Err(err).Str("hostname", req.Meta.Hostname).Msg("Failed to save report")
		http.Error(w, `{"error": "failed to store report"}`, http.StatusInternalServerError)
		return
	}

	log.Info().
		Str("report_id", report.ID).
		Str("hostname", req.Meta.Hostname).
		Str("collection_id", req.Meta.CollectionID).
		Int("errors", len(req.Errors)).
		Msg("Report ingested")

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(models.IngestResponse{
		Status:     "ok",
		ReportID:   report.ID,
		ReceivedAt: now.Format(time.RFC3339),
		Message:    "Report ingested successfully",
	})
}

// ListReports returns a list of all reports
func (h *Handlers) ListReports(w http.ResponseWriter, r *http.Request) {
	// Parse query params
	limit := 100
	offset := 0
	hostname := r.URL.Query().Get("hostname")

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	reports, total, err := h.storage.ListReports(hostname, limit, offset)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list reports")
		http.Error(w, `{"error": "failed to retrieve reports"}`, http.StatusInternalServerError)
		return
	}

	// Convert to summaries
	summaries := make([]models.ReportSummary, len(reports))
	for i, r := range reports {
		summaries[i] = r.ToSummary()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"reports": summaries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// GetReport returns a specific report by ID
func (h *Handlers) GetReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, `{"error": "missing report id"}`, http.StatusBadRequest)
		return
	}

	report, err := h.storage.GetReport(id)
	if err != nil {
		if err == storage.ErrNotFound {
			http.Error(w, `{"error": "report not found"}`, http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("id", id).Msg("Failed to get report")
		http.Error(w, `{"error": "failed to retrieve report"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

// DeleteReport deletes a report by ID
func (h *Handlers) DeleteReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		http.Error(w, `{"error": "missing report id"}`, http.StatusBadRequest)
		return
	}

	if err := h.storage.DeleteReport(id); err != nil {
		if err == storage.ErrNotFound {
			http.Error(w, `{"error": "report not found"}`, http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("id", id).Msg("Failed to delete report")
		http.Error(w, `{"error": "failed to delete report"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListHosts returns a list of all known hosts
func (h *Handlers) ListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.storage.ListHosts()
	if err != nil {
		log.Error().Err(err).Msg("Failed to list hosts")
		http.Error(w, `{"error": "failed to retrieve hosts"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"hosts": hosts,
		"total": len(hosts),
	})
}

// GetHost returns summary for a specific host
func (h *Handlers) GetHost(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")
	if hostname == "" {
		http.Error(w, `{"error": "missing hostname"}`, http.StatusBadRequest)
		return
	}

	host, err := h.storage.GetHost(hostname)
	if err != nil {
		if err == storage.ErrNotFound {
			http.Error(w, `{"error": "host not found"}`, http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("hostname", hostname).Msg("Failed to get host")
		http.Error(w, `{"error": "failed to retrieve host"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(host)
}

// GetHostReports returns all reports for a specific host
func (h *Handlers) GetHostReports(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")
	if hostname == "" {
		http.Error(w, `{"error": "missing hostname"}`, http.StatusBadRequest)
		return
	}

	reports, total, err := h.storage.ListReports(hostname, 100, 0)
	if err != nil {
		log.Error().Err(err).Str("hostname", hostname).Msg("Failed to get host reports")
		http.Error(w, `{"error": "failed to retrieve reports"}`, http.StatusInternalServerError)
		return
	}

	summaries := make([]models.ReportSummary, len(reports))
	for i, r := range reports {
		summaries[i] = r.ToSummary()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"hostname": hostname,
		"reports":  summaries,
		"total":    total,
	})
}

// GetVulnerabilities returns aggregated CVE data across all hosts
func (h *Handlers) GetVulnerabilities(w http.ResponseWriter, r *http.Request) {
	// Get latest report per host
	reports, err := h.storage.GetLatestReportPerHost()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get latest reports")
		http.Error(w, `{"error": "failed to retrieve reports"}`, http.StatusInternalServerError)
		return
	}

	// Aggregate vulnerabilities across all reports
	aggregation := h.aggregateVulnerabilities(reports)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(aggregation)
}

func (h *Handlers) aggregateVulnerabilities(reports []*models.Report) *models.VulnerabilitiesAggregation {
	result := &models.VulnerabilitiesAggregation{
		TotalHosts:  len(reports),
		GeneratedAt: time.Now().UTC(),
		CVEs:        []models.AggregatedCVE{},
	}

	// Map to aggregate CVEs: cve_id -> aggregated data
	cveMap := make(map[string]*models.AggregatedCVE)
	// Track which hosts have vulnerabilities
	hostsWithVulns := make(map[string]bool)
	// Track packages per CVE
	cvePackages := make(map[string]map[string]bool)

	for _, report := range reports {
		vulnData, err := report.ParseVulnerabilityData()
		if err != nil || vulnData == nil || !vulnData.ScanCompleted {
			continue
		}

		hostname := report.Meta.Hostname

		if len(vulnData.Vulnerabilities) > 0 {
			hostsWithVulns[hostname] = true
		}

		for _, vuln := range vulnData.Vulnerabilities {
			cveID := vuln.CVEID
			if cveID == "" {
				continue
			}

			if existing, ok := cveMap[cveID]; ok {
				// Add this host if not already present
				found := false
				for _, h := range existing.AffectedHosts {
					if h == hostname {
						found = true
						break
					}
				}
				if !found {
					existing.AffectedHosts = append(existing.AffectedHosts, hostname)
					existing.AffectedCount++
				}
				// Track package
				if vuln.PackageName != "" {
					if cvePackages[cveID] == nil {
						cvePackages[cveID] = make(map[string]bool)
					}
					cvePackages[cveID][vuln.PackageName] = true
				}
				// Update fixed version if we have one
				if existing.FixedVersion == "" && vuln.FixedVersion != "" {
					existing.FixedVersion = vuln.FixedVersion
				}
			} else {
				// New CVE
				agg := &models.AggregatedCVE{
					CVEID:         cveID,
					Severity:      vuln.Severity,
					Title:         vuln.Title,
					Description:   truncateString(vuln.Description, 500),
					PrimaryURL:    vuln.PrimaryURL,
					FixedVersion:  vuln.FixedVersion,
					PublishedDate: vuln.PublishedDate,
					AffectedHosts: []string{hostname},
					AffectedCount: 1,
				}

				// Extract CVSS v3 score
				if vuln.CVSS != nil {
					if v3Score, ok := vuln.CVSS["v3_score"].(float64); ok {
						agg.CVSSv3Score = v3Score
					}
				}

				cveMap[cveID] = agg

				// Track package
				if vuln.PackageName != "" {
					cvePackages[cveID] = map[string]bool{vuln.PackageName: true}
				}

				// Update severity counts
				switch vuln.Severity {
				case "CRITICAL":
					result.SeverityCounts.Critical++
				case "HIGH":
					result.SeverityCounts.High++
				case "MEDIUM":
					result.SeverityCounts.Medium++
				case "LOW":
					result.SeverityCounts.Low++
				default:
					result.SeverityCounts.Unknown++
				}
			}
		}
	}

	// Convert map to slice and add package names
	cves := make([]models.AggregatedCVE, 0, len(cveMap))
	for cveID, agg := range cveMap {
		// Add package names
		if pkgs, ok := cvePackages[cveID]; ok {
			for pkg := range pkgs {
				agg.PackageNames = append(agg.PackageNames, pkg)
			}
		}
		cves = append(cves, *agg)
	}

	// Sort by severity (critical first), then by affected count
	severityOrder := map[string]int{
		"CRITICAL": 0,
		"HIGH":     1,
		"MEDIUM":   2,
		"LOW":      3,
		"UNKNOWN":  4,
	}

	for i := 0; i < len(cves)-1; i++ {
		for j := i + 1; j < len(cves); j++ {
			swapNeeded := false
			si := severityOrder[cves[i].Severity]
			sj := severityOrder[cves[j].Severity]
			if si > sj {
				swapNeeded = true
			} else if si == sj && cves[i].AffectedCount < cves[j].AffectedCount {
				swapNeeded = true
			}
			if swapNeeded {
				cves[i], cves[j] = cves[j], cves[i]
			}
		}
	}

	result.HostsWithVulns = len(hostsWithVulns)
	result.TotalUniqueCVEs = len(cves)
	result.SeverityCounts.TotalVulnerabilities = len(cves)
	result.CVEs = cves

	return result
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
