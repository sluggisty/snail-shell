package handlers

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
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
			"health":          "GET /health",
			"ingest":          "POST /api/v1/ingest",
			"hosts":           "GET /api/v1/hosts",
			"host":            "GET /api/v1/hosts/{hostname}",
			"vulnerabilities": "GET /api/v1/vulnerabilities",
			"cve_detail":      "GET /api/v1/vulnerabilities/{cveId}",
			"compliance":      "GET /api/v1/compliance",
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
		ID:         req.Meta.Hostname, // Use hostname as ID
		ReceivedAt: now,
		Meta:       req.Meta,
		Data:       req.Data,
		Errors:     req.Errors,
	}

	// Store the report (replaces any previous data for this host)
	if err := h.storage.SaveHost(report); err != nil {
		log.Error().Err(err).Str("hostname", req.Meta.Hostname).Msg("Failed to save host data")
		http.Error(w, `{"error": "failed to store host data"}`, http.StatusInternalServerError)
		return
	}

	log.Info().
		Str("hostname", req.Meta.Hostname).
		Str("collection_id", req.Meta.CollectionID).
		Int("errors", len(req.Errors)).
		Msg("Host data updated")

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(models.IngestResponse{
		Status:     "ok",
		ReportID:   req.Meta.Hostname,
		ReceivedAt: now.Format(time.RFC3339),
		Message:    "Host data updated successfully",
	})
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

// GetHost returns the full data for a specific host
func (h *Handlers) GetHost(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")
	if hostname == "" {
		http.Error(w, `{"error": "missing hostname"}`, http.StatusBadRequest)
		return
	}

	report, err := h.storage.GetHost(hostname)
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
	json.NewEncoder(w).Encode(report)
}

// DeleteHost removes a host
func (h *Handlers) DeleteHost(w http.ResponseWriter, r *http.Request) {
	hostname := chi.URLParam(r, "hostname")
	if hostname == "" {
		http.Error(w, `{"error": "missing hostname"}`, http.StatusBadRequest)
		return
	}

	if err := h.storage.DeleteHost(hostname); err != nil {
		if err == storage.ErrNotFound {
			http.Error(w, `{"error": "host not found"}`, http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("hostname", hostname).Msg("Failed to delete host")
		http.Error(w, `{"error": "failed to delete host"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetVulnerabilities returns aggregated CVE data across all hosts
func (h *Handlers) GetVulnerabilities(w http.ResponseWriter, r *http.Request) {
	reports, err := h.storage.GetAllHosts()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get hosts")
		http.Error(w, `{"error": "failed to retrieve hosts"}`, http.StatusInternalServerError)
		return
	}

	aggregation := h.aggregateVulnerabilities(reports)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(aggregation)
}

// GetCVEDetail returns detailed information about a specific CVE
func (h *Handlers) GetCVEDetail(w http.ResponseWriter, r *http.Request) {
	cveID := chi.URLParam(r, "cveId")
	if cveID == "" {
		http.Error(w, `{"error": "missing CVE ID"}`, http.StatusBadRequest)
		return
	}

	reports, err := h.storage.GetAllHosts()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get hosts")
		http.Error(w, `{"error": "failed to retrieve hosts"}`, http.StatusInternalServerError)
		return
	}

	aggregation := h.aggregateVulnerabilities(reports)

	// Find the specific CVE
	var cveDetail *models.AggregatedCVE
	for i := range aggregation.CVEs {
		if aggregation.CVEs[i].CVEID == cveID {
			cveDetail = &aggregation.CVEs[i]
			break
		}
	}

	if cveDetail == nil {
		http.Error(w, `{"error": "CVE not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cveDetail)
}

func (h *Handlers) aggregateVulnerabilities(reports []*models.Report) *models.VulnerabilitiesAggregation {
	result := &models.VulnerabilitiesAggregation{
		TotalHosts:  len(reports),
		GeneratedAt: time.Now().UTC(),
		CVEs:        []models.AggregatedCVE{},
	}

	cveMap := make(map[string]*models.AggregatedCVE)
	hostsWithVulns := make(map[string]bool)
	cvePackages := make(map[string]map[string]bool)

	for _, report := range reports {
		vulnData, err := report.ParseVulnerabilityData()
		if err != nil || vulnData == nil || !vulnData.ScanCompleted {
			continue
		}

		hostname := report.Meta.Hostname
		lastSeen := report.ReceivedAt

		if len(vulnData.Vulnerabilities) > 0 {
			hostsWithVulns[hostname] = true
		}

		for _, vuln := range vulnData.Vulnerabilities {
			cveID := vuln.CVEID
			if cveID == "" {
				continue
			}

			if existing, ok := cveMap[cveID]; ok {
				// Check if host already exists
				found := false
				for i, h := range existing.AffectedHosts {
					if h.Hostname == hostname {
						found = true
						// Update timestamp if this report is newer
						if h.LastSeen.Before(lastSeen) {
							existing.AffectedHosts[i].LastSeen = lastSeen
						}
						break
					}
				}
				if !found {
					existing.AffectedHosts = append(existing.AffectedHosts, models.AffectedHost{
						Hostname: hostname,
						LastSeen: lastSeen,
					})
					existing.AffectedCount++
				}
				if vuln.PackageName != "" {
					if cvePackages[cveID] == nil {
						cvePackages[cveID] = make(map[string]bool)
					}
					cvePackages[cveID][vuln.PackageName] = true
				}
				if existing.FixedVersion == "" && vuln.FixedVersion != "" {
					existing.FixedVersion = vuln.FixedVersion
				}
			} else {
				agg := &models.AggregatedCVE{
					CVEID:         cveID,
					Severity:      vuln.Severity,
					Title:         vuln.Title,
					Description:   truncateString(vuln.Description, 500),
					PrimaryURL:    vuln.PrimaryURL,
					FixedVersion:  vuln.FixedVersion,
					PublishedDate: vuln.PublishedDate,
					AffectedHosts: []models.AffectedHost{
						{
							Hostname: hostname,
							LastSeen: lastSeen,
						},
					},
					AffectedCount: 1,
				}

				if vuln.CVSS != nil {
					if v3Score, ok := vuln.CVSS["v3_score"].(float64); ok {
						agg.CVSSv3Score = v3Score
					}
				}

				cveMap[cveID] = agg

				if vuln.PackageName != "" {
					cvePackages[cveID] = map[string]bool{vuln.PackageName: true}
				}

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

	cves := make([]models.AggregatedCVE, 0, len(cveMap))
	for cveID, agg := range cveMap {
		if pkgs, ok := cvePackages[cveID]; ok {
			for pkg := range pkgs {
				agg.PackageNames = append(agg.PackageNames, pkg)
			}
		}
		// Sort affected hosts by last seen (most recent first)
		for i := 0; i < len(agg.AffectedHosts)-1; i++ {
			for j := i + 1; j < len(agg.AffectedHosts); j++ {
				if agg.AffectedHosts[i].LastSeen.Before(agg.AffectedHosts[j].LastSeen) {
					agg.AffectedHosts[i], agg.AffectedHosts[j] = agg.AffectedHosts[j], agg.AffectedHosts[i]
				}
			}
		}
		cves = append(cves, *agg)
	}

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

// GetCompliance returns aggregated compliance policy data across all hosts
func (h *Handlers) GetCompliance(w http.ResponseWriter, r *http.Request) {
	reports, err := h.storage.GetAllHosts()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get hosts")
		http.Error(w, `{"error": "failed to retrieve hosts"}`, http.StatusInternalServerError)
		return
	}

	aggregation := h.aggregateCompliance(reports)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(aggregation)
}

func (h *Handlers) aggregateCompliance(reports []*models.Report) *models.ComplianceAggregation {
	result := &models.ComplianceAggregation{
		TotalHosts:  len(reports),
		GeneratedAt: time.Now().UTC(),
		Policies:    []models.AggregatedPolicy{},
	}

	policyMap := make(map[string]*models.AggregatedPolicy)
	hostsWithCompliance := make(map[string]bool)

	for _, report := range reports {
		compData, err := report.ParseComplianceData()
		if err != nil || compData == nil || !compData.ScanCompleted {
			continue
		}

		hostname := report.Meta.Hostname
		hostsWithCompliance[hostname] = true

		profileID := ""
		profileName := ""
		if compData.ProfileInfo != nil {
			profileID = compData.ProfileInfo.ID
			profileName = compData.ProfileInfo.Name
		}
		if profileID == "" {
			profileID = "unknown"
			profileName = "Unknown Profile"
		}

		hostResult := models.HostComplianceResult{
			Hostname:    hostname,
			FailedRules: []models.ComplianceRule{},
		}

		if compData.Summary != nil {
			hostResult.Score = compData.Summary.Score
			hostResult.PassCount = compData.Summary.Pass
			hostResult.FailCount = compData.Summary.Fail
			hostResult.ErrorCount = compData.Summary.Error
			hostResult.TotalRules = compData.Summary.TotalRules
		}

		if compData.ScanTime != nil {
			hostResult.ScanTime = compData.ScanTime.End
		}

		failedCount := 0
		for _, rule := range compData.Rules {
			if rule.Status == "fail" || rule.Status == "error" {
				hostResult.FailedRules = append(hostResult.FailedRules, rule)
				failedCount++
				if failedCount >= 20 {
					break
				}
			}
		}

		if existing, ok := policyMap[profileID]; ok {
			existing.HostCount++
			existing.HostResults = append(existing.HostResults, hostResult)
			totalScore := 0.0
			for _, hr := range existing.HostResults {
				totalScore += hr.Score
			}
			existing.AverageScore = totalScore / float64(len(existing.HostResults))

			if hostResult.Score >= 100 {
				existing.TotalPassing++
			} else {
				existing.TotalFailing++
			}
		} else {
			passing := 0
			failing := 0
			if hostResult.Score >= 100 {
				passing = 1
			} else {
				failing = 1
			}

			policyMap[profileID] = &models.AggregatedPolicy{
				ProfileID:    profileID,
				ProfileName:  profileName,
				ContentFile:  compData.ContentFile,
				HostCount:    1,
				AverageScore: hostResult.Score,
				TotalPassing: passing,
				TotalFailing: failing,
				HostResults:  []models.HostComplianceResult{hostResult},
			}
		}
	}

	policies := make([]models.AggregatedPolicy, 0, len(policyMap))
	for _, policy := range policyMap {
		sortHostResultsByScore(policy.HostResults)
		policies = append(policies, *policy)
	}

	for i := 0; i < len(policies)-1; i++ {
		for j := i + 1; j < len(policies); j++ {
			if policies[i].HostCount < policies[j].HostCount {
				policies[i], policies[j] = policies[j], policies[i]
			}
		}
	}

	result.HostsWithCompliance = len(hostsWithCompliance)
	result.TotalPolicies = len(policies)
	result.Policies = policies

	return result
}

func sortHostResultsByScore(results []models.HostComplianceResult) {
	for i := 0; i < len(results)-1; i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i].Score > results[j].Score {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
}
