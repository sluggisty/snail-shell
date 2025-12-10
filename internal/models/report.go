package models

import (
	"encoding/json"
	"time"
)

// Report represents a collection report from snail-core
type Report struct {
	ID         string          `json:"id"`
	ReceivedAt time.Time       `json:"received_at"`
	Meta       ReportMeta      `json:"meta"`
	Data       json.RawMessage `json:"data"`
	Errors     []string        `json:"errors,omitempty"`
}

// ReportMeta contains metadata about the collection
type ReportMeta struct {
	Hostname     string `json:"hostname"`
	CollectionID string `json:"collection_id"`
	Timestamp    string `json:"timestamp"`
	SnailVersion string `json:"snail_version"`
}

// IngestRequest is the incoming request format from snail-core
type IngestRequest struct {
	Meta   ReportMeta      `json:"meta"`
	Data   json.RawMessage `json:"data"`
	Errors []string        `json:"errors,omitempty"`
}

// IngestResponse is returned after successful ingestion
type IngestResponse struct {
	Status     string `json:"status"`
	ReportID   string `json:"report_id"`
	ReceivedAt string `json:"received_at"`
	Message    string `json:"message,omitempty"`
}

// ReportSummary is a compact version for listing
type ReportSummary struct {
	ID                   string                `json:"id"`
	Hostname             string                `json:"hostname"`
	CollectionID         string                `json:"collection_id"`
	Timestamp            string                `json:"timestamp"`
	ReceivedAt           time.Time             `json:"received_at"`
	HasErrors            bool                  `json:"has_errors"`
	VulnerabilitySummary *VulnerabilitySummary `json:"vulnerability_summary,omitempty"`
}

// HostSummary represents aggregated info about a host
type HostSummary struct {
	Hostname                   string                `json:"hostname"`
	ReportCount                int                   `json:"report_count"`
	FirstSeen                  time.Time             `json:"first_seen"`
	LastSeen                   time.Time             `json:"last_seen"`
	LatestReport               string                `json:"latest_report_id"`
	LatestVulnerabilitySummary *VulnerabilitySummary `json:"latest_vulnerability_summary,omitempty"`
}

// ToSummary converts a Report to ReportSummary
func (r *Report) ToSummary() ReportSummary {
	return ReportSummary{
		ID:                   r.ID,
		Hostname:             r.Meta.Hostname,
		CollectionID:         r.Meta.CollectionID,
		Timestamp:            r.Meta.Timestamp,
		ReceivedAt:           r.ReceivedAt,
		HasErrors:            len(r.Errors) > 0,
		VulnerabilitySummary: r.GetVulnerabilitySummary(),
	}
}

// SystemData represents the parsed system collector data
type SystemData struct {
	OS             map[string]interface{} `json:"os"`
	Kernel         map[string]interface{} `json:"kernel"`
	Hostname       map[string]interface{} `json:"hostname"`
	Uptime         map[string]interface{} `json:"uptime"`
	Boot           map[string]interface{} `json:"boot"`
	Users          map[string]interface{} `json:"users"`
	Locale         map[string]interface{} `json:"locale"`
	Timezone       map[string]interface{} `json:"timezone"`
	Virtualization map[string]interface{} `json:"virtualization"`
}

// VulnerabilitySummary contains counts by severity
type VulnerabilitySummary struct {
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	Critical             int `json:"critical"`
	High                 int `json:"high"`
	Medium               int `json:"medium"`
	Low                  int `json:"low"`
	Unknown              int `json:"unknown"`
}

// Vulnerability represents a single CVE finding
type Vulnerability struct {
	CVEID            string                 `json:"cve_id"`
	Severity         string                 `json:"severity"`
	PackageName      string                 `json:"package_name"`
	InstalledVersion string                 `json:"installed_version"`
	FixedVersion     string                 `json:"fixed_version"`
	Title            string                 `json:"title"`
	Description      string                 `json:"description"`
	Target           string                 `json:"target"`
	TargetType       string                 `json:"target_type"`
	PrimaryURL       string                 `json:"primary_url"`
	References       []string               `json:"references"`
	CVSS             map[string]interface{} `json:"cvss"`
	PublishedDate    string                 `json:"published_date"`
	LastModified     string                 `json:"last_modified"`
}

// VulnerabilityData represents the vulnerability scanner output
type VulnerabilityData struct {
	Scanner         string               `json:"scanner"`
	TrivyAvailable  bool                 `json:"trivy_available"`
	TrivyVersion    string               `json:"trivy_version"`
	ScanCompleted   bool                 `json:"scan_completed"`
	Error           string               `json:"error,omitempty"`
	Summary         VulnerabilitySummary `json:"summary"`
	TotalUniqueCVEs int                  `json:"total_unique_cves"`
	Vulnerabilities []Vulnerability      `json:"vulnerabilities"`
	Targets         []struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		Class string `json:"class"`
	} `json:"targets"`
}

// ParseSystemData extracts system data from the report
func (r *Report) ParseSystemData() (*SystemData, error) {
	var allData map[string]json.RawMessage
	if err := json.Unmarshal(r.Data, &allData); err != nil {
		return nil, err
	}

	var sysData SystemData
	if raw, ok := allData["system"]; ok {
		if err := json.Unmarshal(raw, &sysData); err != nil {
			return nil, err
		}
	}

	return &sysData, nil
}

// ParseVulnerabilityData extracts vulnerability data from the report
func (r *Report) ParseVulnerabilityData() (*VulnerabilityData, error) {
	var allData map[string]json.RawMessage
	if err := json.Unmarshal(r.Data, &allData); err != nil {
		return nil, err
	}

	var vulnData VulnerabilityData
	if raw, ok := allData["vulnerabilities"]; ok {
		if err := json.Unmarshal(raw, &vulnData); err != nil {
			return nil, err
		}
	}

	return &vulnData, nil
}

// GetVulnerabilitySummary returns just the vulnerability summary from the report
func (r *Report) GetVulnerabilitySummary() *VulnerabilitySummary {
	vulnData, err := r.ParseVulnerabilityData()
	if err != nil || vulnData == nil || !vulnData.ScanCompleted {
		return nil
	}
	return &vulnData.Summary
}
