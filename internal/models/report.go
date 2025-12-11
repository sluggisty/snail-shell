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

// HostSummary represents summary info about a host
type HostSummary struct {
	Hostname                   string                `json:"hostname"`
	LastSeen                   time.Time             `json:"last_seen"`
	HasErrors                  bool                  `json:"has_errors"`
	LatestVulnerabilitySummary *VulnerabilitySummary `json:"vulnerability_summary,omitempty"`
	LatestComplianceSummary    *ComplianceSummary    `json:"compliance_summary,omitempty"`
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

// AggregatedCVE represents a CVE affecting multiple hosts
type AggregatedCVE struct {
	CVEID         string   `json:"cve_id"`
	Severity      string   `json:"severity"`
	Title         string   `json:"title"`
	Description   string   `json:"description,omitempty"`
	PrimaryURL    string   `json:"primary_url,omitempty"`
	FixedVersion  string   `json:"fixed_version,omitempty"`
	PublishedDate string   `json:"published_date,omitempty"`
	AffectedHosts []string `json:"affected_hosts"`
	AffectedCount int      `json:"affected_count"`
	PackageNames  []string `json:"package_names,omitempty"`
	CVSSv3Score   float64  `json:"cvss_v3_score,omitempty"`
}

// VulnerabilitiesAggregation is the response for fleet-wide vulnerability data
type VulnerabilitiesAggregation struct {
	TotalHosts      int                  `json:"total_hosts"`
	HostsWithVulns  int                  `json:"hosts_with_vulns"`
	TotalUniqueCVEs int                  `json:"total_unique_cves"`
	SeverityCounts  VulnerabilitySummary `json:"severity_counts"`
	CVEs            []AggregatedCVE      `json:"cves"`
	GeneratedAt     time.Time            `json:"generated_at"`
}

// ComplianceData represents the compliance scanner output
type ComplianceData struct {
	Scanner              string             `json:"scanner"`
	OscapAvailable       bool               `json:"oscap_available"`
	ScapContentAvailable bool               `json:"scap_content_available"`
	ScanCompleted        bool               `json:"scan_completed"`
	OscapVersion         string             `json:"oscap_version,omitempty"`
	ContentFile          string             `json:"content_file,omitempty"`
	Error                string             `json:"error,omitempty"`
	Distro               *ComplianceDistro  `json:"distro,omitempty"`
	ProfileInfo          *ComplianceProfile `json:"profile_info,omitempty"`
	AvailableProfiles    []string           `json:"available_profiles,omitempty"`
	Summary              *ComplianceSummary `json:"summary,omitempty"`
	Rules                []ComplianceRule   `json:"rules,omitempty"`
	ScanTime             *ScanTime          `json:"scan_time,omitempty"`
	RulesTruncated       bool               `json:"rules_truncated,omitempty"`
	TotalFailedRules     int                `json:"total_failed_rules,omitempty"`
}

// ComplianceDistro contains OS distribution info from compliance scan
type ComplianceDistro struct {
	ID           string `json:"id,omitempty"`
	OriginalID   string `json:"original_id,omitempty"`
	Version      string `json:"version,omitempty"`
	MajorVersion string `json:"major_version,omitempty"`
	Name         string `json:"name,omitempty"`
	Like         string `json:"like,omitempty"`
}

// ComplianceProfile contains the scanned profile info
type ComplianceProfile struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"id,omitempty"`
}

// ComplianceSummary contains scan result counts
type ComplianceSummary struct {
	TotalRules    int     `json:"total_rules,omitempty"`
	Pass          int     `json:"pass,omitempty"`
	Fail          int     `json:"fail,omitempty"`
	Error         int     `json:"error,omitempty"`
	Unknown       int     `json:"unknown,omitempty"`
	NotApplicable int     `json:"notapplicable,omitempty"`
	NotChecked    int     `json:"notchecked,omitempty"`
	NotSelected   int     `json:"notselected,omitempty"`
	Informational int     `json:"informational,omitempty"`
	Fixed         int     `json:"fixed,omitempty"`
	Score         float64 `json:"score,omitempty"`
}

// ComplianceRule represents a single compliance check result
type ComplianceRule struct {
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Severity string   `json:"severity,omitempty"`
	Title    string   `json:"title,omitempty"`
	Messages []string `json:"messages,omitempty"`
}

// ScanTime contains when the scan ran
type ScanTime struct {
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
}

// ParseComplianceData extracts compliance data from the report
func (r *Report) ParseComplianceData() (*ComplianceData, error) {
	var allData map[string]json.RawMessage
	if err := json.Unmarshal(r.Data, &allData); err != nil {
		return nil, err
	}

	var compData ComplianceData
	if raw, ok := allData["compliance"]; ok {
		if err := json.Unmarshal(raw, &compData); err != nil {
			return nil, err
		}
	}

	return &compData, nil
}

// GetComplianceSummary returns just the compliance summary from the report
func (r *Report) GetComplianceSummary() *ComplianceSummary {
	compData, err := r.ParseComplianceData()
	if err != nil || compData == nil || !compData.ScanCompleted {
		return nil
	}
	return compData.Summary
}

// HostComplianceResult represents a single host's compliance result for a policy
type HostComplianceResult struct {
	Hostname    string           `json:"hostname"`
	Score       float64          `json:"score"`
	PassCount   int              `json:"pass_count"`
	FailCount   int              `json:"fail_count"`
	ErrorCount  int              `json:"error_count"`
	TotalRules  int              `json:"total_rules"`
	ScanTime    string           `json:"scan_time,omitempty"`
	FailedRules []ComplianceRule `json:"failed_rules,omitempty"`
}

// AggregatedPolicy represents a compliance policy scanned across multiple hosts
type AggregatedPolicy struct {
	ProfileID    string                 `json:"profile_id"`
	ProfileName  string                 `json:"profile_name"`
	ContentFile  string                 `json:"content_file,omitempty"`
	HostCount    int                    `json:"host_count"`
	AverageScore float64                `json:"average_score"`
	TotalFailing int                    `json:"total_failing"` // hosts with score < 100
	TotalPassing int                    `json:"total_passing"` // hosts with score == 100
	HostResults  []HostComplianceResult `json:"host_results"`
}

// ComplianceAggregation is the response for fleet-wide compliance data
type ComplianceAggregation struct {
	TotalHosts          int                `json:"total_hosts"`
	HostsWithCompliance int                `json:"hosts_with_compliance"`
	TotalPolicies       int                `json:"total_policies"`
	Policies            []AggregatedPolicy `json:"policies"`
	GeneratedAt         time.Time          `json:"generated_at"`
}
