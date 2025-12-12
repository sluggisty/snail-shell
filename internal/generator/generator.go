package generator

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/google/uuid"
	"github.com/sluggisty/snail-shell/internal/models"
)

// Generator creates test data for snail-shell
type Generator struct {
	rng *rand.Rand
}

// New creates a new generator
func New() *Generator {
	return &Generator{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// GenerateHosts creates multiple test hosts with realistic data
func (g *Generator) GenerateHosts(count int) ([]*models.Report, error) {
	reports := make([]*models.Report, 0, count)
	
	// Common hostname prefixes
	prefixes := []string{
		"web", "db", "app", "cache", "api", "worker", "proxy", "monitor",
		"mail", "dns", "backup", "storage", "compute", "gateway", "router",
	}
	
	// Common Fedora versions
	fedoraVersions := []string{"42", "41", "40", "39", "38", "37", "36"}
	
	// Common CVEs for testing (real CVE IDs)
	commonCVEs := []struct {
		cveID      string
		severity   string
		packageName string
		title      string
		cvss       float64
	}{
		{"CVE-2024-12345", "CRITICAL", "openssl", "Buffer overflow in OpenSSL", 9.8},
		{"CVE-2024-12346", "HIGH", "curl", "Command injection vulnerability", 8.5},
		{"CVE-2024-12347", "HIGH", "glibc", "Memory corruption issue", 7.8},
		{"CVE-2024-12348", "MEDIUM", "python3", "SQL injection in library", 6.5},
		{"CVE-2024-12349", "MEDIUM", "nginx", "DoS vulnerability", 5.9},
		{"CVE-2024-12350", "LOW", "bash", "Information disclosure", 3.2},
		{"CVE-2024-12351", "CRITICAL", "kernel", "Privilege escalation", 9.1},
		{"CVE-2024-12352", "HIGH", "systemd", "Service hijacking", 7.2},
		{"CVE-2024-12353", "MEDIUM", "postgresql", "Authentication bypass", 6.8},
		{"CVE-2024-12354", "LOW", "vim", "Code execution", 4.1},
	}
	
	for i := 0; i < count; i++ {
		hostname := fmt.Sprintf("%s-%s-%d",
			prefixes[g.rng.Intn(len(prefixes))],
			fedoraVersions[g.rng.Intn(len(fedoraVersions))],
			g.rng.Intn(100)+1,
		)
		
		report, err := g.GenerateHost(hostname, commonCVEs)
		if err != nil {
			return nil, fmt.Errorf("failed to generate host %s: %w", hostname, err)
		}
		
		reports = append(reports, report)
	}
	
	return reports, nil
}

// GenerateHost creates a single test host with realistic data
func (g *Generator) GenerateHost(hostname string, commonCVEs []struct {
	cveID       string
	severity    string
	packageName string
	title       string
	cvss        float64
}) (*models.Report, error) {
	now := time.Now()
	
	// Randomize timestamp (some hosts report more recently than others)
	receivedAt := now.Add(-time.Duration(g.rng.Intn(720)) * time.Hour) // 0-30 days ago
	
	// Generate report data
	data := g.generateReportData(hostname, commonCVEs)
	
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}
	
	return &models.Report{
		ID:         hostname,
		ReceivedAt: receivedAt,
		Meta: models.ReportMeta{
			Hostname:     hostname,
			CollectionID: uuid.New().String(),
			Timestamp:    receivedAt.Format(time.RFC3339),
			SnailVersion: "0.1.0",
		},
		Data:   dataJSON,
		Errors: []string{},
	}, nil
}

// generateReportData creates realistic report data structure
func (g *Generator) generateReportData(hostname string, commonCVEs []struct {
	cveID       string
	severity    string
	packageName string
	title       string
	cvss        float64
}) map[string]interface{} {
	data := make(map[string]interface{})
	
	// System data
	data["system"] = g.generateSystemData(hostname)
	
	// Hardware data
	data["hardware"] = g.generateHardwareData()
	
	// Network data
	data["network"] = g.generateNetworkData()
	
	// Packages data
	data["packages"] = g.generatePackagesData()
	
	// Services data
	data["services"] = g.generateServicesData()
	
	// Filesystem data
	data["filesystem"] = g.generateFilesystemData()
	
	// Security data
	data["security"] = g.generateSecurityData()
	
	// Vulnerabilities data (with some hosts having none, some having many)
	if g.rng.Float32() < 0.85 { // 85% of hosts have vulnerabilities
		data["vulnerabilities"] = g.generateVulnerabilitiesData(commonCVEs)
	}
	
	// Compliance data (some hosts have compliance scans)
	if g.rng.Float32() < 0.70 { // 70% of hosts have compliance data
		data["compliance"] = g.generateComplianceData()
	}
	
	return data
}

func (g *Generator) generateSystemData(hostname string) map[string]interface{} {
	fedoraVersions := []string{"42", "41", "40", "39", "38", "37", "36"}
	version := fedoraVersions[g.rng.Intn(len(fedoraVersions))]
	
	return map[string]interface{}{
		"os": map[string]interface{}{
			"name":         "Fedora Linux",
			"id":           "fedora",
			"version":      version,
			"version_id":   version,
			"architecture": "x86_64",
		},
		"kernel": map[string]interface{}{
			"release": fmt.Sprintf("6.%d.%d", g.rng.Intn(10)+1, g.rng.Intn(100)),
			"version": "#1 SMP PREEMPT_DYNAMIC",
		},
		"hostname": map[string]interface{}{
			"hostname": hostname,
			"fqdn":     fmt.Sprintf("%s.example.com", hostname),
		},
		"uptime": map[string]interface{}{
			"days":    g.rng.Intn(90),
			"hours":   g.rng.Intn(24),
			"minutes": g.rng.Intn(60),
			"human_readable": fmt.Sprintf("%d days, %d hours", g.rng.Intn(90), g.rng.Intn(24)),
		},
		"virtualization": map[string]interface{}{
			"type":       "kvm",
			"is_virtual": true,
		},
	}
}

func (g *Generator) generateHardwareData() map[string]interface{} {
	cpuModels := []string{
		"Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz",
		"AMD Ryzen 7 3700X 8-Core Processor",
		"Intel(R) Xeon(R) CPU E5-2670 v2 @ 2.50GHz",
		"AMD EPYC 7551 32-Core Processor",
	}
	
	cores := []int{2, 4, 8, 16, 32}
	memoryGB := []int{4, 8, 16, 32, 64, 128}
	
	return map[string]interface{}{
		"cpu": map[string]interface{}{
			"model":          cpuModels[g.rng.Intn(len(cpuModels))],
			"physical_cores":  cores[g.rng.Intn(len(cores))],
			"logical_cores":   cores[g.rng.Intn(len(cores))] * 2,
			"load_average": map[string]interface{}{
				"1min":  g.rng.Float64() * 2.0,
				"5min":  g.rng.Float64() * 1.8,
				"15min": g.rng.Float64() * 1.5,
			},
		},
		"memory": map[string]interface{}{
			"total":        memoryGB[g.rng.Intn(len(memoryGB))] * 1024 * 1024 * 1024,
			"total_human":  fmt.Sprintf("%dG", memoryGB[g.rng.Intn(len(memoryGB))]),
			"used":         g.rng.Intn(80) + 10, // 10-90% used
			"available":    g.rng.Intn(70) + 10,
			"percent_used": float64(g.rng.Intn(80)+10) / 100.0,
		},
		"disks": map[string]interface{}{
			"partitions": []map[string]interface{}{
				{
					"device":      "/dev/sda1",
					"mountpoint":  "/",
					"fstype":      "ext4",
					"total_human": fmt.Sprintf("%dG", g.rng.Intn(500)+50),
					"percent_used": float64(g.rng.Intn(70)+10) / 100.0,
				},
			},
		},
	}
}

func (g *Generator) generateNetworkData() map[string]interface{} {
	return map[string]interface{}{
		"interfaces": []map[string]interface{}{
			{
				"name":  "eth0",
				"mac":   g.generateMAC(),
				"is_up": true,
				"addresses": []map[string]interface{}{
					{
						"type":    "ipv4",
						"address": fmt.Sprintf("192.168.%d.%d", g.rng.Intn(255)+1, g.rng.Intn(255)+1),
					},
				},
			},
		},
		"dns": map[string]interface{}{
			"nameservers": []string{"8.8.8.8", "8.8.4.4"},
		},
	}
}

func (g *Generator) generatePackagesData() map[string]interface{} {
	return map[string]interface{}{
		"summary": map[string]interface{}{
			"total_count": g.rng.Intn(2000) + 500,
		},
		"upgradeable": map[string]interface{}{
			"count":         g.rng.Intn(50),
			"security_count": g.rng.Intn(20),
		},
	}
}

func (g *Generator) generateServicesData() map[string]interface{} {
	services := []string{"sshd", "nginx", "postgresql", "redis", "systemd", "NetworkManager"}
	running := make([]map[string]interface{}, 0)
	
	for i := 0; i < g.rng.Intn(5)+3; i++ {
		svc := services[g.rng.Intn(len(services))]
		running = append(running, map[string]interface{}{
			"name":        svc,
			"description": fmt.Sprintf("%s service", svc),
		})
	}
	
	return map[string]interface{}{
		"running_services": running,
		"failed_units":     []map[string]interface{}{},
	}
}

func (g *Generator) generateFilesystemData() map[string]interface{} {
	return map[string]interface{}{
		"mounts": []map[string]interface{}{
			{
				"device":      "/dev/sda1",
				"mountpoint":  "/",
				"fstype":      "ext4",
				"percent_used": float64(g.rng.Intn(70)+10) / 100.0,
			},
		},
	}
}

func (g *Generator) generateSecurityData() map[string]interface{} {
	return map[string]interface{}{
		"selinux": map[string]interface{}{
			"enabled": g.rng.Float32() < 0.8, // 80% have SELinux enabled
			"mode":    []string{"enforcing", "permissive"}[g.rng.Intn(2)],
		},
		"fips": map[string]interface{}{
			"enabled": g.rng.Float32() < 0.3, // 30% have FIPS enabled
		},
	}
}

func (g *Generator) generateVulnerabilitiesData(commonCVEs []struct {
	cveID       string
	severity    string
	packageName string
	title       string
	cvss        float64
}) map[string]interface{} {
	// Each host gets a random subset of CVEs (0-8 CVEs)
	numVulns := g.rng.Intn(9)
	vulnerabilities := make([]map[string]interface{}, 0, numVulns)
	
	// Track which CVEs we've used to avoid duplicates
	used := make(map[int]bool)
	
	severityCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
		"UNKNOWN":  0,
	}
	
	for i := 0; i < numVulns; i++ {
		// Pick a random CVE we haven't used yet
		idx := g.rng.Intn(len(commonCVEs))
		for used[idx] && len(used) < len(commonCVEs) {
			idx = g.rng.Intn(len(commonCVEs))
		}
		used[idx] = true
		
		cve := commonCVEs[idx]
		severityCounts[cve.severity]++
		
		vuln := map[string]interface{}{
			"cve_id":            cve.cveID,
			"severity":          cve.severity,
			"package_name":      cve.packageName,
			"installed_version": fmt.Sprintf("1.%d.%d", g.rng.Intn(10), g.rng.Intn(100)),
			"fixed_version":     fmt.Sprintf("1.%d.%d", g.rng.Intn(10)+5, g.rng.Intn(100)),
			"title":             cve.title,
			"description":       fmt.Sprintf("This is a test description for %s. It affects %s and can lead to security issues.", cve.cveID, cve.packageName),
			"target":            "rootfs",
			"target_type":       "filesystem",
			"primary_url":       fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.cveID),
			"published_date":    time.Now().AddDate(0, -g.rng.Intn(12), -g.rng.Intn(30)).Format("2006-01-02"),
			"cvss": map[string]interface{}{
				"v3_score": cve.cvss,
				"v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
		}
		
		vulnerabilities = append(vulnerabilities, vuln)
	}
	
	return map[string]interface{}{
		"scanner":          "trivy",
		"trivy_available":  true,
		"trivy_version":    "0.55.0",
		"scan_completed":   true,
		"summary": map[string]interface{}{
			"total_vulnerabilities": numVulns,
			"critical":              severityCounts["CRITICAL"],
			"high":                  severityCounts["HIGH"],
			"medium":                severityCounts["MEDIUM"],
			"low":                   severityCounts["LOW"],
			"unknown":               severityCounts["UNKNOWN"],
		},
		"total_unique_cves": numVulns,
		"vulnerabilities":   vulnerabilities,
		"targets": []map[string]interface{}{
			{
				"name":  "rootfs",
				"type":  "filesystem",
				"class": "os-pkgs",
			},
		},
	}
}

func (g *Generator) generateComplianceData() map[string]interface{} {
	score := float64(g.rng.Intn(40) + 60) // 60-100 score
	pass := g.rng.Intn(200) + 150
	fail := g.rng.Intn(50)
	total := pass + fail
	
	return map[string]interface{}{
		"scanner":               "oscap",
		"oscap_available":        true,
		"scap_content_available": true,
		"scan_completed":         true,
		"oscap_version":          "1.3.8",
		"content_file":           "ssg-fedora-ds.xml",
		"distro": map[string]interface{}{
			"id":           "fedora",
			"version":      "42",
			"major_version": "42",
			"name":         "Fedora",
		},
		"profile_info": map[string]interface{}{
			"name": "xccdf_org.ssgproject.content_profile_moderate",
			"id":   "xccdf_org.ssgproject.content_profile_moderate",
		},
		"summary": map[string]interface{}{
			"total_rules": total,
			"pass":        pass,
			"fail":        fail,
			"error":       0,
			"score":       score,
		},
		"scan_time": map[string]interface{}{
			"start": time.Now().Add(-10 * time.Minute).Format(time.RFC3339),
			"end":   time.Now().Format(time.RFC3339),
		},
	}
}

func (g *Generator) generateMAC() string {
	return fmt.Sprintf("52:54:00:%02x:%02x:%02x",
		g.rng.Intn(256),
		g.rng.Intn(256),
		g.rng.Intn(256),
	)
}

