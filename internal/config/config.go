package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds all server configuration
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Auth    AuthConfig    `yaml:"auth"`
	Storage StorageConfig `yaml:"storage"`
}

// ServerConfig holds HTTP server settings
type ServerConfig struct {
	Listen       string `yaml:"listen"`
	ReadTimeout  int    `yaml:"read_timeout"`
	WriteTimeout int    `yaml:"write_timeout"`
	IdleTimeout  int    `yaml:"idle_timeout"`
	TLSCert      string `yaml:"tls_cert"`
	TLSKey       string `yaml:"tls_key"`
}

// AuthConfig holds authentication settings
type AuthConfig struct {
	Enabled  bool     `yaml:"enabled"`
	APIKeys  []string `yaml:"api_keys"`
	AllowAll bool     `yaml:"allow_all"` // For development/testing
}

// StorageConfig holds data storage settings
type StorageConfig struct {
	Type       string `yaml:"type"` // "file", "sqlite", "postgres"
	Path       string `yaml:"path"` // For file/sqlite storage
	DSN        string `yaml:"dsn"`  // For postgres
	MaxReports int    `yaml:"max_reports"`
	Retention  string `yaml:"retention"` // e.g., "30d", "1w"
}

// Default returns a configuration with sensible defaults
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Listen:       ":8080",
			ReadTimeout:  60,
			WriteTimeout: 60,
			IdleTimeout:  120,
		},
		Auth: AuthConfig{
			Enabled:  false,
			AllowAll: true,
		},
		Storage: StorageConfig{
			Type:       "file",
			Path:       "./data/reports",
			MaxReports: 1000,
			Retention:  "30d",
		},
	}
}

// Load reads configuration from a file, falling back to defaults
func Load(path string) (*Config, error) {
	cfg := Default()

	// Check for config file in various locations
	paths := []string{
		path,
		"config.yaml",
		"/etc/snail-shell/config.yaml",
		filepath.Join(os.Getenv("HOME"), ".config", "snail-shell", "config.yaml"),
	}

	var configPath string
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			configPath = p
			break
		}
	}

	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, err
		}

		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	}

	// Override with environment variables
	cfg.applyEnvOverrides()

	return cfg, nil
}

func (c *Config) applyEnvOverrides() {
	if v := os.Getenv("SNAIL_LISTEN"); v != "" {
		c.Server.Listen = v
	}
	if v := os.Getenv("SNAIL_TLS_CERT"); v != "" {
		c.Server.TLSCert = v
	}
	if v := os.Getenv("SNAIL_TLS_KEY"); v != "" {
		c.Server.TLSKey = v
	}
	if v := os.Getenv("SNAIL_API_KEY"); v != "" {
		c.Auth.Enabled = true
		c.Auth.AllowAll = false
		c.Auth.APIKeys = append(c.Auth.APIKeys, v)
	}
	if v := os.Getenv("SNAIL_STORAGE_PATH"); v != "" {
		c.Storage.Path = v
	}
	if v := os.Getenv("SNAIL_STORAGE_TYPE"); v != "" {
		c.Storage.Type = v
	}
	if v := os.Getenv("DATABASE_URL"); v != "" {
		c.Storage.DSN = v
		c.Storage.Type = "postgres"
	}
}

