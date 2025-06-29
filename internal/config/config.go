package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the application
type Config struct {
	Server   ServerConfig   `json:"server"`
	Database DatabaseConfig `json:"database"`
	Workers  WorkersConfig  `json:"workers"`
	Naabu    NaabuConfig    `json:"naabu"`
	Nmap     NmapConfig     `json:"nmap"`
	Logging  LoggingConfig  `json:"logging"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Port         string        `json:"port"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Driver   string `json:"driver"`   // "sqlite" or "postgres"
	Host     string `json:"host"`
	Port     string `json:"port"`
	Database string `json:"database"`
	User     string `json:"user"`
	Password string `json:"password"`
	SSLMode  string `json:"ssl_mode"`
	Timezone string `json:"timezone"`
}

// WorkersConfig holds worker pool configuration
type WorkersConfig struct {
	QuickScanWorkers int `json:"quick_scan_workers"`
	ProbeWorkers     int `json:"probe_workers"`
	DeepScanWorkers  int `json:"deep_scan_workers"`
}

// NaabuConfig holds Naabu scanning configuration
type NaabuConfig struct {
	RateLimit    int           `json:"rate_limit"`    // packets per second
	Timeout      time.Duration `json:"timeout"`      // scan timeout
	Retries      int           `json:"retries"`      // number of retries
	TopPorts     string        `json:"top_ports"`    // default top ports
	Interface    string        `json:"interface"`    // network interface
	SourceIP     string        `json:"source_ip"`    // source IP
	Threads      int           `json:"threads"`      // number of threads
	MaxTargets   int           `json:"max_targets"`  // maximum targets per scan
}

// NmapConfig holds Nmap configuration
type NmapConfig struct {
	BinaryPath     string        `json:"binary_path"`
	ScriptsPath    string        `json:"scripts_path"`
	Timeout        time.Duration `json:"timeout"`
	ScriptTimeout  time.Duration `json:"script_timeout"`
	HostTimeout    time.Duration `json:"host_timeout"`
	MaxRetries     int           `json:"max_retries"`
	MaxHostsGroup  int           `json:"max_hosts_group"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string `json:"level"`  // debug, info, warn, error
	Format string `json:"format"` // json, text
}

// Load loads configuration from environment variables with defaults
func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Port:         getEnv("PORT", "8080"),
			ReadTimeout:  getDurationEnv("SERVER_READ_TIMEOUT", 30*time.Second),
			WriteTimeout: getDurationEnv("SERVER_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:  getDurationEnv("SERVER_IDLE_TIMEOUT", 120*time.Second),
		},
		Database: DatabaseConfig{
			Driver:   getEnv("DB_DRIVER", "sqlite"),
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "5432"),
			Database: getEnv("DB_NAME", "naabu_api.db"),
			User:     getEnv("DB_USER", ""),
			Password: getEnv("DB_PASSWORD", ""),
			SSLMode:  getEnv("DB_SSL_MODE", "disable"),
			Timezone: getEnv("DB_TIMEZONE", "UTC"),
		},
		Workers: WorkersConfig{
			QuickScanWorkers: getIntEnv("QUICK_SCAN_WORKERS", 5),
			ProbeWorkers:     getIntEnv("PROBE_WORKERS", 10),
			DeepScanWorkers:  getIntEnv("DEEP_SCAN_WORKERS", 3),
		},
		Naabu: NaabuConfig{
			RateLimit:  getIntEnv("NAABU_RATE_LIMIT", 1000),
			Timeout:    getDurationEnv("NAABU_TIMEOUT", 5*time.Minute),
			Retries:    getIntEnv("NAABU_RETRIES", 3),
			TopPorts:   getEnv("NAABU_TOP_PORTS", "1000"),
			Interface:  getEnv("NAABU_INTERFACE", ""),
			SourceIP:   getEnv("NAABU_SOURCE_IP", ""),
			Threads:    getIntEnv("NAABU_THREADS", 25),
			MaxTargets: getIntEnv("NAABU_MAX_TARGETS", 100),
		},
		Nmap: NmapConfig{
			BinaryPath:    getEnv("NMAP_BINARY_PATH", "nmap"),
			ScriptsPath:   getEnv("NMAP_SCRIPTS_PATH", "/usr/share/nmap/scripts"),
			Timeout:       getDurationEnv("NMAP_TIMEOUT", 10*time.Minute),
			ScriptTimeout: getDurationEnv("NMAP_SCRIPT_TIMEOUT", 60*time.Second),
			HostTimeout:   getDurationEnv("NMAP_HOST_TIMEOUT", 5*time.Minute),
			MaxRetries:    getIntEnv("NMAP_MAX_RETRIES", 2),
			MaxHostsGroup: getIntEnv("NMAP_MAX_HOSTS_GROUP", 1),
		},
		Logging: LoggingConfig{
			Level:  getEnv("LOG_LEVEL", "info"),
			Format: getEnv("LOG_FORMAT", "json"),
		},
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate server config
	if c.Server.Port == "" {
		return fmt.Errorf("server port cannot be empty")
	}

	// Validate database config
	if c.Database.Driver != "sqlite" && c.Database.Driver != "postgres" {
		return fmt.Errorf("database driver must be 'sqlite' or 'postgres'")
	}

	if c.Database.Driver == "postgres" {
		if c.Database.Host == "" {
			return fmt.Errorf("database host cannot be empty for postgres")
		}
		if c.Database.User == "" {
			return fmt.Errorf("database user cannot be empty for postgres")
		}
		if c.Database.Database == "" {
			return fmt.Errorf("database name cannot be empty for postgres")
		}
	}

	// Validate worker config
	if c.Workers.QuickScanWorkers <= 0 {
		return fmt.Errorf("quick scan workers must be greater than 0")
	}
	if c.Workers.ProbeWorkers <= 0 {
		return fmt.Errorf("probe workers must be greater than 0")
	}
	if c.Workers.DeepScanWorkers <= 0 {
		return fmt.Errorf("deep scan workers must be greater than 0")
	}

	// Validate Naabu config
	if c.Naabu.RateLimit <= 0 {
		return fmt.Errorf("naabu rate limit must be greater than 0")
	}
	if c.Naabu.Threads <= 0 {
		return fmt.Errorf("naabu threads must be greater than 0")
	}

	// Validate logging config
	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if !validLogLevels[c.Logging.Level] {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	return nil
}

// Helper functions

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// GetDatabaseConnectionString returns the database connection string
func (c *Config) GetDatabaseConnectionString() string {
	switch c.Database.Driver {
	case "postgres":
		return fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
			c.Database.Host,
			c.Database.User,
			c.Database.Password,
			c.Database.Database,
			c.Database.Port,
			c.Database.SSLMode,
			c.Database.Timezone,
		)
	case "sqlite":
		return c.Database.Database
	default:
		return ""
	}
}

// IsDevelopment returns true if running in development mode
func (c *Config) IsDevelopment() bool {
	return getEnv("ENV", "development") == "development"
}

// IsProduction returns true if running in production mode
func (c *Config) IsProduction() bool {
	return getEnv("ENV", "development") == "production"
}
