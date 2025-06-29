package probes

import (
	"context"
	"time"

	"naabu-api/internal/models"
)

// ProbeResult represents the result of a service probe
type ProbeResult struct {
	IsVulnerable bool                 `json:"is_vulnerable"`
	Evidence     string               `json:"evidence"`
	ServiceInfo  *models.ServiceInfo  `json:"service_info,omitempty"`
	Error        string               `json:"error,omitempty"`
}

// Probe defines the interface for service-specific probes
type Probe interface {
	// Name returns the probe name
	Name() string
	
	// DefaultPort returns the default port for this service
	DefaultPort() int
	
	// Probe executes the probe against the target
	Probe(ctx context.Context, ip string, port int) (*ProbeResult, error)
	
	// IsRelevantPort returns true if this probe should be run against the given port
	IsRelevantPort(port int) bool
	
	// GetTimeout returns the probe timeout
	GetTimeout() time.Duration
}
