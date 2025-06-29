package probes

import (
	"context"
	"time"
	
	"naabu-api/internal/models"
)

// Probe defines the interface for service-specific probes
type Probe interface {
	// Name returns the probe name
	Name() string
	
	// DefaultPort returns the default port for this service
	DefaultPort() int
	
	// Probe executes the probe against the target
	Probe(ctx context.Context, ip string, port int) (*models.ProbeResult, error)
	
	// IsRelevantPort returns true if this probe should be run against the given port
	IsRelevantPort(port int) bool
	
	// GetTimeout returns the probe timeout
	GetTimeout() time.Duration
}
