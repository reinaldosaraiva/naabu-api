package probes

import (
	"context"
	"fmt"
	"sync"
	"time"

	"naabu-api/internal/models"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Manager coordinates probe execution
type Manager struct {
	probes []Probe
	logger *zap.Logger
}

// NewManager creates a new probe manager
func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		probes: []Probe{
			NewFTPProbe(),
			NewVNCProbe(),
			NewRDPProbe(),
			NewLDAPProbe(),
			NewPPTPProbe(),
			NewRsyncProbe(),
		},
		logger: logger,
	}
}

// ProbeTarget represents a target for probing
type ProbeTarget struct {
	IP   string
	Port int
}

// ProbeResultWithTarget includes the target information
type ProbeResultWithTarget struct {
	Target ProbeTarget
	Probe  string
	Result *ProbeResult
	Error  error
}

// ProbeTargets executes relevant probes against the given targets
func (m *Manager) ProbeTargets(ctx context.Context, scanID uuid.UUID, targets []ProbeTarget) []ProbeResultWithTarget {
	var results []ProbeResultWithTarget
	var wg sync.WaitGroup
	resultsChan := make(chan ProbeResultWithTarget, len(targets)*len(m.probes))

	// Create a semaphore to limit concurrent probes
	semaphore := make(chan struct{}, 20) // Limit to 20 concurrent probes

	for _, target := range targets {
		for _, probe := range m.probes {
			if probe.IsRelevantPort(target.Port) {
				wg.Add(1)
				go func(target ProbeTarget, probe Probe) {
					defer wg.Done()
					
					// Acquire semaphore
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					// Create context with timeout
					probeCtx, cancel := context.WithTimeout(ctx, probe.GetTimeout())
					defer cancel()

					m.logger.Debug("Executing probe",
						zap.String("scan_id", scanID.String()),
						zap.String("probe", probe.Name()),
						zap.String("ip", target.IP),
						zap.Int("port", target.Port),
					)

					startTime := time.Now()
					result, err := probe.Probe(probeCtx, target.IP, target.Port)
					duration := time.Since(startTime)

					if err != nil {
						m.logger.Warn("Probe failed",
							zap.String("scan_id", scanID.String()),
							zap.String("probe", probe.Name()),
							zap.String("ip", target.IP),
							zap.Int("port", target.Port),
							zap.Error(err),
							zap.Duration("duration", duration),
						)
					} else {
						logLevel := zap.InfoLevel
						if result.IsVulnerable {
							logLevel = zap.WarnLevel
						}
						
						m.logger.Log(logLevel, "Probe completed",
							zap.String("scan_id", scanID.String()),
							zap.String("probe", probe.Name()),
							zap.String("ip", target.IP),
							zap.Int("port", target.Port),
							zap.Bool("vulnerable", result.IsVulnerable),
							zap.String("evidence", result.Evidence),
							zap.Duration("duration", duration),
						)
					}

					resultsChan <- ProbeResultWithTarget{
						Target: target,
						Probe:  probe.Name(),
						Result: result,
						Error:  err,
					}
				}(target, probe)
			}
		}
	}

	// Wait for all probes to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	for result := range resultsChan {
		results = append(results, result)
	}

	m.logger.Info("Probe session completed",
		zap.String("scan_id", scanID.String()),
		zap.Int("targets", len(targets)),
		zap.Int("total_probes", len(results)),
		zap.Int("vulnerable_findings", m.countVulnerable(results)),
	)

	return results
}

// ConvertToProbeTargets converts scan results to probe targets
func (m *Manager) ConvertToProbeTargets(scanResults []models.ScanResult) []ProbeTarget {
	var targets []ProbeTarget
	
	for _, result := range scanResults {
		for _, port := range result.Ports {
			if port.State == "open" {
				targets = append(targets, ProbeTarget{
					IP:   result.IP,
					Port: port.Port,
				})
			}
		}
	}

	return targets
}

// ConvertToModelProbeResults converts probe results to database models
func (m *Manager) ConvertToModelProbeResults(scanID uuid.UUID, results []ProbeResultWithTarget) []models.ProbeResult {
	var modelResults []models.ProbeResult
	
	for _, result := range results {
		if result.Error != nil {
			continue // Skip failed probes
		}

		probeType := models.ProbeType(result.Probe)
		modelResult := models.ProbeResult{
			ScanID:       scanID,
			IP:           result.Target.IP,
			Port:         result.Target.Port,
			ProbeType:    probeType,
			IsVulnerable: result.Result.IsVulnerable,
			Evidence:     result.Result.Evidence,
		}

		// Convert service info to JSON string if available
		if result.Result.ServiceInfo != nil {
			serviceInfoJSON := fmt.Sprintf(`{"type":"%s","version":"%s","banner":"%s","confidence":%f}`,
				result.Result.ServiceInfo.Type,
				result.Result.ServiceInfo.Version,
				result.Result.ServiceInfo.Banner,
				result.Result.ServiceInfo.Confidence,
			)
			modelResult.ServiceInfo = serviceInfoJSON
		}

		modelResults = append(modelResults, modelResult)
	}

	return modelResults
}

// GetVulnerableTargets returns targets that were found to be vulnerable
func (m *Manager) GetVulnerableTargets(results []ProbeResultWithTarget) []ProbeTarget {
	var vulnerableTargets []ProbeTarget
	
	for _, result := range results {
		if result.Error == nil && result.Result.IsVulnerable {
			vulnerableTargets = append(vulnerableTargets, result.Target)
		}
	}

	return vulnerableTargets
}

// countVulnerable counts the number of vulnerable findings
func (m *Manager) countVulnerable(results []ProbeResultWithTarget) int {
	count := 0
	for _, result := range results {
		if result.Error == nil && result.Result.IsVulnerable {
			count++
		}
	}
	return count
}

// GetProbeByName returns a probe by name
func (m *Manager) GetProbeByName(name string) Probe {
	for _, probe := range m.probes {
		if probe.Name() == name {
			return probe
		}
	}
	return nil
}

// GetAllProbes returns all available probes
func (m *Manager) GetAllProbes() []Probe {
	return m.probes
}
