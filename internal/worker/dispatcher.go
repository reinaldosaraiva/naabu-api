package worker

import (
	"context"
	"fmt"

	"naabu-api/internal/database"
	"naabu-api/internal/deepscan"
	"naabu-api/internal/models"
	"naabu-api/internal/probes"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Scanner interface defines the methods needed for scanning
type Scanner interface {
	ScanPorts(ctx context.Context, req models.ScanRequest) (models.ScanResponse, error)
}

// Dispatcher coordinates job distribution across different worker pools
type Dispatcher struct {
	quickScanPool *Pool
	probePool     *Pool
	deepScanPool  *Pool
	logger        *zap.Logger
	repo          database.Repository
	scanner       Scanner
	probeManager  *probes.Manager
	nmapScanner   *deepscan.NmapScanner
}

// NewDispatcher creates a new job dispatcher
func NewDispatcher(
	quickScanWorkers, probeWorkers, deepScanWorkers int,
	repo database.Repository,
	scanner Scanner,
	probeManager *probes.Manager,
	nmapScanner *deepscan.NmapScanner,
	logger *zap.Logger,
) *Dispatcher {
	d := &Dispatcher{
		logger:       logger,
		repo:         repo,
		scanner:      scanner,
		probeManager: probeManager,
		nmapScanner:  nmapScanner,
	}

	// Create job handlers
	quickScanHandler := &QuickScanHandler{
		dispatcher: d,
		scanner:    scanner,
		logger:     logger,
	}
	
	probeHandler := &ProbeHandler{
		dispatcher:   d,
		probeManager: probeManager,
		logger:       logger,
	}
	
	deepScanHandler := &DeepScanHandler{
		dispatcher:  d,
		nmapScanner: nmapScanner,
		logger:      logger,
	}

	// Create worker pools
	d.quickScanPool = NewPool(quickScanWorkers, 100, quickScanHandler, logger)
	d.probePool = NewPool(probeWorkers, 200, probeHandler, logger)
	d.deepScanPool = NewPool(deepScanWorkers, 50, deepScanHandler, logger)

	return d
}

// Start starts all worker pools
func (d *Dispatcher) Start(ctx context.Context) {
	d.logger.Info("Starting job dispatcher")
	
	d.quickScanPool.Start(ctx)
	d.probePool.Start(ctx)
	d.deepScanPool.Start(ctx)
	
	d.logger.Info("Job dispatcher started")
}

// Stop stops all worker pools
func (d *Dispatcher) Stop() {
	d.logger.Info("Stopping job dispatcher")
	
	d.quickScanPool.Stop()
	d.probePool.Stop()
	d.deepScanPool.Stop()
	
	d.logger.Info("Job dispatcher stopped")
}

// SubmitQuickScan submits a quick scan job
func (d *Dispatcher) SubmitQuickScan(scanID uuid.UUID, ips []string, ports string) error {
	payload := QuickScanPayload{
		ScanID: scanID,
		IPs:    ips,
		Ports:  ports,
	}
	
	job := Job{
		ID:       fmt.Sprintf("quick_scan_%s", scanID.String()),
		Type:     JobTypeQuickScan,
		ScanID:   scanID.String(),
		Payload:  payload,
		Priority: 1,
		MaxRetry: 3,
	}
	
	return d.quickScanPool.Submit(job)
}

// SubmitProbe submits a probe job
func (d *Dispatcher) SubmitProbe(scanID uuid.UUID, targets []probes.ProbeTarget) error {
	payload := ProbePayload{
		ScanID:  scanID,
		Targets: targets,
	}
	
	job := Job{
		ID:       fmt.Sprintf("probe_%s_%d", scanID.String(), len(targets)),
		Type:     JobTypeProbe,
		ScanID:   scanID.String(),
		Payload:  payload,
		Priority: 2,
		MaxRetry: 2,
	}
	
	return d.probePool.Submit(job)
}

// SubmitDeepScan submits a deep scan job
func (d *Dispatcher) SubmitDeepScan(scanID uuid.UUID, targets []deepscan.ScanTarget) error {
	payload := DeepScanPayload{
		ScanID:  scanID,
		Targets: targets,
	}
	
	job := Job{
		ID:       fmt.Sprintf("deep_scan_%s_%d", scanID.String(), len(targets)),
		Type:     JobTypeDeepScan,
		ScanID:   scanID.String(),
		Payload:  payload,
		Priority: 3,
		MaxRetry: 1,
	}
	
	return d.deepScanPool.Submit(job)
}

// GetStats returns statistics for all worker pools
func (d *Dispatcher) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"quick_scan_pool": d.quickScanPool.GetStats(),
		"probe_pool":      d.probePool.GetStats(),
		"deep_scan_pool":  d.deepScanPool.GetStats(),
	}
}

// Job payload types

type QuickScanPayload struct {
	ScanID uuid.UUID
	IPs    []string
	Ports  string
}

type ProbePayload struct {
	ScanID  uuid.UUID
	Targets []probes.ProbeTarget
}

type DeepScanPayload struct {
	ScanID  uuid.UUID
	Targets []deepscan.ScanTarget
}

// Job handlers

// QuickScanHandler handles quick scan jobs
type QuickScanHandler struct {
	dispatcher *Dispatcher
	scanner    Scanner
	logger     *zap.Logger
}

func (h *QuickScanHandler) HandleJob(ctx context.Context, job Job) error {
	payload, ok := job.Payload.(QuickScanPayload)
	if !ok {
		return fmt.Errorf("invalid payload type for quick scan job")
	}

	h.logger.Info("Executing quick scan",
		zap.String("scan_id", payload.ScanID.String()),
		zap.Strings("ips", payload.IPs),
		zap.String("ports", payload.Ports),
	)

	// Update job status to running
	if err := h.dispatcher.repo.UpdateScanJobStatus(payload.ScanID, models.JobStatusRunning); err != nil {
		h.logger.Error("Failed to update job status", zap.Error(err))
	}

	// Execute scan
	scanRequest := models.ScanRequest{
		IPs:   payload.IPs,
		Ports: payload.Ports,
	}

	result, err := h.scanner.ScanPorts(ctx, scanRequest)
	if err != nil {
		h.dispatcher.repo.UpdateScanJobError(payload.ScanID, err.Error())
		return fmt.Errorf("scan failed: %w", err)
	}

	// Store scan results
	if err := h.dispatcher.repo.UpdateScanJobResults(payload.ScanID, result); err != nil {
		h.logger.Error("Failed to store scan results", zap.Error(err))
	}

	// Convert results to probe targets
	probeTargets := h.dispatcher.probeManager.ConvertToProbeTargets(result.Results)
	
	if len(probeTargets) > 0 {
		// Submit probe jobs
		if err := h.dispatcher.SubmitProbe(payload.ScanID, probeTargets); err != nil {
			h.logger.Error("Failed to submit probe jobs", zap.Error(err))
		}
	}

	h.logger.Info("Quick scan completed",
		zap.String("scan_id", payload.ScanID.String()),
		zap.Int("open_ports", result.Summary.OpenPorts),
		zap.Int("probe_targets", len(probeTargets)),
	)

	return nil
}

// ProbeHandler handles probe jobs
type ProbeHandler struct {
	dispatcher   *Dispatcher
	probeManager *probes.Manager
	logger       *zap.Logger
}

func (h *ProbeHandler) HandleJob(ctx context.Context, job Job) error {
	payload, ok := job.Payload.(ProbePayload)
	if !ok {
		return fmt.Errorf("invalid payload type for probe job")
	}

	h.logger.Info("Executing probes",
		zap.String("scan_id", payload.ScanID.String()),
		zap.Int("targets", len(payload.Targets)),
	)

	// Execute probes
	probeResults := h.probeManager.ProbeTargets(ctx, payload.ScanID, payload.Targets)
	
	// Convert and store probe results
	modelResults := h.probeManager.ConvertToModelProbeResults(payload.ScanID, probeResults)
	
	for _, result := range modelResults {
		if err := h.dispatcher.repo.CreateProbeResult(&result); err != nil {
			h.logger.Error("Failed to store probe result", zap.Error(err))
		}
	}

	// Get vulnerable targets for deep scanning
	vulnerableTargets := h.probeManager.GetVulnerableTargets(probeResults)
	
	if len(vulnerableTargets) > 0 {
		// Convert to deep scan targets
		var deepScanTargets []deepscan.ScanTarget
		for _, target := range vulnerableTargets {
			// Determine probe type based on port
			var probeType models.ProbeType
			switch target.Port {
			case 21:
				probeType = models.ProbeTypeFTP
			case 3389:
				probeType = models.ProbeTypeRDP
			case 389, 636:
				probeType = models.ProbeTypeLDAP
			case 1723:
				probeType = models.ProbeTypePPTP
			case 873:
				probeType = models.ProbeTypeRsync
			default:
				if target.Port >= 5900 && target.Port <= 5999 {
					probeType = models.ProbeTypeVNC
				}
			}
			
			if probeType != "" {
				deepScanTargets = append(deepScanTargets, deepscan.ScanTarget{
					IP:        target.IP,
					Port:      target.Port,
					Protocol:  "tcp",
					ProbeType: probeType,
				})
			}
		}
		
		// Submit deep scan jobs
		if len(deepScanTargets) > 0 {
			if err := h.dispatcher.SubmitDeepScan(payload.ScanID, deepScanTargets); err != nil {
				h.logger.Error("Failed to submit deep scan jobs", zap.Error(err))
			}
		}
	}

	h.logger.Info("Probes completed",
		zap.String("scan_id", payload.ScanID.String()),
		zap.Int("total_probes", len(probeResults)),
		zap.Int("vulnerable_targets", len(vulnerableTargets)),
		zap.Int("deep_scan_targets", len(vulnerableTargets)),
	)

	return nil
}

// DeepScanHandler handles deep scan jobs
type DeepScanHandler struct {
	dispatcher  *Dispatcher
	nmapScanner *deepscan.NmapScanner
	logger      *zap.Logger
}

func (h *DeepScanHandler) HandleJob(ctx context.Context, job Job) error {
	payload, ok := job.Payload.(DeepScanPayload)
	if !ok {
		return fmt.Errorf("invalid payload type for deep scan job")
	}

	h.logger.Info("Executing deep scans",
		zap.String("scan_id", payload.ScanID.String()),
		zap.Int("targets", len(payload.Targets)),
	)

	// Execute deep scans
	results := h.nmapScanner.ExecuteBatchDeepScan(ctx, payload.Targets)
	
	// Convert and store deep scan artifacts
	artifacts := h.nmapScanner.ConvertToDeepScanArtifacts(payload.ScanID, results)
	
	for _, artifact := range artifacts {
		if err := h.dispatcher.repo.CreateDeepScanArtifact(&artifact); err != nil {
			h.logger.Error("Failed to store deep scan artifact", zap.Error(err))
		}
	}

	h.logger.Info("Deep scans completed",
		zap.String("scan_id", payload.ScanID.String()),
		zap.Int("total_scans", len(results)),
		zap.Int("artifacts_stored", len(artifacts)),
	)

	return nil
}
