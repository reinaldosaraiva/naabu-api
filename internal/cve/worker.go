package cve

import (
	"context"
	"fmt"
	"sync"
	"time"

	"naabu-api/internal/models"

	"go.uber.org/zap"
)

// CVEWorkerPool manages concurrent CVE scanning operations
type CVEWorkerPool struct {
	logger        *zap.Logger
	scanner       CVEScanner
	fallback      CVEScanner
	maxWorkers    int
	maxHosts      int
	timeout       time.Duration
}

// NewCVEWorkerPool creates a new worker pool for CVE scanning
func NewCVEWorkerPool(logger *zap.Logger, maxWorkers, maxHosts int, timeout time.Duration) *CVEWorkerPool {
	// Initialize primary scanner (SDK)
	primaryScanner := NewNucleiScanner(logger, timeout)
	
	// Initialize fallback scanner (CLI)
	fallbackScanner := NewNucleiFallbackScanner(logger, timeout)
	
	return &CVEWorkerPool{
		logger:     logger,
		scanner:    primaryScanner,
		fallback:   fallbackScanner,
		maxWorkers: maxWorkers,
		maxHosts:   maxHosts,
		timeout:    timeout,
	}
}

// ScanJob represents a CVE scanning job
type ScanJob struct {
	Targets []string
	Result  chan models.CVEScanResult
}

// ExecuteCVEScan performs CVE scanning with worker pool and fallback
func (cwp *CVEWorkerPool) ExecuteCVEScan(ctx context.Context, targets []string) models.CVEScanResult {
	if len(targets) == 0 {
		return models.CVEScanResult{
			Status:   "ok",
			CVEIDs:   []string{},
			Evidence: []string{},
		}
	}

	// Enforce max hosts limit (requirement: up to 100 hosts)
	if len(targets) > cwp.maxHosts {
		cwp.logger.Warn("Too many targets, limiting to max hosts", 
			zap.Int("requested", len(targets)),
			zap.Int("max_hosts", cwp.maxHosts),
		)
		targets = targets[:cwp.maxHosts]
	}

	cwp.logger.Info("Starting CVE worker pool scan",
		zap.Int("targets", len(targets)),
		zap.Int("max_workers", cwp.maxWorkers),
		zap.Duration("timeout", cwp.timeout),
	)

	// Try primary scanner first (SDK)
	result := cwp.executeWithScanner(ctx, targets, cwp.scanner, "SDK")
	
	// If primary scanner fails, try fallback (CLI)
	if result.Status == "error" {
		cwp.logger.Warn("Primary scanner failed, trying fallback", 
			zap.Strings("evidence", result.Evidence),
		)
		result = cwp.executeWithScanner(ctx, targets, cwp.fallback, "CLI")
	}

	return result
}

// executeWithScanner executes scan with a specific scanner implementation
func (cwp *CVEWorkerPool) executeWithScanner(ctx context.Context, targets []string, scanner CVEScanner, scannerType string) models.CVEScanResult {
	// Update templates before scanning
	updateCtx, updateCancel := context.WithTimeout(ctx, 2*time.Minute)
	defer updateCancel()
	
	if err := scanner.UpdateTemplates(updateCtx); err != nil {
		cwp.logger.Error("Failed to update templates", 
			zap.String("scanner_type", scannerType),
			zap.Error(err),
		)
		// Continue without template update - use existing templates
	}

	// Split targets into chunks for worker distribution
	chunks := cwp.splitTargets(targets, cwp.maxWorkers)
	
	// Create job channels
	jobs := make(chan ScanJob, len(chunks))
	results := make(chan models.CVEScanResult, len(chunks))
	
	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < cwp.maxWorkers && i < len(chunks); i++ {
		wg.Add(1)
		go cwp.worker(ctx, scanner, scannerType, jobs, &wg)
	}
	
	// Send jobs
	for _, chunk := range chunks {
		job := ScanJob{
			Targets: chunk,
			Result:  make(chan models.CVEScanResult, 1),
		}
		jobs <- job
		
		// Collect result from this job
		go func(job ScanJob) {
			defer func() {
				if r := recover(); r != nil {
					// Handle panic from closed channel
					cwp.logger.Debug("Recovered from panic in result collection", zap.Any("panic", r))
				}
			}()
			result := <-job.Result
			select {
			case results <- result:
			case <-ctx.Done():
				// Context cancelled, don't send result
			}
		}(job)
	}
	close(jobs)
	
	// Wait for all workers to complete
	wg.Wait()
	close(results)
	
	// Aggregate results from all workers
	return cwp.aggregateResults(results, scannerType)
}

// worker processes CVE scan jobs
func (cwp *CVEWorkerPool) worker(ctx context.Context, scanner CVEScanner, scannerType string, jobs <-chan ScanJob, wg *sync.WaitGroup) {
	defer wg.Done()
	
	for job := range jobs {
		cwp.logger.Debug("Worker processing job",
			zap.String("scanner_type", scannerType),
			zap.Int("targets", len(job.Targets)),
		)
		
		result := scanner.ScanTargets(ctx, job.Targets)
		job.Result <- result
	}
}

// splitTargets divides targets into chunks for worker distribution
func (cwp *CVEWorkerPool) splitTargets(targets []string, numChunks int) [][]string {
	if numChunks <= 0 || len(targets) == 0 {
		return [][]string{targets}
	}
	
	if numChunks > len(targets) {
		numChunks = len(targets)
	}
	
	chunkSize := len(targets) / numChunks
	remainder := len(targets) % numChunks
	
	chunks := make([][]string, 0, numChunks)
	start := 0
	
	for i := 0; i < numChunks; i++ {
		end := start + chunkSize
		if i < remainder {
			end++
		}
		
		if start < len(targets) {
			chunks = append(chunks, targets[start:end])
		}
		start = end
	}
	
	return chunks
}

// aggregateResults combines results from multiple workers
func (cwp *CVEWorkerPool) aggregateResults(results <-chan models.CVEScanResult, scannerType string) models.CVEScanResult {
	var allCVEIDs []string
	var allEvidence []string
	foundCVEs := make(map[string]bool)
	hasError := false
	hasRisk := false
	
	resultCount := 0
	for result := range results {
		resultCount++
		
		// Track status
		if result.Status == "error" {
			hasError = true
		} else if result.Status == "risk" {
			hasRisk = true
		}
		
		// Deduplicate CVE IDs
		for _, cveID := range result.CVEIDs {
			if !foundCVEs[cveID] {
				foundCVEs[cveID] = true
				allCVEIDs = append(allCVEIDs, cveID)
			}
		}
		
		// Collect evidence
		allEvidence = append(allEvidence, result.Evidence...)
	}
	
	// Determine final status
	finalStatus := "ok"
	if hasError && !hasRisk && len(allCVEIDs) == 0 {
		finalStatus = "error"
	} else if hasRisk || len(allCVEIDs) > 0 {
		finalStatus = "risk"
	}
	
	// Limit evidence to prevent response bloat
	if len(allEvidence) > 50 {
		allEvidence = allEvidence[:50]
		allEvidence = append(allEvidence, fmt.Sprintf("... and %d more evidence items", len(allEvidence)-50))
	}
	
	cwp.logger.Info("CVE scan aggregation complete",
		zap.String("scanner_type", scannerType),
		zap.String("final_status", finalStatus),
		zap.Int("worker_results", resultCount),
		zap.Int("total_cves", len(allCVEIDs)),
		zap.Int("evidence_items", len(allEvidence)),
	)
	
	return models.CVEScanResult{
		Status:   finalStatus,
		CVEIDs:   allCVEIDs,
		Evidence: allEvidence,
	}
}

// UpdateTemplates updates templates using the primary scanner
func (cwp *CVEWorkerPool) UpdateTemplates(ctx context.Context) error {
	cwp.logger.Info("Updating CVE templates via worker pool")
	
	// Try primary scanner first
	err := cwp.scanner.UpdateTemplates(ctx)
	if err != nil {
		cwp.logger.Warn("Primary scanner template update failed, trying fallback", zap.Error(err))
		
		// Try fallback scanner
		err = cwp.fallback.UpdateTemplates(ctx)
		if err != nil {
			return fmt.Errorf("both primary and fallback template updates failed: %w", err)
		}
	}
	
	return nil
}