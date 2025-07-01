package cve

import (
	"context"
	"fmt"
	"strings"
	"time"

	"naabu-api/internal/models"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"go.uber.org/zap"
)

// CVEScanner interface for CVE scanning operations
type CVEScanner interface {
	ScanTargets(ctx context.Context, targets []string) models.CVEScanResult
	UpdateTemplates(ctx context.Context) error
}

// NucleiScanner implements CVE scanning using Nuclei SDK
type NucleiScanner struct {
	logger  *zap.Logger
	timeout time.Duration
}

// NewNucleiScanner creates a new Nuclei-based CVE scanner
func NewNucleiScanner(logger *zap.Logger, timeout time.Duration) *NucleiScanner {
	return &NucleiScanner{
		logger:  logger,
		timeout: timeout,
	}
}

// UpdateTemplates updates Nuclei templates to latest version
func (ns *NucleiScanner) UpdateTemplates(ctx context.Context) error {
	ns.logger.Info("Updating Nuclei templates via SDK")
	
	// Create basic Nuclei engine for template updates using v3 API
	ne, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{"cve"}}),
	)
	if err != nil {
		return fmt.Errorf("failed to create nuclei engine: %w", err)
	}
	defer ne.Close()

	// Note: Template updates are handled automatically by Nuclei v3
	// Templates are fetched/updated as needed during execution
	ns.logger.Info("Nuclei templates ready (v3 handles updates automatically)")
	return nil
}

// ScanTargets executes CVE scanning on provided targets
func (ns *NucleiScanner) ScanTargets(ctx context.Context, targets []string) models.CVEScanResult {
	if len(targets) == 0 {
		return models.CVEScanResult{
			Status:   "ok",
			CVEIDs:   []string{},
			Evidence: []string{},
		}
	}

	ns.logger.Info("Starting CVE scan via SDK", 
		zap.Int("targets", len(targets)),
		zap.Duration("timeout", ns.timeout),
	)

	// Create context with timeout
	ctxWithTimeout, cancel := context.WithTimeout(ctx, ns.timeout)
	defer cancel()

	// Create Nuclei engine with CVE-specific configuration using v3 API
	ne, err := nuclei.NewNucleiEngineCtx(ctxWithTimeout,
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Tags:     []string{"cve"},
			Severity: "critical,high", // Only HIGH/CRITICAL CVEs per requirement
		}),
	)
	if err != nil {
		ns.logger.Error("Failed to create nuclei engine", zap.Error(err))
		return models.CVEScanResult{
			Status:   "error",
			CVEIDs:   []string{},
			Evidence: []string{fmt.Sprintf("Engine creation failed: %s", err.Error())},
		}
	}
	defer ne.Close()

	// Load targets into the engine
	ne.LoadTargets(targets, false) // false = don't probe non-http targets

	// Collect results
	var cveIDs []string
	var evidence []string
	foundCVEs := make(map[string]bool) // Deduplicate CVEs

	// Execute scan with result callback using v3 API
	err = ne.ExecuteWithCallback(func(event *output.ResultEvent) {
		// Extract CVE ID from template or event
		cveID := extractCVEFromSDKResult(event)
		if cveID != "" && !foundCVEs[cveID] {
			foundCVEs[cveID] = true
			cveIDs = append(cveIDs, cveID)
			
			// Add sanitized evidence (limited info only, no PII)
			if event.Host != "" {
				evidence = append(evidence, fmt.Sprintf("URL: %s", event.Host))
			}
		}
		
		ns.logger.Info("CVE found via SDK",
			zap.String("cve_id", cveID),
			zap.String("host", event.Host),
			zap.String("template", event.TemplateID),
		)
	})

	// Handle execution results
	if err != nil {
		if ctxWithTimeout.Err() == context.DeadlineExceeded {
			ns.logger.Warn("CVE scan timeout exceeded via SDK", zap.Duration("timeout", ns.timeout))
			return models.CVEScanResult{
				Status:   "error",
				CVEIDs:   cveIDs, // Return partial results
				Evidence: append(evidence, "Scan timeout exceeded"),
			}
		}
		
		ns.logger.Error("CVE scan execution failed via SDK", zap.Error(err))
		return models.CVEScanResult{
			Status:   "error",
			CVEIDs:   []string{},
			Evidence: []string{fmt.Sprintf("Execution failed: %s", err.Error())},
		}
	}

	// Determine final status
	status := "ok"
	if len(cveIDs) > 0 {
		status = "risk"
	}

	ns.logger.Info("CVE scan completed via SDK",
		zap.String("status", status),
		zap.Int("cves_found", len(cveIDs)),
		zap.Strings("cve_ids", cveIDs),
	)

	return models.CVEScanResult{
		Status:   status,
		CVEIDs:   cveIDs,
		Evidence: evidence,
	}
}

// extractCVEFromSDKResult extracts CVE ID from Nuclei SDK result
func extractCVEFromSDKResult(event *output.ResultEvent) string {
	// Try to extract CVE from template ID (e.g., "CVE-2021-44228")
	if strings.Contains(strings.ToUpper(event.TemplateID), "CVE-") {
		parts := strings.Split(strings.ToUpper(event.TemplateID), "CVE-")
		if len(parts) > 1 {
			// Extract the CVE number part
			cveNumber := strings.Fields(parts[1])[0] // Get first word
			cveNumber = strings.Split(cveNumber, ".")[0] // Remove extension
			return fmt.Sprintf("CVE-%s", cveNumber)
		}
	}

	// Try to extract from template info/classification
	if event.Info.Classification != nil {
		// Check CVE-ID in classification using StringSlice methods
		for _, cveID := range event.Info.Classification.CVEID.ToSlice() {
			if cveID != "" {
				return cveID
			}
		}
	}
	
	// Try references if they exist
	if event.Info.Reference != nil {
		for _, ref := range event.Info.Reference.ToSlice() {
			if strings.Contains(strings.ToUpper(ref), "CVE-") {
				// Extract CVE ID from reference URL
				parts := strings.Split(strings.ToUpper(ref), "CVE-")
				if len(parts) > 1 {
					cveNumber := strings.Split(parts[1], "/")[0]
					cveNumber = strings.Split(cveNumber, "?")[0]
					cveNumber = strings.Split(cveNumber, "#")[0]
					cveNumber = strings.Fields(cveNumber)[0]
					return fmt.Sprintf("CVE-%s", cveNumber)
				}
			}
		}
	}

	// Fallback: use template ID if it looks like a CVE
	if strings.HasPrefix(strings.ToUpper(event.TemplateID), "CVE") {
		return strings.ToUpper(strings.Split(event.TemplateID, ".")[0])
	}

	return ""
}