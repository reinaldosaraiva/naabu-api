package cve

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"naabu-api/internal/models"

	"go.uber.org/zap"
)

// NucleiFallbackScanner implements CVE scanning using Nuclei CLI as fallback
type NucleiFallbackScanner struct {
	logger     *zap.Logger
	timeout    time.Duration
	nucleiPath string
}

// NewNucleiFallbackScanner creates a new fallback CLI scanner
func NewNucleiFallbackScanner(logger *zap.Logger, timeout time.Duration) *NucleiFallbackScanner {
	return &NucleiFallbackScanner{
		logger:     logger,
		timeout:    timeout,
		nucleiPath: "nuclei", // Assume nuclei is in PATH
	}
}

// NucleiResult represents a single result from Nuclei CLI JSON output
type NucleiResult struct {
	TemplateID string                 `json:"template-id"`
	Info       map[string]interface{} `json:"info"`
	Host       string                 `json:"host"`
	Matched    string                 `json:"matched-at"`
	Severity   string                 `json:"severity"`
}

// UpdateTemplates updates Nuclei templates using CLI
func (nfs *NucleiFallbackScanner) UpdateTemplates(ctx context.Context) error {
	nfs.logger.Info("Updating Nuclei templates via CLI")

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctxWithTimeout, nfs.nucleiPath, "-update-templates")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		nfs.logger.Error("Failed to update templates via CLI", 
			zap.Error(err),
			zap.String("output", string(output)),
		)
		return fmt.Errorf("template update failed: %w", err)
	}

	nfs.logger.Info("Nuclei templates updated successfully via CLI")
	return nil
}

// ScanTargets executes CVE scanning using Nuclei CLI
func (nfs *NucleiFallbackScanner) ScanTargets(ctx context.Context, targets []string) models.CVEScanResult {
	if len(targets) == 0 {
		return models.CVEScanResult{
			Status:   "ok",
			CVEIDs:   []string{},
			Evidence: []string{},
		}
	}

	nfs.logger.Info("Starting CVE scan via CLI fallback", 
		zap.Int("targets", len(targets)),
		zap.Duration("timeout", nfs.timeout),
	)

	// Create context with timeout
	ctxWithTimeout, cancel := context.WithTimeout(ctx, nfs.timeout)
	defer cancel()

	// Build nuclei command
	args := []string{
		"-t", "cves/",           // CVE templates directory
		"-json",                 // JSON output
		"-severity", "high,critical", // Only HIGH/CRITICAL
		"-rl", "100",           // Rate limit: 100 requests per second
		"-c", "20",             // Concurrency: 20 threads
		"-timeout", "5",        // Connection timeout: 5 seconds
		"-retries", "1",        // Single retry
		"-silent",              // Reduce noise
	}

	// Add targets
	for _, target := range targets {
		args = append(args, "-u", target)
	}

	nfs.logger.Debug("Executing nuclei CLI", zap.Strings("args", args))

	cmd := exec.CommandContext(ctxWithTimeout, nfs.nucleiPath, args...)
	
	// Get stdout pipe for streaming JSON results
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		nfs.logger.Error("Failed to create stdout pipe", zap.Error(err))
		return models.CVEScanResult{
			Status:   "error",
			CVEIDs:   []string{},
			Evidence: []string{fmt.Sprintf("Pipe creation failed: %s", err.Error())},
		}
	}

	// Start command
	if err := cmd.Start(); err != nil {
		nfs.logger.Error("Failed to start nuclei CLI", zap.Error(err))
		return models.CVEScanResult{
			Status:   "error",
			CVEIDs:   []string{},
			Evidence: []string{fmt.Sprintf("Command start failed: %s", err.Error())},
		}
	}

	// Process streaming JSON results
	var cveIDs []string
	var evidence []string
	foundCVEs := make(map[string]bool)

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var result NucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			nfs.logger.Debug("Failed to parse JSON result", 
				zap.Error(err),
				zap.String("line", line),
			)
			continue
		}

		// Extract CVE ID
		cveID := extractCVEFromCLIResult(&result)
		if cveID != "" && !foundCVEs[cveID] {
			foundCVEs[cveID] = true
			cveIDs = append(cveIDs, cveID)
			
			// Add sanitized evidence
			evidence = append(evidence, fmt.Sprintf("URL: %s", result.Host))
			
			nfs.logger.Info("CVE found via CLI",
				zap.String("cve_id", cveID),
				zap.String("host", result.Host),
				zap.String("template", result.TemplateID),
				zap.String("severity", result.Severity),
			)
		}
	}

	// Wait for command completion
	err = cmd.Wait()
	
	// Handle results
	if err != nil {
		if ctxWithTimeout.Err() == context.DeadlineExceeded {
			nfs.logger.Warn("CVE scan timeout exceeded via CLI", zap.Duration("timeout", nfs.timeout))
			return models.CVEScanResult{
				Status:   "error",
				CVEIDs:   cveIDs, // Return partial results
				Evidence: append(evidence, "Scan timeout exceeded"),
			}
		}
		
		// Non-zero exit might be normal (no results found)
		if exitError, ok := err.(*exec.ExitError); ok {
			nfs.logger.Debug("Nuclei CLI exited with non-zero code", 
				zap.Int("exit_code", exitError.ExitCode()),
			)
		} else {
			nfs.logger.Error("CVE scan execution failed via CLI", zap.Error(err))
			return models.CVEScanResult{
				Status:   "error",
				CVEIDs:   []string{},
				Evidence: []string{fmt.Sprintf("Execution failed: %s", err.Error())},
			}
		}
	}

	// Determine final status
	status := "ok"
	if len(cveIDs) > 0 {
		status = "risk"
	}

	nfs.logger.Info("CVE scan completed via CLI",
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

// extractCVEFromCLIResult extracts CVE ID from CLI JSON result
func extractCVEFromCLIResult(result *NucleiResult) string {
	// Try to extract CVE from template ID
	if strings.Contains(strings.ToUpper(result.TemplateID), "CVE-") {
		parts := strings.Split(strings.ToUpper(result.TemplateID), "CVE-")
		if len(parts) > 1 {
			cveNumber := strings.Fields(parts[1])[0] // Get first word after CVE-
			cveNumber = strings.Split(cveNumber, ".")[0] // Remove file extension
			return fmt.Sprintf("CVE-%s", cveNumber)
		}
	}

	// Try to extract from info classification
	if result.Info != nil {
		if classification, ok := result.Info["classification"].(map[string]interface{}); ok {
			if cveID, ok := classification["cve-id"].(string); ok {
				return cveID
			}
		}
		
		// Try references
		if references, ok := result.Info["reference"].([]interface{}); ok {
			for _, ref := range references {
				if refStr, ok := ref.(string); ok {
					if strings.Contains(strings.ToUpper(refStr), "CVE-") {
						parts := strings.Split(strings.ToUpper(refStr), "CVE-")
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
		}
	}

	// Fallback: use template ID if it looks like a CVE
	if strings.HasPrefix(strings.ToUpper(result.TemplateID), "CVE") {
		return strings.ToUpper(strings.Split(result.TemplateID, ".")[0])
	}

	return ""
}