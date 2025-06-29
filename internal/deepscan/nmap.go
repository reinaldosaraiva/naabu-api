package deepscan

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"naabu-api/internal/models"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// NmapScanner handles Nmap execution and parsing
type NmapScanner struct {
	logger      *zap.Logger
	nmapPath    string
	scriptsPath string
	timeout     time.Duration
}

// NewNmapScanner creates a new Nmap scanner
func NewNmapScanner(logger *zap.Logger) *NmapScanner {
	return &NmapScanner{
		logger:      logger,
		nmapPath:    "nmap", // Assume nmap is in PATH
		scriptsPath: "/usr/share/nmap/scripts", // Default NSE scripts path
		timeout:     5 * time.Minute,
	}
}

// ScanTarget represents a target for deep scanning
type ScanTarget struct {
	IP        string
	Port      int
	Protocol  string
	ProbeType models.ProbeType
}

// ScanResult represents the result of an Nmap scan
type ScanResult struct {
	Target    ScanTarget
	XMLOutput string
	Command   string
	Duration  time.Duration
	Error     error
}

// ExecuteDeepScan runs Nmap with appropriate NSE scripts based on service type
func (s *NmapScanner) ExecuteDeepScan(ctx context.Context, target ScanTarget) *ScanResult {
	result := &ScanResult{
		Target: target,
	}

	// Get NSE scripts for the service type
	scripts := s.getScriptsForService(target.ProbeType)
	if len(scripts) == 0 {
		result.Error = fmt.Errorf("no scripts available for service type: %s", target.ProbeType)
		return result
	}

	// Build Nmap command
	args := []string{
		"-sV",                    // Version detection
		"-sC",                    // Default scripts
		"--script", strings.Join(scripts, ","), // Custom scripts
		"-p", fmt.Sprintf("%d", target.Port),   // Specific port
		"-oX", "-",              // XML output to stdout
		"--host-timeout", "300", // 5 minute host timeout
		"--script-timeout", "60", // 1 minute script timeout
		target.IP,
	}

	result.Command = fmt.Sprintf("nmap %s", strings.Join(args, " "))

	s.logger.Info("Executing Nmap deep scan",
		zap.String("target", fmt.Sprintf("%s:%d", target.IP, target.Port)),
		zap.String("service", string(target.ProbeType)),
		zap.Strings("scripts", scripts),
		zap.String("command", result.Command),
	)

	// Create context with timeout
	scanCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Execute Nmap
	startTime := time.Now()
	cmd := exec.CommandContext(scanCtx, s.nmapPath, args...)
	
	output, err := cmd.Output()
	result.Duration = time.Since(startTime)
	
	if err != nil {
		result.Error = fmt.Errorf("nmap execution failed: %w", err)
		s.logger.Error("Nmap execution failed",
			zap.String("target", fmt.Sprintf("%s:%d", target.IP, target.Port)),
			zap.Error(err),
			zap.Duration("duration", result.Duration),
		)
		return result
	}

	result.XMLOutput = string(output)
	
	s.logger.Info("Nmap deep scan completed",
		zap.String("target", fmt.Sprintf("%s:%d", target.IP, target.Port)),
		zap.String("service", string(target.ProbeType)),
		zap.Duration("duration", result.Duration),
		zap.Int("output_size", len(result.XMLOutput)),
	)

	return result
}

// getScriptsForService returns appropriate NSE scripts for each service type
func (s *NmapScanner) getScriptsForService(probeType models.ProbeType) []string {
	switch probeType {
	case models.ProbeTypeFTP:
		return []string{
			"ftp-anon",
			"ftp-bounce",
			"ftp-libopie",
			"ftp-proftpd-backdoor",
			"ftp-vsftpd-backdoor",
		}
	case models.ProbeTypeVNC:
		return []string{
			"vnc-info",
			"vnc-title",
		}
	case models.ProbeTypeRDP:
		return []string{
			"rdp-enum-encryption",
			"rdp-vuln-ms12-020",
		}
	case models.ProbeTypeLDAP:
		return []string{
			"ldap-rootdse",
			"ldap-search",
		}
	case models.ProbeTypePPTP:
		return []string{
			"pptp-version",
		}
	case models.ProbeTypeRsync:
		return []string{
			"rsync-list-modules",
		}
	default:
		return []string{}
	}
}

// ExecuteBatchDeepScan runs deep scans for multiple targets
func (s *NmapScanner) ExecuteBatchDeepScan(ctx context.Context, targets []ScanTarget) []*ScanResult {
	results := make([]*ScanResult, len(targets))
	
	// Execute scans sequentially to avoid overwhelming the system
	for i, target := range targets {
		results[i] = s.ExecuteDeepScan(ctx, target)
		
		// Small delay between scans to be respectful
		select {
		case <-ctx.Done():
			// If context is cancelled, mark remaining scans as errors
			for j := i + 1; j < len(targets); j++ {
				results[j] = &ScanResult{
					Target: targets[j],
					Error:  ctx.Err(),
				}
			}
			break
		case <-time.After(1 * time.Second):
			// Continue with next scan
		}
	}
	
	return results
}

// ConvertToDeepScanArtifacts converts scan results to database models
func (s *NmapScanner) ConvertToDeepScanArtifacts(scanID uuid.UUID, results []*ScanResult) []models.DeepScanArtifact {
	var artifacts []models.DeepScanArtifact
	
	for _, result := range results {
		if result.Error != nil {
			continue // Skip failed scans
		}

		artifact := models.DeepScanArtifact{
			ScanID:    scanID,
			IP:        result.Target.IP,
			Port:      result.Target.Port,
			Protocol:  result.Target.Protocol,
			Tool:      "nmap",
			Command:   result.Command,
			XMLOutput: result.XMLOutput,
			Status:    "completed",
		}

		artifacts = append(artifacts, artifact)
	}

	return artifacts
}

// ValidateNmapInstallation checks if Nmap is properly installed
func (s *NmapScanner) ValidateNmapInstallation() error {
	// Check if nmap binary exists
	cmd := exec.Command(s.nmapPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("nmap not found or not executable: %w", err)
	}

	version := string(output)
	if !strings.Contains(version, "Nmap") {
		return fmt.Errorf("invalid nmap installation: %s", version)
	}

	// Check if NSE scripts directory exists
	if s.scriptsPath != "" {
		scriptsDir := filepath.Dir(s.scriptsPath)
		if _, err := exec.Command("ls", scriptsDir).Output(); err != nil {
			s.logger.Warn("NSE scripts directory not found",
				zap.String("path", scriptsDir),
				zap.Error(err),
			)
		}
	}

	s.logger.Info("Nmap installation validated",
		zap.String("version", strings.TrimSpace(version)),
		zap.String("scripts_path", s.scriptsPath),
	)

	return nil
}
