package scanner

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

// TLSXScanner handles TLS scanning using tlsx
type TLSXScanner struct {
	logger *zap.Logger
}

// NewTLSXScanner creates a new TLSX scanner instance
func NewTLSXScanner(logger *zap.Logger) *TLSXScanner {
	return &TLSXScanner{
		logger: logger,
	}
}

// TLSXOutput represents the JSON output from tlsx
type TLSXOutput struct {
	Host              string   `json:"host"`
	IP                string   `json:"ip"`
	Port              string   `json:"port"`
	ProbeStatus       bool     `json:"probe_status"`
	TLSVersion        string   `json:"tls_version"`
	Cipher            string   `json:"cipher"`
	SelfSigned        bool     `json:"self_signed"`
	Expired           bool     `json:"expired"`
	MismatchedCN      bool     `json:"mismatched"`
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after"`
	SubjectCN         string   `json:"subject_cn"`
	SubjectAN         []string `json:"subject_an"`
	Issuer            string   `json:"issuer"`
	CertificateSerial string   `json:"certificate_serial"`
	Error             string   `json:"error,omitempty"`
}

// ScanDomains performs TLS scanning on the provided domains
func (s *TLSXScanner) ScanDomains(ctx context.Context, domains []string) ([]models.TLSScanResult, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains provided")
	}

	s.logger.Info("Starting TLS scan", zap.Int("domain_count", len(domains)))

	// Create tlsx command
	args := []string{"-json", "-silent"}
	
	// Add domains as arguments
	for _, domain := range domains {
		args = append(args, "-host", domain)
	}

	cmd := exec.CommandContext(ctx, "tlsx", args...)
	
	// Get stdout pipe
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start tlsx: %w", err)
	}

	// Read and parse output
	scanner := bufio.NewScanner(stdout)
	results := make(map[string]*models.TLSScanResult)
	
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var output TLSXOutput
		if err := json.Unmarshal([]byte(line), &output); err != nil {
			s.logger.Warn("Failed to parse tlsx output", zap.String("line", line), zap.Error(err))
			continue
		}

		// Get or create result for this host
		host := output.Host
		if host == "" {
			host = output.IP
		}
		
		result, exists := results[host]
		if !exists {
			result = &models.TLSScanResult{
				Host:                host,
				IP:                  output.IP,
				IsSelfSigned:        output.SelfSigned,
				IsExpired:           output.Expired,
				IsValidHostname:     !output.MismatchedCN,
				TLSVersions:         []string{},
				Cipher:              []string{},
				WeakCiphers:         []string{},
				DeprecatedProtocols: []string{},
			}
			results[host] = result
		}

		// Update result with this output
		if output.Error != "" {
			result.Error = output.Error
		} else if output.ProbeStatus {
			// Add TLS version
			if output.TLSVersion != "" && !contains(result.TLSVersions, output.TLSVersion) {
				result.TLSVersions = append(result.TLSVersions, output.TLSVersion)
				
				// Check for deprecated protocols
				if isDeprecatedProtocol(output.TLSVersion) && !contains(result.DeprecatedProtocols, output.TLSVersion) {
					result.DeprecatedProtocols = append(result.DeprecatedProtocols, output.TLSVersion)
				}
			}
			
			// Add cipher
			if output.Cipher != "" && !contains(result.Cipher, output.Cipher) {
				result.Cipher = append(result.Cipher, output.Cipher)
				
				// Check for weak ciphers
				if isWeakCipher(output.Cipher) && !contains(result.WeakCiphers, output.Cipher) {
					result.WeakCiphers = append(result.WeakCiphers, output.Cipher)
				}
			}
		}
	}

	// Wait for command to complete
	if err := cmd.Wait(); err != nil {
		// tlsx might exit with non-zero status if some hosts fail
		s.logger.Warn("tlsx command exited with error", zap.Error(err))
	}

	// Convert map to slice
	var finalResults []models.TLSScanResult
	for _, result := range results {
		finalResults = append(finalResults, *result)
	}

	// Add results for domains that were not found
	for _, domain := range domains {
		found := false
		for _, result := range finalResults {
			if result.Host == domain || result.IP == domain {
				found = true
				break
			}
		}
		if !found {
			finalResults = append(finalResults, models.TLSScanResult{
				Host:  domain,
				Error: "Failed to connect or resolve domain",
			})
		}
	}

	s.logger.Info("TLS scan completed", 
		zap.Int("results", len(finalResults)),
		zap.Int("successful", countSuccessful(finalResults)),
	)

	return finalResults, nil
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// isWeakCipher checks if a cipher is considered weak
func isWeakCipher(cipher string) bool {
	weakCiphers := []string{
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
		"TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
		"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
		"TLS_ECDH_RSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		"RC4",
		"3DES",
		"DES",
		"NULL",
		"EXPORT",
		"ANON",
		"MD5",
	}
	
	cipherUpper := strings.ToUpper(cipher)
	for _, weak := range weakCiphers {
		if strings.Contains(cipherUpper, weak) {
			return true
		}
	}
	return false
}

// isDeprecatedProtocol checks if a TLS version is deprecated
func isDeprecatedProtocol(version string) bool {
	deprecated := []string{
		"SSLv2",
		"SSLv3",
		"TLS1.0",
		"TLS1.1",
		"TLSv1.0",
		"TLSv1.1",
	}
	
	versionUpper := strings.ToUpper(strings.ReplaceAll(version, " ", ""))
	for _, dep := range deprecated {
		if strings.Contains(versionUpper, strings.ToUpper(dep)) {
			return true
		}
	}
	return false
}

// countSuccessful counts results without errors
func countSuccessful(results []models.TLSScanResult) int {
	count := 0
	for _, result := range results {
		if result.Error == "" {
			count++
		}
	}
	return count
}

// ScanDomainsWithTimeout performs TLS scanning with a timeout
func (s *TLSXScanner) ScanDomainsWithTimeout(ctx context.Context, domains []string, timeout time.Duration) ([]models.TLSScanResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	return s.ScanDomains(ctx, domains)
}