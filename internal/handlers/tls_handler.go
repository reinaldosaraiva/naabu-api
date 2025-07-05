package handlers

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"naabu-api/internal/models"
	"naabu-api/internal/scanner"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TLSScanHandler handles POST /scan/tls requests
func (h *Handler) TLSScanHandler(c *gin.Context) {
	reqLogger := h.getLogger(c)
	
	var req models.TLSScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		reqLogger.Error("Error decoding JSON", zap.Error(err))
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:     "Invalid JSON: " + err.Error(),
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Validate request
	if err := h.validateTLSScanRequest(req); err != nil {
		reqLogger.Error("Invalid request data", zap.Error(err))
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:     err.Error(),
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Get format parameter (default to json)
	format := c.DefaultQuery("format", "json")
	if format != "json" && format != "csv" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:     "Invalid format parameter. Must be 'json' or 'csv'",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Create TLSX scanner
	tlsxScanner := scanner.NewTLSXScanner(reqLogger)
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Minute)
	defer cancel()
	
	// Perform TLS scan
	reqLogger.Info("Starting TLS scan",
		zap.Int("domain_count", len(req.Domains)),
		zap.String("format", format),
	)
	
	results, err := tlsxScanner.ScanDomains(ctx, req.Domains)
	if err != nil {
		reqLogger.Error("TLS scan failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:     "TLS scan failed: " + err.Error(),
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Log scan completion
	reqLogger.Info("TLS scan completed",
		zap.Int("total_results", len(results)),
		zap.String("format", format),
	)
	
	// Return results based on format
	if format == "csv" {
		h.returnTLSResultsAsCSV(c, results)
	} else {
		c.JSON(http.StatusOK, models.TLSScanResponse{
			Results: results,
		})
	}
}

// validateTLSScanRequest validates the TLS scan request
func (h *Handler) validateTLSScanRequest(req models.TLSScanRequest) error {
	if len(req.Domains) == 0 {
		return fmt.Errorf("'domains' field is required and cannot be empty")
	}
	
	// Maximum 100 domains per request
	if len(req.Domains) > 100 {
		return fmt.Errorf("maximum of 100 domains allowed per request")
	}
	
	// Validate each domain
	for i, domain := range req.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			return fmt.Errorf("empty domain found at position %d", i)
		}
		
		// Basic domain validation
		if err := h.validateDomain(domain); err != nil {
			return fmt.Errorf("invalid domain '%s' at position %d: %v", domain, i, err)
		}
	}
	
	return nil
}

// validateDomain performs basic domain validation
func (h *Handler) validateDomain(domain string) error {
	// Handle IPv6 addresses with brackets
	if strings.HasPrefix(domain, "[") && strings.Contains(domain, "]") {
		// Extract IPv6 address and validate
		endIdx := strings.Index(domain, "]")
		ipv6 := domain[1:endIdx]
		if net.ParseIP(ipv6) == nil {
			return fmt.Errorf("not a valid IPv6 address")
		}
		return nil
	}
	
	// Remove port if present for regular domains/IPs
	if idx := strings.LastIndex(domain, ":"); idx != -1 {
		// Check if this is part of IPv6 (multiple colons)
		if strings.Count(domain, ":") > 1 {
			// This is likely an IPv6 address
			if net.ParseIP(domain) == nil {
				return fmt.Errorf("not a valid IPv6 address")
			}
			return nil
		}
		domain = domain[:idx]
	}
	
	// Check if it's a valid hostname or IP
	if !h.isValidHostname(domain) && net.ParseIP(domain) == nil {
		return fmt.Errorf("not a valid domain name or IP address")
	}
	
	return nil
}

// returnTLSResultsAsCSV returns TLS scan results in CSV format
func (h *Handler) returnTLSResultsAsCSV(c *gin.Context, results []models.TLSScanResult) {
	// Create CSV buffer
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	
	// Write header
	header := []string{
		"host",
		"ip",
		"is_self_signed",
		"is_expired",
		"is_valid_hostname",
		"tls_versions",
		"cipher",
		"weak_ciphers",
		"deprecated_protocols",
		"error",
	}
	
	if err := writer.Write(header); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: "Failed to generate CSV",
		})
		return
	}
	
	// Write data rows
	for _, result := range results {
		row := []string{
			result.Host,
			result.IP,
			strconv.FormatBool(result.IsSelfSigned),
			strconv.FormatBool(result.IsExpired),
			strconv.FormatBool(result.IsValidHostname),
			strings.Join(result.TLSVersions, ";"),
			strings.Join(result.Cipher, ";"),
			strings.Join(result.WeakCiphers, ";"),
			strings.Join(result.DeprecatedProtocols, ";"),
			result.Error,
		}
		
		if err := writer.Write(row); err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{
				Error: "Failed to generate CSV",
			})
			return
		}
	}
	
	writer.Flush()
	
	// Set CSV headers
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"tls_scan_%s.csv\"", time.Now().Format("20060102_150405")))
	
	// Send CSV data
	c.Data(http.StatusOK, "text/csv", buf.Bytes())
}