// +build integration

package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"naabu-api/internal/config"
	"naabu-api/internal/database"
	"naabu-api/internal/handlers"
	"naabu-api/internal/models"
	"naabu-api/internal/worker"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// TestIntegration_TLSScan_JSON tests TLS scanning with JSON output
func TestIntegration_TLSScan_JSON(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if tlsx is available
	if !isTLSXAvailable() {
		t.Skip("tlsx binary not found, skipping integration test")
	}

	// Setup
	gin.SetMode(gin.TestMode)
	logger, _ := zap.NewDevelopment()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: "8080", // Non-zero port for production mode
		},
	}

	// Initialize database
	db := setupTestDatabase(t)
	defer cleanupTestDatabase(db)

	repo := database.NewRepository(db)
	dispatcher := &worker.Dispatcher{} // Mock dispatcher for testing

	// Create handler
	handler := handlers.NewHandler(repo, dispatcher, cfg, logger)

	// Create router
	router := gin.New()
	router.POST("/scan/tls", handler.TLSScanHandler)

	// Test cases
	tests := []struct {
		name            string
		domains         []string
		expectedStatus  int
		checkResponse   func(t *testing.T, resp models.TLSScanResponse)
	}{
		{
			name:           "Scan known good domain",
			domains:        []string{"example.com"},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp models.TLSScanResponse) {
				assert.Len(t, resp.Results, 1)
				result := resp.Results[0]
				assert.Equal(t, "example.com", result.Host)
				assert.NotEmpty(t, result.IP)
				assert.False(t, result.IsSelfSigned)
				assert.False(t, result.IsExpired)
				assert.True(t, result.IsValidHostname)
				assert.NotEmpty(t, result.TLSVersions)
				assert.NotEmpty(t, result.Cipher)
			},
		},
		{
			name:           "Scan self-signed certificate",
			domains:        []string{"self-signed.badssl.com"},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp models.TLSScanResponse) {
				assert.Len(t, resp.Results, 1)
				result := resp.Results[0]
				assert.True(t, result.IsSelfSigned)
			},
		},
		{
			name:           "Scan expired certificate",
			domains:        []string{"expired.badssl.com"},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp models.TLSScanResponse) {
				assert.Len(t, resp.Results, 1)
				result := resp.Results[0]
				assert.True(t, result.IsExpired)
			},
		},
		{
			name:           "Scan multiple domains",
			domains:        []string{"example.com", "google.com"},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp models.TLSScanResponse) {
				assert.Len(t, resp.Results, 2)
				// Check that both domains are in results
				hosts := []string{resp.Results[0].Host, resp.Results[1].Host}
				assert.Contains(t, hosts, "example.com")
				assert.Contains(t, hosts, "google.com")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := models.TLSScanRequest{
				Domains: tt.domains,
			}
			body, _ := json.Marshal(req)

			// Create HTTP request
			httpReq := httptest.NewRequest(http.MethodPost, "/scan/tls?format=json", bytes.NewBuffer(body))
			httpReq.Header.Set("Content-Type", "application/json")

			// Add timeout
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			httpReq = httpReq.WithContext(ctx)

			// Execute request
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httpReq)

			// Check status
			assert.Equal(t, tt.expectedStatus, w.Code)

			if w.Code == http.StatusOK {
				// Parse response
				var resp models.TLSScanResponse
				err := json.Unmarshal(w.Body.Bytes(), &resp)
				assert.NoError(t, err)

				// Check response
				if tt.checkResponse != nil {
					tt.checkResponse(t, resp)
				}
			}
		})
	}
}

// TestIntegration_TLSScan_CSV tests TLS scanning with CSV output
func TestIntegration_TLSScan_CSV(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	if !isTLSXAvailable() {
		t.Skip("tlsx binary not found, skipping integration test")
	}

	// Setup
	gin.SetMode(gin.TestMode)
	logger, _ := zap.NewDevelopment()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: "8080",
		},
	}

	// Initialize database
	db := setupTestDatabase(t)
	defer cleanupTestDatabase(db)

	repo := database.NewRepository(db)
	dispatcher := &worker.Dispatcher{}

	// Create handler
	handler := handlers.NewHandler(repo, dispatcher, cfg, logger)

	// Create router
	router := gin.New()
	router.POST("/scan/tls", handler.TLSScanHandler)

	// Create request
	req := models.TLSScanRequest{
		Domains: []string{"example.com"},
	}
	body, _ := json.Marshal(req)

	// Create HTTP request with CSV format
	httpReq := httptest.NewRequest(http.MethodPost, "/scan/tls?format=csv", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	// Execute request
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httpReq)

	// Check status
	assert.Equal(t, http.StatusOK, w.Code)

	// Check CSV headers
	assert.Equal(t, "text/csv", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), "attachment; filename=")

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(w.Body.String()))
	records, err := reader.ReadAll()
	assert.NoError(t, err)

	// Check CSV structure
	assert.GreaterOrEqual(t, len(records), 2) // Header + at least one row

	// Check header
	expectedHeaders := []string{
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
	assert.Equal(t, expectedHeaders, records[0])

	// Check data row
	if len(records) > 1 {
		assert.Equal(t, "example.com", records[1][0]) // host
		assert.NotEmpty(t, records[1][1])              // ip
		assert.Equal(t, "false", records[1][2])        // is_self_signed
		assert.Equal(t, "false", records[1][3])        // is_expired
		assert.Equal(t, "true", records[1][4])         // is_valid_hostname
	}
}

// TestIntegration_TLSScan_WeakCiphers tests detection of weak ciphers
func TestIntegration_TLSScan_WeakCiphers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	if !isTLSXAvailable() {
		t.Skip("tlsx binary not found, skipping integration test")
	}

	// This test requires a server with known weak ciphers
	// You can set up a test server or use a known public server
	t.Skip("Requires specific test server with weak ciphers")
}

// Helper function to check if tlsx is available
func isTLSXAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "tlsx", "-version")
	err := cmd.Run()
	return err == nil
}

// Helper function to setup test database
func setupTestDatabase(t *testing.T) *gorm.DB {
	config := database.Config{
		Driver:   "sqlite",
		Database: ":memory:",
	}

	err := database.Initialize(config)
	assert.NoError(t, err)

	db := database.GetDB()
	assert.NotNil(t, db)

	err = database.RunMigrations(db)
	assert.NoError(t, err)

	return db
}

// Helper function to cleanup test database
func cleanupTestDatabase(db *gorm.DB) {
	if db != nil {
		sqlDB, _ := db.DB()
		sqlDB.Close()
	}
}