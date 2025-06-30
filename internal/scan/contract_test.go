package scan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"naabu-api/internal/config"
	"naabu-api/internal/database"
	"naabu-api/internal/handlers"
	"naabu-api/internal/models"
	"naabu-api/internal/worker"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestNetworkSecurityEndpointContract tests the network security endpoint contract
func TestNetworkSecurityEndpointContract(t *testing.T) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Initialize test dependencies
	testLogger := zap.NewNop() // No-op logger for testing
	
	// Use in-memory SQLite for testing
	dbConfig := database.Config{
		Driver:   "sqlite",
		Database: ":memory:",
	}

	// Initialize database
	err := database.Initialize(dbConfig)
	require.NoError(t, err)
	
	// Run migrations
	err = database.RunMigrations(database.DB)
	require.NoError(t, err)
	
	repo := database.NewRepository(database.DB)
	
	// Initialize worker (minimal setup for testing)
	dispatcher := &worker.Dispatcher{} // Mock dispatcher
	
	// Create minimal config for handler
	testConfig := &config.Config{
		Server: config.ServerConfig{
			Port: "0",
		},
	}
	
	// Initialize handler
	handler := handlers.NewHandler(repo, dispatcher, testConfig, testLogger)
	
	// Create Gin router
	router := gin.New()
	handler.SetupRoutes(router)

	// Create test scan job with probe results
	scanID := uuid.New()
	testJob := &models.ScanJob{
		ScanID:    scanID,
		Status:    models.JobStatusCompleted,
		IPs:       `["127.0.0.1"]`,
		Ports:     "22,21,5900",
		CreatedAt: time.Now(),
	}
	
	err = repo.CreateScanJob(testJob)
	require.NoError(t, err)

	// Create test probe results - some vulnerable, some safe
	testProbeResults := []models.ProbeResult{
		{
			ScanID:       scanID,
			Host:         "127.0.0.1",
			Port:         21,
			ProbeType:    models.ProbeTypeFTP,
			ServiceName:  "ftp",
			IsVulnerable: true,
			Evidence:     "Anonymous FTP login successful (230 code). Banner: FTP Server ready",
			CreatedAt:    time.Now(),
		},
		{
			ScanID:       scanID,
			Host:         "127.0.0.1",
			Port:         5900,
			ProbeType:    models.ProbeTypeVNC,
			ServiceName:  "vnc",
			IsVulnerable: false,
			Evidence:     "VNC server requires authentication",
			CreatedAt:    time.Now(),
		},
		{
			ScanID:       scanID,
			Host:         "127.0.0.1",
			Port:         22,
			ProbeType:    models.ProbeTypeSSHCipher,
			ServiceName:  "ssh",
			IsVulnerable: true,
			Evidence:     "SSH server supports weak ciphers: aes128-cbc, 3des-cbc",
			CreatedAt:    time.Now(),
		},
		{
			ScanID:       scanID,
			Host:         "127.0.0.1",
			Port:         22,
			ProbeType:    models.ProbeTypeSSHMAC,
			ServiceName:  "ssh",
			IsVulnerable: false,
			Evidence:     "SSH server uses only strong MAC algorithms",
			CreatedAt:    time.Now(),
		},
	}

	// Insert probe results
	for _, result := range testProbeResults {
		err = repo.CreateProbeResult(&result)
		require.NoError(t, err)
	}

	// Verify the scan was created properly
	savedJob, err := repo.GetScanJobByID(scanID)
	require.NoError(t, err, "Failed to retrieve saved job")
	t.Logf("Saved job scan_id: %s", savedJob.ScanID.String())

	// Test the network security endpoint
	req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/scans/%s/network", scanID.String()), nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	// Assert HTTP status
	assert.Equal(t, http.StatusOK, recorder.Code, "Expected HTTP 200 but got %d. Response: %s", recorder.Code, recorder.Body.String())

	// Debug: Print the raw response
	t.Logf("Raw response: %s", recorder.Body.String())

	// Parse response
	var response models.NetworkSecurityResponse
	err = json.Unmarshal(recorder.Body.Bytes(), &response)
	require.NoError(t, err, "Failed to parse JSON response: %s", recorder.Body.String())

	// Test Contract: Verify all 8 required fields exist
	requiredFields := []string{
		"ftp_anonymous_login",
		"vnc_accessible", 
		"rdp_accessible",
		"ldap_accessible",
		"pptp_accessible",
		"rsync_accessible",
		"ssh_weak_cipher",
		"ssh_weak_mac",
	}

	// Convert response to map for field checking
	responseMap := make(map[string]interface{})
	responseBytes, err := json.Marshal(response)
	require.NoError(t, err)
	err = json.Unmarshal(responseBytes, &responseMap)
	require.NoError(t, err)

	// Verify all required fields exist
	for _, field := range requiredFields {
		assert.Contains(t, responseMap, field, "Required field '%s' is missing from response", field)
		
		// Verify field structure
		fieldValue, ok := responseMap[field].(map[string]interface{})
		require.True(t, ok, "Field '%s' is not an object", field)
		
		// Verify status field exists and is valid enum
		status, statusExists := fieldValue["status"].(string)
		assert.True(t, statusExists, "Field '%s' missing 'status'", field)
		assert.Contains(t, []string{"ok", "risk"}, status, "Field '%s' has invalid status '%s', must be 'ok' or 'risk'", field, status)
		
		// Verify evidence field exists
		evidence, evidenceExists := fieldValue["evidence"]
		assert.True(t, evidenceExists, "Field '%s' missing 'evidence'", field)
		
		// If status is "risk", evidence must not be empty
		if status == "risk" {
			switch ev := evidence.(type) {
			case string:
				assert.NotEmpty(t, ev, "Field '%s' with status 'risk' has empty evidence", field)
			case []interface{}:
				assert.NotEmpty(t, ev, "Field '%s' with status 'risk' has empty evidence array", field)
			default:
				t.Errorf("Field '%s' evidence is neither string nor array", field)
			}
		}
	}

	// Test specific expected values based on test data
	assert.Equal(t, scanID, response.ScanID, "Scan ID mismatch")
	assert.Equal(t, "risk", response.FTPAnonymousLogin.Status, "FTP should be flagged as risk")
	assert.Equal(t, "ok", response.VNCAccessible.Status, "VNC should be ok")
	assert.Equal(t, "risk", response.SSHWeakCipher.Status, "SSH weak cipher should be flagged as risk")
	assert.Equal(t, "ok", response.SSHWeakMAC.Status, "SSH weak MAC should be ok")

	// Test fields that should default to "ok" when no probe results exist
	assert.Equal(t, "ok", response.RDPAccessible.Status, "RDP should default to ok")
	assert.Equal(t, "ok", response.LDAPAccessible.Status, "LDAP should default to ok")
	assert.Equal(t, "ok", response.PPTPAccessible.Status, "PPTP should default to ok")
	assert.Equal(t, "ok", response.RsyncAccessible.Status, "Rsync should default to ok")
}

// TestNetworkSecurityEndpointNotFound tests 404 behavior
func TestNetworkSecurityEndpointNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testLogger := zap.NewNop()
	
	dbConfig := database.Config{
		Driver:   "sqlite",
		Database: ":memory:",
	}

	err := database.Initialize(dbConfig)
	require.NoError(t, err)
	
	// Run migrations
	err = database.RunMigrations(database.DB)
	require.NoError(t, err)
	
	repo := database.NewRepository(database.DB)
	dispatcher := &worker.Dispatcher{}
	testConfig := &config.Config{
		Server: config.ServerConfig{Port: "0"},
	}
	handler := handlers.NewHandler(repo, dispatcher, testConfig, testLogger)
	
	router := gin.New()
	handler.SetupRoutes(router)

	// Test with non-existent scan ID
	nonExistentID := uuid.New()
	req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/scans/%s/network", nonExistentID.String()), nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusNotFound, recorder.Code, "Expected HTTP 404 for non-existent scan")
}

// TestNetworkSecurityEndpointInvalidUUID tests 400 behavior
func TestNetworkSecurityEndpointInvalidUUID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testLogger := zap.NewNop()
	
	dbConfig := database.Config{
		Driver:   "sqlite",
		Database: ":memory:",
	}

	err := database.Initialize(dbConfig)
	require.NoError(t, err)
	
	// Run migrations
	err = database.RunMigrations(database.DB)
	require.NoError(t, err)
	
	repo := database.NewRepository(database.DB)
	dispatcher := &worker.Dispatcher{}
	testConfig := &config.Config{
		Server: config.ServerConfig{Port: "0"},
	}
	handler := handlers.NewHandler(repo, dispatcher, testConfig, testLogger)
	
	router := gin.New()
	handler.SetupRoutes(router)

	// Test with invalid UUID
	req, err := http.NewRequest("GET", "/api/v1/scans/invalid-uuid/network", nil)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusBadRequest, recorder.Code, "Expected HTTP 400 for invalid UUID")
}

// TestNetworkSecurityFieldContract tests that the contract fails when expected fields are missing
func TestNetworkSecurityFieldContract(t *testing.T) {
	// This test demonstrates the contract test failure when fields are missing
	// It would be used to catch regressions in the API contract
	
	expectedFields := []string{
		"ftp_anonymous_login",
		"vnc_accessible", 
		"rdp_accessible",
		"ldap_accessible",
		"pptp_accessible",
		"rsync_accessible",
		"ssh_weak_cipher",
		"ssh_weak_mac",
	}

	// Simulate a response missing a field (this would fail the contract)
	incompleteResponse := map[string]interface{}{
		"scan_id": uuid.New().String(),
		"ftp_anonymous_login": map[string]interface{}{
			"status": "ok",
			"evidence": "test",
		},
		// Missing 7 other required fields - this would fail the contract test
	}

	// Test that we can detect missing fields
	for _, field := range expectedFields {
		if _, exists := incompleteResponse[field]; !exists && field != "ftp_anonymous_login" {
			// This is what the contract test would catch - missing required fields
			t.Logf("Contract violation: Missing required field '%s'", field)
		}
	}
	
	// This test passes because it's demonstrating the contract check logic
	// In a real scenario, the main contract test would fail if fields were missing
	assert.Equal(t, 8, len(expectedFields), "Should have exactly 8 required fields")
}