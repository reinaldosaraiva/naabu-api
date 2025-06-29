package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"naabu-api/internal/models"

	"github.com/google/uuid"
)

const baseURL = "http://localhost:8080"

// TestAsyncScanWorkflow tests the complete async scanning workflow
func TestAsyncScanWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test data
	scanRequest := models.ScanRequest{
		IPs:   []string{"127.0.0.1"},
		Ports: "22,80,443",
	}

	// Step 1: Test health endpoint
	t.Run("HealthCheck", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/health")
		if err != nil {
			t.Fatalf("Health check failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	// Step 2: Create async scan job
	var scanID uuid.UUID
	t.Run("CreateScanJob", func(t *testing.T) {
		body, err := json.Marshal(scanRequest)
		if err != nil {
			t.Fatalf("Failed to marshal request: %v", err)
		}

		resp, err := http.Post(baseURL+"/api/v1/scan", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("Failed to create scan job: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusAccepted {
			t.Errorf("Expected status 202, got %d", resp.StatusCode)
		}

		var response models.AsyncScanResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if response.ScanID == uuid.Nil {
			t.Error("Expected valid scan ID")
		}

		if response.Status != models.JobStatusQueued {
			t.Errorf("Expected status 'queued', got '%s'", response.Status)
		}

		scanID = response.ScanID
	})

	// Step 3: Wait and check job status
	t.Run("CheckJobStatus", func(t *testing.T) {
		// Wait a bit for processing
		time.Sleep(2 * time.Second)

		resp, err := http.Get(baseURL + "/api/v1/jobs/" + scanID.String())
		if err != nil {
			t.Fatalf("Failed to get job status: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var jobStatus models.JobStatusResponse
		if err := json.NewDecoder(resp.Body).Decode(&jobStatus); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if jobStatus.ScanID != scanID {
			t.Error("Scan ID mismatch")
		}

		// Job should be completed or running
		if jobStatus.Status != models.JobStatusCompleted && jobStatus.Status != models.JobStatusRunning {
			t.Errorf("Expected status 'completed' or 'running', got '%s'", jobStatus.Status)
		}

		// If completed, check results
		if jobStatus.Status == models.JobStatusCompleted {
			if jobStatus.Results == nil {
				t.Error("Expected results for completed job")
			} else {
				if len(jobStatus.Results.Results) != 1 {
					t.Errorf("Expected 1 IP result, got %d", len(jobStatus.Results.Results))
				}
				if jobStatus.Results.Summary.TotalIPs != 1 {
					t.Errorf("Expected 1 total IP, got %d", jobStatus.Results.Summary.TotalIPs)
				}
			}
		}
	})

	// Step 4: Test stats endpoint
	t.Run("CheckStats", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/v1/stats")
		if err != nil {
			t.Fatalf("Failed to get stats: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		var stats map[string]interface{}
		if err := json.Unmarshal(body, &stats); err != nil {
			t.Fatalf("Failed to decode stats: %v", err)
		}

		if _, ok := stats["stats"]; !ok {
			t.Error("Expected 'stats' field in response")
		}
	})
}

// TestQuickScanCompatibility tests the quick scan endpoint for backward compatibility
func TestQuickScanCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	scanRequest := models.ScanRequest{
		IPs:   []string{"127.0.0.1"},
		Ports: "80",
	}

	body, err := json.Marshal(scanRequest)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := http.Post(baseURL+"/api/v1/scan/quick", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to create quick scan: %v", err)
	}
	defer resp.Body.Close()

	// Quick scan should return scan results directly (synchronous mode for compatibility)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		t.Errorf("Expected status 200 or 202, got %d", resp.StatusCode)
	}
}

// TestInvalidRequests tests error handling
func TestInvalidRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test invalid JSON
	t.Run("InvalidJSON", func(t *testing.T) {
		resp, err := http.Post(baseURL+"/api/v1/scan", "application/json", bytes.NewReader([]byte("invalid json")))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("Expected error status for invalid JSON")
		}
	})

	// Test invalid IP
	t.Run("InvalidIP", func(t *testing.T) {
		invalidRequest := models.ScanRequest{
			IPs:   []string{"invalid-ip"},
			Ports: "80",
		}

		body, _ := json.Marshal(invalidRequest)
		resp, err := http.Post(baseURL+"/api/v1/scan", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
			t.Error("Expected error status for invalid IP")
		}
	})

	// Test non-existent job
	t.Run("NonExistentJob", func(t *testing.T) {
		fakeID := uuid.New()
		resp, err := http.Get(baseURL + "/api/v1/jobs/" + fakeID.String())
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("Expected error status for non-existent job")
		}
	})
}