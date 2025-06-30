package probes

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestSSHProbe_Name(t *testing.T) {
	logger := zaptest.NewLogger(t)
	probe := NewSSHProbe(logger)
	
	if probe.Name() != "ssh" {
		t.Errorf("Expected name 'ssh', got '%s'", probe.Name())
	}
}

func TestSSHProbe_DefaultPort(t *testing.T) {
	logger := zaptest.NewLogger(t)
	probe := NewSSHProbe(logger)
	
	if probe.DefaultPort() != 22 {
		t.Errorf("Expected default port 22, got %d", probe.DefaultPort())
	}
}

func TestSSHProbe_IsRelevantPort(t *testing.T) {
	logger := zaptest.NewLogger(t)
	probe := NewSSHProbe(logger)
	
	testCases := []struct {
		port     int
		expected bool
	}{
		{22, true},
		{2222, true},
		{2020, true},
		{222, true},
		{80, false},
		{443, false},
		{21, false},
	}
	
	for _, tc := range testCases {
		result := probe.IsRelevantPort(tc.port)
		if result != tc.expected {
			t.Errorf("Port %d: expected %v, got %v", tc.port, tc.expected, result)
		}
	}
}

func TestSSHProbe_FindWeakMACs(t *testing.T) {
	logger := zaptest.NewLogger(t)
	probe := NewSSHProbe(logger)
	
	testCases := []struct {
		name        string
		detectedMACs []string
		expectedWeak []string
	}{
		{
			name:         "No MACs",
			detectedMACs: []string{},
			expectedWeak: []string{},
		},
		{
			name:         "Only strong MACs",
			detectedMACs: []string{"hmac-sha2-256", "hmac-sha2-512"},
			expectedWeak: []string{},
		},
		{
			name:         "Only weak MACs",
			detectedMACs: []string{"hmac-md5", "hmac-sha1-96"},
			expectedWeak: []string{"hmac-md5", "hmac-sha1-96"},
		},
		{
			name:         "Mixed MACs",
			detectedMACs: []string{"hmac-md5", "hmac-sha2-256", "hmac-sha1-96"},
			expectedWeak: []string{"hmac-md5", "hmac-sha1-96"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := probe.findWeakMACs(tc.detectedMACs)
			
			if len(result) != len(tc.expectedWeak) {
				t.Errorf("Expected %d weak MACs, got %d", len(tc.expectedWeak), len(result))
				return
			}
			
			for i, expected := range tc.expectedWeak {
				if i >= len(result) || result[i] != expected {
					t.Errorf("Expected weak MAC '%s', got '%s'", expected, result[i])
				}
			}
		})
	}
}

func TestSSHProbe_ExtractMACsFromError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	probe := NewSSHProbe(logger)
	
	testCases := []struct {
		name        string
		errorStr    string
		expectedMACs []string
	}{
		{
			name:         "No MACs in error",
			errorStr:     "connection failed",
			expectedMACs: []string{},
		},
		{
			name:         "Single MAC in error",
			errorStr:     "ssh: no common algorithm for hmac-md5; server offered: hmac-sha2-256",
			expectedMACs: []string{"hmac-md5", "hmac-sha2-256"},
		},
		{
			name:         "Case insensitive matching",
			errorStr:     "Error with HMAC-MD5 and HMAC-SHA1-96",
			expectedMACs: []string{"hmac-md5", "hmac-sha1-96", "hmac-sha1"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := probe.extractMACsFromError(tc.errorStr)
			
			if len(result) != len(tc.expectedMACs) {
				t.Errorf("Expected %d MACs, got %d: %v", len(tc.expectedMACs), len(result), result)
				return
			}
			
			// Check if all expected MACs are present (order doesn't matter)
			for _, expected := range tc.expectedMACs {
				found := false
				for _, actual := range result {
					if expected == actual {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected MAC '%s' not found in result: %v", expected, result)
				}
			}
		})
	}
}

func TestSSHProbe_RemoveDuplicates(t *testing.T) {
	logger := zaptest.NewLogger(t)
	probe := NewSSHProbe(logger)
	
	input := []string{"hmac-md5", "hmac-sha2-256", "hmac-md5", "hmac-sha1-96", "hmac-sha2-256"}
	expected := []string{"hmac-md5", "hmac-sha2-256", "hmac-sha1-96"}
	
	result := probe.removeDuplicates(input)
	
	if len(result) != len(expected) {
		t.Errorf("Expected %d unique items, got %d", len(expected), len(result))
		return
	}
	
	// Check all expected items are present
	for _, expectedItem := range expected {
		found := false
		for _, resultItem := range result {
			if expectedItem == resultItem {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected item '%s' not found in result: %v", expectedItem, result)
		}
	}
}

func TestSSHProbe_ProbeInvalidHost(t *testing.T) {
	logger := zaptest.NewLogger(t)
	probe := NewSSHProbe(logger)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// Test with invalid host
	result, err := probe.Probe(ctx, "192.0.2.1", 22) // RFC 5737 test address
	
	if err != nil {
		t.Errorf("Probe should not return error, got: %v", err)
	}
	
	if result == nil {
		t.Fatal("Result should not be nil")
	}
	
	if result.Host != "192.0.2.1" {
		t.Errorf("Expected host '192.0.2.1', got '%s'", result.Host)
	}
	
	if result.Port != 22 {
		t.Errorf("Expected port 22, got %d", result.Port)
	}
	
	if result.ProbeType != "ssh" {
		t.Errorf("Expected probe type 'ssh', got '%s'", string(result.ProbeType))
	}
	
	if result.Evidence == "" {
		t.Error("Evidence should not be empty for failed connection")
	}
}