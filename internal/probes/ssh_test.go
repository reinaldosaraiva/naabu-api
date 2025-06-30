package probes

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestSSHProbe_Name(t *testing.T) {
	logger := zap.NewNop()
	probe := NewSSHProbe(logger)
	
	if probe.Name() != "ssh" {
		t.Errorf("Expected probe name 'ssh', got '%s'", probe.Name())
	}
}

func TestSSHProbe_DefaultPort(t *testing.T) {
	logger := zap.NewNop()
	probe := NewSSHProbe(logger)
	
	if probe.DefaultPort() != 22 {
		t.Errorf("Expected default port 22, got %d", probe.DefaultPort())
	}
}

func TestSSHProbe_IsRelevantPort(t *testing.T) {
	logger := zap.NewNop()
	probe := NewSSHProbe(logger)
	
	testCases := []struct {
		port     int
		expected bool
	}{
		{22, true},
		{2222, true},
		{21, false},
		{80, false},
		{443, false},
	}
	
	for _, tc := range testCases {
		result := probe.IsRelevantPort(tc.port)
		if result != tc.expected {
			t.Errorf("IsRelevantPort(%d): expected %t, got %t", tc.port, tc.expected, result)
		}
	}
}

func TestSSHProbe_GetTimeout(t *testing.T) {
	logger := zap.NewNop()
	probe := NewSSHProbe(logger)
	
	timeout := probe.GetTimeout()
	expected := 30 * time.Second
	
	if timeout != expected {
		t.Errorf("Expected timeout %v, got %v", expected, timeout)
	}
}

func TestSSHProbe_Probe_InvalidHost(t *testing.T) {
	logger := zap.NewNop()
	probe := NewSSHProbe(logger)
	
	ctx := context.Background()
	
	// Test with non-existent host
	result, err := probe.Probe(ctx, "192.0.2.1", 22) // RFC 5737 test address
	
	// Should return error for connection failure
	if err == nil {
		t.Error("Expected error for invalid host, got nil")
	}
	
	// Or should return result with connection failure evidence
	if err == nil && result != nil && result.Evidence == "" {
		t.Error("Expected evidence of connection failure")
	}
}

func TestIsOldSSHVersion(t *testing.T) {
	testCases := []struct {
		version  string
		expected bool
	}{
		{"6.6", true},
		{"6.5", true},
		{"5.3", true},
		{"4.1", true},
		{"6.7", false},
		{"7.4", false},
		{"8.0", false},
		{"9.1", false},
	}
	
	for _, tc := range testCases {
		result := isOldSSHVersion(tc.version)
		if result != tc.expected {
			t.Errorf("isOldSSHVersion(%s): expected %t, got %t", tc.version, tc.expected, result)
		}
	}
}