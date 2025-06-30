package probes

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
	"naabu-api/internal/models"
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
	
	// Use a shorter timeout for testing
	probe.timeout = 2 * time.Second
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// Test with non-existent host - use a non-routable address for faster failure
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

func TestSSHProbe_Probe_Localhost(t *testing.T) {
	logger := zap.NewNop()
	probe := NewSSHProbe(logger)
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Test against localhost:22 - this may or may not work depending on environment
	result, err := probe.Probe(ctx, "127.0.0.1", 22)
	
	// This test is optional since SSH may not be running on localhost
	if err != nil {
		t.Logf("SSH not available on localhost (expected in CI): %v", err)
		return
	}
	
	if result == nil {
		t.Error("Expected result, got nil")
		return
	}
	
	t.Logf("SSH probe result: vulnerable=%t, version=%s, evidence=%s", 
		result.IsVulnerable, result.ServiceVersion, result.Evidence)
	
	// Basic validation
	if result.ProbeType != models.ProbeTypeSSH {
		t.Errorf("Expected probe type SSH, got %v", result.ProbeType)
	}
	
	if result.ServiceName != "ssh" {
		t.Errorf("Expected service name 'ssh', got %s", result.ServiceName)
	}
}

func TestSSHProbe_WeakCipherDetection(t *testing.T) {
	// Test the weak cipher detection logic directly
	testCases := []struct {
		name            string
		supportedCiphers []string
		supportedMACs    []string
		serverVersion    string
		expectedVuln     bool
		expectedCiphers  []string
		expectedMACs     []string
	}{
		{
			name:            "Modern secure ciphers",
			supportedCiphers: []string{"aes128-ctr", "aes256-ctr", "chacha20-poly1305@openssh.com"},
			supportedMACs:    []string{"hmac-sha2-256", "hmac-sha2-512"},
			serverVersion:    "SSH-2.0-OpenSSH_8.0",
			expectedVuln:     false,
			expectedCiphers:  []string{},
			expectedMACs:     []string{},
		},
		{
			name:            "Old SSH with weak ciphers",
			supportedCiphers: []string{"aes128-cbc", "3des-cbc", "arcfour"},
			supportedMACs:    []string{"hmac-md5", "hmac-sha1-96"},
			serverVersion:    "SSH-2.0-OpenSSH_6.0",
			expectedVuln:     true,
			expectedCiphers:  []string{"aes128-cbc", "3des-cbc", "arcfour"},
			expectedMACs:     []string{"hmac-md5", "hmac-sha1-96"},
		},
		{
			name:            "Mixed ciphers",
			supportedCiphers: []string{"aes128-ctr", "aes128-cbc", "aes256-ctr"},
			supportedMACs:    []string{"hmac-sha2-256", "hmac-md5"},
			serverVersion:    "SSH-2.0-OpenSSH_7.0",
			expectedVuln:     true,
			expectedCiphers:  []string{"aes128-cbc"},
			expectedMACs:     []string{"hmac-md5"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test cipher detection logic
			foundWeakCiphers := []string{}
			foundWeakMACs := []string{}
			
			// Check supported ciphers against weak cipher list
			for _, cipher := range tc.supportedCiphers {
				if isWeak, exists := weakCiphers[cipher]; exists && isWeak {
					foundWeakCiphers = append(foundWeakCiphers, cipher)
				}
			}
			
			// Check supported MACs against weak MAC list
			for _, mac := range tc.supportedMACs {
				if isWeak, exists := weakMACs[mac]; exists && isWeak {
					foundWeakMACs = append(foundWeakMACs, mac)
				}
			}
			
			isVulnerable := len(foundWeakCiphers) > 0 || len(foundWeakMACs) > 0
			
			if isVulnerable != tc.expectedVuln {
				t.Errorf("Expected vulnerable=%t, got %t", tc.expectedVuln, isVulnerable)
			}
			
			if len(foundWeakCiphers) != len(tc.expectedCiphers) {
				t.Errorf("Expected %d weak ciphers, got %d: %v", 
					len(tc.expectedCiphers), len(foundWeakCiphers), foundWeakCiphers)
			}
			
			if len(foundWeakMACs) != len(tc.expectedMACs) {
				t.Errorf("Expected %d weak MACs, got %d: %v", 
					len(tc.expectedMACs), len(foundWeakMACs), foundWeakMACs)
			}
		})
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