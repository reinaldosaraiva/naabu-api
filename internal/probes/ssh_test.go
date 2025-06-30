package probes

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"naabu-api/internal/models"
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
	
	tests := []struct {
		port     int
		expected bool
	}{
		{22, true},
		{2222, true},
		{2020, true},
		{222, true},
		{80, false},
		{443, false},
		{3389, false},
	}
	
	for _, test := range tests {
		result := probe.IsRelevantPort(test.port)
		if result != test.expected {
			t.Errorf("Port %d: expected %v, got %v", test.port, test.expected, result)
		}
	}
}

func TestSSHProbe_GetTimeout(t *testing.T) {
	logger := zaptest.NewLogger(t)
	probe := NewSSHProbe(logger)
	
	expected := 30 * time.Second
	if probe.GetTimeout() != expected {
		t.Errorf("Expected timeout %v, got %v", expected, probe.GetTimeout())
	}
}

func TestSSHProbe_Probe_ConnectionFailure(t *testing.T) {
	logger := zaptest.NewLogger(t)
	probe := NewSSHProbe(logger)
	
	ctx := context.Background()
	result, err := probe.Probe(ctx, "192.0.2.1", 22222)
	
	if err != nil {
		t.Fatalf("Probe should not return error, got: %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected result, got nil")
	}
	
	if result.IsVulnerable {
		t.Error("Expected IsVulnerable to be false for connection failure")
	}
	
	if !strings.Contains(result.Evidence, "Connection failed") {
		t.Errorf("Expected evidence to contain 'Connection failed', got: %s", result.Evidence)
	}
}

func TestSSHProbe_ExtractAlgorithmsFromError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	probe := NewSSHProbe(logger)
	
	tests := []struct {
		name     string
		errStr   string
		prefix   string
		expected []string
	}{
		{
			name:     "extract ciphers",
			errStr:   "ssh: handshake failed: server encrypt cipher: [aes128-ctr aes192-ctr aes256-ctr aes128-cbc]",
			prefix:   "server encrypt cipher",
			expected: []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc"},
		},
		{
			name:     "extract MACs",
			errStr:   "ssh: handshake failed: server MAC: [hmac-sha2-256 hmac-sha2-512 hmac-md5]",
			prefix:   "server MAC",
			expected: []string{"hmac-sha2-256", "hmac-sha2-512", "hmac-md5"},
		},
		{
			name:     "no algorithms found",
			errStr:   "ssh: handshake failed: no common algorithm",
			prefix:   "server encrypt cipher",
			expected: nil,
		},
	}
	
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := probe.extractAlgorithmsFromError(test.errStr, test.prefix)
			
			if len(result) != len(test.expected) {
				t.Errorf("Expected %d algorithms, got %d", len(test.expected), len(result))
				return
			}
			
			for i, alg := range result {
				if alg != test.expected[i] {
					t.Errorf("Algorithm %d: expected %s, got %s", i, test.expected[i], alg)
				}
			}
		})
	}
}

func TestSSHProbe_WeakCipherDetection(t *testing.T) {
	// Test weak cipher detection logic
	weakCipherTests := []struct {
		cipher string
		isWeak bool
	}{
		{"aes128-cbc", true},
		{"aes192-cbc", true},
		{"aes256-cbc", true},
		{"3des-cbc", true},
		{"blowfish-cbc", true},
		{"arcfour", true},
		{"arcfour128", true},
		{"arcfour256", true},
		{"aes128-ctr", false},
		{"aes256-ctr", false},
		{"chacha20-poly1305@openssh.com", false},
	}
	
	for _, test := range weakCipherTests {
		weak, exists := weakCiphers[test.cipher]
		if !exists {
			t.Errorf("Cipher %s not found in weakCiphers map", test.cipher)
			continue
		}
		if weak != test.isWeak {
			t.Errorf("Cipher %s: expected weak=%v, got %v", test.cipher, test.isWeak, weak)
		}
	}
}

func TestSSHProbe_WeakMACDetection(t *testing.T) {
	// Test weak MAC detection logic
	weakMACTests := []struct {
		mac    string
		isWeak bool
	}{
		{"hmac-md5", true},
		{"hmac-md5-96", true},
		{"hmac-sha1-96", true},
		{"hmac-ripemd160", true},
		{"umac-64@openssh.com", true},
		{"hmac-sha2-256", false},
		{"hmac-sha2-512", false},
		{"umac-128@openssh.com", false},
	}
	
	for _, test := range weakMACTests {
		weak, exists := weakMACs[test.mac]
		if !exists {
			t.Errorf("MAC %s not found in weakMACs map", test.mac)
			continue
		}
		if weak != test.isWeak {
			t.Errorf("MAC %s: expected weak=%v, got %v", test.mac, test.isWeak, weak)
		}
	}
}

func TestSSHProbe_ProbeResult(t *testing.T) {
	logger := zap.NewNop()
	probe := NewSSHProbe(logger)
	
	ctx := context.Background()
	result, err := probe.Probe(ctx, "127.0.0.1", 22)
	
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	// Verify result structure
	if result.Host != "127.0.0.1" {
		t.Errorf("Expected host 127.0.0.1, got %s", result.Host)
	}
	if result.Port != 22 {
		t.Errorf("Expected port 22, got %d", result.Port)
	}
	if result.ProbeType != models.ProbeTypeSSH {
		t.Errorf("Expected probe type %s, got %s", models.ProbeTypeSSH, result.ProbeType)
	}
	if result.ServiceName != "ssh" {
		t.Errorf("Expected service name 'ssh', got %s", result.ServiceName)
	}
}

func TestSSHProbe_CreateConfig(t *testing.T) {
	logger := zaptest.NewLogger(t)
	probe := NewSSHProbe(logger)
	
	config := probe.CreateConfig()
	
	if config == nil {
		t.Fatal("Expected config, got nil")
	}
	
	// Check that weak ciphers are included
	expectedCiphers := []string{
		"aes128-cbc", "aes192-cbc", "aes256-cbc",
		"3des-cbc", "blowfish-cbc", "cast128-cbc",
		"arcfour", "arcfour128", "arcfour256",
	}
	
	for i, cipher := range config.Config.Ciphers {
		if i < len(expectedCiphers) && cipher != expectedCiphers[i] {
			t.Errorf("Cipher %d: expected %s, got %s", i, expectedCiphers[i], cipher)
		}
	}
	
	// Check that weak MACs are included
	expectedMACs := []string{
		"hmac-md5", "hmac-md5-96", "hmac-sha1-96",
		"umac-64@openssh.com", "hmac-ripemd160",
		"hmac-ripemd160@openssh.com",
	}
	
	for i, mac := range config.Config.MACs {
		if i < len(expectedMACs) && mac != expectedMACs[i] {
			t.Errorf("MAC %d: expected %s, got %s", i, expectedMACs[i], mac)
		}
	}
}