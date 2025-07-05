package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestTLSXScanner_isWeakCipher(t *testing.T) {
	tests := []struct {
		name     string
		cipher   string
		expected bool
	}{
		{
			name:     "Weak cipher RC4",
			cipher:   "TLS_RSA_WITH_RC4_128_SHA",
			expected: true,
		},
		{
			name:     "Weak cipher 3DES",
			cipher:   "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			expected: true,
		},
		{
			name:     "Weak cipher with lowercase",
			cipher:   "tls_rsa_with_rc4_128_sha",
			expected: true,
		},
		{
			name:     "Strong cipher AES",
			cipher:   "TLS_AES_128_GCM_SHA256",
			expected: false,
		},
		{
			name:     "Strong cipher ECDHE",
			cipher:   "ECDHE-RSA-AES128-GCM-SHA256",
			expected: false,
		},
		{
			name:     "Weak cipher NULL",
			cipher:   "TLS_RSA_WITH_NULL_SHA",
			expected: true,
		},
		{
			name:     "Weak cipher EXPORT",
			cipher:   "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
			expected: true,
		},
		{
			name:     "Weak cipher anonymous",
			cipher:   "TLS_DH_anon_WITH_AES_128_CBC_SHA",
			expected: true,
		},
		{
			name:     "Weak cipher MD5",
			cipher:   "TLS_RSA_WITH_RC4_128_MD5",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isWeakCipher(tt.cipher)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTLSXScanner_isDeprecatedProtocol(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected bool
	}{
		{
			name:     "Deprecated SSLv2",
			version:  "SSLv2",
			expected: true,
		},
		{
			name:     "Deprecated SSLv3",
			version:  "SSLv3",
			expected: true,
		},
		{
			name:     "Deprecated TLS 1.0",
			version:  "TLS1.0",
			expected: true,
		},
		{
			name:     "Deprecated TLS 1.0 with v",
			version:  "TLSv1.0",
			expected: true,
		},
		{
			name:     "Deprecated TLS 1.1",
			version:  "TLS1.1",
			expected: true,
		},
		{
			name:     "Deprecated TLS 1.1 with v",
			version:  "TLSv1.1",
			expected: true,
		},
		{
			name:     "Valid TLS 1.2",
			version:  "TLS1.2",
			expected: false,
		},
		{
			name:     "Valid TLS 1.3",
			version:  "TLS1.3",
			expected: false,
		},
		{
			name:     "Deprecated with lowercase",
			version:  "tlsv1.0",
			expected: true,
		},
		{
			name:     "Deprecated with spaces",
			version:  "TLS 1.0",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isDeprecatedProtocol(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTLSXScanner_contains(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		expected bool
	}{
		{
			name:     "Item exists",
			slice:    []string{"a", "b", "c"},
			item:     "b",
			expected: true,
		},
		{
			name:     "Item does not exist",
			slice:    []string{"a", "b", "c"},
			item:     "d",
			expected: false,
		},
		{
			name:     "Empty slice",
			slice:    []string{},
			item:     "a",
			expected: false,
		},
		{
			name:     "Nil slice",
			slice:    nil,
			item:     "a",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.slice, tt.item)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTLSXScanner_ScanDomains(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	scanner := NewTLSXScanner(logger)

	tests := []struct {
		name        string
		domains     []string
		expectError bool
	}{
		{
			name:        "Empty domains",
			domains:     []string{},
			expectError: true,
		},
		{
			name:        "Valid domains",
			domains:     []string{"example.com", "google.com"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := scanner.ScanDomains(ctx, tt.domains)
			
			if tt.expectError {
				assert.Error(t, err)
			} else {
				// We can't guarantee tlsx is installed in test environment
				// so we just check that the function returns without panic
				t.Skip("Skipping actual scan test - requires tlsx binary")
			}
		})
	}
}

func TestTLSXScanner_ScanDomainsWithTimeout(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	scanner := NewTLSXScanner(logger)

	ctx := context.Background()
	domains := []string{"example.com"}
	timeout := 10 * time.Second

	// Test that function doesn't panic
	_, _ = scanner.ScanDomainsWithTimeout(ctx, domains, timeout)
	
	// We can't test actual functionality without tlsx installed
	t.Skip("Skipping actual scan test - requires tlsx binary")
}