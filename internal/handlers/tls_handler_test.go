package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"naabu-api/internal/config"
	"naabu-api/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestHandler_TLSScanHandler(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	logger, _ := zap.NewDevelopment()
	cfg := &config.Config{}
	
	// Create handler (we'll skip actual scanning in tests)
	handler := NewHandler(nil, nil, cfg, logger)
	
	tests := []struct {
		name           string
		requestBody    interface{}
		queryParams    map[string]string
		expectedStatus int
		expectError    bool
	}{
		{
			name: "Valid request with JSON format",
			requestBody: models.TLSScanRequest{
				Domains: []string{"example.com", "google.com"},
			},
			queryParams:    map[string]string{"format": "json"},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "Valid request with CSV format",
			requestBody: models.TLSScanRequest{
				Domains: []string{"example.com"},
			},
			queryParams:    map[string]string{"format": "csv"},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "Valid request with default format",
			requestBody: models.TLSScanRequest{
				Domains: []string{"example.com"},
			},
			queryParams:    map[string]string{},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "Invalid JSON",
			requestBody:    "invalid json",
			queryParams:    map[string]string{},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "Empty domains",
			requestBody: models.TLSScanRequest{
				Domains: []string{},
			},
			queryParams:    map[string]string{},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "Too many domains",
			requestBody: models.TLSScanRequest{
				Domains: generateDomains(101),
			},
			queryParams:    map[string]string{},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "Invalid format parameter",
			requestBody: models.TLSScanRequest{
				Domains: []string{"example.com"},
			},
			queryParams:    map[string]string{"format": "xml"},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "Domain with empty string",
			requestBody: models.TLSScanRequest{
				Domains: []string{"example.com", "", "google.com"},
			},
			queryParams:    map[string]string{},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip tests that require actual tlsx binary
			if tt.expectedStatus == http.StatusOK {
				t.Skip("Skipping test that requires tlsx binary")
			}
			
			// Create request
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/scan/tls", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			
			// Add query parameters
			q := req.URL.Query()
			for k, v := range tt.queryParams {
				q.Add(k, v)
			}
			req.URL.RawQuery = q.Encode()
			
			// Create response recorder
			w := httptest.NewRecorder()
			
			// Create gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			
			// Call handler
			handler.TLSScanHandler(c)
			
			// Assert status code
			assert.Equal(t, tt.expectedStatus, w.Code)
			
			// Check response based on format
			if tt.expectError {
				var errResp models.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, errResp.Error)
			}
		})
	}
}

func TestHandler_validateTLSScanRequest(t *testing.T) {
	handler := &Handler{}
	
	tests := []struct {
		name        string
		request     models.TLSScanRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid request",
			request: models.TLSScanRequest{
				Domains: []string{"example.com", "google.com"},
			},
			expectError: false,
		},
		{
			name: "Empty domains",
			request: models.TLSScanRequest{
				Domains: []string{},
			},
			expectError: true,
			errorMsg:    "'domains' field is required",
		},
		{
			name: "Too many domains",
			request: models.TLSScanRequest{
				Domains: generateDomains(101),
			},
			expectError: true,
			errorMsg:    "maximum of 100 domains",
		},
		{
			name: "Empty domain in list",
			request: models.TLSScanRequest{
				Domains: []string{"example.com", "", "google.com"},
			},
			expectError: true,
			errorMsg:    "empty domain found",
		},
		{
			name: "Invalid domain",
			request: models.TLSScanRequest{
				Domains: []string{"example.com", "not a domain!@#$", "google.com"},
			},
			expectError: true,
			errorMsg:    "invalid domain",
		},
		{
			name: "Valid IP address",
			request: models.TLSScanRequest{
				Domains: []string{"192.168.1.1", "8.8.8.8"},
			},
			expectError: false,
		},
		{
			name: "Domain with port",
			request: models.TLSScanRequest{
				Domains: []string{"example.com:443"},
			},
			expectError: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateTLSScanRequest(tt.request)
			
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_validateDomain(t *testing.T) {
	handler := &Handler{}
	
	tests := []struct {
		name        string
		domain      string
		expectError bool
	}{
		{
			name:        "Valid domain",
			domain:      "example.com",
			expectError: false,
		},
		{
			name:        "Valid subdomain",
			domain:      "sub.example.com",
			expectError: false,
		},
		{
			name:        "Valid IP",
			domain:      "192.168.1.1",
			expectError: false,
		},
		{
			name:        "Valid IPv6",
			domain:      "2001:db8::1",
			expectError: false,
		},
		{
			name:        "Domain with port",
			domain:      "example.com:443",
			expectError: false,
		},
		{
			name:        "Invalid domain",
			domain:      "not a domain!@#$",
			expectError: true,
		},
		{
			name:        "Empty string",
			domain:      "",
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateDomain(tt.domain)
			
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper function to generate domains for testing
func generateDomains(count int) []string {
	domains := make([]string, count)
	for i := 0; i < count; i++ {
		domains[i] = fmt.Sprintf("example%d.com", i)
	}
	return domains
}

