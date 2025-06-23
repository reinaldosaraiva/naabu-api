package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"naabu-api/internal/models"

	"github.com/sirupsen/logrus/hooks/test"
)

// MockScanner implementa a interface Scanner para testes
type MockScanner struct {
	scanResult models.ScanResponse
	scanError  error
}

func (m *MockScanner) ScanPorts(ctx context.Context, req models.ScanRequest) (models.ScanResponse, error) {
	if m.scanError != nil {
		return models.ScanResponse{}, m.scanError
	}
	return m.scanResult, nil
}

func TestHandler_ScanHandler(t *testing.T) {
	logger, _ := test.NewNullLogger()
	
	tests := []struct {
		name           string
		method         string
		contentType    string
		body           interface{}
		mockResult     models.ScanResponse
		mockError      error
		expectedStatus int
	}{
		{
			name:        "Requisição válida",
			method:      http.MethodPost,
			contentType: "application/json",
			body: models.ScanRequest{
				IPs:   []string{"127.0.0.1"},
				Ports: "80,443",
			},
			mockResult: models.ScanResponse{
				Results: []models.ScanResult{
					{
						IP: "127.0.0.1",
						Ports: []models.Port{
							{Port: 80, Protocol: "tcp", State: "open"},
						},
					},
				},
				Summary: models.Summary{
					TotalIPs:   1,
					TotalPorts: 2,
					OpenPorts:  1,
					Duration:   100,
					Errors:     0,
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Método inválido",
			method:         http.MethodGet,
			contentType:    "application/json",
			body:           models.ScanRequest{},
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "Content-Type inválido",
			method:         http.MethodPost,
			contentType:    "text/plain",
			body:           models.ScanRequest{},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "JSON inválido",
			method:      http.MethodPost,
			contentType: "application/json",
			body:        "invalid json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "IPs vazios",
			method:      http.MethodPost,
			contentType: "application/json",
			body: models.ScanRequest{
				IPs:   []string{},
				Ports: "80",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Configurar mock scanner
			mockScanner := &MockScanner{
				scanResult: tt.mockResult,
				scanError:  tt.mockError,
			}
			
			handler := NewHandler(mockScanner, logger)
			
			// Preparar body da requisição
			var bodyBytes []byte
			if tt.body != nil {
				if str, ok := tt.body.(string); ok {
					bodyBytes = []byte(str)
				} else {
					bodyBytes, _ = json.Marshal(tt.body)
				}
			}
			
			// Criar requisição
			req := httptest.NewRequest(tt.method, "/scan", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", tt.contentType)
			
			// Criar response recorder
			rr := httptest.NewRecorder()
			
			// Executar handler
			handler.ScanHandler(rr, req)
			
			// Verificar status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("esperava status %d, mas obteve %d", tt.expectedStatus, rr.Code)
			}
			
			// Verificar Content-Type para respostas de sucesso
			if tt.expectedStatus == http.StatusOK {
				contentType := rr.Header().Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("esperava Content-Type application/json, mas obteve %s", contentType)
				}
				
				// Verificar se a resposta é um JSON válido
				var response models.ScanResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Errorf("resposta não é um JSON válido: %v", err)
				}
				
				// Verificar se o request ID foi adicionado
				if response.RequestID == "" {
					t.Errorf("request ID não foi adicionado à resposta")
				}
			}
		})
	}
}

func TestHandler_HealthHandler(t *testing.T) {
	logger, _ := test.NewNullLogger()
	mockScanner := &MockScanner{}
	handler := NewHandler(mockScanner, logger)
	
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	
	handler.HealthHandler(rr, req)
	
	// Verificar status code
	if rr.Code != http.StatusOK {
		t.Errorf("esperava status 200, mas obteve %d", rr.Code)
	}
	
	// Verificar Content-Type
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("esperava Content-Type application/json, mas obteve %s", contentType)
	}
	
	// Verificar se a resposta contém os campos esperados
	var health map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &health); err != nil {
		t.Errorf("resposta não é um JSON válido: %v", err)
	}
	
	expectedFields := []string{"status", "timestamp", "version"}
	for _, field := range expectedFields {
		if _, exists := health[field]; !exists {
			t.Errorf("campo '%s' ausente na resposta de heath", field)
		}
	}
}

func TestHandler_validateRequest(t *testing.T) {
	logger, _ := test.NewNullLogger()
	handler := NewHandler(nil, logger)
	
	tests := []struct {
		name      string
		req       models.ScanRequest
		wantError bool
	}{
		{
			name: "Requisição válida",
			req: models.ScanRequest{
				IPs:   []string{"127.0.0.1"},
				Ports: "80",
			},
			wantError: false,
		},
		{
			name: "IPs vazios",
			req: models.ScanRequest{
				IPs:   []string{},
				Ports: "80",
			},
			wantError: true,
		},
		{
			name: "Muitos IPs",
			req: models.ScanRequest{
				IPs:   make([]string, 101), // Mais que o limite de 100
				Ports: "80",
			},
			wantError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateRequest(tt.req)
			
			if tt.wantError && err == nil {
				t.Errorf("esperava erro, mas não ocorreu")
			}
			
			if !tt.wantError && err != nil {
				t.Errorf("não esperava erro, mas ocorreu: %v", err)
			}
		})
	}
}