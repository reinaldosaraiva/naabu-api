// +build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"naabu-api/internal/handlers"
	"naabu-api/internal/models"
	"naabu-api/internal/scanner"
	"naabu-api/pkg/logger"
)

// TestIntegration_ScanLocalhost testa o scan do localhost
func TestIntegration_ScanLocalhost(t *testing.T) {
	if testing.Short() {
		t.Skip("Pulando teste de integração em modo short")
	}
	
	// Configurar serviços
	log := logger.NewLogger()
	scannerService := scanner.NewService(log)
	handler := handlers.NewHandler(scannerService, log)
	
	// Preparar requisição
	req := models.ScanRequest{
		IPs:   []string{"127.0.0.1"},
		Ports: "22,80,443", // Portas comuns que podem estar abertas
	}
	
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Erro ao marshalizar requisição: %v", err)
	}
	
	// Criar requisição HTTP
	httpReq := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	
	// Executar com timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	httpReq = httpReq.WithContext(ctx)
	
	rr := httptest.NewRecorder()
	
	// Executar handler
	handler.ScanHandler(rr, httpReq)
	
	// Verificar resposta
	if rr.Code != http.StatusOK {
		t.Fatalf("Esperava status 200, obteve %d. Body: %s", rr.Code, rr.Body.String())
	}
	
	// Decodificar resposta
	var response models.ScanResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Erro ao decodificar resposta: %v", err)
	}
	
	// Validar estrutura da resposta
	if len(response.Results) != 1 {
		t.Errorf("Esperava 1 resultado, obteve %d", len(response.Results))
	}
	
	if response.Results[0].IP != "127.0.0.1" {
		t.Errorf("Esperava IP 127.0.0.1, obteve %s", response.Results[0].IP)
	}
	
	if response.Summary.TotalIPs != 1 {
		t.Errorf("Esperava TotalIPs = 1, obteve %d", response.Summary.TotalIPs)
	}
	
	if response.RequestID == "" {
		t.Errorf("RequestID não deve estar vazio")
	}
	
	t.Logf("Scan concluído em %dms", response.Summary.Duration)
	t.Logf("Portas abertas encontradas: %d", response.Summary.OpenPorts)
}

// TestIntegration_ScanMultipleIPs testa o scan de múltiplos IPs
func TestIntegration_ScanMultipleIPs(t *testing.T) {
	if testing.Short() {
		t.Skip("Pulando teste de integração em modo short")
	}
	
	log := logger.NewLogger()
	scannerService := scanner.NewService(log)
	handler := handlers.NewHandler(scannerService, log)
	
	req := models.ScanRequest{
		IPs:   []string{"127.0.0.1", "8.8.8.8"}, // Localhost e DNS público do Google
		Ports: "22,53,80,443",
	}
	
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Erro ao marshalizar requisição: %v", err)
	}
	
	httpReq := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	httpReq = httpReq.WithContext(ctx)
	
	rr := httptest.NewRecorder()
	handler.ScanHandler(rr, httpReq)
	
	if rr.Code != http.StatusOK {
		t.Fatalf("Esperava status 200, obteve %d. Body: %s", rr.Code, rr.Body.String())
	}
	
	var response models.ScanResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Erro ao decodificar resposta: %v", err)
	}
	
	if len(response.Results) != 2 {
		t.Errorf("Esperava 2 resultados, obteve %d", len(response.Results))
	}
	
	if response.Summary.TotalIPs != 2 {
		t.Errorf("Esperava TotalIPs = 2, obteve %d", response.Summary.TotalIPs)
	}
	
	// Pelo menos o Google DNS (8.8.8.8) deve ter porta 53 aberta
	googleResult := findResultByIP(response.Results, "8.8.8.8")
	if googleResult != nil {
		hasPort53 := false
		for _, port := range googleResult.Ports {
			if port.Port == 53 {
				hasPort53 = true
				break
			}
		}
		if !hasPort53 {
			t.Logf("Aviso: Porta 53 não detectada como aberta no 8.8.8.8 (pode ser firewall)")
		}
	}
	
	t.Logf("Scan de múltiplos IPs concluído em %dms", response.Summary.Duration)
}

// findResultByIP encontra um resultado pelo IP
func findResultByIP(results []models.ScanResult, ip string) *models.ScanResult {
	for i, result := range results {
		if result.IP == ip {
			return &results[i]
		}
	}
	return nil
}

// BenchmarkScanLocalhost benchmark do scan do localhost
func BenchmarkScanLocalhost(b *testing.B) {
	log := logger.NewLogger()
	scannerService := scanner.NewService(log)
	
	req := models.ScanRequest{
		IPs:   []string{"127.0.0.1"},
		Ports: "80,443",
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := scannerService.ScanPorts(ctx, req)
		cancel()
		
		if err != nil {
			b.Fatalf("Erro no scan: %v", err)
		}
	}
}