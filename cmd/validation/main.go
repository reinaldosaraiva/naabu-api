package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ScanRequest para teste
type ScanRequest struct {
	IPs            []string `json:"ips"`
	Ports          string   `json:"ports,omitempty"`
	EnableProbes   bool     `json:"enable_probes,omitempty"`
	EnableDeepScan bool     `json:"enable_deep_scan,omitempty"`
}

// AsyncScanResponse para teste
type AsyncScanResponse struct {
	ScanID    string `json:"scan_id"`
	Status    string `json:"status"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

// ErrorResponse para teste
type ErrorResponse struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id,omitempty"`
}

func validateTarget(target string) error {
	// 1. Verificar se é um CIDR válido
	if strings.Contains(target, "/") {
		_, _, err := net.ParseCIDR(target)
		if err == nil {
			return nil // CIDR válido
		}
	}
	
	// 2. Verificar se é um IP válido (IPv4 ou IPv6)
	if ip := net.ParseIP(target); ip != nil {
		return nil // IP válido
	}
	
	// 3. Verificar se é um hostname válido
	if isValidHostname(target) {
		return nil // Hostname válido
	}
	
	return fmt.Errorf("não é um IP, hostname ou CIDR válido")
}

func isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}
	
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	
	if !hostnameRegex.MatchString(hostname) {
		return false
	}
	
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return false
		}
	}
	
	return true
}

func validateScanRequest(req ScanRequest) error {
	if len(req.IPs) == 0 {
		return fmt.Errorf("campo 'ips' é obrigatório e não pode estar vazio")
	}
	
	if len(req.IPs) > 100 {
		return fmt.Errorf("máximo de 100 IPs/hostnames/CIDRs permitidos por requisição")
	}
	
	for i, target := range req.IPs {
		target = strings.TrimSpace(target)
		if target == "" {
			return fmt.Errorf("target vazio encontrado na posição %d", i)
		}
		
		if err := validateTarget(target); err != nil {
			return fmt.Errorf("target inválido '%s' na posição %d: %v", target, i, err)
		}
	}
	
	return nil
}

func createScanHandler(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "JSON inválido: " + err.Error(),
		})
		return
	}
	
	// Validar requisição
	if err := validateScanRequest(req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
		})
		return
	}
	
	// Simular criação de job
	scanID := uuid.New().String()
	
	log.Printf("✅ Scan criado com sucesso - ID: %s", scanID)
	log.Printf("📋 Targets validados: %v", req.IPs)
	log.Printf("🔍 Portas: %s", req.Ports)
	log.Printf("🔬 Probes habilitados: %v", req.EnableProbes)
	log.Printf("🔎 Deep scan habilitado: %v", req.EnableDeepScan)
	
	c.JSON(http.StatusAccepted, AsyncScanResponse{
		ScanID:  scanID,
		Status:  "running",
		Message: "Job criado com sucesso - validação de targets OK",
	})
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   "test-validation",
		"message":   "API de teste para validação de targets",
	})
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	
	r := gin.Default()
	
	// Middleware de logging
	r.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	}))
	
	r.Use(gin.Recovery())
	
	// Rotas
	r.GET("/health", healthHandler)
	r.POST("/api/v1/scan", createScanHandler)
	
	log.Println("🚀 Servidor iniciado na porta 8081")
	log.Println("📡 Endpoints disponíveis:")
	log.Println("   GET  /health")
	log.Println("   POST /api/v1/scan")
	log.Println()
	log.Println("✅ Pronto para testar validação de targets!")
	
	if err := r.Run(":8081"); err != nil {
		log.Fatal("Erro ao iniciar servidor:", err)
	}
}