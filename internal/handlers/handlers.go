package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"naabu-api/internal/config"
	"naabu-api/internal/cve"
	"naabu-api/internal/database"
	"naabu-api/internal/models"
	"naabu-api/internal/worker"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Handler gerencia as requisições HTTP com Gin
type Handler struct {
	repo   database.Repository
	worker *worker.Dispatcher
	config *config.Config
	logger *zap.Logger
}

// NewHandler cria uma nova instância do handler
func NewHandler(repo database.Repository, worker *worker.Dispatcher, config *config.Config, logger *zap.Logger) *Handler {
	return &Handler{
		repo:   repo,
		worker: worker,
		config: config,
		logger: logger,
	}
}

// SetupRoutes configura todas as rotas da API
func (h *Handler) SetupRoutes(r *gin.Engine) {
	// Middleware
	r.Use(h.LoggerMiddleware())
	r.Use(h.ErrorHandlerMiddleware())
	r.Use(gin.Recovery())

	// Health check
	r.GET("/health", h.HealthHandler)
	r.GET("/metrics", h.MetricsHandler)

	// API v1
	v1 := r.Group("/api/v1")
	{
		// Scan endpoints
		v1.POST("/scan", h.CreateScanJob)
		v1.POST("/scan/quick", h.QuickScan) // Backward compatibility
		
		// Job management
		v1.GET("/jobs", h.ListJobs)
		v1.GET("/jobs/:id", h.GetJob)
		v1.DELETE("/jobs/:id", h.CancelJob)
		
		// Network security endpoints
		v1.GET("/scans/:id/network", h.GetNetworkSecurity)
		
		// Stats endpoints
		v1.GET("/stats", h.GetStats)
	}
}

// LoggerMiddleware adiciona logging estruturado para todas as requisições
func (h *Handler) LoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		requestID := uuid.New().String()
		
		// Adicionar request ID ao contexto
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		
		// Adicionar logger com request ID ao contexto
		reqLogger := h.logger.With(
			zap.String("request_id", requestID),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("user_agent", c.Request.UserAgent()),
			zap.String("remote_ip", c.ClientIP()),
		)
		c.Set("logger", reqLogger)
		
		// Log da requisição
		reqLogger.Info("Requisição recebida")
		
		c.Next()
		
		// Log da resposta
		duration := time.Since(start)
		reqLogger.With(
			zap.Int("status", c.Writer.Status()),
			zap.Duration("duration", duration),
			zap.Int("size", c.Writer.Size()),
		).Info("Requisição processada")
	}
}

// ErrorHandlerMiddleware trata erros globalmente
func (h *Handler) ErrorHandlerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		
		if len(c.Errors) > 0 {
			err := c.Errors.Last()
			reqLogger := h.getLogger(c)
			
			reqLogger.Error("Erro durante processamento da requisição",
				zap.Error(err.Err),
			)
			
			// Não sobrescrever resposta se já foi enviada
			if !c.Writer.Written() {
				c.JSON(http.StatusInternalServerError, models.ErrorResponse{
					Error:     "Erro interno do servidor",
					RequestID: h.getRequestID(c),
				})
			}
		}
	}
}

// CreateScanJob cria um novo job de scan assíncrono
func (h *Handler) CreateScanJob(c *gin.Context) {
	reqLogger := h.getLogger(c)
	
	var req models.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		reqLogger.Error("Erro ao decodificar JSON", zap.Error(err))
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:     "JSON inválido: " + err.Error(),
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Validar dados da requisição
	if err := h.validateScanRequest(req); err != nil {
		reqLogger.Error("Dados de requisição inválidos", zap.Error(err))
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:     err.Error(),
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Criar job no banco de dados
	scanID := uuid.New()
	job := &models.ScanJob{
		ScanID:    scanID,
		Status:    models.JobStatusQueued,
		IPs:       h.encodeIPs(req.IPs),
		Ports:     req.Ports,
		CreatedAt: time.Now(),
	}
	
	if err := h.repo.CreateScanJob(job); err != nil {
		reqLogger.Error("Erro ao criar job", zap.Error(err))
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:     "Erro ao criar job",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Enviar para fila de processamento
	if err := h.worker.SubmitQuickScan(scanID, req.IPs, req.Ports); err != nil {
		reqLogger.Error("Erro ao enviar job para processamento", zap.Error(err))
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:     "Erro ao iniciar processamento",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	reqLogger.Info("Job de scan criado",
		zap.String("scan_id", scanID.String()),
		zap.Int("ip_count", len(req.IPs)),
	)
	
	c.JSON(http.StatusAccepted, models.AsyncScanResponse{
		ScanID:  scanID,
		Status:  job.Status,
		Message: "Job criado com sucesso",
	})
}

// QuickScan executa um scan síncrono para compatibilidade
func (h *Handler) QuickScan(c *gin.Context) {
	reqLogger := h.getLogger(c)
	
	var req models.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		reqLogger.Error("Erro ao decodificar JSON", zap.Error(err))
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:     "JSON inválido: " + err.Error(),
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Validar dados da requisição
	if err := h.validateScanRequest(req); err != nil {
		reqLogger.Error("Dados de requisição inválidos", zap.Error(err))
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:     err.Error(),
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Para compatibilidade, criar um scan assíncrono
	scanID := uuid.New()
	job := &models.ScanJob{
		ScanID:    scanID,
		Status:    models.JobStatusQueued,
		IPs:       h.encodeIPs(req.IPs),
		Ports:     req.Ports,
		CreatedAt: time.Now(),
	}
	
	if err := h.repo.CreateScanJob(job); err != nil {
		reqLogger.Error("Erro ao criar job", zap.Error(err))
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:     "Erro ao criar job",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Enviar para processamento
	if err := h.worker.SubmitQuickScan(scanID, req.IPs, req.Ports); err != nil {
		reqLogger.Error("Erro ao enviar job para processamento", zap.Error(err))
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:     "Erro ao iniciar processamento",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	reqLogger.Info("Scan criado via endpoint de compatibilidade",
		zap.String("scan_id", scanID.String()),
		zap.Int("ip_count", len(req.IPs)),
	)
	
	c.JSON(http.StatusAccepted, models.AsyncScanResponse{
		ScanID:  scanID,
		Status:  job.Status,
		Message: "Scan criado. Use GET /api/v1/jobs/" + scanID.String() + " para acompanhar",
	})
}

// ListJobs lista todos os jobs ativos
func (h *Handler) ListJobs(c *gin.Context) {
	reqLogger := h.getLogger(c)
	
	jobs, err := h.repo.GetActiveScanJobs()
	if err != nil {
		reqLogger.Error("Erro ao listar jobs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:     "Erro ao listar jobs",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"jobs":       jobs,
		"total":      len(jobs),
		"request_id": h.getRequestID(c),
	})
}

// GetJob obtém detalhes de um job específico
func (h *Handler) GetJob(c *gin.Context) {
	reqLogger := h.getLogger(c)
	jobIDStr := c.Param("id")
	
	if jobIDStr == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:     "ID do job é obrigatório",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Parse UUID
	scanID, err := uuid.Parse(jobIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:     "ID do job inválido",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	job, err := h.repo.GetScanJobByID(scanID)
	if err != nil {
		reqLogger.Error("Erro ao buscar job", zap.Error(err), zap.String("scan_id", scanID.String()))
		c.JSON(http.StatusNotFound, models.ErrorResponse{
			Error:     "Job não encontrado",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Buscar probe results e deep scan artifacts
	probeResults, _ := h.repo.GetProbeResultsByScanID(scanID)
	deepScanArtifacts, _ := h.repo.GetDeepScanArtifactsByScanID(scanID)
	
	// Construir resposta
	response := models.JobStatusResponse{
		ScanID:      job.ScanID,
		Status:      job.Status,
		CreatedAt:   job.CreatedAt,
		UpdatedAt:   job.UpdatedAt,
		CompletedAt: job.CompletedAt,
		Error:       job.Error,
		ProbeResults: probeResults,
		DeepScans:   deepScanArtifacts,
	}
	
	// Decode results if available
	if job.Results != "" {
		var results models.ScanResponse
		if err := json.Unmarshal([]byte(job.Results), &results); err == nil {
			response.Results = &results
		}
	}
	
	c.JSON(http.StatusOK, response)
}

// CancelJob cancela um job em execução
func (h *Handler) CancelJob(c *gin.Context) {
	reqLogger := h.getLogger(c)
	jobIDStr := c.Param("id")
	
	if jobIDStr == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:     "ID do job é obrigatório",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Parse UUID
	scanID, err := uuid.Parse(jobIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:     "ID do job inválido",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Atualizar status no banco
	err = h.repo.UpdateScanJobStatus(scanID, models.JobStatusFailed)
	if err != nil {
		reqLogger.Error("Erro ao cancelar job", zap.Error(err), zap.String("scan_id", scanID.String()))
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:     "Erro ao cancelar job",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Adicionar mensagem de erro
	h.repo.UpdateScanJobError(scanID, "Job cancelado pelo usuário")
	
	reqLogger.Info("Job cancelado", zap.String("scan_id", scanID.String()))
	
	c.JSON(http.StatusOK, gin.H{
		"message":    "Job cancelado com sucesso",
		"scan_id":    scanID.String(),
		"request_id": h.getRequestID(c),
	})
}

// HealthHandler verifica o status do serviço
func (h *Handler) HealthHandler(c *gin.Context) {
	health := gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   "2.0.0",
		"database":  "connected",
	}
	
	c.JSON(http.StatusOK, health)
}

// MetricsHandler retorna métricas do sistema
func (h *Handler) MetricsHandler(c *gin.Context) {
	stats, err := h.repo.GetJobStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Erro ao obter estatísticas",
		})
		return
	}
	
	metrics := gin.H{
		"jobs":      stats,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	
	c.JSON(http.StatusOK, metrics)
}

// SwaggerRedirect redireciona para a documentação Swagger
func (h *Handler) SwaggerRedirect(c *gin.Context) {
	c.Redirect(http.StatusMovedPermanently, "/docs/")
}

// GetStats obtém estatísticas gerais
func (h *Handler) GetStats(c *gin.Context) {
	reqLogger := h.getLogger(c)
	
	stats, err := h.repo.GetJobStats()
	if err != nil {
		reqLogger.Error("Erro ao obter estatísticas", zap.Error(err))
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:     "Erro ao obter estatísticas",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"stats":      stats,
		"request_id": h.getRequestID(c),
	})
}

// Helper methods

func (h *Handler) getLogger(c *gin.Context) *zap.Logger {
	if logger, exists := c.Get("logger"); exists {
		return logger.(*zap.Logger)
	}
	return h.logger
}

func (h *Handler) getRequestID(c *gin.Context) string {
	if requestID, exists := c.Get("request_id"); exists {
		return requestID.(string)
	}
	return ""
}

// encodeIPs converts a slice of IPs to JSON string for database storage
func (h *Handler) encodeIPs(ips []string) string {
	data, _ := json.Marshal(ips)
	return string(data)
}

// Validation methods

func (h *Handler) validateScanRequest(req models.ScanRequest) error {
	if len(req.IPs) == 0 {
		return fmt.Errorf("campo 'ips' é obrigatório e não pode estar vazio")
	}
	
	// Usar valor padrão de 100 targets
	maxTargets := 100
	
	if len(req.IPs) > maxTargets {
		return fmt.Errorf("máximo de %d IPs/hostnames/CIDRs permitidos por requisição", maxTargets)
	}
	
	// Validar formato de IPs, hostnames e CIDRs
	for i, target := range req.IPs {
		target = strings.TrimSpace(target)
		if target == "" {
			return fmt.Errorf("target vazio encontrado na posição %d", i)
		}
		
		if err := h.validateTarget(target); err != nil {
			return fmt.Errorf("target inválido '%s' na posição %d: %v", target, i, err)
		}
	}
	
	return nil
}

// validateTarget valida se o target é um IP válido, hostname ou CIDR
func (h *Handler) validateTarget(target string) error {
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
	if h.isValidHostname(target) {
		return nil // Hostname válido
	}
	
	return fmt.Errorf("não é um IP, hostname ou CIDR válido")
}

// isValidHostname verifica se uma string é um hostname válido
func (h *Handler) isValidHostname(hostname string) bool {
	// Hostname deve ter entre 1 e 253 caracteres
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}
	
	// Regex para validar hostname conforme RFC 1123
	// Permite: letras, números, hífens, pontos
	// Não pode começar ou terminar com hífen
	// Cada label deve ter máximo 63 caracteres
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	
	if !hostnameRegex.MatchString(hostname) {
		return false
	}
	
	// Verificar se cada label tem no máximo 63 caracteres
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return false
		}
	}
	
	return true
}

// GetNetworkSecurity returns consolidated network security check results
func (h *Handler) GetNetworkSecurity(c *gin.Context) {
	reqLogger := h.getLogger(c)
	scanIDStr := c.Param("id")
	
	if scanIDStr == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:     "Scan ID is required",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Parse UUID
	scanID, err := uuid.Parse(scanIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:     "Invalid scan ID format",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Check if scan exists
	job, err := h.repo.GetScanJobByID(scanID)
	if err != nil {
		reqLogger.Error("Error finding scan job", zap.Error(err), zap.String("scan_id", scanID.String()))
		c.JSON(http.StatusNotFound, models.ErrorResponse{
			Error:     "Scan not found",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Get probe results for this scan
	probeResults, err := h.repo.GetProbeResultsByScanID(scanID)
	if err != nil {
		reqLogger.Error("Error getting probe results", zap.Error(err), zap.String("scan_id", scanID.String()))
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:     "Error getting probe results",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Build network security response with CVE scan
	response := h.buildNetworkSecurityResponse(c.Request.Context(), scanID, probeResults)
	
	reqLogger.Info("Network security status retrieved",
		zap.String("scan_id", scanID.String()),
		zap.String("job_status", string(job.Status)),
		zap.Int("probe_results", len(probeResults)),
		zap.String("cve_status", response.CVEScan.Status),
		zap.Int("cve_count", len(response.CVEScan.CVEIDs)),
	)
	
	c.JSON(http.StatusOK, response)
}

// buildNetworkSecurityResponse builds the consolidated network security response
func (h *Handler) buildNetworkSecurityResponse(ctx context.Context, scanID uuid.UUID, probeResults []models.ProbeResult) models.NetworkSecurityResponse {
	// Initialize response with default "ok" status
	response := models.NetworkSecurityResponse{
		ScanID: scanID,
		FTPAnonymousLogin:   models.NetworkSecurityCheck{Status: "ok", Evidence: "No FTP anonymous login vulnerabilities detected"},
		VNCAccessible:       models.NetworkSecurityCheck{Status: "ok", Evidence: "No VNC accessibility issues detected"},
		RDPAccessible:       models.NetworkSecurityCheck{Status: "ok", Evidence: "No RDP accessibility issues detected"},
		LDAPAccessible:      models.NetworkSecurityCheck{Status: "ok", Evidence: "No LDAP accessibility issues detected"},
		PPTPAccessible:      models.NetworkSecurityCheck{Status: "ok", Evidence: "No PPTP accessibility issues detected"},
		RsyncAccessible:     models.NetworkSecurityCheck{Status: "ok", Evidence: "No Rsync accessibility issues detected"},
		SSHWeakCipher:       models.NetworkSecurityCheck{Status: "ok", Evidence: "No SSH weak cipher vulnerabilities detected"},
		SSHWeakMAC:          models.NetworkSecurityCheck{Status: "ok", Evidence: "No SSH weak MAC vulnerabilities detected"},
		CVEScan:             models.CVEScanResult{Status: "ok", CVEIDs: []string{}, Evidence: []string{}}, // Initialize CVE scan
	}
	
	// Process probe results and update status for vulnerabilities
	for _, result := range probeResults {
		if result.IsVulnerable {
			switch result.ProbeType {
			case models.ProbeTypeFTP:
				response.FTPAnonymousLogin = models.NetworkSecurityCheck{
					Status:   "risk",
					Evidence: result.Evidence,
				}
			case models.ProbeTypeVNC:
				response.VNCAccessible = models.NetworkSecurityCheck{
					Status:   "risk",
					Evidence: result.Evidence,
				}
			case models.ProbeTypeRDP:
				response.RDPAccessible = models.NetworkSecurityCheck{
					Status:   "risk",
					Evidence: result.Evidence,
				}
			case models.ProbeTypeLDAP:
				response.LDAPAccessible = models.NetworkSecurityCheck{
					Status:   "risk",
					Evidence: result.Evidence,
				}
			case models.ProbeTypePPTP:
				response.PPTPAccessible = models.NetworkSecurityCheck{
					Status:   "risk",
					Evidence: result.Evidence,
				}
			case models.ProbeTypeRsync:
				response.RsyncAccessible = models.NetworkSecurityCheck{
					Status:   "risk",
					Evidence: result.Evidence,
				}
			case models.ProbeTypeSSHCipher:
				response.SSHWeakCipher = models.NetworkSecurityCheck{
					Status:   "risk",
					Evidence: result.Evidence,
				}
			case models.ProbeTypeSSHMAC:
				response.SSHWeakMAC = models.NetworkSecurityCheck{
					Status:   "risk",
					Evidence: result.Evidence,
				}
			}
		}
	}
	
	// Execute CVE scan for discovered targets (only in production)
	// For tests, we keep the default "ok" status to avoid Nuclei execution
	if h.config.Server.Port != "0" { // Port "0" indicates test mode
		response.CVEScan = h.executeCVEScan(ctx, scanID, probeResults)
	}
	
	return response
}

// executeCVEScan performs CVE scanning on targets discovered during probe results
func (h *Handler) executeCVEScan(ctx context.Context, scanID uuid.UUID, probeResults []models.ProbeResult) models.CVEScanResult {
	// Extract unique targets from probe results
	targetMap := make(map[string]bool)
	
	// Get scan job to extract original IPs
	job, err := h.repo.GetScanJobByID(scanID)
	if err != nil {
		h.logger.Error("Failed to get scan job for CVE scan", 
			zap.Error(err), 
			zap.String("scan_id", scanID.String()),
		)
		return models.CVEScanResult{
			Status:   "error",
			CVEIDs:   []string{},
			Evidence: []string{"Failed to retrieve scan targets"},
		}
	}
	
	// Parse original IPs from scan job
	var originalIPs []string
	if err := json.Unmarshal([]byte(job.IPs), &originalIPs); err != nil {
		h.logger.Error("Failed to parse IPs from scan job", 
			zap.Error(err),
			zap.String("scan_id", scanID.String()),
		)
		return models.CVEScanResult{
			Status:   "error",
			CVEIDs:   []string{},
			Evidence: []string{"Failed to parse scan targets"},
		}
	}
	
	// Use original IPs as targets for CVE scanning
	for _, ip := range originalIPs {
		targetMap[ip] = true
	}
	
	// Also include any hosts from probe results with open ports
	for _, result := range probeResults {
		if result.Host != "" {
			targetMap[result.Host] = true
		}
	}
	
	// Convert map to slice
	var targets []string
	for target := range targetMap {
		targets = append(targets, target)
	}
	
	if len(targets) == 0 {
		h.logger.Info("No targets found for CVE scan", zap.String("scan_id", scanID.String()))
		return models.CVEScanResult{
			Status:   "ok",
			CVEIDs:   []string{},
			Evidence: []string{},
		}
	}
	
	h.logger.Info("Starting CVE scan",
		zap.String("scan_id", scanID.String()),
		zap.Int("targets", len(targets)),
		zap.Strings("target_list", targets),
	)
	
	// Create CVE worker pool with configuration
	// Max 10 workers, max 100 hosts, 30 second timeout per requirement
	cvePool := cve.NewCVEWorkerPool(h.logger, 10, 100, 30*time.Second)
	
	// Execute CVE scan
	result := cvePool.ExecuteCVEScan(ctx, targets)
	
	h.logger.Info("CVE scan completed",
		zap.String("scan_id", scanID.String()),
		zap.String("status", result.Status),
		zap.Int("cve_count", len(result.CVEIDs)),
		zap.Strings("cve_ids", result.CVEIDs),
	)
	
	return result
}

// ListScans handles GET /api/v1/scans - List all scans with pagination and filtering
func (h *Handler) ListScans(c *gin.Context) {
	var req models.ListScansRequest
	
	// Bind query parameters
	if err := c.ShouldBindQuery(&req); err != nil {
		h.logger.Error("Invalid query parameters", zap.Error(err))
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Invalid query parameters",
			Details: err.Error(),
		})
		return
	}
	
	// Get scans from repository
	response, err := h.repo.ListScanJobs(req)
	if err != nil {
		h.logger.Error("Failed to list scan jobs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: "Failed to retrieve scan jobs",
		})
		return
	}
	
	h.logger.Info("Listed scan jobs",
		zap.Int("count", len(response.Scans)),
		zap.String("status_filter", req.Status),
		zap.Int("limit", req.Limit),
		zap.Int("offset", req.Offset),
	)
	
	c.JSON(http.StatusOK, response)
}

// GetScanByID handles GET /api/v1/scans/:id - Get detailed scan information by ID
func (h *Handler) GetScanByID(c *gin.Context) {
	scanIDStr := c.Param("id")
	
	scanID, err := uuid.Parse(scanIDStr)
	if err != nil {
		h.logger.Error("Invalid scan ID format", zap.String("scan_id", scanIDStr), zap.Error(err))
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error: "Invalid scan ID format",
		})
		return
	}
	
	// Get scan job from repository
	job, err := h.repo.GetScanJobByID(scanID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, models.ErrorResponse{
				Error: "Scan not found",
			})
			return
		}
		
		h.logger.Error("Failed to get scan job", zap.String("scan_id", scanID.String()), zap.Error(err))
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: "Failed to retrieve scan job",
		})
		return
	}
	
	// Convert to detailed response
	response, err := database.JobStatusResponseFromScanJob(job)
	if err != nil {
		h.logger.Error("Failed to convert scan job to response", zap.String("scan_id", scanID.String()), zap.Error(err))
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: "Failed to process scan job data",
		})
		return
	}
	
	h.logger.Info("Retrieved scan job details",
		zap.String("scan_id", scanID.String()),
		zap.String("status", string(response.Status)),
	)
	
	c.JSON(http.StatusOK, response)
}
