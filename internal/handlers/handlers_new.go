package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"naabu-api/internal/config"
	"naabu-api/internal/database"
	"naabu-api/internal/models"
	"naabu-api/internal/worker"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
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
	
	// Enviar para fila de processamento usando ExecuteAsync
	go func() {
		if err := h.worker.ExecuteAsync(c.Request.Context(), scanID, req); err != nil {
			reqLogger.Error("Erro ao processar job assíncrono", 
				zap.Error(err),
				zap.String("scan_id", scanID.String()),
			)
		}
	}()
	
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
	
	// Executar scan síncrono através do worker
	response, err := h.worker.ExecuteSync(c.Request.Context(), req)
	if err != nil {
		reqLogger.Error("Erro durante scan", zap.Error(err))
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:     "Erro durante scan",
			RequestID: h.getRequestID(c),
		})
		return
	}
	
	// Adicionar request ID à resposta
	response.RequestID = h.getRequestID(c)
	
	reqLogger.Info("Scan síncrono concluído",
		zap.Int("total_ips", response.Summary.TotalIPs),
		zap.Int("open_ports", response.Summary.OpenPorts),
	)
	
	c.JSON(http.StatusOK, response)
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
	
	// Verificar configuração ou usar valor padrão
	maxIPs := 100
	if h.config != nil && h.config.Naabu.MaxTargets > 0 {
		maxIPs = h.config.Naabu.MaxTargets
	}
	
	if len(req.IPs) > maxIPs {
		return fmt.Errorf("máximo de %d IPs permitidos por requisição", maxIPs)
	}
	
	// Validar formato básico de IPs
	for _, ip := range req.IPs {
		if strings.TrimSpace(ip) == "" {
			return fmt.Errorf("IP vazio encontrado na lista")
		}
	}
	
	return nil
}
