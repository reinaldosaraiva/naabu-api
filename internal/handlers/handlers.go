package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"naabu-api/internal/models"
	"naabu-api/pkg/logger"

	"github.com/sirupsen/logrus"
)

// Scanner interface define os métodos necessários para o serviço de scanner
type Scanner interface {
	ScanPorts(ctx context.Context, req models.ScanRequest) (models.ScanResponse, error)
}

// Handler gerencia as requisições HTTP
type Handler struct {
	scanner Scanner
	logger  *logrus.Logger
}

// NewHandler cria uma nova instância do handler
func NewHandler(scanner Scanner, logger *logrus.Logger) *Handler {
	return &Handler{
		scanner: scanner,
		logger:  logger,
	}
}

// ScanHandler processa requisições de scan de portas
func (h *Handler) ScanHandler(w http.ResponseWriter, r *http.Request) {
	// Adicionar contexto com request ID
	ctx, logEntry := logger.WithRequestID(r.Context(), h.logger)
	
	// Log da requisição recebida
	logEntry.WithFields(logrus.Fields{
		"method":     r.Method,
		"url":        r.URL.String(),
		"user_agent": r.UserAgent(),
		"remote_ip":  r.RemoteAddr,
	}).Info("Requisição recebida")
	
	// Validar método HTTP
	if r.Method != http.MethodPost {
		h.respondWithError(w, logEntry, http.StatusMethodNotAllowed, "Método não permitido", logger.GetRequestID(ctx))
		return
	}
	
	// Validar Content-Type
	if r.Header.Get("Content-Type") != "application/json" {
		h.respondWithError(w, logEntry, http.StatusBadRequest, "Content-Type deve ser application/json", logger.GetRequestID(ctx))
		return
	}
	
	// Decodificar body da requisição
	var req models.ScanRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Rejeitar campos desconhecidos
	
	if err := decoder.Decode(&req); err != nil {
		logEntry.WithError(err).Error("Erro ao decodificar JSON")
		h.respondWithError(w, logEntry, http.StatusBadRequest, "JSON inválido: "+err.Error(), logger.GetRequestID(ctx))
		return
	}
	
	// Validar dados da requisição
	if err := h.validateRequest(req); err != nil {
		logEntry.WithError(err).Error("Dados de requisição inválidos")
		h.respondWithError(w, logEntry, http.StatusBadRequest, err.Error(), logger.GetRequestID(ctx))
		return
	}
	
	// Log dos parâmetros do scan
	logEntry.WithFields(logrus.Fields{
		"ip_count": len(req.IPs),
		"ports":    req.Ports,
	}).Info("Iniciando scan")
	
	// Configurar timeout para operação de scan
	scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	
	// Executar scan
	startTime := time.Now()
	response, err := h.scanner.ScanPorts(scanCtx, req)
	duration := time.Since(startTime)
	
	if err != nil {
		logEntry.WithError(err).WithField("duration", duration).Error("Erro durante scan")
		h.respondWithError(w, logEntry, http.StatusInternalServerError, "Erro interno do servidor", logger.GetRequestID(ctx))
		return
	}
	
	// Adicionar request ID à resposta
	response.RequestID = logger.GetRequestID(ctx)
	
	// Log do resultado
	logEntry.WithFields(logrus.Fields{
		"duration":    duration,
		"total_ips":   response.Summary.TotalIPs,
		"open_ports":  response.Summary.OpenPorts,
		"errors":      response.Summary.Errors,
	}).Info("Scan concluído")
	
	// Responder com sucesso
	h.respondWithJSON(w, logEntry, http.StatusOK, response)
}

// HealthHandler verifica o status do serviço
func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   "1.0.0",
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// validateRequest valida os dados da requisição
func (h *Handler) validateRequest(req models.ScanRequest) error {
	if len(req.IPs) == 0 {
		return fmt.Errorf("campo 'ips' é obrigatório e não pode estar vazio")
	}
	
	if len(req.IPs) > 100 {
		return fmt.Errorf("máximo de 100 IPs permitidos por requisição")
	}
	
	return nil
}

// respondWithError envia uma resposta de erro padronizada
func (h *Handler) respondWithError(w http.ResponseWriter, logEntry *logrus.Entry, statusCode int, message, requestID string) {
	errorResp := models.ErrorResponse{
		Error:     message,
		RequestID: requestID,
	}
	
	logEntry.WithFields(logrus.Fields{
		"status_code": statusCode,
		"error":       message,
	}).Error("Enviando resposta de erro")
	
	h.respondWithJSON(w, logEntry, statusCode, errorResp)
}

// respondWithJSON envia uma resposta JSON
func (h *Handler) respondWithJSON(w http.ResponseWriter, logEntry *logrus.Entry, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logEntry.WithError(err).Error("Erro ao codificar resposta JSON")
		http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
	}
}