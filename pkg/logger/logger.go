package logger

import (
	"context"
	"os"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type contextKey string

const RequestIDKey contextKey = "request_id"

// NewLogger cria um novo logger estruturado
func NewLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.InfoLevel)
	
	// Formato JSON para produção, text para desenvolvimento
	if os.Getenv("ENV") == "production" {
		logger.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}
	
	return logger
}

// WithRequestID adiciona um ID de requisição ao contexto e retorna logger com contexto
func WithRequestID(ctx context.Context, logger *logrus.Logger) (context.Context, *logrus.Entry) {
	requestID := uuid.New().String()
	ctxWithID := context.WithValue(ctx, RequestIDKey, requestID)
	loggerWithID := logger.WithField("request_id", requestID)
	return ctxWithID, loggerWithID
}

// GetRequestID extrai o ID da requisição do contexto
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(RequestIDKey).(string); ok {
		return requestID
	}
	return ""
}