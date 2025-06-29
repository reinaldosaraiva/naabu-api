package logger

import (
	"context"
	"os"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type contextKey string

const (
	RequestIDKey contextKey = "request_id"
	ScanIDKey    contextKey = "scan_id"
)

// NewLogger creates a new zap logger with appropriate configuration
func NewZapLogger() (*zap.Logger, error) {
	var config zap.Config
	
	// Configure logger based on environment
	if os.Getenv("ENV") == "production" {
		config = zap.NewProductionConfig()
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	} else {
		config = zap.NewDevelopmentConfig()
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	
	// Always use JSON encoding for structured logging
	config.Encoding = "json"
	
	logger, err := config.Build()
	if err != nil {
		return nil, err
	}
	
	return logger, nil
}

// WithRequestID adds a request ID to the context and returns logger with context
func WithRequestID(ctx context.Context, logger *zap.Logger) (context.Context, *zap.Logger) {
	requestID := uuid.New().String()
	ctxWithID := context.WithValue(ctx, RequestIDKey, requestID)
	loggerWithID := logger.With(zap.String("request_id", requestID))
	return ctxWithID, loggerWithID
}

// WithScanID adds a scan ID to the context and returns logger with context
func WithScanID(ctx context.Context, logger *zap.Logger, scanID string) (context.Context, *zap.Logger) {
	ctxWithID := context.WithValue(ctx, ScanIDKey, scanID)
	loggerWithID := logger.With(zap.String("scan_id", scanID))
	return ctxWithID, loggerWithID
}

// GetRequestID extracts the request ID from context
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(RequestIDKey).(string); ok {
		return requestID
	}
	return ""
}

// GetScanID extracts the scan ID from context
func GetScanID(ctx context.Context) string {
	if scanID, ok := ctx.Value(ScanIDKey).(string); ok {
		return scanID
	}
	return ""
}

// Legacy compatibility functions for existing code

// NewLogger creates a legacy logger wrapper for backward compatibility
func NewLogger() *LegacyLogger {
	zapLogger, err := NewZapLogger()
	if err != nil {
		// Fallback to a basic logger
		zapLogger = zap.NewNop()
	}
	
	return &LegacyLogger{
		zap: zapLogger,
	}
}

// LegacyLogger provides backward compatibility with logrus interface
type LegacyLogger struct {
	zap *zap.Logger
}

// Info logs an info message
func (l *LegacyLogger) Info(msg string) {
	l.zap.Info(msg)
}

// Error logs an error message
func (l *LegacyLogger) Error(msg string) {
	l.zap.Error(msg)
}

// WithField returns a new logger with a field
func (l *LegacyLogger) WithField(key string, value interface{}) *LegacyLogger {
	return &LegacyLogger{
		zap: l.zap.With(zap.Any(key, value)),
	}
}

// WithFields returns a new logger with multiple fields
func (l *LegacyLogger) WithFields(fields map[string]interface{}) *LegacyLogger {
	zapFields := make([]zap.Field, 0, len(fields))
	for k, v := range fields {
		zapFields = append(zapFields, zap.Any(k, v))
	}
	return &LegacyLogger{
		zap: l.zap.With(zapFields...),
	}
}

// WithError returns a new logger with an error field
func (l *LegacyLogger) WithError(err error) *LegacyLogger {
	return &LegacyLogger{
		zap: l.zap.With(zap.Error(err)),
	}
}