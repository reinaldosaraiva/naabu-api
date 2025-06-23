package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"naabu-api/internal/handlers"
	"naabu-api/internal/scanner"
	"naabu-api/pkg/logger"
)

func main() {
	// Configurar logger
	logger := logger.NewLogger()
	
	// Inicializar scanner service
	scannerService := scanner.NewService(logger)
	
	// Configurar handlers
	handler := handlers.NewHandler(scannerService, logger)
	
	// Configurar servidor HTTP
	mux := http.NewServeMux()
	mux.HandleFunc("/scan", handler.ScanHandler)
	mux.HandleFunc("/health", handler.HealthHandler)
	
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	// Channel para capturar sinais de shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	
	// Iniciar servidor em goroutine separada
	go func() {
		logger.WithField("port", "8080").Info("Servidor iniciado")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Falha ao iniciar servidor")
		}
	}()
	
	// Aguardar sinal de shutdown
	<-stop
	logger.Info("Recebido sinal de shutdown")
	
	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := server.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Erro durante shutdown")
	} else {
		logger.Info("Servidor finalizado gracefully")
	}
}