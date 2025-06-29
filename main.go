package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"naabu-api/internal/config"
	"naabu-api/internal/database"
	"naabu-api/internal/deepscan"
	"naabu-api/internal/handlers"
	"naabu-api/internal/probes"
	"naabu-api/internal/scanner"
	"naabu-api/internal/worker"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func main() {
	// Load configuration
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Initialize logger
	logger := initializeLogger(cfg)
	defer logger.Sync()

	logger.Info("Starting Naabu API server",
		zap.String("version", "1.0.0"),
		zap.String("env", getEnv("ENV", "development")),
	)

	// Initialize database
	dbConfig := database.Config{
		Host:     cfg.Database.Host,
		Port:     cfg.Database.Port,
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
		Database: cfg.Database.Database,
		SSLMode:  cfg.Database.SSLMode,
		Timezone: cfg.Database.Timezone,
		Driver:   cfg.Database.Driver,
	}

	if err := database.Initialize(dbConfig); err != nil {
		logger.Fatal("Failed to initialize database", zap.Error(err))
	}
	defer database.Close()

	// Run database migrations
	if err := database.RunMigrations(database.GetDB()); err != nil {
		logger.Fatal("Failed to run migrations", zap.Error(err))
	}

	// Create additional indexes for performance
	if err := database.CreateIndexes(database.GetDB()); err != nil {
		logger.Error("Failed to create indexes", zap.Error(err))
	}

	// Initialize repository
	repo := database.NewRepository(database.GetDB())

	// Initialize scanner service
	scannerService := scanner.NewService(logger, cfg)

	// Initialize probe manager
	probeManager := probes.NewManager(logger)

	// Initialize Nmap scanner
	nmapScanner := deepscan.NewNmapScanner(logger)

	// Initialize worker dispatcher
	dispatcher := worker.NewDispatcher(
		cfg.Workers.QuickScanWorkers,
		cfg.Workers.ProbeWorkers,
		cfg.Workers.DeepScanWorkers,
		repo,
		scannerService,
		probeManager,
		nmapScanner,
		logger,
	)

	// Initialize handlers
	handler := handlers.NewHandler(repo, dispatcher, cfg, logger)

	// Configure Gin
	if cfg.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// Setup routes
	router := gin.New()
	handler.SetupRoutes(router)

	// Start worker pools
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dispatcher.Start(ctx)
	defer dispatcher.Stop()

	// Configure HTTP server
	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in a goroutine
	go func() {
		logger.Info("Starting HTTP server", zap.String("port", cfg.Server.Port))
		if err := srv.ListenAndServe(); err != nil && err.Error() != "http: Server closed" {
			logger.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server forced to shutdown", zap.Error(err))
	} else {
		logger.Info("Server shutdown gracefully")
	}
}

func initializeLogger(cfg *config.Config) *zap.Logger {
	var logger *zap.Logger
	var err error

	if cfg.IsProduction() {
		logger, err = zap.NewProduction()
	} else {
		logger, err = zap.NewDevelopment()
	}

	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	return logger
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}