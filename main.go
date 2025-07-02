package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"strconv"
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
	// Initialize Zap logger
	zapLogger, err := zap.NewProduction()
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer zapLogger.Sync()

	// Load configuration
	cfg := config.Load()
	
	// Get environment
	env := os.Getenv("ENV")
	if env == "" {
		env = "development"
	}
	
	// Convert port string to int for logging
	port, _ := strconv.Atoi(cfg.Server.Port)
	
	zapLogger.Info("Configuration loaded",
		zap.String("env", env),
		zap.Int("port", port))

	// Initialize database
	dbConfig := database.Config{
		Driver:   cfg.Database.Driver,
		Database: cfg.Database.Database,
		Host:     cfg.Database.Host,
		Port:     cfg.Database.Port,
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
		SSLMode:  cfg.Database.SSLMode,
		Timezone: cfg.Database.Timezone,
	}

	if err := database.Initialize(dbConfig); err != nil {
		zapLogger.Fatal("Failed to initialize database", zap.Error(err))
	}

	db := database.GetDB()
	if db == nil {
		zapLogger.Fatal("Database connection is nil")
	}

	// Auto-migrate database schemas
	if err := database.RunMigrations(db); err != nil {
		zapLogger.Fatal("Failed to migrate database", zap.Error(err))
	}

	// Initialize repository
	repo := database.NewRepository(db)

	// Initialize scanner service
	scannerService := scanner.NewService(zapLogger, cfg)

	// Initialize probe manager
	probeManager := probes.NewManager(zapLogger)

	// Initialize Nmap scanner
	nmapScanner := deepscan.NewNmapScanner(zapLogger)

	// Initialize worker dispatcher
	dispatcher := worker.NewDispatcher(
		cfg.Workers.QuickScanWorkers,
		cfg.Workers.ProbeWorkers,
		cfg.Workers.DeepScanWorkers,
		repo,
		scannerService,
		probeManager,
		nmapScanner,
		zapLogger,
	)

	// Create context for worker pools
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start worker pools
	dispatcher.Start(ctx)
	defer dispatcher.Stop()

	// Initialize HTTP handlers
	handler := handlers.NewHandler(repo, dispatcher, cfg, zapLogger)

	// Setup Gin router
	if env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	
	// Setup logger middleware
	router.Use(handler.LoggerMiddleware())

	// Setup routes
	router.POST("/scan", handler.CreateScanJob)
	router.GET("/health", handler.HealthHandler)
	router.GET("/metrics", handler.MetricsHandler)
	
	// API v1 routes
	api := router.Group("/api/v1")
	{
		api.GET("/scans", handler.ListScans)              // List all scans with pagination
		api.GET("/scans/:id", handler.GetScanByID)        // Get detailed scan by ID
		api.GET("/scans/:id/network", handler.GetNetworkSecurity) // Get network security results
	}
	
	// Swagger documentation
	router.Static("/docs", "./docs")
	router.GET("/", handler.SwaggerRedirect)

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Channel for capturing shutdown signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start server in separate goroutine
	go func() {
		zapLogger.Info("Starting server", zap.String("port", cfg.Server.Port))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zapLogger.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for shutdown signal
	<-stop
	zapLogger.Info("Received shutdown signal")

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Shutdown worker pools first
	dispatcher.Stop()
	
	// Then shutdown HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		zapLogger.Error("Error during server shutdown", zap.Error(err))
	} else {
		zapLogger.Info("Server shutdown completed")
	}

	// Close database connection
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.Close()
	}

	zapLogger.Info("Application shutdown completed")
}