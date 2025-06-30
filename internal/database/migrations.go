package database

import (
	"log"

	"naabu-api/internal/models"

	"gorm.io/gorm"
)

// RunMigrations runs all database migrations
func RunMigrations(db *gorm.DB) error {
	log.Println("Running database migrations...")

	// Auto-migrate all models
	err := db.AutoMigrate(
		&models.ScanJob{},
		&models.ProbeResult{},
		&models.DeepScanArtifact{},
	)
	if err != nil {
		return err
	}

	log.Println("Database migrations completed successfully")
	return nil
}

// CreateIndexes creates additional database indexes for performance
func CreateIndexes(db *gorm.DB) error {
	log.Println("Creating database indexes...")

	// Create indexes for better query performance
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status)",
		"CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at ON scan_jobs(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_probe_results_scan_id_host ON probe_results(scan_id, host)",
		"CREATE INDEX IF NOT EXISTS idx_probe_results_vulnerable ON probe_results(is_vulnerable)",
		"CREATE INDEX IF NOT EXISTS idx_deep_scan_artifacts_scan_id_host ON deep_scan_artifacts(scan_id, host)",
	}

	for _, index := range indexes {
		if err := db.Exec(index).Error; err != nil {
			log.Printf("Warning: Failed to create index: %v", err)
		}
	}

	log.Println("Database indexes created successfully")
	return nil
}
