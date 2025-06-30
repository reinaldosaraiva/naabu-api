package database

import (
	"encoding/json"
	"fmt"
	"time"

	"naabu-api/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Repository interface defines database operations
type Repository interface {
	// ScanJob operations
	CreateScanJob(job *models.ScanJob) error
	GetScanJobByID(scanID uuid.UUID) (*models.ScanJob, error)
	UpdateScanJobStatus(scanID uuid.UUID, status models.JobStatus) error
	UpdateScanJobResults(scanID uuid.UUID, results models.ScanResponse) error
	UpdateScanJobError(scanID uuid.UUID, errorMsg string) error
	MarkScanJobCompleted(scanID uuid.UUID) error
	GetActiveScanJobs() ([]models.ScanJob, error)
	GetScanJobsByStatus(status models.JobStatus) ([]models.ScanJob, error)
	DeleteOldJobs(olderThan time.Time) error

	// ProbeResult operations
	CreateProbeResult(result *models.ProbeResult) error
	CreateProbeResults(results []*models.ProbeResult) error
	GetProbeResultsByScanID(scanID uuid.UUID) ([]models.ProbeResult, error)
	GetProbeResultsByHost(host string) ([]models.ProbeResult, error)
	GetVulnerableProbeResults(scanID uuid.UUID) ([]models.ProbeResult, error)
	GetProbeResultsByType(probeType models.ProbeType) ([]models.ProbeResult, error)

	// DeepScanArtifact operations
	CreateDeepScanArtifact(artifact *models.DeepScanArtifact) error
	CreateDeepScanArtifacts(artifacts []*models.DeepScanArtifact) error
	GetDeepScanArtifactsByScanID(scanID uuid.UUID) ([]models.DeepScanArtifact, error)
	GetDeepScanArtifactsByHost(host string) ([]models.DeepScanArtifact, error)
	GetDeepScanArtifactsByType(artifactType string) ([]models.DeepScanArtifact, error)

	// Stats and monitoring
	GetJobStats() (*models.JobStats, error)
	
	// Health check
	Ping() error
}

// repository implements the Repository interface
type repository struct {
	db *gorm.DB
}

// NewRepository creates a new repository instance
func NewRepository(db *gorm.DB) Repository {
	return &repository{db: db}
}

// ScanJob operations

func (r *repository) CreateScanJob(job *models.ScanJob) error {
	return r.db.Create(job).Error
}

func (r *repository) GetScanJobByID(scanID uuid.UUID) (*models.ScanJob, error) {
	var job models.ScanJob
	err := r.db.Where("scan_id = ?", scanID).First(&job).Error
	if err != nil {
		return nil, err
	}
	return &job, nil
}

func (r *repository) UpdateScanJobStatus(scanID uuid.UUID, status models.JobStatus) error {
	updates := map[string]interface{}{
		"status":     status,
		"updated_at": time.Now(),
	}

	if status == models.JobStatusCompleted || status == models.JobStatusFailed {
		updates["completed_at"] = time.Now()
	}

	return r.db.Model(&models.ScanJob{}).
		Where("scan_id = ?", scanID).
		Updates(updates).Error
}

func (r *repository) UpdateScanJobResults(scanID uuid.UUID, results models.ScanResponse) error {
	resultsJSON, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	return r.db.Model(&models.ScanJob{}).
		Where("scan_id = ?", scanID).
		Updates(map[string]interface{}{
			"results":    string(resultsJSON),
			"status":     models.JobStatusCompleted,
			"updated_at": time.Now(),
			"completed_at": time.Now(),
		}).Error
}

func (r *repository) UpdateScanJobError(scanID uuid.UUID, errorMsg string) error {
	return r.db.Model(&models.ScanJob{}).
		Where("scan_id = ?", scanID).
		Updates(map[string]interface{}{
			"error":        errorMsg,
			"status":       models.JobStatusFailed,
			"updated_at":   time.Now(),
			"completed_at": time.Now(),
		}).Error
}

func (r *repository) MarkScanJobCompleted(scanID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&models.ScanJob{}).
		Where("scan_id = ?", scanID).
		Updates(map[string]interface{}{
			"status":       models.JobStatusCompleted,
			"completed_at": &now,
			"updated_at":   now,
		}).Error
}

func (r *repository) GetActiveScanJobs() ([]models.ScanJob, error) {
	var jobs []models.ScanJob
	err := r.db.Where("status IN ?", []models.JobStatus{
		models.JobStatusQueued,
		models.JobStatusRunning,
	}).Order("created_at DESC").Find(&jobs).Error
	return jobs, err
}

func (r *repository) GetScanJobsByStatus(status models.JobStatus) ([]models.ScanJob, error) {
	var jobs []models.ScanJob
	err := r.db.Where("status = ?", status).Order("created_at DESC").Find(&jobs).Error
	return jobs, err
}

func (r *repository) DeleteOldJobs(olderThan time.Time) error {
	// Delete in order: artifacts -> probe results -> jobs
	tx := r.db.Begin()
	
	// Get scan IDs for old jobs
	var scanIDs []uuid.UUID
	if err := tx.Model(&models.ScanJob{}).
		Where("created_at < ?", olderThan).
		Pluck("scan_id", &scanIDs).Error; err != nil {
		tx.Rollback()
		return err
	}
	
	if len(scanIDs) == 0 {
		tx.Rollback()
		return nil
	}
	
	// Delete artifacts
	if err := tx.Where("scan_id IN ?", scanIDs).Delete(&models.DeepScanArtifact{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	
	// Delete probe results
	if err := tx.Where("scan_id IN ?", scanIDs).Delete(&models.ProbeResult{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	
	// Delete jobs
	if err := tx.Where("scan_id IN ?", scanIDs).Delete(&models.ScanJob{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	
	return tx.Commit().Error
}

// ProbeResult operations

func (r *repository) CreateProbeResult(result *models.ProbeResult) error {
	return r.db.Create(result).Error
}

func (r *repository) CreateProbeResults(results []*models.ProbeResult) error {
	if len(results) == 0 {
		return nil
	}
	return r.db.CreateInBatches(results, 100).Error
}

func (r *repository) GetProbeResultsByHost(host string) ([]models.ProbeResult, error) {
	var results []models.ProbeResult
	err := r.db.Where("host = ?", host).Order("created_at DESC").Find(&results).Error
	return results, err
}

func (r *repository) GetProbeResultsByType(probeType models.ProbeType) ([]models.ProbeResult, error) {
	var results []models.ProbeResult
	err := r.db.Where("probe_type = ?", probeType).Order("created_at DESC").Find(&results).Error
	return results, err
}

func (r *repository) GetProbeResultsByScanID(scanID uuid.UUID) ([]models.ProbeResult, error) {
	var results []models.ProbeResult
	err := r.db.Where("scan_id = ?", scanID).Find(&results).Error
	return results, err
}

func (r *repository) GetVulnerableProbeResults(scanID uuid.UUID) ([]models.ProbeResult, error) {
	var results []models.ProbeResult
	err := r.db.Where("scan_id = ? AND is_vulnerable = ?", scanID, true).Find(&results).Error
	return results, err
}

// DeepScanArtifact operations

func (r *repository) CreateDeepScanArtifact(artifact *models.DeepScanArtifact) error {
	return r.db.Create(artifact).Error
}

func (r *repository) CreateDeepScanArtifacts(artifacts []*models.DeepScanArtifact) error {
	if len(artifacts) == 0 {
		return nil
	}
	return r.db.CreateInBatches(artifacts, 50).Error
}

func (r *repository) GetDeepScanArtifactsByHost(host string) ([]models.DeepScanArtifact, error) {
	var artifacts []models.DeepScanArtifact
	err := r.db.Where("host = ?", host).Order("created_at DESC").Find(&artifacts).Error
	return artifacts, err
}

func (r *repository) GetDeepScanArtifactsByType(artifactType string) ([]models.DeepScanArtifact, error) {
	var artifacts []models.DeepScanArtifact
	err := r.db.Where("artifact_type = ?", artifactType).Order("created_at DESC").Find(&artifacts).Error
	return artifacts, err
}

func (r *repository) GetDeepScanArtifactsByScanID(scanID uuid.UUID) ([]models.DeepScanArtifact, error) {
	var artifacts []models.DeepScanArtifact
	err := r.db.Where("scan_id = ?", scanID).Find(&artifacts).Error
	return artifacts, err
}

// Stats and monitoring

func (r *repository) GetJobStats() (*models.JobStats, error) {
	var stats models.JobStats
	
	// Total jobs
	if err := r.db.Model(&models.ScanJob{}).Count(&stats.Total).Error; err != nil {
		return nil, err
	}
	
	// Jobs by status
	statusCounts := []struct {
		Status models.JobStatus
		Count  int64
	}{}
	
	if err := r.db.Model(&models.ScanJob{}).
		Select("status, count(*) as count").
		Group("status").
		Scan(&statusCounts).Error; err != nil {
		return nil, err
	}
	
	// Map counts to stats
	for _, sc := range statusCounts {
		switch sc.Status {
		case models.JobStatusQueued:
			stats.Queued = sc.Count
		case models.JobStatusRunning:
			stats.Running = sc.Count
		case models.JobStatusCompleted:
			stats.Completed = sc.Count
		case models.JobStatusFailed:
			stats.Failed = sc.Count
		case models.JobStatusCancelled:
			stats.Cancelled = sc.Count
		}
	}
	
	return &stats, nil
}

// Health check
func (r *repository) Ping() error {
	sqlDB, err := r.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

// Helper functions

// JobStatusResponseFromScanJob converts a ScanJob to JobStatusResponse
func JobStatusResponseFromScanJob(job *models.ScanJob) (*models.JobStatusResponse, error) {
	response := &models.JobStatusResponse{
		ScanID:            job.ScanID,
		Status:            job.Status,
		CreatedAt:         job.CreatedAt,
		UpdatedAt:         job.UpdatedAt,
		CompletedAt:       job.CompletedAt,
		Error:             job.Error,
		ProbeResults:      job.ProbeResults,
		DeepScans:         job.DeepScanArtifacts,
	}

	// Parse results if available
	if job.Results != "" {
		var scanResponse models.ScanResponse
		if err := json.Unmarshal([]byte(job.Results), &scanResponse); err == nil {
			response.Results = &scanResponse
		}
	}

	return response, nil
}
