package database

import (
	"encoding/json"
	"fmt"
	"strings"
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
	GetActiveScanJobs() ([]models.ScanJob, error)

	// ProbeResult operations
	CreateProbeResult(result *models.ProbeResult) error
	GetProbeResultsByScanID(scanID uuid.UUID) ([]models.ProbeResult, error)
	GetVulnerableProbeResults(scanID uuid.UUID) ([]models.ProbeResult, error)

	// DeepScanArtifact operations
	CreateDeepScanArtifact(artifact *models.DeepScanArtifact) error
	GetDeepScanArtifactsByScanID(scanID uuid.UUID) ([]models.DeepScanArtifact, error)

	// Stats and monitoring
	GetJobStats() (map[string]int64, error)
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
	err := r.db.Preload("ProbeResults").Preload("DeepScans").
		Where("scan_id = ?", scanID).First(&job).Error
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

func (r *repository) GetActiveScanJobs() ([]models.ScanJob, error) {
	var jobs []models.ScanJob
	err := r.db.Where("status IN ?", []models.JobStatus{
		models.JobStatusQueued,
		models.JobStatusRunning,
	}).Find(&jobs).Error
	return jobs, err
}

// ProbeResult operations

func (r *repository) CreateProbeResult(result *models.ProbeResult) error {
	return r.db.Create(result).Error
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

func (r *repository) GetDeepScanArtifactsByScanID(scanID uuid.UUID) ([]models.DeepScanArtifact, error) {
	var artifacts []models.DeepScanArtifact
	err := r.db.Where("scan_id = ?", scanID).Find(&artifacts).Error
	return artifacts, err
}

// Stats and monitoring

func (r *repository) GetJobStats() (map[string]int64, error) {
	stats := make(map[string]int64)

	// Count jobs by status
	var statusCounts []struct {
		Status string
		Count  int64
	}

	err := r.db.Model(&models.ScanJob{}).
		Select("status, count(*) as count").
		Group("status").
		Scan(&statusCounts).Error
	if err != nil {
		return nil, err
	}

	for _, sc := range statusCounts {
		stats[strings.ToLower(string(sc.Status))] = sc.Count
	}

	// Total vulnerable findings
	var vulnerableCount int64
	err = r.db.Model(&models.ProbeResult{}).
		Where("is_vulnerable = ?", true).
		Count(&vulnerableCount).Error
	if err != nil {
		return nil, err
	}
	stats["vulnerable_findings"] = vulnerableCount

	// Total deep scans
	var deepScanCount int64
	err = r.db.Model(&models.DeepScanArtifact{}).Count(&deepScanCount).Error
	if err != nil {
		return nil, err
	}
	stats["deep_scans"] = deepScanCount

	return stats, nil
}

// Helper functions

// JobStatusResponseFromScanJob converts a ScanJob to JobStatusResponse
func JobStatusResponseFromScanJob(job *models.ScanJob) (*models.JobStatusResponse, error) {
	response := &models.JobStatusResponse{
		ScanID:       job.ScanID,
		Status:       job.Status,
		CreatedAt:    job.CreatedAt,
		UpdatedAt:    job.UpdatedAt,
		CompletedAt:  job.CompletedAt,
		Error:        job.Error,
		ProbeResults: job.ProbeResults,
		DeepScans:    job.DeepScans,
	}

	// Calculate progress based on status
	switch job.Status {
	case models.JobStatusQueued:
		response.Progress = 0
	case models.JobStatusRunning:
		response.Progress = 50 // Could be more sophisticated based on actual progress
	case models.JobStatusCompleted:
		response.Progress = 100
	case models.JobStatusFailed:
		response.Progress = 0
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
