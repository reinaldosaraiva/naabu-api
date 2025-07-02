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

	// Listing and pagination
	ListScanJobs(req models.ListScansRequest) (*models.ListScansResponse, error)
	GetScanJobSummaryByID(scanID uuid.UUID) (*models.ScanJobSummary, error)

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

// ListScanJobs retrieves paginated list of scan jobs with filtering and sorting
func (r *repository) ListScanJobs(req models.ListScansRequest) (*models.ListScansResponse, error) {
	// Set defaults
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 20
	}
	if req.Offset < 0 {
		req.Offset = 0
	}
	if req.SortBy == "" {
		req.SortBy = "created_at"
	}
	
	// Build query
	query := r.db.Model(&models.ScanJob{})
	
	// Apply filters
	if req.Status != "" {
		query = query.Where("status = ?", req.Status)
	}
	
	// Count total items
	var totalItems int64
	if err := query.Count(&totalItems).Error; err != nil {
		return nil, fmt.Errorf("failed to count scan jobs: %w", err)
	}
	
	// Apply sorting
	sortOrder := "ASC"
	if req.SortDesc {
		sortOrder = "DESC"
	}
	query = query.Order(req.SortBy + " " + sortOrder)
	
	// Apply pagination
	query = query.Limit(req.Limit).Offset(req.Offset)
	
	// Fetch data
	var jobs []models.ScanJob
	if err := query.Find(&jobs).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch scan jobs: %w", err)
	}
	
	// Convert to summaries
	summaries := make([]models.ScanJobSummary, len(jobs))
	for i, job := range jobs {
		summary, err := r.scanJobToSummary(&job)
		if err != nil {
			return nil, fmt.Errorf("failed to convert job to summary: %w", err)
		}
		summaries[i] = *summary
	}
	
	// Calculate pagination info
	currentPage := (req.Offset / req.Limit) + 1
	totalPages := int((totalItems + int64(req.Limit) - 1) / int64(req.Limit))
	
	pagination := models.PaginationInfo{
		CurrentPage: currentPage,
		PerPage:     req.Limit,
		TotalItems:  totalItems,
		TotalPages:  totalPages,
		HasNext:     currentPage < totalPages,
		HasPrev:     currentPage > 1,
	}
	
	return &models.ListScansResponse{
		Scans:      summaries,
		Pagination: pagination,
	}, nil
}

// GetScanJobSummaryByID retrieves a scan job summary by scan ID
func (r *repository) GetScanJobSummaryByID(scanID uuid.UUID) (*models.ScanJobSummary, error) {
	var job models.ScanJob
	err := r.db.Where("scan_id = ?", scanID).First(&job).Error
	if err != nil {
		return nil, err
	}
	
	return r.scanJobToSummary(&job)
}

// scanJobToSummary converts a ScanJob to ScanJobSummary with calculated fields
func (r *repository) scanJobToSummary(job *models.ScanJob) (*models.ScanJobSummary, error) {
	// Parse IPs from JSON string
	var ips []string
	if err := json.Unmarshal([]byte(job.IPs), &ips); err != nil {
		// Fallback: try as single string
		ips = []string{job.IPs}
	}
	
	summary := &models.ScanJobSummary{
		ID:          job.ID,
		ScanID:      job.ScanID,
		Status:      job.Status,
		IPs:         ips,
		Ports:       job.Ports,
		CreatedAt:   job.CreatedAt,
		UpdatedAt:   job.UpdatedAt,
		CompletedAt: job.CompletedAt,
	}
	
	// Calculate duration if completed
	if job.CompletedAt != nil {
		duration := job.CompletedAt.Sub(job.CreatedAt).Milliseconds()
		summary.Duration = &duration
	}
	
	// Extract error summary (first 100 chars)
	if job.Error != "" {
		errorSummary := job.Error
		if len(errorSummary) > 100 {
			errorSummary = errorSummary[:97] + "..."
		}
		summary.ErrorSummary = errorSummary
	}
	
	// Parse results for summary stats
	if job.Results != "" {
		var scanResponse models.ScanResponse
		if err := json.Unmarshal([]byte(job.Results), &scanResponse); err == nil {
			summary.TotalPorts = scanResponse.Summary.TotalPorts
			summary.OpenPorts = scanResponse.Summary.OpenPorts
			summary.VulnerablePorts = scanResponse.Summary.VulnerablePorts
			summary.ProbesRun = scanResponse.Summary.ProbesRun
		}
	}
	
	return summary, nil
}
