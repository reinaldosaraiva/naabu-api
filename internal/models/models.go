package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// JobStatus representa os possíveis estados de um job
type JobStatus string

const (
	JobStatusQueued     JobStatus = "queued"
	JobStatusRunning    JobStatus = "running"
	JobStatusCompleted  JobStatus = "completed"
	JobStatusFailed     JobStatus = "failed"
	JobStatusCancelled  JobStatus = "cancelled"
)

// ProbeType representa os tipos de probes disponíveis
type ProbeType string

const (
	ProbeTypeFTP       ProbeType = "ftp"
	ProbeTypeVNC       ProbeType = "vnc"
	ProbeTypeRDP       ProbeType = "rdp"
	ProbeTypeLDAP      ProbeType = "ldap"
	ProbeTypePPTP      ProbeType = "pptp"
	ProbeTypeRsync     ProbeType = "rsync"
	ProbeTypeSSHCipher ProbeType = "ssh_weak_cipher"
	ProbeTypeSSHMAC    ProbeType = "ssh_weak_mac"
)

// ScanRequest representa a requisição de scan
type ScanRequest struct {
	IPs             []string `json:"ips" validate:"required,dive"`              // Aceita IPs, hostnames, CIDRs
	Ports           string   `json:"ports,omitempty"`
	EnableProbes    bool     `json:"enable_probes,omitempty"`
	EnableDeepScan  bool     `json:"enable_deep_scan,omitempty"`
	ProbeTypes      []string `json:"probe_types,omitempty"`
}

// ScanResult representa o resultado do scan para um IP específico
type ScanResult struct {
	IP    string `json:"ip"`
	Ports []Port `json:"ports"`
	Error string `json:"error,omitempty"`
}

// Port representa uma porta encontrada
type Port struct {
	Port            int           `json:"port"`
	Protocol        string        `json:"protocol"`
	State           string        `json:"state"`
	ServiceName     string        `json:"service_name,omitempty"`
	ServiceVersion  string        `json:"service_version,omitempty"`
	IsVulnerable    bool          `json:"is_vulnerable,omitempty"`
	ProbeResults    []ProbeResult `json:"probe_results,omitempty"`
}

// ScanResponse representa a resposta completa do scan
type ScanResponse struct {
	Results   []ScanResult `json:"results"`
	Summary   Summary      `json:"summary"`
	RequestID string       `json:"request_id"`
}

// Summary contém estatísticas do scan
type Summary struct {
	TotalIPs        int `json:"total_ips"`
	TotalPorts      int `json:"total_ports"`
	OpenPorts       int `json:"open_ports"`
	VulnerablePorts int `json:"vulnerable_ports"`
	ProbesRun       int `json:"probes_run"`
	DeepScansRun    int `json:"deep_scans_run"`
	Duration        int `json:"duration_ms"`
	Errors          int `json:"errors"`
}

// Database Models (GORM)

// ScanJob representa um job de scan no banco de dados
type ScanJob struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	ScanID      uuid.UUID `json:"scan_id" gorm:"type:uuid;uniqueIndex;not null"`
	Status      JobStatus `json:"status" gorm:"type:varchar(20);not null;default:'queued'"`
	IPs         string    `json:"ips" gorm:"type:text;not null"`
	Ports       string    `json:"ports" gorm:"type:varchar(1000)"`
	Results     string    `json:"results" gorm:"type:text"`
	Error       string    `json:"error" gorm:"type:text"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	CompletedAt *time.Time `json:"completed_at"`
	
	// Relationships
	ProbeResults      []ProbeResult      `json:"probe_results,omitempty" gorm:"foreignKey:ScanID;references:ScanID"`
	DeepScanArtifacts []DeepScanArtifact `json:"deep_scan_artifacts,omitempty" gorm:"foreignKey:ScanID;references:ScanID"`
}

// ProbeResult representa o resultado de um probe específico
type ProbeResult struct {
	ID            uint      `json:"id" gorm:"primaryKey"`
	ScanID        uuid.UUID `json:"scan_id" gorm:"type:uuid;not null;index"`
	Host          string    `json:"host" gorm:"type:varchar(45);not null;index"`
	Port          int       `json:"port" gorm:"not null;index"`
	ProbeType     ProbeType `json:"probe_type" gorm:"type:varchar(20);not null"`
	ServiceName   string    `json:"service_name" gorm:"type:varchar(100)"`
	ServiceVersion string   `json:"service_version" gorm:"type:varchar(200)"`
	IsVulnerable  bool      `json:"is_vulnerable" gorm:"not null;default:false"`
	Evidence      string    `json:"evidence" gorm:"type:text"`
	Banner        string    `json:"banner" gorm:"type:text"`
	CreatedAt     time.Time `json:"created_at"`
	
	// Relationship
	ScanJob ScanJob `json:"-" gorm:"foreignKey:ScanID;references:ScanID"`
}

// DeepScanArtifact representa artefatos do Nmap (XML, etc.)
type DeepScanArtifact struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	ScanID       uuid.UUID `json:"scan_id" gorm:"type:uuid;not null;index"`
	Host         string    `json:"host" gorm:"type:varchar(45);not null;index"`
	Port         int       `json:"port" gorm:"not null;index"`
	ArtifactType string    `json:"artifact_type" gorm:"type:varchar(50);not null"` // "nmap_xml", "script_output"
	Content      string    `json:"content" gorm:"type:text;not null"`
	ScriptNames  string    `json:"script_names" gorm:"type:varchar(500)"` // NSE scripts usados
	CreatedAt    time.Time `json:"created_at"`
	
	// Relationship
	ScanJob ScanJob `json:"-" gorm:"foreignKey:ScanID;references:ScanID"`
}

// Response Models

// AsyncScanResponse resposta para scan assíncrono
type AsyncScanResponse struct {
	ScanID    uuid.UUID `json:"scan_id"`
	Status    JobStatus `json:"status"`
	Message   string    `json:"message"`
	RequestID string    `json:"request_id,omitempty"`
}

// JobStatusResponse resposta detalhada do status do job
type JobStatusResponse struct {
	ScanID            uuid.UUID           `json:"scan_id"`
	Status            JobStatus           `json:"status"`
	CreatedAt         time.Time           `json:"created_at"`
	UpdatedAt         time.Time           `json:"updated_at"`
	CompletedAt       *time.Time          `json:"completed_at"`
	Error             string              `json:"error,omitempty"`
	Results           *ScanResponse       `json:"results,omitempty"`
	ProbeResults      []ProbeResult       `json:"probe_results,omitempty"`
	DeepScans         []DeepScanArtifact  `json:"deep_scans,omitempty"`
	RequestID         string              `json:"request_id,omitempty"`
}

// JobStats estatísticas dos jobs
type JobStats struct {
	Total       int64 `json:"total"`
	Queued      int64 `json:"queued"`
	Running     int64 `json:"running"`
	Completed   int64 `json:"completed"`
	Failed      int64 `json:"failed"`
	Cancelled   int64 `json:"cancelled"`
}

// ErrorResponse representa uma resposta de erro
type ErrorResponse struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id,omitempty"`
	Code      int    `json:"code,omitempty"`
	Details   string `json:"details,omitempty"`
}

// Probe Configuration Models

type ProbeConfig struct {
	Enabled     bool          `json:"enabled"`
	Timeout     time.Duration `json:"timeout"`
	MaxRetries  int           `json:"max_retries"`
	Concurrency int           `json:"concurrency"`
}

type FTPProbeConfig struct {
	ProbeConfig
	TestAnonymous bool     `json:"test_anonymous"`
	TestUsernames []string `json:"test_usernames,omitempty"`
}

type VNCProbeConfig struct {
	ProbeConfig
	RFBVersion string `json:"rfb_version"`
}

type RDPProbeConfig struct {
	ProbeConfig
	TestEncryption bool `json:"test_encryption"`
}

type LDAPProbeConfig struct {
	ProbeConfig
	TestAnonymous bool `json:"test_anonymous"`
}

type PPTPProbeConfig struct {
	ProbeConfig
}

type RsyncProbeConfig struct {
	ProbeConfig
	TestModules bool `json:"test_modules"`
}

type SSHProbeConfig struct {
	ProbeConfig
	TestWeakMACs bool `json:"test_weak_macs"`
}

// NetworkSecurityCheck represents the status and evidence of a security check
type NetworkSecurityCheck struct {
	Status   string      `json:"status"`   // "ok" or "risk"
	Evidence interface{} `json:"evidence"` // string or array
}

// CVEScanResult represents the result of CVE scanning using Nuclei
type CVEScanResult struct {
	Status   string   `json:"status"`   // "ok" | "risk" | "error"
	CVEIDs   []string `json:"cve_id"`   // Lista de CVEs encontrados
	Evidence []string `json:"evidence"` // Evidências (URLs, banners limitados)
}

// NetworkSecurityResponse represents the consolidated network security status
type NetworkSecurityResponse struct {
	ScanID              uuid.UUID             `json:"scan_id"`
	FTPAnonymousLogin   NetworkSecurityCheck  `json:"ftp_anonymous_login"`
	VNCAccessible       NetworkSecurityCheck  `json:"vnc_accessible"`
	RDPAccessible       NetworkSecurityCheck  `json:"rdp_accessible"`
	LDAPAccessible      NetworkSecurityCheck  `json:"ldap_accessible"`
	PPTPAccessible      NetworkSecurityCheck  `json:"pptp_accessible"`
	RsyncAccessible     NetworkSecurityCheck  `json:"rsync_accessible"`
	SSHWeakCipher       NetworkSecurityCheck  `json:"ssh_weak_cipher"`
	SSHWeakMAC          NetworkSecurityCheck  `json:"ssh_weak_mac"`
	CVEScan             CVEScanResult         `json:"cve_scan"`
}

// ListScansRequest represents query parameters for listing scans
type ListScansRequest struct {
	Status   string `form:"status" json:"status,omitempty"`     // Filter by status
	Limit    int    `form:"limit" json:"limit,omitempty"`       // Number of items per page (default: 20, max: 100)
	Offset   int    `form:"offset" json:"offset,omitempty"`     // Starting position (default: 0)
	SortBy   string `form:"sort_by" json:"sort_by,omitempty"`   // Sort field (default: created_at)
	SortDesc bool   `form:"sort_desc" json:"sort_desc,omitempty"` // Sort direction (default: true)
}

// ListScansResponse represents the response for listing scans
type ListScansResponse struct {
	Scans      []ScanJobSummary `json:"scans"`
	Pagination PaginationInfo   `json:"pagination"`
}

// ScanJobSummary represents a summary of a scan job for listing
type ScanJobSummary struct {
	ID          uint       `json:"id"`
	ScanID      uuid.UUID  `json:"scan_id"`
	Status      JobStatus  `json:"status"`
	IPs         []string   `json:"ips"`
	Ports       string     `json:"ports,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CompletedAt *time.Time `json:"completed_at"`
	Duration    *int64     `json:"duration_ms,omitempty"` // milliseconds
	ErrorSummary string    `json:"error_summary,omitempty"`
	// Summary stats
	TotalPorts      int `json:"total_ports,omitempty"`
	OpenPorts       int `json:"open_ports,omitempty"`
	VulnerablePorts int `json:"vulnerable_ports,omitempty"`
	ProbesRun       int `json:"probes_run,omitempty"`
}

// PaginationInfo represents pagination metadata
type PaginationInfo struct {
	CurrentPage int   `json:"current_page"`
	PerPage     int   `json:"per_page"`
	TotalItems  int64 `json:"total_items"`
	TotalPages  int   `json:"total_pages"`
	HasNext     bool  `json:"has_next"`
	HasPrev     bool  `json:"has_prev"`
}

// Migration helpers
func (ScanJob) TableName() string {
	return "scan_jobs"
}

func (ProbeResult) TableName() string {
	return "probe_results"
}

func (DeepScanArtifact) TableName() string {
	return "deep_scan_artifacts"
}

// BeforeCreate hooks para UUID
func (sj *ScanJob) BeforeCreate(tx *gorm.DB) error {
	if sj.ScanID == uuid.Nil {
		sj.ScanID = uuid.New()
	}
	return nil
}

// Index definitions for better query performance
func (ScanJob) Indexes() []string {
	return []string{
		"idx_scan_jobs_scan_id",
		"idx_scan_jobs_status",
		"idx_scan_jobs_created_at",
	}
}

func (ProbeResult) Indexes() []string {
	return []string{
		"idx_probe_results_scan_id",
		"idx_probe_results_host_port",
		"idx_probe_results_probe_type",
		"idx_probe_results_vulnerable",
	}
}

func (DeepScanArtifact) Indexes() []string {
	return []string{
		"idx_deep_scan_artifacts_scan_id",
		"idx_deep_scan_artifacts_host_port",
		"idx_deep_scan_artifacts_type",
	}
}