package models

import (
	"time"

	"github.com/google/uuid"
)

// ScanRequest representa a requisição de scan
type ScanRequest struct {
	IPs   []string `json:"ips" validate:"required,dive,ip"`
	Ports string   `json:"ports,omitempty"`
}

// ScanResult representa o resultado do scan para um IP específico
type ScanResult struct {
	IP    string `json:"ip"`
	Ports []Port `json:"ports"`
	Error string `json:"error,omitempty"`
}

// Port representa uma porta encontrada
type Port struct {
	Port            int    `json:"port"`
	Protocol        string `json:"protocol"`
	State           string `json:"state"`
	ServiceName     string `json:"service_name,omitempty"`
	ServiceVersion  string `json:"service_version,omitempty"`
	IsVulnerable    bool   `json:"is_vulnerable,omitempty"`
}

// ScanResponse representa a resposta completa do scan
type ScanResponse struct {
	Results   []ScanResult `json:"results"`
	Summary   Summary      `json:"summary"`
	RequestID string       `json:"request_id"`
}

// Summary contém estatísticas do scan
type Summary struct {
	TotalIPs     int `json:"total_ips"`
	TotalPorts   int `json:"total_ports"`
	OpenPorts    int `json:"open_ports"`
	Duration     int `json:"duration_ms"`
	Errors       int `json:"errors"`
}

// ErrorResponse representa uma resposta de erro
type ErrorResponse struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id,omitempty"`
}

// Job Management Models

// JobStatus representa os possíveis status de um job
type JobStatus string

const (
	JobStatusQueued    JobStatus = "queued"
	JobStatusRunning   JobStatus = "running"
	JobStatusCompleted JobStatus = "completed"
	JobStatusFailed    JobStatus = "failed"
)

// ScanJob representa um job de scan na base de dados
type ScanJob struct {
	ID          uint             `json:"-" gorm:"primaryKey"`
	ScanID      uuid.UUID        `json:"scan_id" gorm:"type:uuid;uniqueIndex;not null"`
	Status      JobStatus        `json:"status" gorm:"type:varchar(20);not null;default:'queued'"`
	IPs         string           `json:"ips" gorm:"type:text;not null"` // JSON array as string
	Ports       string           `json:"ports" gorm:"type:varchar(500)"`
	CreatedAt   time.Time        `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time        `json:"updated_at" gorm:"autoUpdateTime"`
	CompletedAt *time.Time       `json:"completed_at,omitempty"`
	Error       string           `json:"error,omitempty" gorm:"type:text"`
	Results     string           `json:"results,omitempty" gorm:"type:text"` // JSON as string
	ProbeResults []ProbeResult   `json:"probe_results,omitempty" gorm:"foreignKey:ScanID;references:ScanID"`
	DeepScans   []DeepScanArtifact `json:"deep_scans,omitempty" gorm:"foreignKey:ScanID;references:ScanID"`
}

// JobStatusResponse para endpoint GET /scan/{id}
type JobStatusResponse struct {
	ScanID      uuid.UUID        `json:"scan_id"`
	Status      JobStatus        `json:"status"`
	Progress    int              `json:"progress"` // percentage 0-100
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	CompletedAt *time.Time       `json:"completed_at,omitempty"`
	Error       string           `json:"error,omitempty"`
	Results     *ScanResponse    `json:"results,omitempty"`
	ProbeResults []ProbeResult   `json:"probe_results,omitempty"`
	DeepScans   []DeepScanArtifact `json:"deep_scans,omitempty"`
}

// Service Detection Models

// ServiceInfo representa informações sobre um serviço detectado
type ServiceInfo struct {
	Type       string  `json:"type"`       // ftp, vnc, rdp, ldap, pptp, rsync
	Version    string  `json:"version,omitempty"`
	Banner     string  `json:"banner,omitempty"`
	Confidence float32 `json:"confidence"` // 0.0 to 1.0
}

// Probe Results Models

// ProbeType representa os tipos de probes suportados
type ProbeType string

const (
	ProbeTypeFTP   ProbeType = "ftp"
	ProbeTypeVNC   ProbeType = "vnc"
	ProbeTypeRDP   ProbeType = "rdp"
	ProbeTypeLDAP  ProbeType = "ldap"
	ProbeTypePPTP  ProbeType = "pptp"
	ProbeTypeRsync ProbeType = "rsync"
)

// ProbeResult representa o resultado de um probe específico
type ProbeResult struct {
	ID           uint      `json:"-" gorm:"primaryKey"`
	ScanID       uuid.UUID `json:"scan_id" gorm:"type:uuid;not null;index"`
	IP           string    `json:"ip" gorm:"type:varchar(45);not null"`
	Port         int       `json:"port" gorm:"not null"`
	ProbeType    ProbeType `json:"probe_type" gorm:"type:varchar(20);not null"`
	IsVulnerable bool      `json:"is_vulnerable" gorm:"not null;default:false"`
	Evidence     string    `json:"evidence,omitempty" gorm:"type:text"`
	ServiceInfo  string    `json:"service_info,omitempty" gorm:"type:text"` // JSON as string
	CreatedAt    time.Time `json:"created_at" gorm:"autoCreateTime"`
}

// Deep Scan Models

// DeepScanArtifact representa artefactos de deep scan (Nmap XML)
type DeepScanArtifact struct {
	ID        uint      `json:"-" gorm:"primaryKey"`
	ScanID    uuid.UUID `json:"scan_id" gorm:"type:uuid;not null;index"`
	IP        string    `json:"ip" gorm:"type:varchar(45);not null"`
	Port      int       `json:"port" gorm:"not null"`
	Protocol  string    `json:"protocol" gorm:"type:varchar(10);not null"`
	Tool      string    `json:"tool" gorm:"type:varchar(50);not null;default:'nmap'"`
	Command   string    `json:"command" gorm:"type:text"`
	XMLOutput string    `json:"xml_output" gorm:"type:text"`
	Status    string    `json:"status" gorm:"type:varchar(20);default:'completed'"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
}

// Async Response Models

// AsyncScanResponse para POST /scan (202 response)
type AsyncScanResponse struct {
	ScanID  uuid.UUID `json:"scan_id"`
	Status  JobStatus `json:"status"`
	Message string    `json:"message"`
}