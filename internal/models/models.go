package models

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
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
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