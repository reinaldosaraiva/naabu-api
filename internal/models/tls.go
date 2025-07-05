package models

// TLSScanRequest represents the request for TLS scanning
type TLSScanRequest struct {
	Domains []string `json:"domains" validate:"required,dive,required"`
}

// TLSScanResult represents TLS scan result for a single host
type TLSScanResult struct {
	Host                string   `json:"host"`
	IP                  string   `json:"ip"`
	IsSelfSigned        bool     `json:"is_self_signed"`
	IsExpired           bool     `json:"is_expired"`
	IsValidHostname     bool     `json:"is_valid_hostname"`
	TLSVersions         []string `json:"tls_versions"`
	Cipher              []string `json:"cipher"`
	WeakCiphers         []string `json:"weak_ciphers"`
	DeprecatedProtocols []string `json:"deprecated_protocols"`
	Error               string   `json:"error,omitempty"`
}

// TLSScanResponse represents the response for TLS scanning
type TLSScanResponse struct {
	Results []TLSScanResult `json:"results"`
}