package probes

import (
	"context"
	"fmt"
	"net"
	"time"

	"naabu-api/internal/models"
)

// RDPProbe implements RDP encryption detection
type RDPProbe struct {
	timeout time.Duration
}

// NewRDPProbe creates a new RDP probe
func NewRDPProbe() *RDPProbe {
	return &RDPProbe{
		timeout: 30 * time.Second,
	}
}

func (p *RDPProbe) Name() string {
	return "rdp"
}

func (p *RDPProbe) DefaultPort() int {
	return 3389
}

func (p *RDPProbe) GetTimeout() time.Duration {
	return p.timeout
}

func (p *RDPProbe) IsRelevantPort(port int) bool {
	return port == 3389
}

func (p *RDPProbe) Probe(ctx context.Context, ip string, port int) (*ProbeResult, error) {
	result := &ProbeResult{}
	
	// Create connection with timeout
	dialer := &net.Dialer{Timeout: p.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Set read/write deadlines
	conn.SetDeadline(time.Now().Add(p.timeout))
	
	// Build RDP Connection Request packet
	// This is a simplified RDP connection request for protocol detection
	rdpConnectionRequest := []byte{
		// TPKT Header
		0x03, 0x00, 0x00, 0x13, // version, reserved, length (19 bytes)
		// COTP Header
		0x0e, // length indicator
		0xe0, // connection request
		0x00, 0x00, // destination reference
		0x00, 0x00, // source reference
		0x00, // class option
		// RDP Negotiation Request
		0x01, // TYPE_RDP_NEG_REQ
		0x00, // flags
		0x08, 0x00, // length
		0x00, 0x00, 0x00, 0x00, // requested protocols (none - standard RDP)
	}

	// Send connection request
	_, err = conn.Write(rdpConnectionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to send RDP connection request: %w", err)
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read RDP response: %w", err)
	}

	if n < 4 {
		return nil, fmt.Errorf("response too short: %d bytes", n)
	}

	// Check TPKT header
	if response[0] != 0x03 {
		result.Evidence = fmt.Sprintf("Non-RDP service detected. Response: %x", response[:min(n, 20)])
		return result, nil
	}

	// Parse response length from TPKT header
	responseLength := int(response[2])<<8 | int(response[3])
	
	// Look for RDP negotiation response
	protocolDetected := "Standard RDP"
	encryptionLevel := "Unknown"
	isVulnerable := false

	// Check for negotiation response in the packet
	for i := 7; i < n-4; i++ {
		if response[i] == 0x02 { // TYPE_RDP_NEG_RSP
			if i+7 < n {
				selectedProtocol := response[i+4] | (response[i+5] << 8) | (response[i+6] << 16) | (response[i+7] << 24)
				switch selectedProtocol {
				case 0x00000000:
					protocolDetected = "Standard RDP"
					encryptionLevel = "Low"
					isVulnerable = true
				case 0x00000001:
					protocolDetected = "RDP with TLS"
					encryptionLevel = "Medium"
				case 0x00000002:
					protocolDetected = "RDP with CredSSP"
					encryptionLevel = "High"
				}
				break
			}
		} else if response[i] == 0x03 { // TYPE_RDP_NEG_FAILURE
			result.Evidence = fmt.Sprintf("RDP negotiation failed. Response length: %d", responseLength)
			return result, nil
		}
	}

	// If no negotiation response found, assume standard RDP
	if protocolDetected == "Standard RDP" && encryptionLevel == "Unknown" {
		encryptionLevel = "Low"
		isVulnerable = true
	}

	// Set vulnerability based on encryption level
	result.IsVulnerable = isVulnerable
	
	if isVulnerable {
		result.Evidence = fmt.Sprintf("RDP with weak encryption detected. Protocol: %s | Encryption: %s | Response length: %d", 
			protocolDetected, encryptionLevel, responseLength)
	} else {
		result.Evidence = fmt.Sprintf("RDP with secure encryption. Protocol: %s | Encryption: %s | Response length: %d", 
			protocolDetected, encryptionLevel, responseLength)
	}

	// Extract service information
	result.ServiceInfo = &models.ServiceInfo{
		Type:       "rdp",
		Version:    protocolDetected,
		Banner:     fmt.Sprintf("RDP/%s", encryptionLevel),
		Confidence: 0.90,
	}

	return result, nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
