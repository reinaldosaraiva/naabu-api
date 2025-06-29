package probes

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"naabu-api/internal/models"
)

// VNCProbe implements VNC security detection
type VNCProbe struct {
	timeout time.Duration
}

// NewVNCProbe creates a new VNC probe
func NewVNCProbe() *VNCProbe {
	return &VNCProbe{
		timeout: 30 * time.Second,
	}
}

func (p *VNCProbe) Name() string {
	return "vnc"
}

func (p *VNCProbe) DefaultPort() int {
	return 5900
}

func (p *VNCProbe) GetTimeout() time.Duration {
	return p.timeout
}

func (p *VNCProbe) IsRelevantPort(port int) bool {
	// VNC typically uses ports 5900-5999
	return port >= 5900 && port <= 5999
}

func (p *VNCProbe) Probe(ctx context.Context, ip string, port int) (*ProbeResult, error) {
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
	
	// Read RFB protocol version from server
	versionBuf := make([]byte, 12)
	n, err := conn.Read(versionBuf)
	if err != nil || n != 12 {
		return nil, fmt.Errorf("failed to read RFB version: %w", err)
	}
	
	serverVersion := string(versionBuf)
	
	// Check if it's a valid RFB protocol
	if !strings.HasPrefix(serverVersion, "RFB ") {
		result.Evidence = fmt.Sprintf("Non-VNC service detected: %s", serverVersion)
		return result, nil
	}

	// Send back compatible version (RFB 003.003)
	clientVersion := "RFB 003.003\n"
	_, err = conn.Write([]byte(clientVersion))
	if err != nil {
		return nil, fmt.Errorf("failed to send client version: %w", err)
	}

	// Read security types
	securityTypesBuf := make([]byte, 1)
	_, err = conn.Read(securityTypesBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read security types length: %w", err)
	}
	
	numSecurityTypes := int(securityTypesBuf[0])
	
	// Check for authentication failure (0 security types)
	if numSecurityTypes == 0 {
		// Read reason length and reason
		reasonLenBuf := make([]byte, 4)
		_, err = conn.Read(reasonLenBuf)
		if err == nil {
			reasonLen := int(reasonLenBuf[3]) // Assuming little endian, simple approach
			if reasonLen > 0 && reasonLen < 1000 {
				reasonBuf := make([]byte, reasonLen)
				conn.Read(reasonBuf)
				result.Evidence = fmt.Sprintf("VNC connection failed: %s | Server version: %s", 
					string(reasonBuf), serverVersion)
			}
		}
		return result, nil
	}

	// Read security types
	securityTypes := make([]byte, numSecurityTypes)
	_, err = conn.Read(securityTypes)
	if err != nil {
		return nil, fmt.Errorf("failed to read security types: %w", err)
	}

	// Analyze security types
	var hasNone, hasVNCAuth, hasVeNCrypt bool
	var securityTypeNames []string
	
	for _, secType := range securityTypes {
		switch secType {
		case 1:
			hasNone = true
			securityTypeNames = append(securityTypeNames, "None")
		case 2:
			hasVNCAuth = true
			securityTypeNames = append(securityTypeNames, "VNC Authentication")
		case 19:
			hasVeNCrypt = true
			securityTypeNames = append(securityTypeNames, "VeNCrypt")
		case 20:
			securityTypeNames = append(securityTypeNames, "SASL")
		default:
			securityTypeNames = append(securityTypeNames, fmt.Sprintf("Unknown(%d)", secType))
		}
	}

	// Determine vulnerability
	if hasNone {
		result.IsVulnerable = true
		result.Evidence = fmt.Sprintf("VNC with no authentication detected. Server version: %s | Security types: %s", 
			strings.TrimSpace(serverVersion), strings.Join(securityTypeNames, ", "))
	} else if hasVNCAuth && !hasVeNCrypt {
		result.IsVulnerable = true
		result.Evidence = fmt.Sprintf("VNC with weak authentication detected. Server version: %s | Security types: %s", 
			strings.TrimSpace(serverVersion), strings.Join(securityTypeNames, ", "))
	} else {
		result.Evidence = fmt.Sprintf("VNC with secure authentication. Server version: %s | Security types: %s", 
			strings.TrimSpace(serverVersion), strings.Join(securityTypeNames, ", "))
	}

	// Extract service information
	result.ServiceInfo = &models.ServiceInfo{
		Type:       "vnc",
		Version:    strings.TrimSpace(serverVersion),
		Banner:     strings.TrimSpace(serverVersion),
		Confidence: 0.95,
	}

	return result, nil
}
