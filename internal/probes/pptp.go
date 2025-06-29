package probes

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"naabu-api/internal/models"
)

// PPTPProbe implements PPTP legacy VPN detection
type PPTPProbe struct {
	timeout time.Duration
}

// NewPPTPProbe creates a new PPTP probe
func NewPPTPProbe() *PPTPProbe {
	return &PPTPProbe{
		timeout: 30 * time.Second,
	}
}

func (p *PPTPProbe) Name() string {
	return "pptp"
}

func (p *PPTPProbe) DefaultPort() int {
	return 1723
}

func (p *PPTPProbe) GetTimeout() time.Duration {
	return p.timeout
}

func (p *PPTPProbe) IsRelevantPort(port int) bool {
	return port == 1723
}

func (p *PPTPProbe) Probe(ctx context.Context, ip string, port int) (*models.ProbeResult, error) {
	result := &models.ProbeResult{}
	
	// Create connection with timeout
	dialer := &net.Dialer{Timeout: p.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Set read/write deadlines
	conn.SetDeadline(time.Now().Add(p.timeout))
	
	// Build PPTP Start-Control-Connection-Request
	pptpRequest := make([]byte, 156)
	
	// PPTP Header
	binary.BigEndian.PutUint16(pptpRequest[0:2], 156) // Length
	binary.BigEndian.PutUint16(pptpRequest[2:4], 1)   // PPTP Message Type (Control Message)
	binary.BigEndian.PutUint32(pptpRequest[4:8], 0x1a2b3c4d) // Magic Cookie
	binary.BigEndian.PutUint16(pptpRequest[8:10], 1)  // Control Type (Start-Control-Connection-Request)
	binary.BigEndian.PutUint16(pptpRequest[10:12], 0) // Reserved
	
	// Protocol Version
	binary.BigEndian.PutUint16(pptpRequest[12:14], 0x0100) // Version 1.0
	
	// Framing Capabilities
	binary.BigEndian.PutUint32(pptpRequest[16:20], 0x00000003) // Async + Sync framing
	
	// Bearer Capabilities  
	binary.BigEndian.PutUint32(pptpRequest[20:24], 0x00000003) // Analog + Digital access
	
	// Maximum Channels
	binary.BigEndian.PutUint16(pptpRequest[24:26], 1) // 1 channel
	
	// Firmware Revision
	binary.BigEndian.PutUint16(pptpRequest[26:28], 0x0100) // Firmware 1.0
	
	// Host Name (64 bytes) - fill with "NaabuProbe"
	copy(pptpRequest[28:28+64], "NaabuProbe")
	
	// Vendor String (64 bytes) - fill with "Security Scanner"
	copy(pptpRequest[28+64:28+64+64], "Security Scanner")

	// Send PPTP request
	_, err = conn.Write(pptpRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to send PPTP request: %w", err)
	}

	// Read response
	response := make([]byte, 200)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read PPTP response: %w", err)
	}

	if n < 12 {
		result.Evidence = fmt.Sprintf("Invalid PPTP response: too short (%d bytes)", n)
		return result, nil
	}

	// Parse PPTP response
	length := binary.BigEndian.Uint16(response[0:2])
	messageType := binary.BigEndian.Uint16(response[2:4])
	magicCookie := binary.BigEndian.Uint32(response[4:8])
	controlType := binary.BigEndian.Uint16(response[8:10])

	// Check if it's a valid PPTP response
	if magicCookie != 0x1a2b3c4d || messageType != 1 {
		result.Evidence = fmt.Sprintf("Non-PPTP service detected. Magic: %x, MsgType: %d", magicCookie, messageType)
		return result, nil
	}

	// Check if it's a Start-Control-Connection-Reply
	if controlType == 2 && n >= 156 {
		// Parse result code
		resultCode := binary.BigEndian.Uint16(response[12:14])
		errorCode := binary.BigEndian.Uint16(response[14:16])
		protocolVersion := binary.BigEndian.Uint16(response[16:18])
		
		if resultCode == 1 { // Success
			result.IsVulnerable = true
			result.Evidence = fmt.Sprintf("PPTP legacy VPN detected and connection established. "+
				"Protocol version: %x, Length: %d", protocolVersion, length)
		} else {
			result.IsVulnerable = true // Still vulnerable, just connection failed
			result.Evidence = fmt.Sprintf("PPTP legacy VPN detected but connection failed. "+
				"Result code: %d, Error code: %d, Protocol version: %x", resultCode, errorCode, protocolVersion)
		}
		
		// Extract host and vendor info if available
		if n >= 156 {
			hostName := string(response[32:96])
			vendorString := string(response[96:160])
			
			// Clean up strings (remove null bytes)
			hostName = strings.TrimRight(hostName, "\x00")
			vendorString = strings.TrimRight(vendorString, "\x00")
			
			if hostName != "" || vendorString != "" {
				result.Evidence += fmt.Sprintf(" | Host: %s | Vendor: %s", hostName, vendorString)
			}
		}
	} else {
		result.Evidence = fmt.Sprintf("PPTP protocol detected but unexpected control type: %d (length: %d)", controlType, length)
		result.IsVulnerable = true // PPTP is inherently vulnerable
	}

	// Extract service information
	result.ServiceName = "pptp"
	result.ServiceVersion = "PPTP VPN"
	result.Banner = fmt.Sprintf("PPTP/1.0 (Magic: %x)", magicCookie)

	return result, nil
}
