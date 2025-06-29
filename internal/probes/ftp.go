package probes

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"naabu-api/internal/models"
)

// FTPProbe implements anonymous FTP detection
type FTPProbe struct {
	timeout time.Duration
}

// NewFTPProbe creates a new FTP probe
func NewFTPProbe() *FTPProbe {
	return &FTPProbe{
		timeout: 30 * time.Second,
	}
}

func (p *FTPProbe) Name() string {
	return "ftp"
}

func (p *FTPProbe) DefaultPort() int {
	return 21
}

func (p *FTPProbe) GetTimeout() time.Duration {
	return p.timeout
}

func (p *FTPProbe) IsRelevantPort(port int) bool {
	return port == 21 || port == 2121
}

func (p *FTPProbe) Probe(ctx context.Context, ip string, port int) (*ProbeResult, error) {
	result := &ProbeResult{}
	
	// Create connection with timeout
	dialer := &net.Dialer{Timeout: p.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(p.timeout))
	
	// Read FTP banner
	reader := bufio.NewReader(conn)
	banner, _, err := reader.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("failed to read banner: %w", err)
	}
	
	bannerStr := string(banner)
	
	// Check if banner indicates FTP service
	if !strings.Contains(strings.ToLower(bannerStr), "ftp") {
		result.Evidence = fmt.Sprintf("Non-FTP service detected: %s", bannerStr)
		return result, nil
	}

	// Send USER anonymous command
	_, err = conn.Write([]byte("USER anonymous\r\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to send USER command: %w", err)
	}

	// Read response
	userResponse, _, err := reader.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("failed to read USER response: %w", err)
	}
	
	userResponseStr := string(userResponse)
	
	// If server accepts anonymous user (331 response), send PASS command
	if strings.HasPrefix(userResponseStr, "331") {
		_, err = conn.Write([]byte("PASS anonymous@\r\n"))
		if err != nil {
			return nil, fmt.Errorf("failed to send PASS command: %w", err)
		}

		// Read password response
		passResponse, _, err := reader.ReadLine()
		if err != nil {
			return nil, fmt.Errorf("failed to read PASS response: %w", err)
		}
		
		passResponseStr := string(passResponse)
		
		// Check if login was successful (230 response)
		if strings.HasPrefix(passResponseStr, "230") {
			result.IsVulnerable = true
			result.Evidence = fmt.Sprintf("Anonymous FTP login successful. Banner: %s | Login response: %s", 
				bannerStr, passResponseStr)
		} else {
			result.Evidence = fmt.Sprintf("Anonymous FTP login failed. Banner: %s | Login response: %s", 
				bannerStr, passResponseStr)
		}
	} else if strings.HasPrefix(userResponseStr, "230") {
		// User logged in immediately without password (even more vulnerable)
		result.IsVulnerable = true
		result.Evidence = fmt.Sprintf("Anonymous FTP login without password. Banner: %s | Response: %s", 
			bannerStr, userResponseStr)
	} else {
		result.Evidence = fmt.Sprintf("Anonymous FTP not allowed. Banner: %s | Response: %s", 
			bannerStr, userResponseStr)
	}

	// Extract service information
	result.ServiceInfo = &models.ServiceInfo{
		Type:       "ftp",
		Banner:     bannerStr,
		Confidence: 0.95,
	}

	// Try to extract version from banner
	if strings.Contains(bannerStr, "(") && strings.Contains(bannerStr, ")") {
		start := strings.Index(bannerStr, "(")
		end := strings.Index(bannerStr, ")")
		if end > start {
			result.ServiceInfo.Version = strings.TrimSpace(bannerStr[start+1 : end])
		}
	}

	return result, nil
}
