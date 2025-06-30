package probes

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"go.uber.org/zap"
	"naabu-api/internal/models"
)

// SSHMACProbe implements SSH weak MAC detection
type SSHMACProbe struct {
	logger  *zap.Logger
	timeout time.Duration
}

// WeakMACs contains MACs marked as insecure
var weakMACsOnly = map[string]bool{
	"hmac-md5":                   true,
	"hmac-md5-96":                true,
	"hmac-sha1-96":               true,
	"hmac-ripemd160":             true,
	"hmac-ripemd160@openssh.com": true,
	"umac-64@openssh.com":        true, // Weak due to short tag
}

// NewSSHMACProbe creates a new SSH MAC probe
func NewSSHMACProbe(logger *zap.Logger) *SSHMACProbe {
	return &SSHMACProbe{
		logger:  logger,
		timeout: 30 * time.Second,
	}
}

func (p *SSHMACProbe) Name() string {
	return "ssh_weak_mac"
}

func (p *SSHMACProbe) DefaultPort() int {
	return 22
}

func (p *SSHMACProbe) GetTimeout() time.Duration {
	return p.timeout
}

func (p *SSHMACProbe) IsRelevantPort(port int) bool {
	return port == 22 || port == 2222 || port == 2020 || port == 222
}

// Probe executes SSH weak MAC detection
func (p *SSHMACProbe) Probe(ctx context.Context, ip string, port int) (*models.ProbeResult, error) {
	result := &models.ProbeResult{
		Host:         ip,
		Port:         port,
		ProbeType:    models.ProbeTypeSSHMAC,
		ServiceName:  "ssh",
		IsVulnerable: false,
		CreatedAt:    time.Now(),
	}

	p.logger.Debug("Starting SSH MAC probe",
		zap.String("host", ip),
		zap.Int("port", port),
	)

	// Create connection with timeout
	dialer := &net.Dialer{Timeout: p.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		result.Evidence = fmt.Sprintf("Connection failed: %v", err)
		return result, nil
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(p.timeout))

	// Try to extract weak MACs during handshake
	weakMACsFound, serverMACs, serverVersion, probeErr := p.probeSSHMACs(conn, ip, port)
	
	// Set service information
	if serverVersion != "" {
		result.ServiceVersion = serverVersion
	}

	// Build evidence based on findings
	var evidence []string
	
	if len(weakMACsFound) > 0 {
		evidence = append(evidence, fmt.Sprintf("SSH server supports weak MAC algorithms: %s", strings.Join(weakMACsFound, ", ")))
		if len(serverMACs) > 0 {
			evidence = append(evidence, fmt.Sprintf("All server MACs: %s", strings.Join(serverMACs, ", ")))
		}
		result.IsVulnerable = true
	}
	
	if probeErr != nil && !result.IsVulnerable {
		evidence = append(evidence, fmt.Sprintf("Probe error: %v", probeErr))
	}
	
	if len(evidence) > 0 {
		result.Evidence = strings.Join(evidence, " | ")
	} else {
		result.Evidence = "SSH server uses only strong MAC algorithms"
	}
	
	p.logger.Debug("SSH MAC probe completed",
		zap.String("host", ip),
		zap.Int("port", port),
		zap.Bool("vulnerable", result.IsVulnerable),
		zap.String("evidence", result.Evidence),
	)

	return result, nil
}

// probeSSHMACs attempts to extract supported MACs during SSH handshake
func (p *SSHMACProbe) probeSSHMACs(conn net.Conn, ip string, port int) ([]string, []string, string, error) {
	var weakMACsFound []string
	var serverMACs []string
	var serverVersion string

	// Create SSH client config with weak MACs first
	clientConfig := &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
		Config: ssh.Config{
			MACs: []string{
				// Weak MACs first
				"hmac-md5", "hmac-md5-96", "hmac-sha1-96",
				"umac-64@openssh.com", "hmac-ripemd160",
				"hmac-ripemd160@openssh.com",
				// Then secure ones
				"hmac-sha2-256", "hmac-sha2-512",
				"umac-128@openssh.com",
				"hmac-sha2-256-etm@openssh.com",
				"hmac-sha2-512-etm@openssh.com",
			},
		},
	}

	// Attempt SSH handshake
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, fmt.Sprintf("%s:%d", ip, port), clientConfig)
	if err != nil {
		// Parse error to extract server algorithms
		errStr := err.Error()
		
		// Extract server version
		if strings.Contains(errStr, "SSH-") {
			parts := strings.Split(errStr, " ")
			for _, part := range parts {
				if strings.HasPrefix(part, "SSH-") {
					serverVersion = strings.TrimSpace(part)
					break
				}
			}
		}
		
		// Extract MACs from error
		if strings.Contains(errStr, "server MAC") {
			serverMACs = p.extractAlgorithmsFromError(errStr, "server MAC")
			for _, mac := range serverMACs {
				if weakMACsOnly[mac] {
					weakMACsFound = append(weakMACsFound, mac)
				}
			}
		}
		
		return weakMACsFound, serverMACs, serverVersion, err
	}
	
	// If connection successful, we negotiated with weak algorithms
	if sshConn != nil {
		defer sshConn.Close()
		
		// Get negotiated algorithms
		if sshConn.ServerVersion() != nil {
			serverVersion = string(sshConn.ServerVersion())
		}
		
		// The negotiated MAC is weak since we offered weak ones first
		weakMACsFound = append(weakMACsFound, "negotiated-weak-mac")
	}
	
	// Close channels
	go ssh.DiscardRequests(reqs)
	for range chans {
		// Drain channels
	}
	
	return weakMACsFound, serverMACs, serverVersion, nil
}

// extractAlgorithmsFromError parses SSH error messages to extract algorithm lists
func (p *SSHMACProbe) extractAlgorithmsFromError(errStr, prefix string) []string {
	// Look for pattern like "server MAC: [hmac-sha2-256 hmac-sha2-512 ...]"
	idx := strings.Index(errStr, prefix)
	if idx == -1 {
		return nil
	}
	
	// Find the algorithm list in brackets
	startIdx := strings.Index(errStr[idx:], "[")
	endIdx := strings.Index(errStr[idx:], "]")
	
	if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
		return nil
	}
	
	// Extract and parse the list
	algList := errStr[idx+startIdx+1 : idx+endIdx]
	algorithms := strings.Fields(algList)
	
	return algorithms
}