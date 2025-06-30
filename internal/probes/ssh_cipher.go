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

// SSHCipherProbe implements SSH weak cipher detection
type SSHCipherProbe struct {
	logger  *zap.Logger
	timeout time.Duration
}

// WeakCiphers contains ciphers marked as insecure
var weakCiphersOnly = map[string]bool{
	"aes128-cbc":     true,
	"aes192-cbc":     true,
	"aes256-cbc":     true,
	"3des-cbc":       true,
	"blowfish-cbc":   true,
	"cast128-cbc":    true,
	"arcfour":        true,
	"arcfour128":     true,
	"arcfour256":     true,
}

// NewSSHCipherProbe creates a new SSH cipher probe
func NewSSHCipherProbe(logger *zap.Logger) *SSHCipherProbe {
	return &SSHCipherProbe{
		logger:  logger,
		timeout: 30 * time.Second,
	}
}

func (p *SSHCipherProbe) Name() string {
	return "ssh_weak_cipher"
}

func (p *SSHCipherProbe) DefaultPort() int {
	return 22
}

func (p *SSHCipherProbe) GetTimeout() time.Duration {
	return p.timeout
}

func (p *SSHCipherProbe) IsRelevantPort(port int) bool {
	return port == 22 || port == 2222 || port == 2020 || port == 222
}

// Probe executes SSH weak cipher detection
func (p *SSHCipherProbe) Probe(ctx context.Context, ip string, port int) (*models.ProbeResult, error) {
	result := &models.ProbeResult{
		Host:         ip,
		Port:         port,
		ProbeType:    models.ProbeTypeSSHCipher,
		ServiceName:  "ssh",
		IsVulnerable: false,
		CreatedAt:    time.Now(),
	}

	p.logger.Debug("Starting SSH cipher probe",
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

	// Try to extract weak ciphers during handshake
	weakCiphersFound, serverCiphers, serverVersion, probeErr := p.probeSSHCiphers(conn, ip, port)
	
	// Set service information
	if serverVersion != "" {
		result.ServiceVersion = serverVersion
	}

	// Build evidence based on findings
	var evidence []string
	
	if len(weakCiphersFound) > 0 {
		evidence = append(evidence, fmt.Sprintf("SSH server supports weak ciphers: %s", strings.Join(weakCiphersFound, ", ")))
		if len(serverCiphers) > 0 {
			evidence = append(evidence, fmt.Sprintf("All server ciphers: %s", strings.Join(serverCiphers, ", ")))
		}
		result.IsVulnerable = true
	}
	
	if probeErr != nil && !result.IsVulnerable {
		evidence = append(evidence, fmt.Sprintf("Probe error: %v", probeErr))
	}
	
	if len(evidence) > 0 {
		result.Evidence = strings.Join(evidence, " | ")
	} else {
		result.Evidence = "SSH server uses only strong ciphers"
	}
	
	p.logger.Debug("SSH cipher probe completed",
		zap.String("host", ip),
		zap.Int("port", port),
		zap.Bool("vulnerable", result.IsVulnerable),
		zap.String("evidence", result.Evidence),
	)

	return result, nil
}

// probeSSHCiphers attempts to extract supported ciphers during SSH handshake
func (p *SSHCipherProbe) probeSSHCiphers(conn net.Conn, ip string, port int) ([]string, []string, string, error) {
	var weakCiphersFound []string
	var serverCiphers []string
	var serverVersion string

	// Create SSH client config with weak ciphers first
	clientConfig := &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
		Config: ssh.Config{
			Ciphers: []string{
				// Weak ciphers first
				"aes128-cbc", "aes192-cbc", "aes256-cbc",
				"3des-cbc", "blowfish-cbc", "cast128-cbc",
				"arcfour", "arcfour128", "arcfour256",
				// Then secure ones
				"aes128-ctr", "aes192-ctr", "aes256-ctr",
				"chacha20-poly1305@openssh.com",
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
		
		// Extract ciphers from error
		if strings.Contains(errStr, "server encrypt cipher") {
			serverCiphers = p.extractAlgorithmsFromError(errStr, "server encrypt cipher")
			for _, cipher := range serverCiphers {
				if weakCiphersOnly[cipher] {
					weakCiphersFound = append(weakCiphersFound, cipher)
				}
			}
		}
		
		return weakCiphersFound, serverCiphers, serverVersion, err
	}
	
	// If connection successful, we negotiated with weak algorithms
	if sshConn != nil {
		defer sshConn.Close()
		
		// Get negotiated algorithms
		if sshConn.ServerVersion() != nil {
			serverVersion = string(sshConn.ServerVersion())
		}
		
		// The negotiated cipher is weak since we offered weak ones first
		weakCiphersFound = append(weakCiphersFound, "negotiated-weak-cipher")
	}
	
	// Close channels
	go ssh.DiscardRequests(reqs)
	for range chans {
		// Drain channels
	}
	
	return weakCiphersFound, serverCiphers, serverVersion, nil
}

// extractAlgorithmsFromError parses SSH error messages to extract algorithm lists
func (p *SSHCipherProbe) extractAlgorithmsFromError(errStr, prefix string) []string {
	// Look for pattern like "server encrypt cipher: [aes128-ctr aes192-ctr ...]"
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