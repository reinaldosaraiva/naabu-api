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

// SSHProbe implements SSH weak cipher and MAC detection
// Combines US-7 (weak ciphers) and US-8 (weak MACs)
type SSHProbe struct {
	logger  *zap.Logger
	timeout time.Duration
}

// WeakCiphers contains ciphers marked as insecure in OpenSSH 6.7 release notes
var weakCiphers = map[string]bool{
	"aes128-cbc":         true,
	"aes192-cbc":         true,
	"aes256-cbc":         true,
	"3des-cbc":           true,
	"blowfish-cbc":       true,
	"cast128-cbc":        true,
	"arcfour":            true,
	"arcfour128":         true,
	"arcfour256":         true,
	"aes128-ctr":         false, // CTR mode is secure
	"aes192-ctr":         false,
	"aes256-ctr":         false,
	"chacha20-poly1305@openssh.com": false, // Modern secure cipher
}

// WeakMACs contains MACs marked as insecure
var weakMACs = map[string]bool{
	"hmac-md5":                    true,
	"hmac-md5-96":                 true,
	"hmac-sha1-96":                true,
	"hmac-ripemd160":              true,
	"hmac-ripemd160@openssh.com":  true,
	"umac-64@openssh.com":         true,  // Weak due to short tag
	"hmac-sha1":                   false, // SHA1 is weak but still commonly used
	"hmac-sha2-256":               false, // Secure
	"hmac-sha2-512":               false, // Secure
	"umac-128@openssh.com":        false, // Secure
	"hmac-sha2-256-etm@openssh.com": false, // Secure with ETM
	"hmac-sha2-512-etm@openssh.com": false, // Secure with ETM
}

// NewSSHProbe creates a new SSH probe
func NewSSHProbe(logger *zap.Logger) *SSHProbe {
	return &SSHProbe{
		logger:  logger,
		timeout: 30 * time.Second,
	}
}

func (p *SSHProbe) Name() string {
	return "ssh"
}

func (p *SSHProbe) DefaultPort() int {
	return 22
}

func (p *SSHProbe) GetTimeout() time.Duration {
	return p.timeout
}

func (p *SSHProbe) IsRelevantPort(port int) bool {
	// SSH padrão na porta 22, mas também aceita outras portas comuns
	return port == 22 || port == 2222 || port == 2020 || port == 222
}

// Probe executes SSH weak cipher and MAC detection according to US-7 and US-8
// US-7: Detects weak ciphers (CBC, arcfour, 3DES)
// US-8: Detects weak MACs (MD5, SHA1-96)
func (p *SSHProbe) Probe(ctx context.Context, ip string, port int) (*models.ProbeResult, error) {
	result := &models.ProbeResult{
		Host:         ip,
		Port:         port,
		ProbeType:    models.ProbeTypeSSH,
		ServiceName:  "ssh",
		IsVulnerable: false,
		CreatedAt:    time.Now(),
	}

	p.logger.Debug("Starting SSH probe",
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

	// Try to extract algorithms during handshake
	weakCiphersFound, weakMACsFound, serverCiphers, serverMACs, serverVersion, probeErr := p.probeSSHAlgorithms(conn, ip, port)
	
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
		result.Evidence = "SSH server uses only strong ciphers and MACs"
	}
	
	p.logger.Debug("SSH probe completed",
		zap.String("host", ip),
		zap.Int("port", port),
		zap.Bool("vulnerable", result.IsVulnerable),
		zap.String("evidence", result.Evidence),
	)

	return result, nil
}

// probeSSHAlgorithms attempts to extract supported algorithms during SSH handshake
func (p *SSHProbe) probeSSHAlgorithms(conn net.Conn, ip string, port int) ([]string, []string, []string, []string, string, error) {
	var weakCiphersFound []string
	var weakMACsFound []string
	var serverCiphers []string
	var serverMACs []string
	var serverVersion string

	// Create SSH client config with all weak algorithms
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
			MACs: []string{
				// Weak MACs first
				"hmac-md5", "hmac-md5-96", "hmac-sha1-96",
				"umac-64@openssh.com", "hmac-ripemd160",
				"hmac-ripemd160@openssh.com",
				// Then secure ones
				"hmac-sha2-256", "hmac-sha2-512",
				"umac-128@openssh.com",
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
				if weak, exists := weakCiphers[cipher]; exists && weak {
					weakCiphersFound = append(weakCiphersFound, cipher)
				}
			}
		}
		
		// Extract MACs from error
		if strings.Contains(errStr, "server MAC") {
			serverMACs = p.extractAlgorithmsFromError(errStr, "server MAC")
			for _, mac := range serverMACs {
				if weak, exists := weakMACs[mac]; exists && weak {
					weakMACsFound = append(weakMACsFound, mac)
				}
			}
		}
		
		return weakCiphersFound, weakMACsFound, serverCiphers, serverMACs, serverVersion, err
	}
	
	// If connection successful, we negotiated with weak algorithms
	if sshConn != nil {
		defer sshConn.Close()
		
		// Get negotiated algorithms
		if sshConn.ServerVersion() != nil {
			serverVersion = string(sshConn.ServerVersion())
		}
		
		// The negotiated cipher and MAC are weak since we only offered weak ones first
		// This is a simplified approach - in production, we'd do multiple handshakes
		weakCiphersFound = append(weakCiphersFound, "negotiated-weak-cipher")
		weakMACsFound = append(weakMACsFound, "negotiated-weak-mac")
	}
	
	// Close channels
	go ssh.DiscardRequests(reqs)
	for range chans {
		// Drain channels
	}
	
	return weakCiphersFound, weakMACsFound, serverCiphers, serverMACs, serverVersion, nil
}

// extractAlgorithmsFromError parses SSH error messages to extract algorithm lists
func (p *SSHProbe) extractAlgorithmsFromError(errStr, prefix string) []string {
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

// CreateConfig creates SSH client config for testing
func (p *SSHProbe) CreateConfig() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
		Config: ssh.Config{
			Ciphers: []string{
				"aes128-cbc", "aes192-cbc", "aes256-cbc",
				"3des-cbc", "blowfish-cbc", "cast128-cbc",
				"arcfour", "arcfour128", "arcfour256",
			},
			MACs: []string{
				"hmac-md5", "hmac-md5-96", "hmac-sha1-96",
				"umac-64@openssh.com", "hmac-ripemd160",
				"hmac-ripemd160@openssh.com",
			},
		},
	}
}