package probes

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"naabu-api/internal/models"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// SSHProbe implementa probe para SSH (porta 22)
// US-8: Detecta MACs fracos durante handshake SSH
type SSHProbe struct {
	logger  *zap.Logger
	timeout time.Duration
}

// NewSSHProbe cria uma nova instância do probe SSH
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

// Lista de MACs considerados fracos de acordo com guias de hardening
var weakMACs = []string{
	"hmac-md5",
	"hmac-md5-96",
	"hmac-sha1-96",
	"umac-64@openssh.com",
	"hmac-ripemd160",
	"hmac-ripemd160@openssh.com",
}

// Probe executa o probe SSH conforme US-8
// Critério: Given porta 22 aberta; When o probe extrai MACsClient durante o handshake SSH;
// Then se aparecer qualquer MAC listado como frágil marcar vuln = true e registrar os MACs no evidence
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

	// Try different approaches to extract MAC algorithms
	weakMACSFound, serverMACs, serverVersion, probeErr := p.probeSSHAlgorithms(conn, ip, port)
	
	// Set service information
	if serverVersion != "" {
		result.ServiceVersion = serverVersion
		result.Banner = serverVersion
	} else {
		result.ServiceVersion = "SSH service detected"
	}

	// Analyze results
	if len(weakMACSFound) > 0 {
		result.IsVulnerable = true
		result.Evidence = fmt.Sprintf("SSH server supports weak MAC algorithms: %s", 
			strings.Join(weakMACSFound, ", "))
		
		if len(serverMACs) > len(weakMACSFound) {
			result.Evidence += fmt.Sprintf(" | All server MACs: %s", 
				strings.Join(serverMACs, ", "))
		}
	} else if len(serverMACs) > 0 {
		result.Evidence = fmt.Sprintf("SSH server supports secure MAC algorithms: %s", 
			strings.Join(serverMACs, ", "))
	} else if probeErr != nil {
		result.Evidence = fmt.Sprintf("SSH probe error: %v", probeErr)
	} else {
		result.Evidence = "SSH service detected, but unable to determine MAC algorithms"
	}

	p.logger.Debug("SSH probe completed",
		zap.String("host", ip),
		zap.Int("port", port),
		zap.Bool("vulnerable", result.IsVulnerable),
		zap.Strings("weak_macs", weakMACSFound),
	)

	return result, nil
}

// probeSSHAlgorithms attempts to discover supported MAC algorithms through SSH handshake
func (p *SSHProbe) probeSSHAlgorithms(conn net.Conn, ip string, port int) ([]string, []string, string, error) {
	var weakMACSFound []string
	var serverMACs []string
	var serverVersion string

	// First attempt: Try with minimal config to get server's preferred algorithms
	config1 := &ssh.ClientConfig{
		User:            "probe",
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         p.timeout / 2,
		Config: ssh.Config{
			// Request only weak MACs to see if server supports them
			MACs: weakMACs,
		},
	}

	sshConn, _, _, err := ssh.NewClientConn(conn, fmt.Sprintf("%s:%d", ip, port), config1)
	if sshConn != nil {
		serverVersion = string(sshConn.ServerVersion())
		sshConn.Close()
		
		// If connection succeeded with weak MACs, server supports them
		for _, mac := range weakMACs {
			weakMACSFound = append(weakMACSFound, mac)
			serverMACs = append(serverMACs, mac)
		}
		
		return weakMACSFound, serverMACs, serverVersion, nil
	}

	// Second attempt: Parse error messages for algorithm negotiation info
	if err != nil {
		serverMACs = p.extractMACsFromError(err.Error())
		weakMACSFound = p.findWeakMACs(serverMACs)
		
		// Try to extract server version from error if available
		if serverVersion == "" {
			serverVersion = p.extractServerVersionFromError(err.Error())
		}
	}

	// Third attempt: Try with default algorithms to establish what server supports
	if len(serverMACs) == 0 {
		config2 := &ssh.ClientConfig{
			User:            "probe",
			Auth:            []ssh.AuthMethod{},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         p.timeout / 2,
		}

		// Create new connection for second attempt
		conn2, err2 := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), p.timeout/2)
		if err2 == nil {
			defer conn2.Close()
			conn2.SetReadDeadline(time.Now().Add(p.timeout / 2))
			
			sshConn2, _, _, err3 := ssh.NewClientConn(conn2, fmt.Sprintf("%s:%d", ip, port), config2)
			if sshConn2 != nil {
				if serverVersion == "" {
					serverVersion = string(sshConn2.ServerVersion())
				}
				sshConn2.Close()
			}
			
			if err3 != nil {
				moreMACs := p.extractMACsFromError(err3.Error())
				serverMACs = append(serverMACs, moreMACs...)
				moreWeak := p.findWeakMACs(moreMACs)
				weakMACSFound = append(weakMACSFound, moreWeak...)
			}
		}
	}

	// Remove duplicates
	weakMACSFound = p.removeDuplicates(weakMACSFound)
	serverMACs = p.removeDuplicates(serverMACs)

	return weakMACSFound, serverMACs, serverVersion, err
}

// extractMACsFromError tries to extract MAC algorithms from SSH error messages
func (p *SSHProbe) extractMACsFromError(errorStr string) []string {
	var detectedMACs []string
	errorLower := strings.ToLower(errorStr)
	
	// Look for MAC algorithm names in the error message
	allKnownMACs := append(weakMACs, "hmac-sha2-256", "hmac-sha2-512", "umac-128@openssh.com", "hmac-sha1")
	for _, mac := range allKnownMACs {
		if strings.Contains(errorLower, strings.ToLower(mac)) {
			detectedMACs = append(detectedMACs, mac)
		}
	}
	
	return detectedMACs
}

// findWeakMACs identifies weak MAC algorithms from a list of detected MACs
func (p *SSHProbe) findWeakMACs(detectedMACs []string) []string {
	var weakDetected []string
	
	for _, detected := range detectedMACs {
		for _, weak := range weakMACs {
			if strings.EqualFold(detected, weak) {
				weakDetected = append(weakDetected, detected)
				break
			}
		}
	}
	
	return weakDetected
}

// extractServerVersionFromError tries to extract SSH server version from error messages
func (p *SSHProbe) extractServerVersionFromError(errorStr string) string {
	// Look for patterns like "SSH-2.0-OpenSSH_7.4" in error messages
	if strings.Contains(errorStr, "SSH-") {
		parts := strings.Split(errorStr, "SSH-")
		if len(parts) > 1 {
			versionPart := "SSH-" + strings.Fields(parts[1])[0]
			return strings.Trim(versionPart, "\"'")
		}
	}
	return ""
}

// removeDuplicates removes duplicate strings from a slice
func (p *SSHProbe) removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	
	return result
}