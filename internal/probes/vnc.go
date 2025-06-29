package probes

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"naabu-api/internal/models"

	"go.uber.org/zap"
)

// VNCProbe implementa probe para VNC (porta 5900)
// US-2: Detecta versão e métodos de segurança do VNC
type VNCProbe struct {
	logger  *zap.Logger
	timeout time.Duration
}

// NewVNCProbe cria uma nova instância do probe VNC
func NewVNCProbe(logger *zap.Logger) *VNCProbe {
	return &VNCProbe{
		logger:  logger,
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

// Probe executa o probe VNC conforme US-2
// Critério: Given a porta 5900 aberta; When o probe envia handshake RFB 003.003;
// Then deve retornar protocolVersion e securityTypes, marcando vuln=true se não houver VeNCrypt ou senha
func (p *VNCProbe) Probe(ctx context.Context, ip string, port int) (*models.ProbeResult, error) {
	result := &models.ProbeResult{
		Host:         ip,
		Port:         port,
		ProbeType:    models.ProbeTypeVNC,
		ServiceName:  "vnc",
		IsVulnerable: false,
		CreatedAt:    time.Now(),
	}
	p.logger.Debug("Starting VNC probe",
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

	// Set read/write deadlines
	conn.SetDeadline(time.Now().Add(p.timeout))
	
	// US-2 Criterion: Read RFB protocol version from server
	versionBuf := make([]byte, 12)
	n, err := conn.Read(versionBuf)
	if err != nil || n != 12 {
		result.Evidence = fmt.Sprintf("Failed to read RFB version: %v", err)
		return result, nil
	}
	
	serverVersion := string(versionBuf)
	result.Banner = strings.TrimSpace(serverVersion)
	
	// Check if it's a valid RFB protocol
	if !strings.HasPrefix(serverVersion, "RFB ") {
		result.Evidence = fmt.Sprintf("Non-VNC service detected: %s", serverVersion)
		return result, nil
	}

	// US-2 Criterion: Send handshake RFB 003.003
	clientVersion := "RFB 003.003\n"
	_, err = conn.Write([]byte(clientVersion))
	if err != nil {
		result.Evidence = fmt.Sprintf("Failed to send RFB 003.003 handshake: %v", err)
		return result, nil
	}

	// Read security types
	securityTypesBuf := make([]byte, 1)
	_, err = conn.Read(securityTypesBuf)
	if err != nil {
		result.Evidence = fmt.Sprintf("Failed to read security types length: %v", err)
		return result, nil
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
		result.Evidence = fmt.Sprintf("Failed to read security types: %v", err)
		return result, nil
	}

	// US-2 Criterion: Analyze security types
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

	// US-2 Criterion: Mark vuln=true if no VeNCrypt or password
	if hasNone {
		result.IsVulnerable = true
		result.Evidence = fmt.Sprintf("VNC with NO authentication detected. protocolVersion: %s | securityTypes: %s", 
			strings.TrimSpace(serverVersion), strings.Join(securityTypeNames, ", "))
		
		p.logger.Warn("Vulnerable VNC server found - no authentication",
			zap.String("host", ip),
			zap.Int("port", port),
			zap.String("version", serverVersion),
		)
	} else if hasVNCAuth && !hasVeNCrypt {
		result.IsVulnerable = true
		result.Evidence = fmt.Sprintf("VNC with weak authentication detected. protocolVersion: %s | securityTypes: %s", 
			strings.TrimSpace(serverVersion), strings.Join(securityTypeNames, ", "))
		
		p.logger.Warn("Vulnerable VNC server found - weak authentication",
			zap.String("host", ip),
			zap.Int("port", port),
			zap.String("version", serverVersion),
		)
	} else {
		result.Evidence = fmt.Sprintf("VNC with secure authentication. protocolVersion: %s | securityTypes: %s", 
			strings.TrimSpace(serverVersion), strings.Join(securityTypeNames, ", "))
	}

	// Extract service version
	result.ServiceVersion = extractVNCVersion(serverVersion)

	return result, nil
}

// extractVNCVersion extrai informações de versão do protocolo RFB
func extractVNCVersion(rfbVersion string) string {
	rfbVersion = strings.TrimSpace(rfbVersion)
	
	// Formato padrão: "RFB 003.008" ou similar
	if strings.HasPrefix(rfbVersion, "RFB ") {
		versionPart := strings.TrimPrefix(rfbVersion, "RFB ")
		return fmt.Sprintf("RFB Protocol %s", versionPart)
	}
	
	return rfbVersion
}
