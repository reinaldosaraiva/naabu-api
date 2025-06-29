package probes

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"naabu-api/internal/models"

	"go.uber.org/zap"
)

// FTPProbe implementa probe para FTP (porta 21)
// US-1: Detecta se o servidor FTP aceita login anônimo
type FTPProbe struct {
	logger  *zap.Logger
	timeout time.Duration
}

// NewFTPProbe cria uma nova instância do probe FTP
func NewFTPProbe(logger *zap.Logger) *FTPProbe {
	return &FTPProbe{
		logger:  logger,
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
	// FTP padrão na porta 21, mas também aceita outras portas comuns
	return port == 21 || port == 2121 || port == 990 || port == 989
}

// Probe executa o probe FTP conforme US-1
// Critério: Given a porta 21 aberta; When o probe envia USER anonymous;
// Then se a resposta contiver código 230 o campo vuln deve ser true e evidence registrar o banner
func (p *FTPProbe) Probe(ctx context.Context, ip string, port int) (*models.ProbeResult, error) {
	result := &models.ProbeResult{
		Host:         ip,
		Port:         port,
		ProbeType:    models.ProbeTypeFTP,
		ServiceName:  "ftp",
		IsVulnerable: false,
		CreatedAt:    time.Now(),
	}
	p.logger.Debug("Starting FTP probe",
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
	
	// Read FTP banner
	reader := bufio.NewReader(conn)
	banner, _, err := reader.ReadLine()
	if err != nil {
		result.Evidence = fmt.Sprintf("Failed to read banner: %v", err)
		return result, nil
	}
	
	bannerStr := string(banner)
	result.Banner = bannerStr
	
	// Check if banner indicates FTP service
	if !strings.Contains(strings.ToLower(bannerStr), "ftp") {
		result.Evidence = fmt.Sprintf("Non-FTP service detected: %s", bannerStr)
		return result, nil
	}

	// US-1 Criterion: Send USER anonymous command
	_, err = conn.Write([]byte("USER anonymous\r\n"))
	if err != nil {
		result.Evidence = fmt.Sprintf("Failed to send USER command: %v", err)
		return result, nil
	}

	// Read USER response
	userResponse, _, err := reader.ReadLine()
	if err != nil {
		result.Evidence = fmt.Sprintf("Failed to read USER response: %v", err)
		return result, nil
	}
	
	userResponseStr := string(userResponse)
	
	// US-1 Criterion: Check response codes
	if strings.HasPrefix(userResponseStr, "331") {
		// 331 = Password required for anonymous
		_, err = conn.Write([]byte("PASS anonymous@example.com\r\n"))
		if err != nil {
			result.Evidence = fmt.Sprintf("Failed to send PASS command: %v", err)
			return result, nil
		}

		// Read password response
		passResponse, _, err := reader.ReadLine()
		if err != nil {
			result.Evidence = fmt.Sprintf("Failed to read PASS response: %v", err)
			return result, nil
		}
		
		passResponseStr := string(passResponse)
		
		// US-1 Criterion: Check if response contains code 230
		if strings.HasPrefix(passResponseStr, "230") {
			result.IsVulnerable = true
			result.Evidence = fmt.Sprintf("Anonymous FTP login successful (230 code). Banner: %s", bannerStr)
			result.ServiceVersion = extractFTPVersion(bannerStr)
			
			p.logger.Warn("Vulnerable FTP server found - anonymous login allowed",
				zap.String("host", ip),
				zap.Int("port", port),
				zap.String("banner", bannerStr),
			)
		} else {
			result.Evidence = fmt.Sprintf("Anonymous login rejected: %s. Banner: %s", passResponseStr, bannerStr)
		}
	} else if strings.HasPrefix(userResponseStr, "230") {
		// 230 = User logged in without password (highly vulnerable!)
		result.IsVulnerable = true
		result.Evidence = fmt.Sprintf("Anonymous FTP login without password (230 code). Banner: %s", bannerStr)
		result.ServiceVersion = extractFTPVersion(bannerStr)
		
		p.logger.Warn("Highly vulnerable FTP server found - anonymous login without password",
			zap.String("host", ip),
			zap.Int("port", port),
			zap.String("banner", bannerStr),
		)
	} else {
		result.Evidence = fmt.Sprintf("Anonymous user rejected: %s. Banner: %s", userResponseStr, bannerStr)
	}

	// Always try to detect service version
	if result.ServiceVersion == "" {
		result.ServiceVersion = extractFTPVersion(bannerStr)
	}

	return result, nil
}

// extractFTPVersion extrai informações de versão do banner FTP
func extractFTPVersion(banner string) string {
	banner = strings.ToLower(banner)
	
	// Padrões comuns de servidores FTP
	patterns := map[string]string{
		"vsftpd":     "vsftpd",
		"proftpd":    "ProFTPD",
		"pure-ftpd":  "Pure-FTPd",
		"filezilla":  "FileZilla Server",
		"microsoft":  "Microsoft FTP Service",
		"serv-u":     "Serv-U FTP Server",
		"wu-ftpd":    "WU-FTPD",
		"ncftp":      "NcFTP Server",
	}

	for pattern, name := range patterns {
		if strings.Contains(banner, pattern) {
			// Tentar extrair versão
			if strings.Contains(banner, "version") || strings.Contains(banner, "v") {
				return fmt.Sprintf("%s (version detected in banner)", name)
			}
			return name
		}
	}

	// Se não encontrou padrão conhecido, retornar parte do banner
	if len(banner) > 50 {
		return banner[:50] + "..."
	}
	return banner
}
