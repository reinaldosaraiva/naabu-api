package scanner

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"naabu-api/internal/config"
	"naabu-api/internal/models"

	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
	"go.uber.org/zap"
)

// Service gerencia operações de port scanning
type Service struct {
	logger *zap.Logger
	config *config.Config
}

// NewService cria uma nova instância do serviço de scanner
func NewService(logger *zap.Logger, config *config.Config) *Service {
	return &Service{
		logger: logger,
		config: config,
	}
}

// ScanPorts executa o scan de portas nos IPs especificados
func (s *Service) ScanPorts(ctx context.Context, req models.ScanRequest) (models.ScanResponse, error) {
	startTime := time.Now()
	
	s.logger.Info("Starting port scan",
		zap.Strings("ips", req.IPs),
		zap.String("ports", req.Ports),
	)
	
	// Validar IPs
	validIPs, err := s.validateIPs(req.IPs)
	if err != nil {
		return models.ScanResponse{}, fmt.Errorf("erro na validação de IPs: %w", err)
	}
	
	// Preparar portas para scan
	ports := s.preparePorts(req.Ports)
	
	// Executar scan para cada IP usando streaming JSON
	results := make([]models.ScanResult, 0, len(validIPs))
	totalOpenPorts := 0
	errors := 0
	
	for _, ip := range validIPs {
		result, err := s.scanSingleIPStreaming(ctx, ip, ports)
		if err != nil {
			s.logger.Error("Error scanning IP",
				zap.String("ip", ip),
				zap.Error(err),
			)
			result = models.ScanResult{
				IP:    ip,
				Ports: []models.Port{},
				Error: err.Error(),
			}
			errors++
		} else {
			totalOpenPorts += len(result.Ports)
		}
		results = append(results, result)
	}
	
	duration := time.Since(startTime)
	
	response := models.ScanResponse{
		Results: results,
		Summary: models.Summary{
			TotalIPs:   len(validIPs),
			TotalPorts: len(ports),
			OpenPorts:  totalOpenPorts,
			Duration:   int(duration.Milliseconds()),
			Errors:     errors,
		},
	}
	
	s.logger.Info("Port scan completed",
		zap.Duration("duration", duration),
		zap.Int("total_ips", len(validIPs)),
		zap.Int("open_ports", totalOpenPorts),
		zap.Int("errors", errors),
	)
	
	return response, nil
}

// ScanPortsStreaming executes port scan with JSON streaming output
func (s *Service) ScanPortsStreaming(ctx context.Context, req models.ScanRequest, resultCallback func(models.Port)) error {
	// Validar IPs
	validIPs, err := s.validateIPs(req.IPs)
	if err != nil {
		return fmt.Errorf("erro na validação de IPs: %w", err)
	}
	
	// Preparar portas para scan
	ports := s.preparePorts(req.Ports)
	
	s.logger.Info("Starting streaming port scan",
		zap.Strings("ips", validIPs),
		zap.Int("total_ports", len(ports)),
	)
	
	// Executar scan com streaming
	for _, ip := range validIPs {
		if err := s.scanSingleIPStreamingCallback(ctx, ip, ports, resultCallback); err != nil {
			s.logger.Error("Error in streaming scan",
				zap.String("ip", ip),
				zap.Error(err),
			)
			return err
		}
	}
	
	return nil
}

// validateIPs valida e normaliza a lista de IPs
func (s *Service) validateIPs(ips []string) ([]string, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("lista de IPs não pode estar vazia")
	}
	
	validIPs := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("IP inválido: %s", ip)
		}
		validIPs = append(validIPs, ip)
	}
	
	return validIPs, nil
}

// preparePorts converte string de portas em slice de inteiros
func (s *Service) preparePorts(portStr string) []int {
	// Use configured default ports or fallback
	defaultPorts := []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 873}
	
	if portStr == "" {
		if s.config.Naabu.TopPorts != "" {
			portStr = s.config.Naabu.TopPorts
		} else {
			return defaultPorts
		}
	}
	
	var ports []int
	portParts := strings.Split(portStr, ",")
	
	for _, part := range portParts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		
		// Suporte para ranges (ex: 80-85)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err1 == nil && err2 == nil && start <= end && start > 0 && end <= 65535 {
					for i := start; i <= end; i++ {
						ports = append(ports, i)
					}
					continue
				}
			}
		}
		
		// Porta individual
		if port, err := strconv.Atoi(part); err == nil && port > 0 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	
	if len(ports) == 0 {
		return defaultPorts
	}
	
	return ports
}

// scanSingleIPStreaming executa o scan em um único IP com novo método streaming
func (s *Service) scanSingleIPStreaming(ctx context.Context, ip string, ports []int) (models.ScanResult, error) {
	// Canal para capturar resultados
	resultChan := make(chan *result.HostResult, 100)
	
	// Configurar opções do naabu com configurações do config
	options := &runner.Options{
		Host:              []string{ip},
		Ports:             strings.Join(intSliceToStringSlice(ports), ","),
		Timeout:           int(s.config.Naabu.Timeout.Milliseconds()),
		Retries:           s.config.Naabu.Retries,
		Rate:              s.config.Naabu.RateLimit,
		Threads:           s.config.Naabu.Threads,
		Verbose:           false,
		Silent:            true,
		EnableProgressBar: false,
		Verify:            false,
		ScanAllIPS:        false,
		JSON:              true, // Enable JSON output for streaming
		OnResult: func(hr *result.HostResult) {
			select {
			case resultChan <- hr:
			default:
				// Canal cheio, ignorar resultado
			}
		},
	}
	
	// Set interface if configured
	if s.config.Naabu.Interface != "" {
		options.Interface = s.config.Naabu.Interface
	}
	
	// Set source IP if configured
	if s.config.Naabu.SourceIP != "" {
		options.SourceIP = s.config.Naabu.SourceIP
	}
	
	// Criar runner
	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		return models.ScanResult{}, fmt.Errorf("erro ao criar runner: %w", err)
	}
	defer naabuRunner.Close()
	
	// Executar scan em goroutine
	go func() {
		defer close(resultChan)
		if err := naabuRunner.RunEnumeration(ctx); err != nil {
			s.logger.Error("Error in enumeration",
				zap.String("ip", ip),
				zap.Error(err),
			)
		}
	}()
	
	// Coletar resultados
	var scanPorts []models.Port
	
	// Timeout baseado na configuração
	timeoutCtx, cancel := context.WithTimeout(ctx, s.config.Naabu.Timeout)
	defer cancel()
	
	for {
		select {
		case result, ok := <-resultChan:
			if !ok {
				// Canal fechado, scan finalizado
				return models.ScanResult{
					IP:    ip,
					Ports: scanPorts,
				}, nil
			}
			
			if result != nil {
				for _, port := range result.Ports {
					scanPorts = append(scanPorts, models.Port{
						Port:     port.Port,
						Protocol: "tcp",
						State:    "open",
					})
				}
			}
			
		case <-timeoutCtx.Done():
			return models.ScanResult{}, fmt.Errorf("timeout durante scan do IP %s", ip)
		}
	}
}

// scanSingleIPStreamingCallback executa scan com callback para cada porta encontrada
func (s *Service) scanSingleIPStreamingCallback(ctx context.Context, ip string, ports []int, callback func(models.Port)) error {
	// Configurar opções do naabu
	options := &runner.Options{
		Host:              []string{ip},
		Ports:             strings.Join(intSliceToStringSlice(ports), ","),
		Timeout:           int(s.config.Naabu.Timeout.Milliseconds()),
		Retries:           s.config.Naabu.Retries,
		Rate:              s.config.Naabu.RateLimit,
		Threads:           s.config.Naabu.Threads,
		Verbose:           false,
		Silent:            true,
		EnableProgressBar: false,
		Verify:            false,
		ScanAllIPS:        false,
		JSON:              true,
		OnResult: func(hr *result.HostResult) {
			if hr != nil {
				for _, port := range hr.Ports {
					// Call callback for each found port
					callback(models.Port{
						Port:     port.Port,
						Protocol: "tcp",
						State:    "open",
					})
				}
			}
		},
	}
	
	// Set interface if configured
	if s.config.Naabu.Interface != "" {
		options.Interface = s.config.Naabu.Interface
	}
	
	// Set source IP if configured
	if s.config.Naabu.SourceIP != "" {
		options.SourceIP = s.config.Naabu.SourceIP
	}
	
	// Criar runner
	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		return fmt.Errorf("erro ao criar runner: %w", err)
	}
	defer naabuRunner.Close()
	
	// Execute scan
	if err := naabuRunner.RunEnumeration(ctx); err != nil {
		return fmt.Errorf("erro na enumeração: %w", err)
	}
	
	return nil
}

// intSliceToStringSlice converte slice de inteiros para slice de strings
func intSliceToStringSlice(ints []int) []string {
	strings := make([]string, len(ints))
	for i, v := range ints {
		strings[i] = strconv.Itoa(v)
	}
	return strings
}