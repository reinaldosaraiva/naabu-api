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

// RsyncProbe implements rsync module enumeration
type RsyncProbe struct {
	timeout time.Duration
}

// NewRsyncProbe creates a new rsync probe
func NewRsyncProbe() *RsyncProbe {
	return &RsyncProbe{
		timeout: 30 * time.Second,
	}
}

func (p *RsyncProbe) Name() string {
	return "rsync"
}

func (p *RsyncProbe) DefaultPort() int {
	return 873
}

func (p *RsyncProbe) GetTimeout() time.Duration {
	return p.timeout
}

func (p *RsyncProbe) IsRelevantPort(port int) bool {
	return port == 873
}

func (p *RsyncProbe) Probe(ctx context.Context, ip string, port int) (*ProbeResult, error) {
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
	
	// Send newline to request module list
	_, err = conn.Write([]byte("\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to send module list request: %w", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	var modules []string
	var banner string
	isFirst := true
	
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// First line might be a banner or error
		if isFirst {
			banner = line
			isFirst = false
			
			// Check if it looks like an rsync error or non-rsync service
			if strings.Contains(strings.ToLower(line), "error") ||
			   strings.Contains(strings.ToLower(line), "denied") ||
			   !strings.Contains(strings.ToLower(line), "rsync") {
				result.Evidence = fmt.Sprintf("Rsync service error or non-rsync service: %s", line)
				return result, nil
			}
		}
		
		// Parse module entries
		// Format is typically: "module_name<tab>comment"
		if strings.Contains(line, "\t") {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) >= 1 {
				moduleName := strings.TrimSpace(parts[0])
				if moduleName != "" && !strings.HasPrefix(moduleName, "@") {
					modules = append(modules, line)
				}
			}
		} else if line != "" && !strings.HasPrefix(line, "@") {
			// Some rsync servers don't use tabs
			modules = append(modules, line)
		}
		
		// Limit reading to prevent hanging
		if len(modules) > 50 {
			break
		}
	}

	if len(modules) == 0 {
		if banner != "" {
			result.Evidence = fmt.Sprintf("Rsync service detected but no modules available. Banner: %s", banner)
		} else {
			result.Evidence = "Rsync service detected but no response to module list request"
		}
		return result, nil
	}

	// Analyze modules for vulnerability
	hasWritableModules := false
	var writableModules []string
	var allModules []string
	
	for _, module := range modules {
		allModules = append(allModules, strings.TrimSpace(module))
		
		// Look for indicators of writable modules
		moduleLower := strings.ToLower(module)
		if strings.Contains(moduleLower, "write") ||
		   strings.Contains(moduleLower, "upload") ||
		   strings.Contains(moduleLower, "backup") ||
		   strings.Contains(moduleLower, "tmp") ||
		   strings.Contains(moduleLower, "temp") {
			hasWritableModules = true
			writableModules = append(writableModules, strings.TrimSpace(module))
		}
	}

	// Determine vulnerability
	if len(modules) > 0 {
		result.IsVulnerable = true
		
		if hasWritableModules {
			result.Evidence = fmt.Sprintf("Rsync service with potentially writable modules detected. "+
				"Total modules: %d | Potentially writable: %s | All modules: %s",
				len(modules), strings.Join(writableModules, "; "), strings.Join(allModules, "; "))
		} else {
			result.Evidence = fmt.Sprintf("Rsync service with accessible modules detected. "+
				"Total modules: %d | Modules: %s",
				len(modules), strings.Join(allModules, "; "))
		}
		
		if banner != "" {
			result.Evidence += fmt.Sprintf(" | Banner: %s", banner)
		}
	}

	// Extract service information
	result.ServiceInfo = &models.ServiceInfo{
		Type:       "rsync",
		Version:    "rsync daemon",
		Banner:     banner,
		Confidence: 0.95,
	}

	return result, nil
}
