package probes

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"naabu-api/internal/models"
)

// LDAPProbe implements LDAP anonymous bind detection
type LDAPProbe struct {
	timeout time.Duration
}

// NewLDAPProbe creates a new LDAP probe
func NewLDAPProbe() *LDAPProbe {
	return &LDAPProbe{
		timeout: 30 * time.Second,
	}
}

func (p *LDAPProbe) Name() string {
	return "ldap"
}

func (p *LDAPProbe) DefaultPort() int {
	return 389
}

func (p *LDAPProbe) GetTimeout() time.Duration {
	return p.timeout
}

func (p *LDAPProbe) IsRelevantPort(port int) bool {
	return port == 389 || port == 636 || port == 3268 || port == 3269
}

func (p *LDAPProbe) Probe(ctx context.Context, ip string, port int) (*models.ProbeResult, error) {
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
	
	// Build LDAP anonymous bind request
	// This is a simplified LDAP packet for anonymous bind
	ldapBindRequest := []byte{
		// LDAP Message
		0x30, 0x0c, // SEQUENCE, length=12
		0x02, 0x01, 0x01, // messageID = 1
		// BindRequest
		0x60, 0x07, // APPLICATION[0], length=7
		0x02, 0x01, 0x03, // version = 3
		0x04, 0x00, // name = "" (anonymous)
		0x80, 0x00, // simple authentication, no password
	}

	// Send bind request
	_, err = conn.Write(ldapBindRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to send LDAP bind request: %w", err)
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read LDAP response: %w", err)
	}

	if n < 7 {
		result.Evidence = fmt.Sprintf("Invalid LDAP response: too short (%d bytes)", n)
		return result, nil
	}

	// Check if it's a valid LDAP response (starts with SEQUENCE)
	if response[0] != 0x30 {
		result.Evidence = fmt.Sprintf("Non-LDAP service detected. Response: %x", response[:min(n, 20)])
		return result, nil
	}

	// Look for bind response and result code
	bindSuccess := false
	var resultCode int = -1
	
	// Simple parsing - look for bind response pattern
	for i := 0; i < n-10; i++ {
		if response[i] == 0x61 { // BindResponse
			// Look for result code (should be within next few bytes)
			for j := i; j < min(i+20, n-3); j++ {
				if response[j] == 0x0a && j+2 < n { // ENUMERATED (result code)
					resultCode = int(response[j+2])
					if resultCode == 0 { // success
						bindSuccess = true
					}
					break
				}
			}
			break
		}
	}

	if bindSuccess {
		// Anonymous bind successful - now try RootDSE query
		rootDSERequest := []byte{
			// LDAP Message
			0x30, 0x25, // SEQUENCE, length=37
			0x02, 0x01, 0x02, // messageID = 2
			// SearchRequest
			0x63, 0x20, // APPLICATION[3], length=32
			0x04, 0x00, // baseObject = "" (RootDSE)
			0x0a, 0x01, 0x00, // scope = baseObject (0)
			0x0a, 0x01, 0x00, // derefAliases = never (0)
			0x02, 0x01, 0x00, // sizeLimit = 0
			0x02, 0x01, 0x00, // timeLimit = 0
			0x01, 0x01, 0x00, // typesOnly = false
			// Filter: (objectClass=*)
			0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73,
			// Attributes
			0x30, 0x00, // empty attributes list (get all)
		}

		_, err = conn.Write(rootDSERequest)
		if err == nil {
			// Try to read RootDSE response
			rootDSEResponse := make([]byte, 2048)
			rn, err := conn.Read(rootDSEResponse)
			if err == nil && rn > 50 {
				// Look for naming contexts in the response
				responseStr := string(rootDSEResponse[:rn])
				containsNamingContext := strings.Contains(responseStr, "namingContexts") ||
					strings.Contains(responseStr, "defaultNamingContext") ||
					strings.Contains(responseStr, "rootDomainNamingContext")

				if containsNamingContext {
					result.IsVulnerable = true
					result.Evidence = fmt.Sprintf("LDAP anonymous bind successful with RootDSE information disclosure. "+
						"Response contains naming context information (%d bytes)", rn)
				} else {
					result.IsVulnerable = true
					result.Evidence = fmt.Sprintf("LDAP anonymous bind successful but limited information disclosure (%d bytes)", rn)
				}
			} else {
				result.IsVulnerable = true
				result.Evidence = "LDAP anonymous bind successful but failed to query RootDSE"
			}
		} else {
			result.IsVulnerable = true
			result.Evidence = "LDAP anonymous bind successful but failed to send RootDSE query"
		}
	} else {
		if resultCode >= 0 {
			result.Evidence = fmt.Sprintf("LDAP anonymous bind failed with result code: %d", resultCode)
		} else {
			result.Evidence = "LDAP anonymous bind failed - authentication required"
		}
	}

	// Extract service information
	serviceVersion := "Unknown"
	if port == 636 || port == 3269 {
		serviceVersion = "LDAPS (SSL/TLS)"
	} else {
		serviceVersion = "LDAP (Plain)"
	}

	result.ServiceName = "ldap"
	result.ServiceVersion = serviceVersion
	result.Banner = fmt.Sprintf("LDAP on port %d", port)

	return result, nil
}
