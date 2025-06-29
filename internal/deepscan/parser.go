package deepscan

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// NmapRun represents the root element of Nmap XML output
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Scanner string   `xml:"scanner,attr"`
	Args    string   `xml:"args,attr"`
	Start   string   `xml:"start,attr"`
	Version string   `xml:"version,attr"`
	Hosts   []Host   `xml:"host"`
}

// Host represents a scanned host
type Host struct {
	Status   Status   `xml:"status"`
	Address  Address  `xml:"address"`
	Hostnames []Hostname `xml:"hostnames>hostname"`
	Ports    Ports    `xml:"ports"`
	Scripts  []Script `xml:"hostscript>script"`
}

// Status represents host status
type Status struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// Address represents host address
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

// Hostname represents host name
type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// Ports represents port scan results
type Ports struct {
	Ports []Port `xml:"port"`
}

// Port represents a single port
type Port struct {
	Protocol string    `xml:"protocol,attr"`
	PortID   int       `xml:"portid,attr"`
	State    PortState `xml:"state"`
	Service  Service   `xml:"service"`
	Scripts  []Script  `xml:"script"`
}

// PortState represents port state information
type PortState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// Service represents service detection information
type Service struct {
	Name       string `xml:"name,attr"`
	Product    string `xml:"product,attr"`
	Version    string `xml:"version,attr"`
	ExtraInfo  string `xml:"extrainfo,attr"`
	Method     string `xml:"method,attr"`
	Conf       string `xml:"conf,attr"`
	CPEs       []CPE  `xml:"cpe"`
}

// CPE represents Common Platform Enumeration
type CPE struct {
	Value string `xml:",chardata"`
}

// Script represents NSE script output
type Script struct {
	ID     string   `xml:"id,attr"`
	Output string   `xml:"output,attr"`
	Tables []Table  `xml:"table"`
	Elems  []Element `xml:"elem"`
}

// Table represents script table output
type Table struct {
	Key   string    `xml:"key,attr"`
	Elems []Element `xml:"elem"`
	Tables []Table   `xml:"table"`
}

// Element represents script element output
type Element struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// XMLParser parses Nmap XML output
type XMLParser struct{}

// NewXMLParser creates a new XML parser
func NewXMLParser() *XMLParser {
	return &XMLParser{}
}

// ParseNmapXML parses Nmap XML output and returns structured data
func (p *XMLParser) ParseNmapXML(xmlData string) (*NmapRun, error) {
	var nmapRun NmapRun
	
	if err := xml.Unmarshal([]byte(xmlData), &nmapRun); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	
	return &nmapRun, nil
}

// ExtractVulnerabilities extracts vulnerability information from parsed XML
func (p *XMLParser) ExtractVulnerabilities(nmapRun *NmapRun) []VulnerabilityFinding {
	var findings []VulnerabilityFinding
	
	for _, host := range nmapRun.Hosts {
		if host.Status.State != "up" {
			continue
		}
		
		hostIP := host.Address.Addr
		
		// Check host-level scripts for vulnerabilities
		for _, script := range host.Scripts {
			if vulnInfo := p.analyzeScript(script); vulnInfo != nil {
				finding := VulnerabilityFinding{
					IP:          hostIP,
					Port:        0, // Host-level finding
					Protocol:    "",
					ServiceName: "",
					ScriptID:    script.ID,
					Severity:    vulnInfo.Severity,
					Title:       vulnInfo.Title,
					Description: vulnInfo.Description,
					Evidence:    script.Output,
				}
				findings = append(findings, finding)
			}
		}
		
		// Check port-level scripts for vulnerabilities
		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}
			
			for _, script := range port.Scripts {
				if vulnInfo := p.analyzeScript(script); vulnInfo != nil {
					finding := VulnerabilityFinding{
						IP:          hostIP,
						Port:        port.PortID,
						Protocol:    port.Protocol,
						ServiceName: port.Service.Name,
						ScriptID:    script.ID,
						Severity:    vulnInfo.Severity,
						Title:       vulnInfo.Title,
						Description: vulnInfo.Description,
						Evidence:    script.Output,
					}
					findings = append(findings, finding)
				}
			}
		}
	}
	
	return findings
}

// VulnerabilityFinding represents a vulnerability found during deep scan
type VulnerabilityFinding struct {
	IP          string
	Port        int
	Protocol    string
	ServiceName string
	ScriptID    string
	Severity    string
	Title       string
	Description string
	Evidence    string
}

// VulnerabilityInfo contains vulnerability metadata
type VulnerabilityInfo struct {
	Severity    string
	Title       string
	Description string
}

// analyzeScript analyzes a script output to determine if it indicates a vulnerability
func (p *XMLParser) analyzeScript(script Script) *VulnerabilityInfo {
	scriptID := strings.ToLower(script.ID)
	output := strings.ToLower(script.Output)
	
	// Define vulnerability patterns for each script
	switch {
	case strings.Contains(scriptID, "ftp-anon"):
		if strings.Contains(output, "anonymous ftp login allowed") {
			return &VulnerabilityInfo{
				Severity:    "Medium",
				Title:       "Anonymous FTP Access",
				Description: "FTP server allows anonymous access",
			}
		}
		
	case strings.Contains(scriptID, "vnc-info"):
		if strings.Contains(output, "security types") && strings.Contains(output, "none") {
			return &VulnerabilityInfo{
				Severity:    "High",
				Title:       "VNC Without Authentication",
				Description: "VNC server allows connections without authentication",
			}
		}
		
	case strings.Contains(scriptID, "rdp-enum-encryption"):
		if strings.Contains(output, "rdp encryption level: low") ||
		   strings.Contains(output, "rdp encryption level: medium") {
			return &VulnerabilityInfo{
				Severity:    "Medium",
				Title:       "RDP Weak Encryption",
				Description: "RDP server uses weak encryption",
			}
		}
		
	case strings.Contains(scriptID, "ldap-rootdse"):
		if strings.Contains(output, "namingcontexts") ||
		   strings.Contains(output, "defaultnamingcontext") {
			return &VulnerabilityInfo{
				Severity:    "Low",
				Title:       "LDAP Information Disclosure",
				Description: "LDAP server discloses directory information",
			}
		}
		
	case strings.Contains(scriptID, "rsync-list-modules"):
		if strings.Contains(output, "modules available") {
			return &VulnerabilityInfo{
				Severity:    "Medium",
				Title:       "Rsync Modules Exposed",
				Description: "Rsync server exposes accessible modules",
			}
		}
		
	case strings.Contains(scriptID, "vuln"):
		// Generic vulnerability scripts
		if strings.Contains(output, "vulnerable") ||
		   strings.Contains(output, "exploitable") {
			return &VulnerabilityInfo{
				Severity:    "High",
				Title:       fmt.Sprintf("Vulnerability: %s", script.ID),
				Description: "Potential vulnerability detected",
			}
		}
	}
	
	return nil
}

// GetServiceInfo extracts service information from parsed XML
func (p *XMLParser) GetServiceInfo(nmapRun *NmapRun) map[string]ServiceDetails {
	services := make(map[string]ServiceDetails)
	
	for _, host := range nmapRun.Hosts {
		if host.Status.State != "up" {
			continue
		}
		
		hostIP := host.Address.Addr
		
		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}
			
			key := fmt.Sprintf("%s:%d", hostIP, port.PortID)
			service := ServiceDetails{
				IP:        hostIP,
				Port:      port.PortID,
				Protocol:  port.Protocol,
				State:     port.State.State,
				Service:   port.Service.Name,
				Product:   port.Service.Product,
				Version:   port.Service.Version,
				ExtraInfo: port.Service.ExtraInfo,
			}
			
			// Add CPE information
			for _, cpe := range port.Service.CPEs {
				service.CPEs = append(service.CPEs, cpe.Value)
			}
			
			services[key] = service
		}
	}
	
	return services
}

// ServiceDetails contains detailed service information
type ServiceDetails struct {
	IP        string
	Port      int
	Protocol  string
	State     string
	Service   string
	Product   string
	Version   string
	ExtraInfo string
	CPEs      []string
}
