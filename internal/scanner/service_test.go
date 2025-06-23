package scanner

import (
	"context"
	"testing"

	"naabu-api/internal/models"

	"github.com/sirupsen/logrus/hooks/test"
)

func TestService_validateIPs(t *testing.T) {
	logger, _ := test.NewNullLogger()
	service := NewService(logger)
	
	tests := []struct {
		name      string
		ips       []string
		wantError bool
		wantCount int
	}{
		{
			name:      "IPs válidos",
			ips:       []string{"192.168.1.1", "10.0.0.1"},
			wantError: false,
			wantCount: 2,
		},
		{
			name:      "Lista vazia",
			ips:       []string{},
			wantError: true,
			wantCount: 0,
		},
		{
			name:      "IP inválido",
			ips:       []string{"invalid-ip"},
			wantError: true,
			wantCount: 0,
		},
		{
			name:      "Mistura de IPs válidos e inválidos",
			ips:       []string{"192.168.1.1", "invalid-ip"},
			wantError: true,
			wantCount: 0,
		},
		{
			name:      "IPs com espaços",
			ips:       []string{" 192.168.1.1 ", "  10.0.0.1"},
			wantError: false,
			wantCount: 2,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.validateIPs(tt.ips)
			
			if tt.wantError && err == nil {
				t.Errorf("esperava erro, mas não ocorreu")
			}
			
			if !tt.wantError && err != nil {
				t.Errorf("não esperava erro, mas ocorreu: %v", err)
			}
			
			if len(result) != tt.wantCount {
				t.Errorf("esperava %d IPs, mas obteve %d", tt.wantCount, len(result))
			}
		})
	}
}

func TestService_preparePorts(t *testing.T) {
	logger, _ := test.NewNullLogger()
	service := NewService(logger)
	
	tests := []struct {
		name      string
		portStr   string
		wantPorts []int
	}{
		{
			name:      "String vazia - usa portas padrão",
			portStr:   "",
			wantPorts: []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080},
		},
		{
			name:      "Portas individuais",
			portStr:   "80,443,22",
			wantPorts: []int{80, 443, 22},
		},
		{
			name:      "Range de portas",
			portStr:   "80-83",
			wantPorts: []int{80, 81, 82, 83},
		},
		{
			name:      "Mistura de portas e ranges",
			portStr:   "22,80-82,443",
			wantPorts: []int{22, 80, 81, 82, 443},
		},
		{
			name:      "Portas com espaços",
			portStr:   " 80 , 443 , 22 ",
			wantPorts: []int{80, 443, 22},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.preparePorts(tt.portStr)
			
			if len(result) != len(tt.wantPorts) {
				t.Errorf("esperava %d portas, mas obteve %d", len(tt.wantPorts), len(result))
				return
			}
			
			for i, port := range result {
				if port != tt.wantPorts[i] {
					t.Errorf("esperava porta %d na posição %d, mas obteve %d", tt.wantPorts[i], i, port)
				}
			}
		})
	}
}

func TestService_ScanPorts_Validation(t *testing.T) {
	logger, _ := test.NewNullLogger()
	service := NewService(logger)
	
	tests := []struct {
		name      string
		req       models.ScanRequest
		wantError bool
	}{
		{
			name: "Requisição válida",
			req: models.ScanRequest{
				IPs:   []string{"127.0.0.1"},
				Ports: "80,443",
			},
			wantError: false,
		},
		{
			name: "IPs vazios",
			req: models.ScanRequest{
				IPs:   []string{},
				Ports: "80",
			},
			wantError: true,
		},
		{
			name: "IP inválido",
			req: models.ScanRequest{
				IPs:   []string{"invalid-ip"},
				Ports: "80",
			},
			wantError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.ScanPorts(context.Background(), tt.req)
			
			if tt.wantError && err == nil {
				t.Errorf("esperava erro, mas não ocorreu")
			}
			
			if !tt.wantError && err != nil {
				t.Errorf("não esperava erro, mas ocorreu: %v", err)
			}
		})
	}
}