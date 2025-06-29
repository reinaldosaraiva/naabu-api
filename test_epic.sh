#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

API_URL="http://localhost:8082"

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}TESTE DOS 6 REQUISITOS DO ÉPICO${NC}"
echo -e "${YELLOW}========================================${NC}"

echo -e "\n${GREEN}Teste 1: API aceita hosts e retorna scan_id com status running${NC}"
echo "Testando com IP, hostname e CIDR..."

# Test 1.1: IP address
echo -e "\n1.1 Testando com IP (201.23.19.144):"
RESPONSE=$(curl -s -X POST $API_URL/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["201.23.19.144"],
    "ports": "21,22,80,443,3389,5900",
    "enable_probes": true,
    "enable_deep_scan": true
  }')
echo "$RESPONSE" | jq '.'
SCAN_ID_IP=$(echo "$RESPONSE" | jq -r '.scan_id')

# Test 1.2: Hostname
echo -e "\n1.2 Testando com hostname (api3.riskrate.com.br):"
RESPONSE=$(curl -s -X POST $API_URL/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["api3.riskrate.com.br"],
    "ports": "21,389,636,873,1723",
    "enable_probes": true,
    "enable_deep_scan": true
  }')
echo "$RESPONSE" | jq '.'
SCAN_ID_HOST=$(echo "$RESPONSE" | jq -r '.scan_id')

# Test 1.3: CIDR
echo -e "\n1.3 Testando com CIDR (192.168.1.0/30):"
RESPONSE=$(curl -s -X POST $API_URL/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.0/30"],
    "ports": "22,80",
    "enable_probes": true,
    "enable_deep_scan": true
  }')
echo "$RESPONSE" | jq '.'
SCAN_ID_CIDR=$(echo "$RESPONSE" | jq -r '.scan_id')

# Test 1.4: Multiple types
echo -e "\n1.4 Testando com múltiplos tipos (IP + hostname):"
RESPONSE=$(curl -s -X POST $API_URL/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["8.8.8.8", "google.com"],
    "ports": "53,443",
    "enable_probes": true,
    "enable_deep_scan": true
  }')
echo "$RESPONSE" | jq '.'
SCAN_ID_MULTI=$(echo "$RESPONSE" | jq -r '.scan_id')

echo -e "\n${YELLOW}Aguardando 5 segundos para verificar status...${NC}"
sleep 5

echo -e "\n${GREEN}Teste 2: Verificar job pools ativos e sistema funcionando${NC}"

# Check scan status
echo -e "\n2.1 Verificando status do scan IP:"
curl -s $API_URL/scan/$SCAN_ID_IP | jq '.'

echo -e "\n2.2 Verificando logs do container para pools ativos:"
docker logs naabu-api 2>&1 | grep -E "(worker pool|Job dispatcher|Executing)" | tail -10

echo -e "\n${GREEN}Teste 3: Resultados detalhados (aguardando conclusão dos scans)${NC}"
echo "Aguardando 30 segundos para conclusão dos scans..."
sleep 30

echo -e "\n3.1 Verificando resultados do scan IP:"
curl -s $API_URL/scan/$SCAN_ID_IP | jq '.'

echo -e "\n3.2 Verificando métricas do sistema:"
curl -s $API_URL/metrics | jq '.'

echo -e "\n${GREEN}Preparando ambiente local para testes de probes...${NC}"

# Create test files for epic testing
cat > test_probe_targets.json << 'EOF'
{
  "ftp_test": {
    "ip": "ftp.dlptest.com",
    "port": 21,
    "expected": "anonymous FTP"
  },
  "vnc_test": {
    "ip": "localhost", 
    "port": 5900,
    "expected": "VNC without auth"
  },
  "rdp_test": {
    "ip": "localhost",
    "port": 3389,
    "expected": "RDP weak encryption"
  },
  "ldap_test": {
    "ip": "ldap.forumsys.com",
    "port": 389,
    "expected": "anonymous bind"
  },
  "pptp_test": {
    "ip": "localhost",
    "port": 1723,
    "expected": "PPTP legacy VPN"
  },
  "rsync_test": {
    "ip": "rsync.cyberciti.biz",
    "port": 873,
    "expected": "accessible modules"
  }
}
EOF

echo -e "\n${YELLOW}Testes preparados. Execute os próximos testes manualmente ou continue o script.${NC}"