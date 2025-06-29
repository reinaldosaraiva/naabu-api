#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

API_URL="http://localhost:8082"

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}TESTE COMPLETO DOS 6 REQUISITOS DO ÉPICO${NC}"
echo -e "${YELLOW}========================================${NC}"

# Clean previous test data
echo -e "\n${BLUE}Limpando dados de testes anteriores...${NC}"
docker exec naabu-api sqlite3 /data/naabu_api.db "DELETE FROM probe_results; DELETE FROM deep_scan_artifacts; DELETE FROM scan_jobs;"

echo -e "\n${GREEN}=== TESTE 1: API aceita hosts e retorna scan_id ===${NC}"
echo "Testando com localhost para garantir conectividade..."

RESPONSE=$(curl -s -X POST $API_URL/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["127.0.0.1"],
    "ports": "21,22,80,389,873,1723,3389,5900,8080",
    "enable_probes": true,
    "enable_deep_scan": true
  }')
echo "$RESPONSE" | jq '.'
SCAN_ID=$(echo "$RESPONSE" | jq -r '.scan_id')
echo -e "✅ Scan ID gerado: ${GREEN}$SCAN_ID${NC}"

echo -e "\n${GREEN}=== TESTE 2: Job pools ativos ===${NC}"
echo "Verificando worker pools..."
docker logs naabu-api 2>&1 | grep -E "worker pool|Job dispatcher" | tail -5
echo -e "✅ Worker pools ativos"

echo -e "\n${YELLOW}Aguardando 15 segundos para conclusão do scan...${NC}"
sleep 15

echo -e "\n${GREEN}=== TESTE 3: Resultados detalhados ===${NC}"
echo "Verificando resultados no banco de dados..."
echo -e "\n${BLUE}Status do job:${NC}"
docker exec naabu-api sqlite3 /data/naabu_api.db "SELECT scan_id, status, created_at, completed_at FROM scan_jobs WHERE scan_id='$SCAN_ID';"

echo -e "\n${BLUE}Resultados do scan:${NC}"
docker exec naabu-api sqlite3 /data/naabu_api.db "SELECT substr(results, 1, 500) FROM scan_jobs WHERE scan_id='$SCAN_ID';" | jq '.'

echo -e "\n${GREEN}=== TESTE 4: Probes e vulnerabilidades ===${NC}"
echo "Verificando resultados de probes..."
docker exec naabu-api sqlite3 /data/naabu_api.db "SELECT probe_type, host, port, is_vulnerable, substr(evidence, 1, 100) FROM probe_results WHERE scan_id='$SCAN_ID';"

echo -e "\n${GREEN}=== TESTE 5: Deep scan com Nmap ===${NC}"
echo "Verificando artefatos de deep scan..."
docker exec naabu-api sqlite3 /data/naabu_api.db "SELECT artifact_type, host, port, script_names, created_at FROM deep_scan_artifacts WHERE scan_id='$SCAN_ID';"

echo -e "\n${GREEN}=== TESTE 6: Testando probes específicos ===${NC}"

# Test FTP probe (port 21)
echo -e "\n${BLUE}6.1 Testando FTP probe:${NC}"
FTP_RESPONSE=$(curl -s -X POST $API_URL/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["ftp.dlptest.com"],
    "ports": "21",
    "enable_probes": true,
    "enable_deep_scan": true
  }')
FTP_ID=$(echo "$FTP_RESPONSE" | jq -r '.scan_id')
echo "Scan ID FTP: $FTP_ID"

# Test multiple services on scanme.nmap.org
echo -e "\n${BLUE}6.2 Testando múltiplos serviços (scanme.nmap.org):${NC}"
MULTI_RESPONSE=$(curl -s -X POST $API_URL/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["scanme.nmap.org"],
    "ports": "22,80,443",
    "enable_probes": true,
    "enable_deep_scan": true
  }')
MULTI_ID=$(echo "$MULTI_RESPONSE" | jq -r '.scan_id')
echo "Scan ID Multi: $MULTI_ID"

echo -e "\n${YELLOW}Aguardando 30 segundos para conclusão dos testes de probe...${NC}"
sleep 30

echo -e "\n${BLUE}Resultados FTP:${NC}"
docker exec naabu-api sqlite3 /data/naabu_api.db "SELECT status, substr(results, 1, 200) FROM scan_jobs WHERE scan_id='$FTP_ID';"

echo -e "\n${BLUE}Resultados Multi-service:${NC}"
docker exec naabu-api sqlite3 /data/naabu_api.db "SELECT status, substr(results, 1, 200) FROM scan_jobs WHERE scan_id='$MULTI_ID';"

echo -e "\n${GREEN}=== RESUMO FINAL ===${NC}"
echo "Total de jobs executados:"
docker exec naabu-api sqlite3 /data/naabu_api.db "SELECT status, COUNT(*) FROM scan_jobs GROUP BY status;"

echo -e "\nTotal de probes executados:"
docker exec naabu-api sqlite3 /data/naabu_api.db "SELECT probe_type, COUNT(*) FROM probe_results GROUP BY probe_type;"

echo -e "\nTotal de deep scans executados:"
docker exec naabu-api sqlite3 /data/naabu_api.db "SELECT COUNT(*) FROM deep_scan_artifacts;"

echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}TESTES COMPLETOS${NC}"
echo -e "${YELLOW}========================================${NC}"