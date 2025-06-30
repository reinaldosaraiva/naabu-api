#!/bin/bash

# Exemplos de uso da API naabu

BASE_URL="http://localhost:8082"

echo "=== Exemplos de uso da API naabu ==="
echo

# 1. Health check
echo "1. Health Check:"
curl -X GET "${BASE_URL}/health" | jq '.'
echo
echo

# 2. Scan básico - localhost
echo "2. Scan básico do localhost:"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["127.0.0.1"],
    "ports": "22,80,443"
  }' | jq '.'
echo
echo

# 3. Scan com portas padrão
echo "3. Scan com portas padrão (sem especificar portas):"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["127.0.0.1"]
  }' | jq '.'
echo
echo

# 4. Scan de múltiplos IPs
echo "4. Scan de múltiplos IPs:"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["127.0.0.1", "8.8.8.8"],
    "ports": "53,80,443"
  }' | jq '.'
echo
echo

# 5. Scan com range de portas
echo "5. Scan com range de portas:"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["127.0.0.1"],
    "ports": "80-85,443"
  }' | jq '.'
echo
echo

# 6. Exemplo de erro - IP inválido
echo "6. Exemplo de erro - IP inválido:"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["invalid-ip"],
    "ports": "80"
  }' | jq '.'
echo
echo

# 7. Exemplo de erro - sem IPs
echo "7. Exemplo de erro - sem IPs:"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": [],
    "ports": "80"
  }' | jq '.'
echo
echo

# 8. Exemplo de erro - método inválido
echo "8. Exemplo de erro - método inválido:"
curl -X GET "${BASE_URL}/scan" | jq '.'
echo
echo

# 9. Scan com probes habilitados
echo "9. Scan com probes habilitados (detecção de vulnerabilidades):"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["scanme.nmap.org"],
    "ports": "21,22,80,389,443,873,1723,3389,5900",
    "enable_probes": true
  }' | jq '.'
echo
echo

# 10. Scan com deep scan habilitado
echo "10. Scan completo com probes e deep scan:"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["testphp.vulnweb.com"],
    "ports": "21,22,80,443",
    "enable_probes": true,
    "enable_deep_scan": true
  }' | jq '.'
echo
echo

# 11. Scan de rede CIDR
echo "11. Scan de rede CIDR:"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.0/30"],
    "ports": "22,80,443"
  }' | jq '.'
echo
echo

# 12. Listar jobs ativos
echo "12. Listar todos os jobs:"
curl -X GET "${BASE_URL}/api/v1/jobs" | jq '.'
echo
echo

# 13. Verificar métricas
echo "13. Verificar métricas do sistema:"
curl -X GET "${BASE_URL}/metrics" | jq '.'
echo
echo

# 14. Testando probes específicos
echo "=== Testando Probes Específicos ==="
echo

# 14.1 FTP Probe
echo "14.1. Teste do FTP Probe (porta 21):"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["ftp.debian.org"],
    "ports": "21",
    "enable_probes": true
  }' | jq '.'
echo
echo

# 14.2 VNC Probe
echo "14.2. Teste do VNC Probe (porta 5900):"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.100"],
    "ports": "5900-5910",
    "enable_probes": true
  }' | jq '.'
echo
echo

# 14.3 RDP Probe
echo "14.3. Teste do RDP Probe (porta 3389):"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.10"],
    "ports": "3389",
    "enable_probes": true
  }' | jq '.'
echo
echo

# 14.4 LDAP Probe
echo "14.4. Teste do LDAP Probe (porta 389):"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["ldap.forumsys.com"],
    "ports": "389",
    "enable_probes": true
  }' | jq '.'
echo
echo

# 14.5 PPTP Probe
echo "14.5. Teste do PPTP Probe (porta 1723):"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.1"],
    "ports": "1723",
    "enable_probes": true
  }' | jq '.'
echo
echo

# 14.6 rsync Probe
echo "14.6. Teste do rsync Probe (porta 873):"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["rsync.samba.org"],
    "ports": "873",
    "enable_probes": true
  }' | jq '.'
echo
echo

# 14.7 SSH Weak Cipher Probe
echo "14.7. Teste do SSH Weak Cipher Probe (porta 22):"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["github.com"],
    "ports": "22",
    "enable_probes": true
  }' | jq '.'
echo
echo

# 14.8 SSH Weak MAC Probe
echo "14.8. Teste do SSH Weak MAC Probe (porta 22):"
curl -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["gitlab.com"],
    "ports": "22",
    "enable_probes": true
  }' | jq '.'
echo
echo

# 15. Network Security Endpoint
echo "=== Testando Network Security Endpoint ==="
echo

# 15.1 Criar scan para testar network security
echo "15.1. Criar scan completo para network security:"
SCAN_ID=$(curl -s -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.1", "scanme.nmap.org"],
    "ports": "21,22,389,873,1723,3389,5900",
    "enable_probes": true
  }' | jq -r '.scan_id')

echo "Scan ID criado: $SCAN_ID"
echo "Aguardando 30 segundos para processamento..."
sleep 30
echo
echo

# 15.2 Obter status de network security
echo "15.2. Obter status consolidado de network security:"
curl -X GET "${BASE_URL}/api/v1/scans/${SCAN_ID}/network" | jq '.'
echo
echo

# 15.3 Teste com scan_id inválido
echo "15.3. Teste com scan_id inválido:"
curl -X GET "${BASE_URL}/api/v1/scans/invalid-uuid/network" | jq '.'
echo
echo

# 15.4 Teste com scan_id não existente
echo "15.4. Teste com scan_id não existente:"
curl -X GET "${BASE_URL}/api/v1/scans/550e8400-e29b-41d4-a716-446655440000/network" | jq '.'
echo
echo

# 16. Exemplo completo de workflow
echo "=== Exemplo Completo de Workflow ==="
echo

echo "16.1. Criando scan de auditoria de segurança:"
AUDIT_SCAN_ID=$(curl -s -X POST "${BASE_URL}/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.0/24"],
    "ports": "21,22,389,873,1723,3389,5900",
    "enable_probes": true,
    "enable_deep_scan": true
  }' | jq -r '.scan_id')

echo "Scan de auditoria criado: $AUDIT_SCAN_ID"
echo

echo "16.2. Verificando status do job:"
curl -X GET "${BASE_URL}/api/v1/jobs/${AUDIT_SCAN_ID}" | jq '.status'
echo

echo "16.3. Aguardando processamento (simulado)..."
echo "Em produção, você pode fazer polling do status até completion"
echo

echo "16.4. Obtendo relatório de network security:"
echo "curl -X GET \"${BASE_URL}/api/v1/scans/${AUDIT_SCAN_ID}/network\" | jq '.'"
echo

echo "=== Fim dos exemplos ==="
echo
echo "Para mais informações, consulte a documentação Swagger em:"
echo "${BASE_URL}/docs/"
echo