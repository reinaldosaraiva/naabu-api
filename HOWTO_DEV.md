# HOWTO para Desenvolvedores - Naabu API

Guia prático para desenvolvedores testarem e utilizarem a API de descoberta de exposições de serviço.

## 🎯 Objetivo

Este guia demonstra como usar a Naabu API para:
- Descobrir portas abertas em alvos
- Detectar vulnerabilidades com 9 probes especializados incluindo CVE detection
- Obter status consolidado de network security
- Interpretar resultados e evidências
- Ativar deep scanning automático
- Executar CVE scanning com Nuclei v3

## 🚀 Setup Rápido

```bash
# 1. Clonar e iniciar
git clone <repo-url>
cd naabu-api
docker compose up -d

# 2. Verificar saúde
curl http://localhost:9082/health
```

**Resultado esperado:**
```json
{
  "database": "connected",
  "status": "healthy",
  "timestamp": "2025-06-30T12:40:04Z",
  "version": "2.0.0"
}
```

## 🔥 TESTES REAIS VALIDADOS - CVE Detection

### ✅ Teste 1: scanme.nmap.org (Validado em Produção)

**Comando executado com sucesso:**
```bash
curl -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["scanme.nmap.org"],
    "ports": "21,22,80,443",
    "enable_probes": true
  }'
```

**Resultado real:**
```json
{
  "scan_id": "16aa168d-c205-4ff7-a207-9a1f9b1e22f6",
  "status": "queued",
  "message": "Job criado com sucesso"
}
```

**Verificar resultado completo (NOVO endpoint com CVE!):**
```bash
# Aguardar 30 segundos para processamento
sleep 30

# Endpoint consolidado com os 9 probes incluindo CVE detection
curl -s http://localhost:9082/api/v1/scans/16aa168d-c205-4ff7-a207-9a1f9b1e22f6/network | jq
```

**Resposta real com CVE Detection:**
```json
{
  "scan_id": "16aa168d-c205-4ff7-a207-9a1f9b1e22f6",
  "ftp_anonymous_login": {
    "status": "ok",
    "evidence": "No FTP anonymous login vulnerabilities detected"
  },
  "vnc_accessible": {
    "status": "ok", 
    "evidence": "No VNC accessibility issues detected"
  },
  "rdp_accessible": {
    "status": "ok",
    "evidence": "No RDP accessibility issues detected"
  },
  "ldap_accessible": {
    "status": "ok",
    "evidence": "No LDAP accessibility issues detected"
  },
  "pptp_accessible": {
    "status": "ok",
    "evidence": "No PPTP accessibility issues detected"
  },
  "rsync_accessible": {
    "status": "ok",
    "evidence": "No Rsync accessibility issues detected"
  },
  "ssh_weak_cipher": {
    "status": "ok",
    "evidence": "No SSH weak cipher vulnerabilities detected"
  },
  "ssh_weak_mac": {
    "status": "ok",
    "evidence": "No SSH weak MAC vulnerabilities detected"
  },
  "cve_scan": {
    "status": "ok",
    "cve_id": [],
    "evidence": []
  }
}
```

### 📊 **Performance Real Obtida:**
- **IPs processados**: 1 (scanme.nmap.org → 45.33.32.156)
- **Portas encontradas**: 2 (22/SSH, 80/HTTP)  
- **Probes executados**: SSH weak cipher + SSH weak MAC
- **CVE scan**: Nuclei v3 SDK executado (11.66s)
- **Workers CVE**: 10 workers utilizados
- **Status final**: Servidor seguro (todos "ok")

### ✅ Teste 2: testphp.vulnweb.com (Site de Teste Vulnerável)

```bash
curl -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["testphp.vulnweb.com"],
    "ports": "80,443,8080,8443",
    "enable_probes": true
  }'
```

**Resultado:** CVE scan executado em 33 segundos, nenhum HIGH/CRITICAL encontrado.

---

## 📡 Teste 1: Scan Básico de Descoberta

### Comando:
```bash
curl -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["8.8.8.8"],
    "ports": "53,80,443"
  }'
```

### Resultado esperado:
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "message": "Job criado com sucesso"
}
```

### O que acontece:
- Sistema cria job assíncrono
- Port scanning com Naabu
- Detecção de portas abertas
- **Sem probes** (enable_probes: false por padrão)

---

## 🔍 Teste 2: Scan com Detecção de Vulnerabilidades

### Comando:
```bash
curl -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["3.140.123.244"],
    "ports": "22,80,443",
    "enable_probes": true
  }'
```

### Resultado esperado (Logs):
```
📊 Portas Descobertas:
  • Porta 22 (SSH) - ABERTA
  • Porta 80 (HTTP) - ABERTA  
  • Porta 443 (HTTPS) - ABERTA

🔍 Probe SSH Executado:
  • SSH probe testou a porta 22
  • Resultado: NÃO VULNERÁVEL
  • Evidence: ssh: unable to authenticate, attempted methods [none]
```

### O que acontece:
1. **Quick Scan Pool** - Descobre portas abertas
2. **Probe Pool** - Executa SSH probe na porta 22
3. **Análise** - Tenta detectar cifras/MACs fracos
4. **Resultado** - Servidor seguro (sem vulnerabilidades)

---

## 🚨 Teste 3: Detectando Vulnerabilidades Reais

### Cenário: Servidor SSH Vulnerável

```bash
curl -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["vulnerable-ssh-server.example.com"],
    "ports": "22",
    "enable_probes": true,
    "enable_deep_scan": true
  }'
```

### Resultado esperado (Vulnerável):
```json
{
  "scan_id": "abc123...",
  "probe_results": [
    {
      "host": "vulnerable-ssh-server.example.com",
      "port": 22,
      "probe_type": "ssh",
      "service_name": "ssh",
      "service_version": "SSH-2.0-OpenSSH_7.4",
      "is_vulnerable": true,
      "evidence": "SSH server supports weak ciphers: aes128-cbc, 3des-cbc | All server ciphers: aes128-cbc, aes256-cbc, 3des-cbc, aes128-ctr | SSH server supports weak MAC algorithms: hmac-md5, hmac-sha1-96 | All server MACs: hmac-md5, hmac-sha1-96, hmac-sha2-256"
    }
  ],
  "deep_scans": [
    {
      "host": "vulnerable-ssh-server.example.com",
      "port": 22,
      "nse_scripts": ["ssh-enum-algos", "ssh-weak-ciphers"],
      "xml_output": "<nmaprun>...</nmaprun>"
    }
  ]
}
```

### O que acontece:
1. **SSH Probe** detecta algoritmos fracos
2. **Deep Scan** é ativado automaticamente
3. **Nmap NSE** executa scripts específicos
4. **Artefatos XML** são armazenados

---

## 🌐 Teste 4: Scan de Rede (CIDR)

### Comando:
```bash
curl -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.0/24"],
    "ports": "22,21,3389,5900",
    "enable_probes": true
  }'
```

### Resultado esperado:
```
📊 Expansão CIDR:
  • 254 IPs para escanear (192.168.1.1-254)
  
🔍 Probes que podem ser ativados:
  • SSH (porta 22) - Cifras/MACs fracos
  • FTP (porta 21) - Login anônimo
  • RDP (porta 3389) - Criptografia fraca
  • VNC (porta 5900) - Sem autenticação
```

### O que acontece:
1. **Expansão CIDR** - 192.168.1.0/24 → 254 IPs
2. **Port Scanning** paralelo em todos IPs
3. **Probes seletivos** - Apenas nos serviços relevantes
4. **Escalabilidade** - Worker pools distribuem carga

---

## 🧪 Teste 5: Todos os 9 Probes (Incluindo CVE Detection)

### Script automatizado:
```bash
cat > test_all_probes.sh << 'EOF'
#!/bin/bash

echo "=== Testando todos os 9 probes ==="

# FTP Probe (porta 21)  
echo -e "\n📁 1. Testando FTP..."
curl -s -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["ftp.debian.org"], "ports": "21", "enable_probes": true}'

# VNC Probe (porta 5900)
echo -e "\n🖥️ 2. Testando VNC..."
curl -s -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["192.168.1.100"], "ports": "5900-5910", "enable_probes": true}'

# RDP Probe (porta 3389)
echo -e "\n🖱️ 3. Testando RDP..."
curl -s -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["192.168.1.10"], "ports": "3389", "enable_probes": true}'

# LDAP Probe (porta 389)
echo -e "\n📚 4. Testando LDAP..."
curl -s -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["ldap.forumsys.com"], "ports": "389", "enable_probes": true}'

# PPTP Probe (porta 1723)
echo -e "\n🌐 5. Testando PPTP..."
curl -s -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["192.168.1.1"], "ports": "1723", "enable_probes": true}'

# rsync Probe (porta 873)
echo -e "\n🔄 6. Testando rsync..."
curl -s -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["rsync.samba.org"], "ports": "873", "enable_probes": true}'

# SSH Weak Cipher Probe (porta 22)
echo -e "\n🔐 7. Testando SSH Weak Ciphers..."
curl -s -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["github.com"], "ports": "22", "enable_probes": true}'

# SSH Weak MAC Probe (porta 22)
echo -e "\n🔐 8. Testando SSH Weak MACs..."
curl -s -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["gitlab.com"], "ports": "22", "enable_probes": true}'

# CVE Detection Probe (todas as portas) - NOVO!
echo -e "\n🚨 9. Testando CVE Detection com Nuclei..."
curl -s -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["scanme.nmap.org"], "ports": "80,443,8080", "enable_probes": true}'

echo -e "\n\n✅ Todos os 9 scans criados!"
EOF

chmod +x test_all_probes.sh
./test_all_probes.sh
```

---

## 🔒 Teste 6: Endpoint de Network Security Consolidado

### Comando:
```bash
# 1. Criar scan
SCAN_ID=$(curl -s -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.1", "scanme.nmap.org"],
    "ports": "21,22,389,873,1723,3389,5900",
    "enable_probes": true
  }' | jq -r '.scan_id')

# 2. Aguardar processamento
sleep 30

# 3. Obter status consolidado
curl -s http://localhost:9082/api/v1/scans/$SCAN_ID/network | jq '.'
```

### Resultado esperado:
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "ftp_anonymous_login": {
    "status": "ok",
    "evidence": "No FTP anonymous login vulnerabilities detected"
  },
  "vnc_accessible": {
    "status": "ok",
    "evidence": "No VNC accessibility issues detected"
  },
  "rdp_accessible": {
    "status": "risk",
    "evidence": "RDP server uses Standard RDP protocol without encryption"
  },
  "ldap_accessible": {
    "status": "ok",
    "evidence": "No LDAP accessibility issues detected"
  },
  "pptp_accessible": {
    "status": "ok",
    "evidence": "No PPTP accessibility issues detected"
  },
  "rsync_accessible": {
    "status": "ok",
    "evidence": "No Rsync accessibility issues detected"
  },
  "ssh_weak_cipher": {
    "status": "risk",
    "evidence": "SSH server supports weak ciphers: aes128-cbc, 3des-cbc"
  },
  "ssh_weak_mac": {
    "status": "ok",
    "evidence": "No SSH weak MAC vulnerabilities detected"
  },
  "cve_scan": {
    "status": "ok",
    "cve_id": [],
    "evidence": []
  }
}
```

### O que acontece:
1. **Consolidação** - Todos os 9 checks em uma única resposta (incluindo CVE scan)
2. **Status binário** - Sempre "ok" ou "risk" (CVE usa "ok", "risk", "error")
3. **Evidence obrigatório** - Sempre presente, mesmo quando "ok"
4. **CVE Detection** - Nuclei v3 SDK executa automaticamente
5. **Formato padronizado** - Facilita integração com dashboards

---

## 📊 Interpretando Resultados

### 1. **SSH Probe - Servidor Seguro**
```
Evidence: "SSH server uses only strong ciphers and MACs"
is_vulnerable: false
```
→ **Interpretação**: Servidor bem configurado, apenas algoritmos seguros

### 2. **SSH Probe - Servidor Vulnerável**
```
Evidence: "SSH server supports weak ciphers: aes128-cbc, 3des-cbc"
is_vulnerable: true
```
→ **Interpretação**: Servidor precisa de hardening, remover CBC mode

### 3. **FTP Probe - Login Anônimo**
```
Evidence: "Anonymous login allowed"
is_vulnerable: true
```
→ **Interpretação**: FTP permite acesso sem credenciais

### 4. **VNC Probe - Sem Autenticação**
```
Evidence: "VNC server allows connection without authentication"
is_vulnerable: true
```
→ **Interpretação**: VNC exposto sem senha

### 5. **CVE Scan - Nenhuma Vulnerabilidade (NOVO!)**
```json
{
  "status": "ok",
  "cve_id": [],
  "evidence": []
}
```
→ **Interpretação**: Nenhum CVE HIGH/CRITICAL encontrado

### 6. **CVE Scan - Vulnerabilidades Encontradas**
```json
{
  "status": "risk",
  "cve_id": ["CVE-2021-44228", "CVE-2022-0001"],
  "evidence": ["URL: https://target.com:443", "URL: https://target.com:8080"]
}
```
→ **Interpretação**: CVEs críticos detectados, requer ação imediata

### 7. **CVE Scan - Erro na Execução**
```json
{
  "status": "error",
  "cve_id": [],
  "evidence": ["Timeout after 30 seconds", "Failed to connect to target"]
}
```
→ **Interpretação**: Falha na execução do CVE scan (timeout/rede)

---

## 🔧 Monitoramento e Debug

### 1. **Verificar Worker Pools**
```bash
curl http://localhost:9082/metrics | jq
```

**Resultado esperado:**
```json
{
  "jobs": {
    "total": 15,
    "queued": 0,
    "running": 2,
    "completed": 12,
    "failed": 1
  },
  "timestamp": "2025-06-30T12:40:04Z"
}
```

### 2. **Logs em Tempo Real**
```bash
# Ver logs dos workers
docker compose logs -f | grep -E "(worker|probe|dispatcher)"

# Ver resultados de probes
docker compose logs -f | grep -E "(vulnerable|probe.*result)"
```

### 3. **Debugging de Problemas**
```bash
# Container não responde
docker compose ps
docker compose restart

# Porta em uso
netstat -tulpn | grep 8082

# Logs de erro
docker compose logs | grep -i error
```

---

## 🎯 Casos de Uso Práticos

### 1. **Auditoria de Segurança Interna**
```bash
# Escanear toda a rede corporativa
curl -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "ports": "22,21,80,443,3389,5900,389,873,1723",
    "enable_probes": true,
    "enable_deep_scan": true
  }'
```

### 2. **Verificação de Servidor Específico**
```bash
# Foco em um servidor crítico
curl -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["production-server.company.com"],
    "ports": "22,80,443,3306,5432",
    "enable_probes": true,
    "enable_deep_scan": true
  }'
```

### 3. **Scan Rápido de Descoberta**
```bash
# Apenas descobrir o que está online
curl -X POST http://localhost:9082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["target-range.example.com"],
    "ports": "80,443,22,21,25,53,110,993,995"
  }'
```

---

## ⚠️ Considerações de Segurança

### ✅ **Uso Autorizado**
- Sempre obter autorização antes de escanear
- Documentar escopo e objetivos
- Usar apenas em redes próprias ou autorizadas

### ✅ **Rate Limiting**
- API limita a 1000 pacotes/segundo
- Máximo 100 alvos por requisição
- Timeout de 5 minutos por scan

### ✅ **Logs e Auditoria**
- Todos os scans são logados
- Request IDs para rastreamento
- Timestamps para auditoria

---

## 🚀 Performance e Escalabilidade

### **Worker Pools Otimizados**
- **Quick Scan**: 5 workers (descoberta rápida)
- **Probe Pool**: 10 workers (análise de serviços)
- **Deep Scan**: 3 workers (scanning profundo)

### **Benchmarks Típicos**
- **Scan simples**: 1-3 segundos
- **Rede /24**: 2-5 minutos
- **Deep scan**: +30-60 segundos por vulnerabilidade

### **Limites de Recursos**
- **CPU**: ~50% durante scans intensos
- **Memória**: ~200MB base + 50MB por job ativo
- **Rede**: Rate limit configurável

---

## 📚 Documentação Adicional

- **Swagger UI**: http://localhost:9082/docs/
- **API Reference**: Todos endpoints documentados
- **Try it out**: Interface interativa
- **Examples**: Casos de uso reais

## 🤝 Contribuindo

1. **Issues**: Reportar bugs e sugestões
2. **Testing**: Validar novos probes
3. **Documentation**: Melhorar guias
4. **Security**: Reportar vulnerabilidades responsavelmente

---

**🎯 Este guia demonstra o poder da Naabu API para descoberta e validação de exposições de serviço em larga escala!**