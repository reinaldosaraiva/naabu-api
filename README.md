# Naabu API - Descoberta de Exposições de Serviço 🔍

API REST para descoberta e validação de exposições de serviço em larga escala com detecção automática de vulnerabilidades.

## ⚠️ AVISO IMPORTANTE
Esta ferramenta realiza **port scanning** e **detecção de vulnerabilidades**. Use **APENAS** em redes próprias ou com autorização explícita. O uso não autorizado pode ser ilegal.

## 🚀 Quick Start

### Docker Compose (Recomendado)

```bash
# 1. Clonar repositório
git clone <repo-url>
cd naabu-api

# 2. Iniciar serviço
docker compose up -d

# 3. Verificar status
curl http://localhost:8082/health

# API estará disponível em http://localhost:8082
# Documentação Swagger em http://localhost:8082/docs/
```

### Atualizar Versão em Produção

```bash
# 1. Parar versão atual
docker compose down

# 2. Atualizar código
git pull origin master

# 3. Reconstruir e iniciar
docker compose up -d --build

# 4. Verificar saúde
curl http://localhost:8082/health
```

## 📋 Características Principais

- ✅ **Port Scanning com Naabu** - Scanner rápido e eficiente
- ✅ **6 Probes de Vulnerabilidade** - FTP, VNC, RDP, LDAP, PPTP, rsync
- ✅ **Deep Scanning Automático** - Nmap NSE scripts quando vulnerabilidades são detectadas
- ✅ **Suporte Completo** - IPs, hostnames e notação CIDR
- ✅ **Worker Pools** - 3 pools especializados para máxima performance
- ✅ **API Assíncrona** - Jobs em background com tracking por UUID
- ✅ **Documentação Swagger** - Interface interativa em `/docs/`

## 📡 Guia Prático de Uso

### 1. Scan Básico de IP

```bash
curl -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.1"],
    "ports": "80,443,22"
  }'
```

**Resposta:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "message": "Job criado com sucesso"
}
```

### 2. Scan com Hostname

```bash
curl -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["google.com"],
    "ports": "80,443"
  }'
```

### 3. Scan de Rede (CIDR)

```bash
curl -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.0/24"],
    "ports": "22,3389,5900"
  }'
```

### 4. Scan Completo com Probes

```bash
curl -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.1", "example.com", "10.0.0.0/24"],
    "ports": "21,22,80,389,443,873,1723,3389,5900-5910",
    "enable_probes": true,
    "enable_deep_scan": true
  }'
```

### 5. Verificar Status do Job

```bash
# Substituir pelo scan_id recebido
curl http://localhost:8082/api/v1/jobs/550e8400-e29b-41d4-a716-446655440000
```

### 6. Listar Jobs Ativos

```bash
curl http://localhost:8082/api/v1/jobs
```

### 7. Métricas do Sistema

```bash
curl http://localhost:8082/metrics
```

## 🔍 Probes de Vulnerabilidade

A API detecta automaticamente as seguintes vulnerabilidades:

| Probe | Porta | Vulnerabilidade Detectada |
|-------|-------|---------------------------|
| **FTP** | 21 | Login anônimo habilitado |
| **VNC** | 5900-5999 | Sem autenticação |
| **RDP** | 3389 | Criptografia fraca (sem TLS/CredSSP) |
| **LDAP** | 389, 636 | Bind anônimo permitido |
| **PPTP** | 1723 | VPN legacy vulnerável |
| **rsync** | 873 | Módulos públicos acessíveis |
| **SSH** | 22 | Cifras fracas (CBC, 3DES) e MACs fracos (MD5, SHA1-96) |

## 🚨 Novo: Detecção de SSH com Algoritmos Fracos

### Como usar o SSH Probe

```bash
# Scan básico para SSH
curl -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.1"],
    "ports": "22",
    "enable_probes": true
  }'

# Scan de múltiplos servidores SSH
curl -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["github.com", "gitlab.com", "192.168.1.0/24"],
    "ports": "22,2222",
    "enable_probes": true
  }'
```

### O que o SSH Probe detecta

1. **Cifras Fracas (US-7)**:
   - CBC mode: aes128-cbc, aes192-cbc, aes256-cbc
   - Legacy: 3des-cbc, blowfish-cbc, cast128-cbc
   - Inseguras: arcfour, arcfour128, arcfour256

2. **MACs Fracos (US-8)**:
   - MD5: hmac-md5, hmac-md5-96
   - SHA1 curto: hmac-sha1-96
   - Obsoletos: hmac-ripemd160, umac-64

### Exemplo de Resultado Vulnerável

```json
{
  "host": "192.168.1.1",
  "port": 22,
  "probe_type": "ssh",
  "service_name": "ssh",
  "service_version": "SSH-2.0-OpenSSH_7.4",
  "is_vulnerable": true,
  "evidence": "SSH server supports weak ciphers: aes128-cbc, 3des-cbc | All server ciphers: aes128-cbc, aes256-cbc, 3des-cbc, aes128-ctr | SSH server supports weak MAC algorithms: hmac-md5, hmac-sha1-96 | All server MACs: hmac-md5, hmac-sha1-96, hmac-sha2-256"
}
```

## 🎯 Testando os 6 Requisitos do Épico

### Requisito 1: API aceita IPs, Hostnames e CIDRs

```bash
# Teste com IP
curl -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["8.8.8.8"], "ports": "53,443"}'

# Teste com Hostname
curl -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["google.com"], "ports": "80,443"}'

# Teste com CIDR
curl -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["192.168.1.0/24"], "ports": "22,80"}'

# Teste misto (IP + Hostname + CIDR)
curl -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["8.8.8.8", "example.com", "10.0.0.0/30"], "ports": "80,443"}'
```

### Requisito 2: Sistema de Worker Pools

```bash
# Verificar pools ativos nas métricas
curl http://localhost:8082/metrics | jq '.'

# Ver logs dos workers em ação
docker compose logs -f | grep -E "(worker|pool|dispatcher)"

# Criar múltiplos jobs para ver workers paralelos
for i in {1..5}; do
  curl -X POST http://localhost:8082/scan \
    -H "Content-Type: application/json" \
    -d "{\"ips\": [\"192.168.1.$i\"], \"ports\": \"80\"}" &
done
```

### Requisito 3: Resultados com Detecção de Vulnerabilidades

```bash
# 1. Criar scan com probes habilitados
SCAN_ID=$(curl -s -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["scanme.nmap.org"],
    "ports": "21,22,80,389,873,1723,3389,5900",
    "enable_probes": true
  }' | jq -r '.scan_id')

echo "Scan ID: $SCAN_ID"

# 2. Aguardar 30 segundos
sleep 30

# 3. Ver resultados detalhados
curl -s http://localhost:8082/api/v1/jobs/$SCAN_ID | jq '{
  status: .status,
  ports_found: .results.results[0].ports,
  vulnerabilities: .probe_results[] | select(.is_vulnerable == true)
}'
```

### Requisito 4: Deep Scan Automático com Nmap

```bash
# 1. Scan em alvo com vulnerabilidade conhecida
SCAN_ID=$(curl -s -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["testphp.vulnweb.com"],
    "ports": "21,80,443",
    "enable_probes": true,
    "enable_deep_scan": true
  }' | jq -r '.scan_id')

# 2. Aguardar processamento
sleep 60

# 3. Ver deep scan results
curl -s http://localhost:8082/api/v1/jobs/$SCAN_ID | jq '.deep_scans'
```

### Requisito 5: Artefatos XML do Nmap

```bash
# Continuar do scan anterior ou criar novo
curl -s http://localhost:8082/api/v1/jobs/$SCAN_ID | jq -r '.deep_scans[0].xml_output' > nmap_output.xml

# Ver scripts NSE executados
curl -s http://localhost:8082/api/v1/jobs/$SCAN_ID | jq '.deep_scans[0].nse_scripts'

# Validar XML
xmllint --noout nmap_output.xml && echo "XML válido!"
```

### Requisito 6: Todos os Probes Funcionando (Agora com SSH!)

```bash
# Criar arquivo com alvos de teste para cada probe
cat > test_all_probes.sh << 'EOF'
#!/bin/bash

echo "=== Testando todos os 7 probes ==="

# FTP Probe (porta 21)
echo -e "\n1. Testando FTP..."
curl -s -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["ftp.debian.org"], "ports": "21", "enable_probes": true}'

# VNC Probe (porta 5900)
echo -e "\n2. Testando VNC..."
curl -s -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["192.168.1.100"], "ports": "5900-5910", "enable_probes": true}'

# RDP Probe (porta 3389)  
echo -e "\n3. Testando RDP..."
curl -s -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["192.168.1.10"], "ports": "3389", "enable_probes": true}'

# LDAP Probe (porta 389)
echo -e "\n4. Testando LDAP..."
curl -s -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["ldap.forumsys.com"], "ports": "389", "enable_probes": true}'

# PPTP Probe (porta 1723)
echo -e "\n5. Testando PPTP..."
curl -s -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["192.168.1.1"], "ports": "1723", "enable_probes": true}'

# rsync Probe (porta 873)
echo -e "\n6. Testando rsync..."
curl -s -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["rsync.samba.org"], "ports": "873", "enable_probes": true}'

# SSH Probe (porta 22) - NOVO!
echo -e "\n7. Testando SSH (cifras e MACs fracos)..."
curl -s -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["github.com", "192.168.1.1"], "ports": "22", "enable_probes": true}'

echo -e "\n\nTodos os scans criados! Use 'curl http://localhost:8082/api/v1/jobs' para ver status"
EOF

chmod +x test_all_probes.sh
./test_all_probes.sh
```

### Verificando Resultados Completos

```bash
# Listar todos os jobs para pegar IDs
curl -s http://localhost:8082/api/v1/jobs | jq -r '.jobs[] | "\(.scan_id) - \(.status)"'

# Ver resumo de vulnerabilidades encontradas
for job in $(curl -s http://localhost:8082/api/v1/jobs | jq -r '.jobs[].scan_id'); do
  echo "=== Job: $job ==="
  curl -s http://localhost:8082/api/v1/jobs/$job | jq '{
    status: .status,
    vulnerabilities: [.probe_results[] | select(.is_vulnerable == true) | {
      host: .host,
      port: .port,
      probe: .probe_type,
      evidence: .evidence
    }]
  }'
done
```

## 📊 Formato de Resposta

### Resposta de Scan Criado
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "message": "Job criado com sucesso"
}
```

### Status do Job
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "created_at": "2025-06-29T10:30:00Z",
  "completed_at": "2025-06-29T10:30:45Z",
  "results": {
    "results": [
      {
        "ip": "192.168.1.1",
        "ports": [
          {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh"
          }
        ]
      }
    ],
    "summary": {
      "total_ips": 1,
      "open_ports": 1,
      "duration_ms": 45000
    }
  },
  "probe_results": [
    {
      "host": "192.168.1.1",
      "port": 21,
      "probe_type": "ftp",
      "service_name": "vsftpd",
      "service_version": "3.0.3",
      "is_vulnerable": true,
      "evidence": "Anonymous login allowed"
    }
  ],
  "deep_scans": [
    {
      "host": "192.168.1.1",
      "port": 21,
      "nse_scripts": ["ftp-anon", "ftp-bounce"],
      "xml_output": "<nmaprun>...</nmaprun>"
    }
  ]
}
```

## 🛠️ Endpoints da API

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `POST` | `/scan` | Criar novo job de scan |
| `GET` | `/health` | Verificar saúde da API |
| `GET` | `/metrics` | Obter métricas do sistema |
| `GET` | `/api/v1/jobs` | Listar todos os jobs |
| `GET` | `/api/v1/jobs/:id` | Detalhes de um job |
| `DELETE` | `/api/v1/jobs/:id` | Cancelar um job |
| `GET` | `/docs/` | Documentação Swagger |

## 📝 Parâmetros de Scan

| Campo | Tipo | Obrigatório | Descrição |
|-------|------|-------------|-----------|
| `ips` | string[] | Sim | Lista de IPs, hostnames ou CIDRs |
| `ports` | string | Não | Portas a escanear (default: portas comuns) |
| `enable_probes` | boolean | Não | Ativar detecção de vulnerabilidades |
| `enable_deep_scan` | boolean | Não | Ativar Nmap NSE para vulnerabilidades |

### Formato de Portas
- Individual: `"80,443,8080"`
- Range: `"1-1000"`
- Misto: `"22,80,443,1000-2000,8080"`

### Formato de Alvos
- IP: `"192.168.1.1"`
- IPv6: `"2001:db8::1"`
- Hostname: `"example.com"`
- CIDR: `"10.0.0.0/24"`

## 🐳 Docker

### Variáveis de Ambiente

```yaml
# docker-compose.yml
environment:
  - ENV=production
  - PORT=8080
  - DB_DRIVER=sqlite
  - QUICK_SCAN_WORKERS=5
  - PROBE_WORKERS=10
  - DEEP_SCAN_WORKERS=3
  - NAABU_RATE_LIMIT=1000
  - NAABU_TIMEOUT=5m
```

### Comandos Úteis

```bash
# Ver logs
docker compose logs -f

# Executar shell no container
docker compose exec naabu-api /bin/bash

# Ver estatísticas
docker stats naabu-api

# Backup do banco
docker compose exec naabu-api sqlite3 /data/naabu_api.db .dump > backup.sql
```

## 🔧 Desenvolvimento

### Pré-requisitos
- Go 1.21+
- Docker e Docker Compose
- libpcap-dev (Linux) ou libpcap (macOS)

### Setup Local

```bash
# Instalar dependências
make deps

# Executar testes
make test

# Build local
make build

# Executar localmente
make run
```

### Comandos Make

```bash
make help              # Ver todos comandos
make test-unit         # Testes unitários
make test-integration  # Testes de integração
make test-coverage     # Relatório de cobertura
make lint              # Verificar código
make fmt               # Formatar código
```

## ⚠️ Segurança

### Boas Práticas
1. **NUNCA** execute em redes sem autorização
2. Use autenticação em produção
3. Configure firewall apropriado
4. Monitore logs para detectar abuso
5. Implemente rate limiting por cliente

### Limites de Segurança
- Máximo 100 alvos por requisição
- Timeout de 5 minutos por scan
- Rate limit de 1000 pacotes/segundo
- Validação rigorosa de entrada

## 📊 Monitoramento

### Health Check
```bash
# Verificar saúde
curl http://localhost:8082/health

# Métricas
curl http://localhost:8082/metrics | jq
```

### Logs Estruturados
```bash
# Ver logs em tempo real
docker compose logs -f

# Filtrar por scan_id
docker compose logs | grep "scan_id:550e8400"

# Filtrar erros
docker compose logs | grep "error"
```

## 🚀 Performance

### Worker Pools
- **Quick Scan**: 5 workers para descoberta rápida
- **Probe Pool**: 10 workers para detecção de serviços
- **Deep Scan**: 3 workers para análise profunda

### Otimizações
- Scanning paralelo por alvo
- Cache de resolução DNS
- Timeouts agressivos
- Rate limiting configurável

## 📚 Documentação Completa

- **Swagger UI**: http://localhost:8082/docs/
- **OpenAPI Spec**: http://localhost:8082/docs/swagger.yaml
- **Exemplos**: Ver pasta `examples/`

## 🤝 Suporte

Para questões e suporte:
- Issues: GitHub Issues
- Documentação: Wiki do projeto
- Swagger: http://localhost:8082/docs/

## ⚖️ Licença

Software para fins de segurança defensiva. Use com responsabilidade e sempre com autorização apropriada.