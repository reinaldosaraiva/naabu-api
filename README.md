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