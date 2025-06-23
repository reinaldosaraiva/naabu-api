# Naabu API 🔍

Um serviço HTTP minimalista em Go para realizar port scanning utilizando o SDK oficial da ProjectDiscovery (naabu/v2).

## ⚠️ AVISO IMPORTANTE
Esta ferramenta realiza **port scanning**. Use **APENAS** em redes próprias ou com autorização explícita. O uso não autorizado pode ser ilegal. Leia [SECURITY.md](SECURITY.md) antes de usar.

## 🚀 Quick Start

### Setup Automático (Mais Fácil!)

```bash
# 1. Clonar/baixar os arquivos do projeto
# 2. Executar script de setup
chmod +x setup.sh
./setup.sh

# Pronto! O serviço estará rodando em http://localhost:8081
```

### Setup Manual com Docker

```bash
# 1. Clonar/baixar os arquivos do projeto
# 2. Build da imagem
docker build -t naabu-api .

# 3. Executar container
docker run -p 8081:8080 naabu-api

# 4. Testar API
curl -X POST http://localhost:8081/scan \
  -H "Content-Type: application/json" \
  -d '{"ips":["127.0.0.1"], "ports":"80,443"}'
```

### Executando Localmente

```bash
# 1. Instalar dependências do sistema (Ubuntu/Debian)
sudo apt-get update && sudo apt-get install -y libpcap-dev

# 2. Instalar dependências Go
make deps

# 3. Compilar
make build

# 4. Executar
make run
# OU
./build/naabu-api
```

## 📋 Características

- **API REST**: Endpoint simples para scan de portas
- **SDK Nativo**: Usa naabu/v2 diretamente, sem subprocessos
- **Logging Estruturado**: Logs JSON com contexto por requisição
- **Validação Robusta**: Validação de IPs e portas
- **Testes Completos**: Testes unitários e de integração
- **Graceful Shutdown**: Finalização controlada do servidor
- **Segurança**: Validações de entrada e limites de requisição

## Estrutura do Projeto

```
naabu-api/
├── main.go                     # Ponto de entrada da aplicação
├── go.mod                      # Dependências do módulo
├── Makefile                    # Comandos de build e teste
├── Dockerfile                  # Imagem Docker
├── pkg/
│   └── logger/                 # Logger estruturado
│       └── logger.go
├── internal/
│   ├── models/                 # Modelos de dados
│   │   └── models.go
│   ├── handlers/               # Handlers HTTP
│   │   ├── handlers.go
│   │   └── handlers_test.go
│   └── scanner/                # Serviço de scanning
│       ├── service.go
│       └── service_test.go
├── examples/
│   └── curl_examples.sh        # Exemplos de uso
└── integration_test.go         # Testes de integração
```

## API

### POST /scan

Executa scan de portas nos IPs especificados.

**Requisição:**
```json
{
  "ips": ["192.168.1.1", "10.0.0.1"],
  "ports": "80,443,22-25"
}
```

**Resposta:**
```json
{
  "results": [
    {
      "ip": "192.168.1.1",
      "ports": [
        {
          "port": 80,
          "protocol": "tcp",
          "state": "open"
        }
      ],
      "error": ""
    }
  ],
  "summary": {
    "total_ips": 1,
    "total_ports": 3,
    "open_ports": 1,
    "duration_ms": 1250,
    "errors": 0
  },
  "request_id": "uuid-da-requisição"
}
```

### GET /health

Verifica o status do serviço.

**Resposta:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

## 🐳 Docker

### Build e Execução Manual

```bash
# Build da imagem
docker build -t naabu-api .

# Executar container (porta 8081 no host -> 8080 no container)
docker run -d \
  --name naabu-api-container \
  -p 8081:8080 \
  --restart unless-stopped \
  naabu-api

# Ver logs
docker logs -f naabu-api-container

# Parar container
docker stop naabu-api-container

# Remover container
docker rm naabu-api-container
```

### Usando Docker Compose

Crie um arquivo `docker-compose.yml`:

```yaml
version: '3.8'
services:
  naabu-api:
    build: .
    ports:
      - "8081:8080"
    restart: unless-stopped
    environment:
      - ENV=production
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

```bash
# Subir serviço
docker-compose up -d

# Ver logs
docker-compose logs -f

# Parar serviço
docker-compose down
```

## 📡 Como Usar a API

### 1. Health Check

```bash
curl http://localhost:8081/health
```

**Resposta:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

### 2. Scan Básico

```bash
curl -X POST http://localhost:8081/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["127.0.0.1"],
    "ports": "22,80,443"
  }'
```

### 3. Scan de Múltiplos IPs

```bash
curl -X POST http://localhost:8081/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["127.0.0.1", "8.8.8.8"],
    "ports": "53,80,443"
  }'
```

### 4. Scan com Range de Portas

```bash
curl -X POST http://localhost:8081/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["127.0.0.1"],
    "ports": "80-85,443,8080"
  }'
```

### 5. Scan com Portas Padrão

```bash
curl -X POST http://localhost:8081/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["127.0.0.1"]
  }'
```

### Exemplos Automatizados

```bash
# Executar todos os exemplos
chmod +x examples/curl_examples.sh
./examples/curl_examples.sh
```

## 🔧 Desenvolvimento Local

### Pré-requisitos

- Go 1.21+
- libpcap-dev (Ubuntu/Debian) ou libpcap (macOS)

### Setup

```bash
# Clonar projeto
git clone <repo-url>
cd naabu-api

# Instalar dependências
make deps

# Executar testes
make test

# Compilar
make build

# Executar
make run
```

### Comandos Disponíveis

```bash
make help          # Ver todos os comandos
make build          # Compilar aplicação
make run            # Executar aplicação
make test           # Executar todos os testes
make test-unit      # Testes unitários
make test-integration # Testes de integração
make docker-build   # Build Docker
make clean          # Limpar arquivos de build
```

## Configuração

### Variáveis de Ambiente

- `ENV=production`: Ativa logs em formato JSON
- `PORT=8080`: Porta do servidor (padrão: 8080)

### Limites

- **Máximo de IPs por requisição**: 100
- **Timeout de scan**: 5 minutos
- **Timeout de conexão**: 5 segundos
- **Rate limit**: 1000 conexões/segundo

## Pontos Críticos de Segurança

### Entrada de Dados
- ✅ Validação rigorosa de IPs
- ✅ Sanitização de portas
- ✅ Limite de IPs por requisição
- ✅ Timeouts para evitar DoS

### Rede
- ⚠️ **ATENÇÃO**: Ferramenta de scanning pode ser considerada maliciosa
- ⚠️ Use apenas em redes próprias ou com autorização
- ⚠️ Considere implementar autenticação/autorização
- ⚠️ Monitore logs para uso abusivo

### Recursos
- ✅ Limite de goroutines (via rate limit)
- ✅ Timeouts em todas as operações
- ✅ Graceful shutdown

## Pontos de Performance

### Otimizações Implementadas
- Scanning paralelo por IP
- Rate limiting configurável
- Timeouts agressivos
- Pools de conexão (naabu internal)

### Métricas
- Duração de cada scan
- Contadores de sucesso/erro
- Request ID para rastreamento

### Possíveis Melhorias
- Cache de resultados
- Metrics endpoint (Prometheus)
- Rate limiting por IP cliente
- Database para histórico

## Desenvolvimento

### Testes

```bash
# Testes unitários
make test-unit

# Testes de integração
make test-integration

# Coverage
make test-coverage

# Benchmarks
make benchmark
```

### Qualidade de Código

```bash
# Formatação
make fmt

# Linting
make lint

# Security check
make security

# Vet
make vet
```

### Comandos Docker no Makefile

```bash
make docker-build          # Build da imagem
make docker-run            # Executar container (foreground)
make docker-run-detached   # Executar container (background)
make docker-stop           # Parar container
make docker-remove         # Remover container
make docker-logs           # Ver logs do container
make docker-compose-up     # Subir com docker-compose
make docker-compose-down   # Parar docker-compose
make docker-compose-logs   # Ver logs do docker-compose
```

## 🔍 Testando o Serviço

### Após subir o container:

```bash
# 1. Verificar se está rodando
curl http://localhost:8081/health

# 2. Teste rápido
curl -X POST http://localhost:8081/scan \
  -H "Content-Type: application/json" \
  -d '{"ips":["127.0.0.1"], "ports":"80,443"}'

# 3. Executar todos os exemplos
./examples/curl_examples.sh
```

### Resposta de Exemplo:

```json
{
  "results": [
    {
      "ip": "127.0.0.1",
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open"
        }
      ],
      "error": ""
    }
  ],
  "summary": {
    "total_ips": 1,
    "total_ports": 3,
    "open_ports": 1,
    "duration_ms": 1250,
    "errors": 0
  },
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

## 🛠️ Troubleshooting

### Container não inicia

```bash
# Verificar logs
docker logs naabu-api

# Verificar se a porta está em uso
netstat -tulpn | grep 8081

# Usar porta diferente
docker run -p 9090:8080 naabu-api
```

### Permissões (Linux)

Se houver erros de permissão para raw sockets:

```bash
# Executar com capabilities
docker run --cap-add=NET_RAW --cap-add=NET_ADMIN -p 8081:8080 naabu-api

# OU executar como privileged (menos seguro)
docker run --privileged -p 8081:8080 naabu-api
```

### Firewall/Rede

```bash
# Verificar conectividade
curl -v http://localhost:8081/health

# Verificar container
docker ps
docker inspect naabu-api
```

## 📊 Monitoramento

### Logs em Tempo Real

```bash
# Container direto
docker logs -f naabu-api-container

# Docker Compose
docker-compose logs -f

# Filtrar logs de erro
docker logs naabu-api-container 2>&1 | grep ERROR
```

### Health Check

O container inclui health check automático que verifica `/health` a cada 30 segundos.

```bash
# Ver status do health check
docker inspect naabu-api --format='{{.State.Health.Status}}'
```

## 🚀 Deploy em Produção

### Considerações Importantes

1. **Nunca execute em ambiente público sem autenticação**
2. **Use HTTPS em produção**
3. **Configure firewall apropriado**
4. **Monitore logs e métricas**
5. **Implemente rate limiting por IP**

### Exemplo com Nginx Proxy

```nginx
server {
    listen 443 ssl;
    server_name naabu-api.empresa.com;
    
    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 📚 Documentação Adicional

- [SECURITY.md](SECURITY.md) - Guia completo de segurança
- [examples/](examples/) - Exemplos de uso
- [Makefile](Makefile) - Comandos disponíveis

## 🤝 Contribuição

Este projeto é para fins educacionais e de segurança defensiva. Contribuições são bem-vindas para melhorar a segurança e funcionalidade.

## ⚖️ Licença

Este projeto é apenas para fins educacionais e de segurança defensiva. Use com responsabilidade e sempre obtenha autorização antes de realizar port scanning.