# 🔍 Naabu API - Serviço de Port Scanning

Um serviço HTTP completo em Go para realizar port scanning utilizando o SDK oficial da ProjectDiscovery (naabu/v2).

## ⚠️ AVISO IMPORTANTE DE SEGURANÇA
Esta ferramenta realiza **port scanning**. Use **APENAS** em redes próprias ou com autorização explícita por escrito. O uso não autorizado pode ser **ILEGAL** em muitas jurisdições. Leia [SECURITY.md](SECURITY.md) obrigatoriamente antes de usar.

---

## 🚀 Setup Rápido (3 comandos!)

```bash
# 1. Executar script de setup automático
chmod +x setup.sh && ./setup.sh

# 2. Testar se está funcionando
curl http://localhost:8081/health

# 3. Fazer um scan teste
curl -X POST http://localhost:8081/scan \
  -H "Content-Type: application/json" \
  -d '{"ips":["127.0.0.1"], "ports":"22,80,443"}'
```

**🎉 Pronto! O serviço está rodando na porta 8081**

---

## 📋 O que você recebeu

### ✅ **Serviço Completo**
- **API REST** com endpoints `/scan` e `/health`
- **SDK nativo** naabu/v2 (sem subprocessos)
- **Logging estruturado** com request IDs únicos
- **Validações robustas** de entrada
- **Docker** pronto para produção
- **Testes** unitários e de integração
- **Documentação** completa

### ✅ **Funcionalidades**
- Scan de **múltiplos IPs** simultaneamente
- Suporte a **ranges de portas** (ex: `80-85`)
- **Portas padrão** quando não especificadas
- **Timeouts** configuráveis (anti-DoS)
- **Graceful shutdown**
- **Métricas** de performance

### ✅ **Segurança**
- Validação rigorosa de IPs e portas
- Limite de 100 IPs por requisição
- Timeouts agressivos (5min máximo)
- Logs de auditoria completos
- Usuário não-root no container

---

## 🐳 Docker (Recomendado)

### Opção 1: Setup Automático
```bash
./setup.sh  # Faz tudo automaticamente
```

### Opção 2: Docker Compose
```bash
docker-compose up -d    # Subir serviço
docker-compose logs -f  # Ver logs
docker-compose down     # Parar serviço
```

### Opção 3: Docker Manual
```bash
docker build -t naabu-api .
docker run -d -p 8081:8080 --name naabu-api naabu-api
```

---

## 📡 Como Usar a API

### 1. Health Check
```bash
curl http://localhost:8081/health
```

### 2. Scan Básico
```bash
curl -X POST http://localhost:8081/scan \
  -H "Content-Type: application/json" \
  -d '{"ips":["127.0.0.1"], "ports":"22,80,443"}'
```

### 3. Scan Múltiplos IPs
```bash
curl -X POST http://localhost:8081/scan \
  -H "Content-Type: application/json" \
  -d '{"ips":["127.0.0.1","8.8.8.8"], "ports":"53,80,443"}'
```

### 4. Range de Portas
```bash
curl -X POST http://localhost:8081/scan \
  -H "Content-Type: application/json" \
  -d '{"ips":["127.0.0.1"], "ports":"80-85,443,8080"}'
```

### 5. Exemplos Automatizados
```bash
chmod +x examples/curl_examples.sh
./examples/curl_examples.sh
```

---

## 📊 Exemplo de Resposta

```json
{
  "results": [
    {
      "ip": "127.0.0.1",
      "ports": [
        {"port": 22, "protocol": "tcp", "state": "open"},
        {"port": 80, "protocol": "tcp", "state": "open"}
      ],
      "error": ""
    }
  ],
  "summary": {
    "total_ips": 1,
    "total_ports": 3,
    "open_ports": 2,
    "duration_ms": 1250,
    "errors": 0
  },
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

---

## 🛠️ Comandos Úteis

```bash
# Desenvolvimento
make build              # Compilar
make run                # Executar local
make test               # Rodar testes
make deps               # Instalar dependências

# Docker
make docker-build       # Build imagem
make docker-run         # Executar container
make docker-logs        # Ver logs
make docker-stop        # Parar container

# Docker Compose
make docker-compose-up  # Subir serviços
make docker-compose-down # Parar serviços
make docker-compose-logs # Ver logs

# Ver todos os comandos
make help
```

---

## 🚨 Troubleshooting

### Container não inicia
```bash
docker logs naabu-api          # Ver erros
netstat -tulpn | grep 8081     # Verificar porta
docker run -p 9090:8080 naabu-api  # Usar porta diferente
```

### Permissões (Linux)
```bash
# Se houver erros de permissão para raw sockets
docker run --cap-add=NET_RAW --cap-add=NET_ADMIN -p 8081:8080 naabu-api
```

### API não responde
```bash
curl -v http://localhost:8081/health  # Debug conexão
docker ps                             # Verificar container
docker inspect naabu-api              # Detalhes do container
```

---

## 🔒 Considerações de Segurança

### ⚠️ **NUNCA FAÇA ISSO:**
- ❌ Usar sem autorização
- ❌ Executar em ambiente público sem autenticação
- ❌ Fazer scan de IPs que não são seus
- ❌ Ignorar logs e alertas

### ✅ **SEMPRE FAÇA ISSO:**
- ✅ Obter autorização por escrito
- ✅ Usar apenas em redes próprias
- ✅ Monitorar logs de uso
- ✅ Implementar autenticação em produção
- ✅ Configurar firewall apropriado

### 📚 **Leitura Obrigatória:**
- [SECURITY.md](SECURITY.md) - Guia completo de segurança
- [examples/](examples/) - Exemplos de uso seguro

---

## 📁 Estrutura do Projeto

```
naabu-api/
├── main.go                    # Servidor HTTP principal
├── docker-compose.yml        # Docker Compose
├── setup.sh                  # Script de setup automático
├── pkg/logger/               # Logger estruturado
├── internal/
│   ├── models/               # Modelos de dados
│   ├── handlers/             # Handlers HTTP + testes
│   └── scanner/              # Serviço de scanning + testes
├── examples/
│   └── curl_examples.sh      # Exemplos de uso
├── integration_test.go       # Testes de integração
├── Makefile                  # Comandos utilitários
├── Dockerfile                # Imagem Docker
├── README.md                 # Documentação principal
└── SECURITY.md              # Guia de segurança
```

---

## 🎯 Próximos Passos

1. **Teste básico**: Execute `./setup.sh` e teste a API
2. **Leia a segurança**: Estude [SECURITY.md](SECURITY.md) cuidadosamente
3. **Execute exemplos**: Use `./examples/curl_examples.sh`
4. **Para produção**: Implemente autenticação e HTTPS
5. **Monitore**: Configure logs centralizados

---

## ⚖️ Licença e Responsabilidade

Este projeto é desenvolvido para fins **educacionais** e de **segurança defensiva**. 

**Você é 100% responsável pelo uso desta ferramenta.** Use com sabedoria, responsabilidade e sempre dentro da lei.

**Desenvolvido com ❤️ para a comunidade de segurança.**