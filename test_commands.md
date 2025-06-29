# Comandos para Testar Targets Específicos

## 🎯 Teste 1: Hostname + IP (api3.riskrate.com.br + 201.23.19.144)

```bash
curl -X POST http://localhost:8081/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": [
      "api3.riskrate.com.br",
      "201.23.19.144"
    ],
    "ports": "80,443,22,21,3389,5900",
    "enable_probes": true,
    "enable_deep_scan": true
  }'
```

## 🎯 Teste 2: Apenas Hostname

```bash
curl -X POST http://localhost:8081/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": [
      "api3.riskrate.com.br"
    ],
    "ports": "80,443,22",
    "enable_probes": true
  }'
```

## 🎯 Teste 3: Apenas IP

```bash
curl -X POST http://localhost:8081/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": [
      "201.23.19.144"
    ],
    "ports": "21,22,80,443,3389,5900",
    "enable_probes": true,
    "enable_deep_scan": true
  }'
```

## 🎯 Teste 4: Mix com Outros Formatos

```bash
curl -X POST http://localhost:8081/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": [
      "api3.riskrate.com.br",
      "201.23.19.144",
      "google.com",
      "127.0.0.1"
    ],
    "ports": "80,443",
    "enable_probes": false
  }'
```

## 🔍 Monitorar Status do Job

Após executar qualquer scan acima, use o `scan_id` retornado:

```bash
# Substitua {SCAN_ID} pelo ID retornado
curl http://localhost:8081/api/v1/jobs/{SCAN_ID}
```

## ✅ Health Check

```bash
curl http://localhost:8081/health
```

## 📊 Estatísticas

```bash
curl http://localhost:8081/api/v1/stats
```

## 🧪 Teste de Validação (deve falhar)

### Hostname inválido:
```bash
curl -X POST http://localhost:8081/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": [
      "invalid..hostname..com"
    ],
    "ports": "80"
  }'
```

### IP inválido:
```bash
curl -X POST http://localhost:8081/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": [
      "999.999.999.999"
    ],
    "ports": "80"
  }'
```

## 🚀 Comando Simples para Começar

```bash
curl -X POST http://localhost:8081/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"ips":["api3.riskrate.com.br","201.23.19.144"],"ports":"80,443","enable_probes":true}'
```