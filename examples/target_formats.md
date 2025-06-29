# Formatos de Target Aceitos pela API

O sistema **aceita múltiplos formatos** no campo `ips` da requisição:

## ✅ Formatos Suportados

### 1. Endereços IP (IPv4)
```json
{
  "ips": [
    "192.168.1.1",
    "10.0.0.1", 
    "8.8.8.8"
  ]
}
```

### 2. Endereços IP (IPv6)
```json
{
  "ips": [
    "2001:db8::1",
    "::1",
    "fe80::1"
  ]
}
```

### 3. Hostnames/Domínios
```json
{
  "ips": [
    "google.com",
    "example.org",
    "server.interno.empresa.com",
    "mail-server",
    "web01.lab"
  ]
}
```

### 4. Redes CIDR (IPv4)
```json
{
  "ips": [
    "192.168.1.0/24",
    "10.0.0.0/16", 
    "172.16.0.0/12"
  ]
}
```

### 5. Redes CIDR (IPv6)
```json
{
  "ips": [
    "2001:db8::/32",
    "fe80::/64"
  ]
}
```

### 6. Misturado (Recomendado)
```json
{
  "ips": [
    "192.168.1.0/24",
    "google.com",
    "10.0.0.1",
    "server.empresa.com",
    "2001:db8::1"
  ],
  "ports": "21,22,80,443,3389,5900",
  "enable_probes": true,
  "enable_deep_scan": true
}
```

## 🔍 Validação Implementada

### Regras de Validação:
- ✅ **IPv4/IPv6**: Valida usando `net.ParseIP()`
- ✅ **CIDR**: Valida usando `net.ParseCIDR()`  
- ✅ **Hostname**: Valida conforme RFC 1123
  - Máximo 253 caracteres total
  - Cada label máximo 63 caracteres
  - Permite: `a-z`, `A-Z`, `0-9`, `-`, `.`
  - Não pode começar/terminar com `-`

### Limites:
- **Máximo**: 100 targets por requisição (configurável)
- **Mínimo**: 1 target obrigatório
- **Hostname**: Até 253 caracteres
- **Label**: Até 63 caracteres por parte

## 📡 Exemplos de Uso

### Scan de Rede Corporativa
```bash
curl -X POST http://localhost:8081/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": [
      "192.168.0.0/24",
      "servidor-web.empresa.com", 
      "10.0.1.50"
    ],
    "ports": "21,22,80,443,3389,5900",
    "enable_probes": true,
    "enable_deep_scan": true
  }'
```

### Scan de Serviços Externos
```bash
curl -X POST http://localhost:8081/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": [
      "google.com",
      "github.com",
      "stackoverflow.com"
    ],
    "ports": "80,443",
    "enable_probes": false
  }'
```

### Scan de Lab/Desenvolvimento
```bash
curl -X POST http://localhost:8081/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": [
      "localhost",
      "127.0.0.1",
      "::1",
      "dev-server",
      "test-db.local"
    ],
    "enable_probes": true
  }'
```

## ⚠️ Notas Importantes

1. **Resolução DNS**: Hostnames são resolvidos pelo sistema durante o scan
2. **CIDR Expansion**: Redes CIDR são expandidas para IPs individuais
3. **IPv6**: Totalmente suportado em todos os componentes
4. **Performance**: Misturar muitos CIDRs grandes pode impactar performance
5. **Segurança**: Sempre obter autorização antes de escanear targets externos

## 🚀 Benefícios

- **Flexibilidade**: Aceita qualquer formato de target válido
- **Conveniência**: Não precisa resolver hostnames manualmente  
- **Escalabilidade**: Suporta redes inteiras via CIDR
- **Compatibilidade**: IPv4 e IPv6 nativamente suportados
- **Validação**: Rejeita targets malformados antes do scan