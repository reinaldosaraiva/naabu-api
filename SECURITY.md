# Segurança e Pontos Críticos

## ⚠️ AVISOS IMPORTANTES

### Uso Responsável
- Esta ferramenta realiza **port scanning**, uma atividade que pode ser considerada **intrusiva**
- Use **APENAS** em redes próprias ou com **autorização explícita**
- O uso não autorizado pode ser **ilegal** em muitas jurisdições
- **NÃO** use contra sistemas de terceiros sem permissão

### Considerações Legais
- Port scanning pode ser interpretado como **tentativa de invasão**
- Alguns países têm leis específicas contra scanning não autorizado
- **Sempre** obtenha autorização por escrito antes de usar
- Considere implementar **autenticação/autorização** antes de produção

## 🔒 Implementações de Segurança

### Validação de Entrada
- ✅ **Validação rigorosa de IPs**: Impede IPs malformados
- ✅ **Sanitização de portas**: Valida ranges e valores
- ✅ **Limite de IPs**: Máximo 100 IPs por requisição
- ✅ **Timeouts agressivos**: Evita DoS e hanging

### Controle de Recursos
- ✅ **Rate limiting**: 1000 conexões/segundo por IP
- ✅ **Timeout de requisição**: 5 minutos máximo
- ✅ **Timeout de conexão**: 5 segundos por tentativa
- ✅ **Graceful shutdown**: Finalização controlada

### Logging e Auditoria
- ✅ **Request ID único**: Rastreamento de requisições
- ✅ **Logs estruturados**: JSON para análise
- ✅ **Log de IPs origem**: Auditoria de uso
- ✅ **Métricas de performance**: Duração e taxas de erro

## 🚨 Riscos e Mitigações

### Riscos Potenciais

1. **Uso Malicioso**
   - Risco: Scanning de redes não autorizadas
   - Mitigação: Implementar autenticação forte

2. **Sobrecarga de Rede**
   - Risco: Flood de requisições de scan
   - Mitigação: Rate limiting e timeouts

3. **Exposição do Serviço**
   - Risco: API pública acessível
   - Mitigação: Usar em redes privadas ou com VPN

4. **Log Poisoning**
   - Risco: Injection de dados maliciosos nos logs
   - Mitigação: Sanitização de logs implementada

### Melhorias de Segurança Recomendadas

#### Para Produção (Essencial)
- [ ] **Autenticação**: JWT ou API Key
- [ ] **Autorização**: Controle de acesso por usuário
- [ ] **HTTPS**: TLS 1.3 obrigatório
- [ ] **Rate Limiting por IP**: Limite por cliente
- [ ] **Whitelist de IPs**: Apenas ranges autorizados
- [ ] **WAF**: Web Application Firewall

#### Para Ambiente Corporativo
- [ ] **RBAC**: Role-Based Access Control
- [ ] **Audit Logs**: Logs de auditoria completos
- [ ] **Alertas**: Notificações de uso suspeito
- [ ] **Integração SIEM**: Logs centralizados
- [ ] **Compliance**: GDPR, SOC2, etc.

## 🛡️ Configuração Segura

### Variáveis de Ambiente Recomendadas
```bash
# Produção
ENV=production
PORT=8080
MAX_IPS_PER_REQUEST=10    # Reduzir em produção
SCAN_TIMEOUT=30000        # 30 segundos máximo
RATE_LIMIT=100            # Conexões por segundo
AUTH_REQUIRED=true        # Habilitar autenticação
```

### Configuração de Firewall
```bash
# Permitir apenas IPs específicos
iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

### Configuração de Proxy Reverso (Nginx)
```nginx
server {
    listen 443 ssl;
    server_name naabu-api.example.com;
    
    # Limites de rate
    limit_req_zone $binary_remote_addr zone=api:10m rate=1r/s;
    limit_req zone=api burst=5 nodelay;
    
    # Headers de segurança
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## 📊 Monitoramento de Segurança

### Métricas Importantes
- **Requests por IP**: Detectar uso abusivo
- **IPs únicos**: Monitorar dispersão geográfica
- **Taxas de erro**: Indicar tentativas maliciosas
- **Duração de scans**: Detectar padrões anômalos

### Alertas Recomendados
- Mais de 100 requests por IP/hora
- Scan de mais de 1000 portas
- Tentativas de scan em IPs privados
- Timeouts excessivos (>50% das requisições)

## 🚀 Deploy Seguro

### Docker Seguro
```dockerfile
# Usar imagem mínima
FROM alpine:latest

# Usuário não-root
RUN adduser -D -s /bin/sh appuser
USER appuser

# Capabilities mínimas
USER 1000:1000
```

### Kubernetes
```yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: naabu-api
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
```

## 📞 Contato de Segurança

Em caso de vulnerabilidades encontradas:
- **NÃO** divulgue publicamente
- Reporte de forma responsável
- Aguarde confirmação antes de disclosure

---

**Lembre-se**: Esta ferramenta é poderosa e deve ser usada com responsabilidade. Sempre considere as implicações legais e éticas antes do uso.