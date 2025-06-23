#!/bin/bash

# Exemplos de uso da API naabu

BASE_URL="http://localhost:8081"

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