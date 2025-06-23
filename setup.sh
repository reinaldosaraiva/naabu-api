#!/bin/bash

# Script de setup rápido para Naabu API
set -e

echo "🔍 Naabu API - Setup Rápido"
echo "================================"

# Verificar se Docker está instalado
if ! command -v docker &> /dev/null; then
    echo "❌ Docker não encontrado. Por favor, instale o Docker primeiro."
    echo "   https://docs.docker.com/get-docker/"
    exit 1
fi

# Verificar se Docker Compose está disponível
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "⚠️  Docker Compose não encontrado. Usando Docker diretamente."
    USE_COMPOSE=false
else
    USE_COMPOSE=true
fi

echo "✅ Docker encontrado"

# Build da imagem
echo ""
echo "🔧 Fazendo build da imagem..."
docker build -t naabu-api . || {
    echo "❌ Erro no build da imagem"
    exit 1
}

echo "✅ Imagem criada com sucesso"

# Escolher método de execução
echo ""
if [ "$USE_COMPOSE" = true ]; then
    echo "🚀 Iniciando com Docker Compose..."
    docker-compose up -d || {
        echo "❌ Erro ao iniciar com Docker Compose"
        exit 1
    }
    echo "✅ Serviço iniciado com Docker Compose"
else
    echo "🚀 Iniciando container Docker..."
    
    # Parar container existente se houver
    docker stop naabu-api-container 2>/dev/null || true
    docker rm naabu-api-container 2>/dev/null || true
    
    docker run -d \
        --name naabu-api-container \
        -p 8081:8080 \
        --restart unless-stopped \
        naabu-api || {
        echo "❌ Erro ao iniciar container"
        exit 1
    }
    echo "✅ Container iniciado"
fi

# Aguardar serviço ficar disponível
echo ""
echo "⏳ Aguardando serviço ficar disponível..."
for i in {1..30}; do
    if curl -s http://localhost:8081/health > /dev/null 2>&1; then
        echo "✅ Serviço está respondendo!"
        break
    fi
    echo -n "."
    sleep 1
done

echo ""

# Teste básico
echo "🧪 Executando teste básico..."
HEALTH_RESPONSE=$(curl -s http://localhost:8081/health)
if echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
    echo "✅ Health check passou!"
else
    echo "❌ Health check falhou"
    echo "Resposta: $HEALTH_RESPONSE"
fi

# Teste de scan
echo ""
echo "🔍 Executando teste de scan..."
SCAN_RESPONSE=$(curl -s -X POST http://localhost:8081/scan \
    -H "Content-Type: application/json" \
    -d '{"ips":["127.0.0.1"], "ports":"22,80"}' | head -c 100)

if echo "$SCAN_RESPONSE" | grep -q "results"; then
    echo "✅ Teste de scan passou!"
else
    echo "❌ Teste de scan falhou"
    echo "Resposta: $SCAN_RESPONSE"
fi

echo ""
echo "🎉 Setup concluído!"
echo ""
echo "📡 Serviço disponível em: http://localhost:8081"
echo ""
echo "🔗 Links úteis:"
echo "   Health: http://localhost:8081/health"
echo "   Logs:   docker logs -f naabu-api-container"
if [ "$USE_COMPOSE" = true ]; then
    echo "   Parar:  docker-compose down"
else
    echo "   Parar:  docker stop naabu-api-container"
fi
echo ""
echo "📖 Exemplos de uso:"
echo "   ./examples/curl_examples.sh"
echo ""
echo "⚠️  LEMBRE-SE: Use apenas em redes próprias ou com autorização!"
echo "   Leia SECURITY.md para mais informações."