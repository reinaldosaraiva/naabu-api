# Multi-stage build para otimizar tamanho da imagem
FROM golang:1.24-bookworm AS builder

# Instalar dependências necessárias incluindo libpcap
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Definir diretório de trabalho
WORKDIR /app

# Copiar go mod e sum files
COPY go.mod go.sum ./

# Download de dependências
RUN go mod download

# Copiar código fonte
COPY . .

# Build do aplicativo
RUN CGO_ENABLED=1 go build -o naabu-api .

# Imagem final - usando Debian slim
FROM debian:bookworm-slim

# Instalar runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpcap0.8 \
    nmap \
    nmap-common \
    sqlite3 \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Criar usuário não-root
RUN useradd -m -s /bin/bash appuser

# Criar diretório para SQLite database
RUN mkdir -p /data && chown appuser:appuser /data

WORKDIR /app

# Copiar binário da imagem builder
COPY --from=builder /app/naabu-api .

# Copiar documentação
COPY --chown=appuser:appuser docs /app/docs

# Mudar para usuário não-root
USER appuser

# Volume para dados persistentes
VOLUME ["/data"]

# Variáveis de ambiente padrão
ENV DB_DRIVER=sqlite
ENV DB_NAME=/data/naabu_api.db
ENV PORT=8080
ENV LOG_LEVEL=info

# Expor porta
EXPOSE 8080

# Comando de execução
CMD ["./naabu-api"]