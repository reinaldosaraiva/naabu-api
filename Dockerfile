# Multi-stage build para otimizar tamanho da imagem
FROM golang:1.21-alpine AS builder

# Instalar dependências necessárias incluindo libpcap
RUN apk add --no-cache git ca-certificates gcc musl-dev libpcap-dev

# Definir diretório de trabalho
WORKDIR /app

# Copiar go mod e sum files
COPY go.mod go.sum ./

# Download de dependências
RUN go mod download

# Copiar código fonte
COPY . .

# Build do aplicativo (CGO habilitado para libpcap)
RUN CGO_ENABLED=1 GOOS=linux go build -a -o main .

# Imagem final
FROM alpine:latest

# Instalar ca-certificates e libpcap para runtime
RUN apk --no-cache add ca-certificates libpcap

# Criar usuário não-root
RUN adduser -D -s /bin/sh appuser

WORKDIR /root/

# Copiar binário da imagem builder
COPY --from=builder /app/main .

# Mudar para usuário não-root
USER appuser

# Expor porta
EXPOSE 8080

# Comando de execução
CMD ["./main"]