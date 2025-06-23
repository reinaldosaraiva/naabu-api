# Makefile para naabu-api

# Variáveis
APP_NAME=naabu-api
BUILD_DIR=./build
MAIN_FILE=./main.go

# Comandos de build
.PHONY: build clean test test-integration test-unit run fmt vet deps help

build: ## Compila o aplicativo
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(APP_NAME) $(MAIN_FILE)
	@echo "Build completed: $(BUILD_DIR)/$(APP_NAME)"

clean: ## Remove arquivos de build
	@echo "Cleaning build directory..."
	@rm -rf $(BUILD_DIR)
	@go clean

test: test-unit test-integration ## Executa todos os testes

test-unit: ## Executa testes unitários
	@echo "Running unit tests..."
	@go test -v ./internal/...

test-integration: ## Executa testes de integração
	@echo "Running integration tests..."
	@go test -v -tags=integration .

test-coverage: ## Executa testes com coverage
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

run: ## Executa o aplicativo
	@echo "Starting $(APP_NAME)..."
	@go run $(MAIN_FILE)

fmt: ## Formata o código
	@echo "Formatting code..."
	@go fmt ./...

vet: ## Executa go vet
	@echo "Running go vet..."
	@go vet ./...

deps: ## Instala dependências
	@echo "Installing dependencies..."
	@go mod tidy
	@go mod download

deps-update: ## Atualiza dependências
	@echo "Updating dependencies..."
	@go get -u ./...
	@go mod tidy

lint: ## Executa linter (requer golangci-lint)
	@echo "Running linter..."
	@golangci-lint run

security: ## Executa verificação de segurança (requer gosec)
	@echo "Running security check..."
	@gosec ./...

benchmark: ## Executa benchmarks
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem ./...

docker-build: ## Constrói imagem Docker
	@echo "Building Docker image..."
	@docker build -t $(APP_NAME) .

docker-run: ## Executa container Docker
	@echo "Running Docker container..."
	@docker run -p 8081:8080 $(APP_NAME)

docker-run-detached: ## Executa container Docker em background
	@echo "Running Docker container in background..."
	@docker run -d --name $(APP_NAME)-container -p 8081:8080 --restart unless-stopped $(APP_NAME)

docker-stop: ## Para container Docker
	@echo "Stopping Docker container..."
	@docker stop $(APP_NAME)-container || true

docker-remove: ## Remove container Docker
	@echo "Removing Docker container..."
	@docker rm $(APP_NAME)-container || true

docker-logs: ## Mostra logs do container
	@echo "Showing Docker container logs..."
	@docker logs -f $(APP_NAME)-container

docker-compose-up: ## Inicia serviços com docker-compose
	@echo "Starting services with docker-compose..."
	@docker-compose up -d

docker-compose-down: ## Para serviços com docker-compose
	@echo "Stopping services with docker-compose..."
	@docker-compose down

docker-compose-logs: ## Mostra logs do docker-compose
	@echo "Showing docker-compose logs..."
	@docker-compose logs -f

help: ## Mostra esta ajuda
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

# Default target
.DEFAULT_GOAL := help